# -*- coding: utf-8 -*-
"""Local web UI for Mars/xlog log decryption with history and preview."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, stream_with_context

from script_runner import default_script, list_scripts, resolve_script, run_script

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / ".uploads"
HISTORY_FILE = UPLOAD_ROOT / "history.json"
DEVICE_ELOG_DIR = UPLOAD_ROOT / "device-elog"
DEVICE_ELOG_FILE = "latest.xlog"
DEVICE_PKG = "com.tcl.eshow"
DEVICE_REL_DIR = "files/elog"
DEVICE_ABS_DIR = "/data/data/com.tcl.eshow/files/elog"
_DEVICE_LIST_FAIL_MARKERS = (
    "not debuggable",
    "unknown package",
    "package not found",
    "is unknown",
    "inaccessible or not found",
    "permission denied",
    "no such file or directory",
    "not found",
    "invalid uid",
    "su: ",
    "error:",
)
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB
PREVIEW_LINES = 400
SEARCH_MAX_HITS = 2000

app = Flask(__name__)
app.secret_key = "easy-log-watch-local"
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

UPLOAD_ROOT.mkdir(exist_ok=True)
_history_lock = threading.Lock()
_legacy_scan_lock = threading.Lock()
_legacy_scanned = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _is_xlog_or_zip(name: str) -> bool:
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return (base.endswith(".xlog") and not base.endswith(".xlog.log")) or base.endswith(".zip")


_INVALID_WIN_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def _safe_segment(part: str) -> str:
    """Sanitize one path segment; keep Unicode (unlike secure_filename)."""
    s = _INVALID_WIN_CHARS.sub("_", (part or "").strip()).rstrip(". ")
    if not s or s in (".", ".."):
        return ""
    # Windows reserved device names
    if s.upper().split(".")[0] in {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }:
        s = "_" + s
    return s[:180]


def _safe_relpath(name: str) -> str:
    """Keep relative folder structure safely (for directory uploads)."""
    raw = (name or "file").replace("\\", "/")
    parts = [_safe_segment(p) for p in Path(raw).parts if p not in ("", ".", "..")]
    parts = [p for p in parts if p]
    return "/".join(parts) if parts else "file"


def _unique_relpath(work_dir: Path, rel: str) -> str:
    """Avoid silent overwrite when names collide."""
    candidate = rel
    stem = Path(rel)
    n = 1
    while (work_dir / candidate).exists():
        candidate = f"{stem.with_suffix('')}_{n}{stem.suffix}"
        n += 1
    return candidate


def _rel(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def _load_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_history(items: list[dict]) -> None:
    tmp = HISTORY_FILE.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, HISTORY_FILE)


def _upsert_job(job: dict) -> None:
    with _history_lock:
        items = _load_history()
        items = [x for x in items if x.get("id") != job["id"]]
        items.insert(0, job)
        _save_history(items)


def _get_job(job_id: str) -> dict | None:
    with _history_lock:
        for item in _load_history():
            if item.get("id") == job_id:
                return item
        return None


def _update_job_fields(job_id: str, **fields) -> dict | None:
    with _history_lock:
        items = _load_history()
        for item in items:
            if item.get("id") != job_id:
                continue
            for key, value in fields.items():
                item[key] = value
            _save_history(items)
            return item
        return None


def _job_dir(job_id: str) -> Path:
    # Only allow hex job ids (uuid4.hex) to avoid path tricks like ".."
    if not job_id or not re.fullmatch(r"[0-9a-fA-F]{16,64}", job_id):
        raise ValueError("invalid job id")
    path = (UPLOAD_ROOT / job_id).resolve()
    if not str(path).startswith(str(UPLOAD_ROOT.resolve())):
        raise ValueError("invalid job id")
    return path


def _external_allowlist(job: dict) -> set[str]:
    allowed: set[str] = set()

    def add(raw: object) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        allowed.add(_path_key(raw))

    for group in ("sources", "decoded"):
        for item in job.get(group) or []:
            if isinstance(item, dict):
                add(item.get("path"))
    add(job.get("zip"))
    return allowed


def _resolve_job_file(job_id: str, rel_path: str) -> Path:
    job = _get_job(job_id)
    if job and job.get("external"):
        if _path_key(rel_path) not in _external_allowlist(job):
            raise ValueError("invalid path")
        full = Path(rel_path).resolve()
        if not full.is_file():
            raise FileNotFoundError(rel_path)
        return full

    base = _job_dir(job_id)
    # normalize and reject absolute / traversal
    rel = Path(rel_path.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("invalid path")
    full = (base / rel).resolve()
    if not str(full).startswith(str(base.resolve())):
        raise ValueError("invalid path")
    if not full.is_file():
        raise FileNotFoundError(rel_path)
    return full


def _file_meta(path: Path, work_dir: Path, *, force_decoded: bool = False) -> dict:
    name = path.name
    if force_decoded or name.endswith(".xlog.log") or name.lower().endswith((".log", ".txt")):
        kind = "decoded"
    else:
        kind = "source"
    return {
        "name": name,
        "path": _rel(path, work_dir),
        "size": path.stat().st_size,
        "kind": kind,
    }


def _is_preview_text_name(name: str) -> bool:
    """Plaintext / already-decoded logs suitable for direct preview (not raw .xlog)."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    if not base or base in (".", ".."):
        return False
    if base.endswith(".xlog") and not base.endswith(".xlog.log"):
        return False
    return base.endswith(
        (
            ".log",
            ".txt",
            ".xlog.log",
            ".md",
            ".csv",
            ".json",
            ".text",
            ".out",
        )
    )


def _is_raw_xlog_name(name: str) -> bool:
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base.endswith(".xlog") and not base.endswith(".xlog.log")


def _unique_file(path: Path) -> Path:
    """Next free path beside ``path`` (``name_1.ext``, ``name_2.ext``, ...)."""
    if not path.exists():
        return path
    n = 1
    while True:
        cand = path.with_name(f"{path.stem}_{n}{path.suffix}")
        if not cand.exists():
            return cand
        n += 1


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path, *, avoid: Path | None = None) -> list[Path]:
    """Extract zip members into ``dest`` (the source file's directory).

    Rejects absolute paths and ``..``. Does not overwrite ``avoid`` (the zip
    itself) or an existing file of a different size.
    """
    dest = dest.resolve()
    avoid_key = ""
    if avoid is not None:
        try:
            avoid_key = str(avoid.resolve()).lower()
        except OSError:
            avoid_key = str(avoid).lower()
    written: list[Path] = []
    dest_prefix = str(dest) + os.sep

    for info in zf.infolist():
        name = (info.filename or "").replace("\\", "/")
        if not name or name.endswith("/"):
            continue
        if Path(name).is_absolute() or name.startswith("/") or name.startswith("../") or "/../" in name:
            continue
        parts = [p for p in Path(name).parts if p not in ("", ".", "..")]
        if not parts:
            continue
        target = (dest.joinpath(*parts)).resolve()
        target_key = os.path.normcase(str(target))
        if target_key != os.path.normcase(str(dest)) and not target_key.startswith(os.path.normcase(dest_prefix)):
            continue
        if avoid_key and str(target).lower() == avoid_key:
            target = _unique_file(target)
        elif target.exists():
            if not target.is_file():
                continue
            try:
                same_size = target.stat().st_size == info.file_size
            except OSError:
                same_size = False
            if not same_size:
                target = _unique_file(target)
            else:
                written.append(target)
                continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
        written.append(target)
    return written


def _xlogs_from_zip(zip_path: Path) -> list[Path]:
    """Unpack a zip into its own directory and return the .xlog files there."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        extracted = _safe_extract_zip(zf, zip_path.parent, avoid=zip_path)
    return [p for p in extracted if p.is_file() and _is_raw_xlog_name(p.name)]


def _extract_xlogs(work_dir: Path, uploaded_path: Path) -> list[Path]:
    """Collect .xlog files. Zips unpack beside the archive, not into a side folder."""
    del work_dir  # layout follows the uploaded file's own directory
    if uploaded_path.suffix.lower() == ".zip":
        return _xlogs_from_zip(uploaded_path)
    if _is_raw_xlog_name(uploaded_path.name):
        return [uploaded_path]
    return []


def _external_meta(path: Path, *, kind: str | None = None) -> dict:
    name = path.name
    if kind is None:
        if name.lower().endswith(".xlog.log") or name.lower().endswith((".log", ".txt")):
            kind = "decoded"
        else:
            kind = "source"
    return {
        "name": name,
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "kind": kind,
    }


def _path_key(path: Path | str) -> str:
    try:
        return str(Path(path).resolve()).replace("/", "\\").lower()
    except OSError:
        return str(path).replace("/", "\\").lower()


_SCAN_FILE_CAP = 2000


def _scan_local_inputs(paths: list[str]) -> tuple[list[dict], bool]:
    """List .xlog / .zip under the paths the user picked. Returns (items, truncated)."""
    items: list[dict] = []
    seen: set[str] = set()
    truncated = False

    def add(fp: Path, base: Path) -> None:
        nonlocal truncated
        if len(items) >= _SCAN_FILE_CAP:
            truncated = True
            return
        key = _path_key(fp)
        if key in seen:
            return
        seen.add(key)
        try:
            rel = fp.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            rel = fp.name
        try:
            size = fp.stat().st_size
        except OSError:
            size = 0
        items.append(
            {
                "path": str(fp.resolve()),
                "name": fp.name,
                "rel": rel,
                "size": size,
            }
        )

    for raw in paths:
        p = Path(raw).expanduser()
        if not p.exists():
            continue
        try:
            p = p.resolve()
        except OSError:
            continue
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
                for fname in filenames:
                    if len(items) >= _SCAN_FILE_CAP:
                        truncated = True
                        break
                    fp = Path(dirpath) / fname
                    if _is_raw_xlog_name(fname) or fp.suffix.lower() == ".zip":
                        add(fp, p)
                if truncated:
                    break
        elif p.is_file() and (_is_raw_xlog_name(p.name) or p.suffix.lower() == ".zip"):
            add(p, p.parent)
    items.sort(key=lambda x: x["rel"].lower())
    return items, truncated


def _collect_local_xlogs(paths: list[Path]) -> list[Path]:
    """Expand files / folders / zips. Plaintext is later written beside each .xlog."""
    xlogs: list[Path] = []
    seen: set[str] = set()

    def add_xlog(fp: Path) -> None:
        if not fp.is_file() or not _is_raw_xlog_name(fp.name):
            return
        key = _path_key(fp)
        if key in seen:
            return
        seen.add(key)
        xlogs.append(fp.resolve())

    def take_file(fp: Path) -> None:
        if fp.suffix.lower() == ".zip":
            for item in _xlogs_from_zip(fp):
                add_xlog(item)
        else:
            add_xlog(fp)

    for raw in paths:
        p = raw.resolve()
        if not p.exists():
            continue
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
                for fname in filenames:
                    take_file(Path(dirpath) / fname)
        else:
            take_file(p)
    return xlogs


_pick_lock = threading.Lock()


def _reject_cross_site() -> str | None:
    origin = (request.headers.get("Origin") or "").strip().rstrip("/")
    if not origin:
        return None
    host = (request.host or "").strip().lower()
    from urllib.parse import urlparse

    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return "拒绝来自其它页面的请求"
    if parsed.netloc.lower() == host:
        return None
    if parsed.hostname in ("127.0.0.1", "localhost") and parsed.port in (None, 5000):
        return None
    return "拒绝来自其它页面的请求"


def _pick_paths(mode: str) -> list[str] | None:
    """Open a native file/folder dialog. None means the user cancelled."""
    if mode not in ("files", "folder"):
        raise ValueError("无效的选择模式")
    if not _pick_lock.acquire(blocking=False):
        raise RuntimeError("已经有一个选择窗口开着")
    try:
        if os.name == "nt":
            return _pick_windows(mode)
        if sys.platform == "darwin":
            return _pick_mac(mode)
        return _pick_linux(mode)
    finally:
        _pick_lock.release()


def _pick_windows(mode: str) -> list[str] | None:
    import subprocess
    import tempfile

    fd, out_name = tempfile.mkstemp(prefix="easy-log-pick-", suffix=".txt")
    os.close(fd)
    out = Path(out_name)
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$out = $env:EASY_LOG_PICK_OUT
$mode = $env:EASY_LOG_PICK_MODE
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.Opacity = 0
$owner.Width = 1
$owner.Height = 1
$owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$owner.Show()
$owner.Activate()
try {
  if ($mode -eq "folder") {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "选择包含 .xlog 的文件夹。解密后的文件会放在源文件同一目录。"
    $dlg.ShowNewFolderButton = $false
    if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
      Set-Content -LiteralPath $out -Value $dlg.SelectedPath -Encoding utf8
    }
  } else {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Multiselect = $true
    $dlg.Title = "选择要解密的 .xlog 或 .zip（结果写在源文件同一目录）"
    $dlg.Filter = "xlog / zip (*.xlog;*.zip)|*.xlog;*.zip|所有文件 (*.*)|*.*"
    $dlg.CheckFileExists = $true
    if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
      $dlg.FileNames | Set-Content -LiteralPath $out -Encoding utf8
    }
  }
} finally {
  $owner.Close()
  $owner.Dispose()
}
"""
    fd_ps, ps_name = tempfile.mkstemp(prefix="easy-log-pick-", suffix=".ps1")
    os.close(fd_ps)
    ps1 = Path(ps_name)
    env = os.environ.copy()
    env["EASY_LOG_PICK_OUT"] = str(out)
    env["EASY_LOG_PICK_MODE"] = mode
    try:
        ps1.write_text(script, encoding="utf-8-sig")
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-STA",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ps1),
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            msg = "无法打开选择窗口"
            if detail:
                msg += "：" + detail[:400]
            raise RuntimeError(msg)
        if not out.is_file() or out.stat().st_size == 0:
            return None
        text = out.read_text(encoding="utf-8-sig", errors="replace")
        lines = [ln.strip().strip('"') for ln in text.splitlines() if ln.strip()]
        return lines or None
    finally:
        ps1.unlink(missing_ok=True)
        out.unlink(missing_ok=True)


def _pick_mac(mode: str) -> list[str] | None:
    import subprocess

    if mode == "folder":
        script = 'POSIX path of (choose folder with prompt "选择包含日志的文件夹，解密结果会写在源文件旁边")'
    else:
        script = (
            'set fs to choose file with multiple selections allowed '
            'with prompt "选择 .xlog 或 .zip，解密结果会写在源文件旁边"\n'
            'set out to ""\n'
            "repeat with f in fs\n"
            "set out to out & POSIX path of f & linefeed\n"
            "end repeat\n"
            "out"
        )
    proc = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    err = proc.stderr or ""
    if proc.returncode != 0:
        if "User canceled" in err or "-128" in err:
            return None
        raise RuntimeError("无法打开选择窗口：" + err.strip()[:400])
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    return lines or None


def _pick_linux(mode: str) -> list[str] | None:
    import subprocess

    zenity = shutil.which("zenity")
    if not zenity:
        raise RuntimeError("未找到 zenity，无法打开系统文件选择窗口")
    cmd = [zenity, "--file-selection", "--title=选择日志（解密结果写在源文件旁边）"]
    if mode == "folder":
        cmd.append("--directory")
    else:
        cmd.extend(["--multiple", "--separator=\n"])
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    if proc.returncode != 0:
        return None
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    return lines or None


def _coerce_local_paths(raw_list: list) -> list[Path]:
    if not isinstance(raw_list, list):
        raise ValueError("请选择要解密的文件")
    out: list[Path] = []
    seen: set[str] = set()
    for raw in raw_list:
        if not isinstance(raw, str) or not raw.strip():
            continue
        p = Path(raw.strip()).expanduser()
        if not p.is_absolute():
            raise ValueError("需要源文件的绝对路径")
        if not p.exists():
            raise ValueError("找不到：" + str(p))
        resolved = p.resolve()
        key = _path_key(resolved)
        if key in seen:
            continue
        seen.add(key)
        out.append(resolved)
        if len(out) > _SCAN_FILE_CAP:
            break
    if not out:
        raise ValueError("请选择要解密的文件")
    return out


def _zip_outputs(output_files: list[Path], zip_path: Path, base: Path) -> Path:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in output_files:
            try:
                arcname = _rel(f, base)
            except ValueError:
                arcname = f.name
            zf.write(f, arcname=arcname)
    return zip_path


def _scan_legacy_jobs() -> None:
    """Import upload folders that exist but are missing from history.json."""
    with _history_lock:
        items = _load_history()
        known = {x.get("id") for x in items}
        changed = False

        for child in UPLOAD_ROOT.iterdir():
            if not child.is_dir() or child.name in known:
                continue
            # Skip non-job folders
            try:
                _job_dir(child.name)
            except ValueError:
                continue
            sources = []
            decoded = []
            for root, _, files in os.walk(child):
                for fname in files:
                    p = Path(root) / fname
                    lower = fname.lower()
                    if lower.endswith(".xlog.log"):
                        decoded.append(_file_meta(p, child))
                    elif lower.endswith(".xlog"):
                        sources.append(_file_meta(p, child))
            if not sources and not decoded:
                continue
            mtime = datetime.fromtimestamp(child.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            zip_name = "decoded_logs.zip" if (child / "decoded_logs.zip").is_file() else None
            items.append(
                {
                    "id": child.name,
                    "created_at": mtime,
                    "title": decoded[0]["name"] if decoded else (sources[0]["name"] if sources else child.name),
                    "note": "",
                    "uploads": [],
                    "sources": sources,
                    "decoded": decoded,
                    "failed": [],
                    "zip": zip_name,
                }
            )
            changed = True

        if changed:
            items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            _save_history(items)


# Defer legacy scan until first history access / server start (faster cold start)


def _ensure_legacy_scanned() -> None:
    global _legacy_scanned
    if _legacy_scanned:
        return
    with _legacy_scan_lock:
        if _legacy_scanned:
            return
        _scan_legacy_jobs()
        _legacy_scanned = True


@app.route("/")
def index():
    from flask import make_response

    # Serve as plain HTML (no Jinja) so JS "{{" / template literals never break the page
    html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/history", methods=["GET"])
def api_history():
    _ensure_legacy_scanned()
    with _history_lock:
        items = _load_history()
    summary = []
    for item in items:
        jid = item.get("id")
        if not jid:
            continue
        created = item.get("created_at") or ""
        summary.append(
            {
                "id": jid,
                "created_at": created,
                "date": created[:10] if len(created) >= 10 else "未知日期",
                "title": item.get("title"),
                "note": item.get("note") or "",
                "script": item.get("script") or item.get("decoder") or "",
                "script_name": item.get("script_name")
                or item.get("decoder_name")
                or item.get("script")
                or item.get("decoder")
                or "",
                "source_count": len(item.get("sources") or []),
                "decoded_count": len(item.get("decoded") or []),
                "failed_count": len(item.get("failed") or []),
                "external": bool(item.get("external")),
                "device": bool(item.get("device_dir")),
                "device_key": item.get("device_key") or "",
                "device_serial": item.get("device_serial") or "",
            }
        )
    return jsonify({"ok": True, "items": summary})


@app.route("/api/history/<job_id>", methods=["GET"])
def api_history_detail(job_id: str):
    try:
        _job_dir(job_id)
    except ValueError:
        return jsonify({"ok": False, "error": "无效的任务 ID"}), 400
    job = _get_job(job_id)
    if not job:
        return jsonify({"ok": False, "error": "记录不存在"}), 404
    return jsonify({"ok": True, "job": job})


@app.route("/api/history/<job_id>", methods=["PATCH"])
def api_history_patch(job_id: str):
    try:
        _job_dir(job_id)
    except ValueError:
        return jsonify({"ok": False, "error": "无效的任务 ID"}), 400
    data = request.get_json(silent=True) or {}
    fields = {}
    if "title" in data:
        title = str(data.get("title") or "").strip()
        if not title:
            return jsonify({"ok": False, "error": "标题不能为空"}), 400
        fields["title"] = title[:120]
    if "note" in data:
        fields["note"] = str(data.get("note") or "").strip()[:200]
    if not fields:
        return jsonify({"ok": False, "error": "没有可更新字段"}), 400
    job = _update_job_fields(job_id, **fields)
    if not job:
        return jsonify({"ok": False, "error": "记录不存在"}), 404
    return jsonify({"ok": True, "job": job})


@app.route("/api/history/<job_id>", methods=["DELETE"])
def api_history_delete(job_id: str):
    try:
        work = _job_dir(job_id)
    except ValueError:
        return jsonify({"ok": False, "error": "无效的任务 ID"}), 400
    removed = None
    with _history_lock:
        items = _load_history()
        removed = next((x for x in items if x.get("id") == job_id), None)
        new_items = [x for x in items if x.get("id") != job_id]
        if removed is None:
            return jsonify({"ok": False, "error": "记录不存在"}), 404
        _save_history(new_items)
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    if isinstance(removed, dict):
        _remove_device_elog_dir(removed.get("device_dir"))
    return jsonify({"ok": True})


@app.route("/api/scripts", methods=["GET"])
def api_scripts():
    items = list_scripts()
    return jsonify(
        {
            "ok": True,
            "items": items,
            "default": default_script(),
        }
    )


@app.route("/api/import-preview", methods=["POST"])
def api_import_preview():
    """Import already-decoded / plaintext files (or pasted text) for preview + search."""
    files = [f for f in request.files.getlist("files") if f and f.filename]
    pasted = request.form.get("text")
    pasted_name = (request.form.get("filename") or "pasted.txt").strip() or "pasted.txt"

    job_id = uuid.uuid4().hex
    work_dir = UPLOAD_ROOT / job_id
    work_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []

    try:
        for storage in files:
            orig = storage.filename or "file"
            if not _is_preview_text_name(orig):
                continue
            rel = _unique_relpath(work_dir, _safe_relpath(orig))
            # Keep a .log-like name so UI treats it as previewable text
            target = work_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            storage.save(target)
            if target.is_file() and target.stat().st_size > 0:
                saved.append(target)

        if pasted is not None and str(pasted).strip():
            text_body = str(pasted)
            if len(text_body.encode("utf-8")) > 20 * 1024 * 1024:
                shutil.rmtree(work_dir, ignore_errors=True)
                return jsonify({"ok": False, "error": "粘贴文本超过 20MB，请改为拖入文件"}), 400
            safe = _safe_relpath(pasted_name if _is_preview_text_name(pasted_name) else "pasted.txt")
            if not safe.lower().endswith((".txt", ".log", ".md", ".text", ".out")):
                safe = safe + ".txt"
            out = work_dir / _unique_relpath(work_dir, safe)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text_body, encoding="utf-8", errors="replace")
            saved.append(out)

        if not saved:
            shutil.rmtree(work_dir, ignore_errors=True)
            return jsonify(
                {
                    "ok": False,
                    "error": "未找到可预览的文本（支持 .log / .txt / .xlog.log / .md / .csv / .json 等；原始 .xlog 请放到上方解密区）",
                }
            ), 400
    except Exception as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        return jsonify({"ok": False, "error": "导入失败：" + str(e)}), 500

    names = [p.name for p in saved]
    if len(names) == 1:
        title = f"预览：{names[0]}"
    else:
        title = f"预览：{names[0]} 等 {len(names)} 个文件"
    job = {
        "id": job_id,
        "created_at": _now_iso(),
        "title": title[:120],
        "note": "拖入 / 粘贴直接预览（未走解密脚本）",
        "script": "",
        "script_name": "直接预览",
        "uploads": names,
        "sources": [],
        "decoded": [_file_meta(p, work_dir, force_decoded=True) for p in saved],
        "failed": [],
        "zip": None,
    }
    _upsert_job(job)
    return jsonify({"ok": True, "job": job})


def _common_dir(paths: list[Path]) -> Path:
    parents = [p.resolve().parent.parts for p in paths if str(p)]
    if not parents:
        return Path(".")
    common: list[str] = []
    for segs in zip(*parents):
        if len(set(segs)) != 1:
            break
        common.append(segs[0])
    if not common:
        return paths[0].resolve().parent
    return Path(*common)


def _ndjson_response(generate):
    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _subprocess_kwargs() -> dict:
    if os.name != "nt":
        return {}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {
        "startupinfo": startup,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
    }


def _sh_single_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def _safe_device_filename(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned or cleaned in (".", "..") or "/" in cleaned or "\\" in cleaned:
        raise ValueError("无效的设备文件名")
    if any(ord(ch) < 32 for ch in cleaned):
        raise ValueError("无效的设备文件名")
    return cleaned


def _newest_device_filename(listing: str) -> str | None:
    """First regular file in an `ls -1tp` listing (newest first, dirs end with /)."""
    for raw in (listing or "").splitlines():
        line = raw.strip()
        if not line or line.endswith("/") or ": " in line:
            continue
        try:
            return _safe_device_filename(line)
        except ValueError:
            continue
    return None


def _listing_ok(stdout: str, stderr: str, returncode: int) -> tuple[bool, str | None]:
    blob = f"{stderr}\n{stdout}".lower()
    if returncode != 0 or any(marker in blob for marker in _DEVICE_LIST_FAIL_MARKERS):
        return False, None
    return True, _newest_device_filename(stdout)


def _adb_text(adb: str, args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [adb, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        **_subprocess_kwargs(),
    )


def _require_adb() -> str:
    path = shutil.which("adb")
    if not path:
        raise RuntimeError("未找到 adb，请安装 platform-tools 并加入 PATH")
    return path


def _parse_adb_devices(stdout: str) -> list[dict]:
    rows: list[dict] = []
    for line in (stdout or "").splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[0].lower().startswith("list"):
            continue
        state = parts[1]
        if state not in ("device", "offline", "unauthorized"):
            continue
        meta = dict(re.findall(r"(\w+):(\S+)", line))
        rows.append(
            {
                "serial": parts[0],
                "state": state,
                "model": meta.get("model") or "",
                "product": meta.get("product") or "",
            }
        )
    return rows


def _online_devices(adb: str) -> tuple[list[dict], str]:
    proc = _adb_text(adb, ["devices", "-l"], timeout=15)
    if proc.returncode != 0:
        detail = ((proc.stderr or "") or (proc.stdout or "")).strip()
        message = "adb devices 失败"
        if detail:
            message += "：" + detail.splitlines()[0][:200]
        raise RuntimeError(message)
    rows = _parse_adb_devices(proc.stdout or "")
    online = [row for row in rows if row["state"] == "device"]
    other = [
        f"{row['serial']}（{row['state']}）"
        for row in rows
        if row["state"] in ("offline", "unauthorized")
    ]
    return online, "、".join(other)


def _usable_device_text(value: str) -> str:
    text = (value or "").strip()
    if not text or text.lower() in {"unknown", "null", "none", "0"}:
        return ""
    return text


_online_identity_cache: dict = {"at": 0.0, "devices": []}
_online_identity_lock = threading.Lock()


def _list_online_identities() -> list[dict]:
    """Online adb devices with a stable hardware key. Cached briefly."""
    now = time.monotonic()
    with _online_identity_lock:
        if now - float(_online_identity_cache["at"]) < 1:
            return list(_online_identity_cache["devices"])
    try:
        adb = _require_adb()
        online, _offline = _online_devices(adb)
    except RuntimeError:
        devices: list[dict] = []
    else:
        devices = []
        for row in online:
            identity = _device_identity(adb, row["serial"], row.get("model") or "")
            devices.append(
                {
                    "serial": row["serial"],
                    "model": identity["model"] or row.get("model") or "",
                    "key": identity["key"],
                }
            )
    with _online_identity_lock:
        _online_identity_cache["at"] = time.monotonic()
        _online_identity_cache["devices"] = devices
    return devices


@app.route("/api/adb-devices", methods=["GET"])
def api_adb_devices():
    blocked = _reject_cross_site()
    if blocked:
        return jsonify({"ok": False, "error": blocked}), 403
    return jsonify({"ok": True, "devices": _list_online_identities()})


def _device_identity(adb: str, serial: str, model_hint: str) -> dict:
    """Stable key is the hardware serial when the device reports one."""
    hw = ""
    model = _usable_device_text(model_hint)
    try:
        proc = _adb_text(
            adb,
            ["-s", serial, "shell", "echo SERIAL=$(getprop ro.serialno); echo MODEL=$(getprop ro.product.model)"],
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        proc = None
    if proc is not None:
        for line in (proc.stdout or "").replace("\r", "").splitlines():
            if line.startswith("SERIAL="):
                hw = _usable_device_text(line[7:])
            elif line.startswith("MODEL=") and not model:
                model = _usable_device_text(line[6:])
    return {"key": hw or serial, "serial": serial, "model": model}


def _safe_device_dir_name(key: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", key).strip(" .")
    if not cleaned or cleaned.upper() in {"CON", "PRN", "AUX", "NUL"}:
        cleaned = "device"
    return cleaned[:48]


def _device_slot(key: str) -> tuple[str, Path]:
    job_id = hashlib.sha256(("easy-log-watch-device:" + key).encode("utf-8")).hexdigest()[:32]
    folder = (DEVICE_ELOG_DIR / (_safe_device_dir_name(key) + "_" + job_id[:8])).resolve()
    root = DEVICE_ELOG_DIR.resolve()
    if folder.parent != root:
        raise ValueError("无效的设备目录")
    return job_id, folder


def _remove_device_elog_dir(raw: object) -> None:
    if not isinstance(raw, str) or not raw.strip():
        return
    root = DEVICE_ELOG_DIR.resolve()
    try:
        target = Path(raw).resolve()
    except OSError:
        return
    if target != root and root in target.parents and target.is_dir():
        shutil.rmtree(target, ignore_errors=True)


def _cat_command(mode: str, name: str) -> str:
    safe = _safe_device_filename(name)
    if mode == "run-as":
        path = f"{DEVICE_REL_DIR}/{safe}"
        inner = "cat " + _sh_single_quote(path)
        return f"run-as {DEVICE_PKG} sh -c {_sh_single_quote(inner)}"
    path = f"{DEVICE_ABS_DIR}/{safe}"
    inner = _sh_single_quote("cat " + _sh_single_quote(path))
    if mode == "su0":
        return f"su 0 sh -c {inner}"
    if mode == "suc":
        return f"su -c {inner}"
    if mode == "root":
        return f"sh -c {inner}"
    raise RuntimeError("未知的读取方式")


def _device_elog_access(adb: str, serial: str) -> tuple[str, str]:
    """Return ``(mode, newest filename)``. mode is run-as, su0, suc, or root."""
    attempts = [
        ("run-as", f"run-as {DEVICE_PKG} ls -1tp {DEVICE_REL_DIR}"),
        ("su0", f"su 0 ls -1tp {DEVICE_ABS_DIR}"),
        ("suc", f"su -c {_sh_single_quote('ls -1tp ' + DEVICE_ABS_DIR)}"),
    ]
    errors: list[str] = []

    def try_list(mode: str, command: str) -> tuple[str, str] | None:
        try:
            proc = _adb_text(adb, ["-s", serial, "shell", command], timeout=20)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("列出 elog 超时") from e
        ok, name = _listing_ok(proc.stdout or "", proc.stderr or "", proc.returncode)
        if not ok:
            detail = ((proc.stderr or "") or (proc.stdout or "")).strip()
            if detail:
                errors.append(detail.splitlines()[0][:180])
            return None
        if not name:
            raise RuntimeError("elog 目录里没有日志文件")
        return mode, name

    for mode, command in attempts:
        found = try_list(mode, command)
        if found:
            return found

    try:
        ident = _adb_text(adb, ["-s", serial, "shell", "id"], timeout=15)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("检查设备权限超时") from e
    if "uid=0" in (ident.stdout or ""):
        found = try_list("root", f"ls -1tp {DEVICE_ABS_DIR}")
        if found:
            return found

    message = (
        f"无法读取 {DEVICE_ABS_DIR}/：应用不可调试且没有 su。"
        "请自行执行 adb root，或换用可调试包后再试。"
    )
    if errors:
        message += "（" + errors[0] + "）"
    raise RuntimeError(message)


def _pull_device_file(adb: str, serial: str, mode: str, name: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    if tmp.exists():
        try:
            tmp.unlink()
        except OSError:
            pass
    command = _cat_command(mode, name)
    proc = subprocess.Popen(
        [adb, "-s", serial, "exec-out", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **_subprocess_kwargs(),
    )
    err_box: dict[str, object] = {"data": b"", "exc": None}

    def read_err() -> None:
        if proc.stderr is None:
            return
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = proc.stderr.read(4096)
            if not chunk:
                break
            if total < 4000:
                chunks.append(chunk)
                total += len(chunk)
        err_box["data"] = b"".join(chunks)

    def read_out() -> None:
        try:
            if proc.stdout is None:
                return
            with open(tmp, "wb") as out:
                while True:
                    chunk = proc.stdout.read(256 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
        except Exception as exc:
            err_box["exc"] = exc
            try:
                proc.kill()
            except OSError:
                pass

    err_thread = threading.Thread(target=read_err, daemon=True)
    out_thread = threading.Thread(target=read_out, daemon=True)
    err_thread.start()
    out_thread.start()
    out_thread.join(180)
    if out_thread.is_alive():
        proc.kill()
        out_thread.join(5)
        err_thread.join(5)
        try:
            tmp.unlink()
        except OSError:
            pass
        raise RuntimeError("拉取超时")
    try:
        code = proc.wait(timeout=20)
    except subprocess.TimeoutExpired as e:
        proc.kill()
        raise RuntimeError("拉取超时") from e
    err_thread.join(5)
    write_exc = err_box.get("exc")
    if isinstance(write_exc, Exception):
        try:
            tmp.unlink()
        except OSError:
            pass
        raise RuntimeError("写入本地文件失败：" + str(write_exc)) from write_exc
    detail = bytes(err_box.get("data") or b"").decode("utf-8", errors="replace").strip()
    size = tmp.stat().st_size if tmp.is_file() else 0
    if code != 0 or size <= 0:
        try:
            tmp.unlink()
        except OSError:
            pass
        message = "拉取失败"
        if detail:
            message += "：" + detail.splitlines()[0][:300]
        raise RuntimeError(message)
    os.replace(tmp, dest)


def _keep_only_latest_pair(directory: Path) -> None:
    keep = {DEVICE_ELOG_FILE, DEVICE_ELOG_FILE + ".log"}
    if not directory.is_dir():
        return
    for child in directory.iterdir():
        if child.name in keep or not child.is_file():
            continue
        try:
            child.unlink()
        except OSError:
            pass


_DEVICE_MODE_LABEL = {
    "run-as": "run-as",
    "su0": "su",
    "suc": "su",
    "root": "root",
}


@app.route("/api/device-elog", methods=["POST"])
def api_device_elog():
    """Pull the newest file in the device elog dir, decrypt, and overwrite the local pair."""
    blocked = _reject_cross_site()
    if blocked:
        return jsonify({"ok": False, "error": blocked}), 403

    data = request.get_json(silent=True) or {}
    script_name = (data.get("script") or default_script()).strip()
    requested = str(data.get("serial") or "").strip()
    if any(ord(ch) < 32 for ch in requested) or len(requested) > 200:
        return jsonify({"ok": False, "error": "无效的设备序列号"}), 400
    try:
        script_path = resolve_script(script_name)
        adb = _require_adb()
        online, offline_note = _online_devices(adb)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    script_label = script_path.name

    if requested:
        chosen = next((row for row in online if row["serial"] == requested), None)
        if not chosen:
            return jsonify({"ok": False, "error": "这台设备当前不在线：" + requested}), 400
    elif len(online) > 1:
        return jsonify({"ok": False, "need_device": True, "devices": online})
    elif len(online) == 1:
        chosen = online[0]
    else:
        message = "没有处于 device 状态的设备。请确认已打开 USB 调试并授权。"
        if offline_note:
            message += "当前：" + offline_note + "。"
        return jsonify({"ok": False, "error": message}), 400

    serial = chosen["serial"]
    model_hint = chosen.get("model") or ""

    def generate():
        def emit(payload: dict) -> str:
            return json.dumps(payload, ensure_ascii=False) + "\n"

        try:
            yield emit(
                {
                    "type": "progress",
                    "stage": "prepare",
                    "current": 0,
                    "total": 1,
                    "percent": 8,
                    "message": f"正在连接 {serial} …",
                }
            )
            identity = _device_identity(adb, serial, model_hint)
            job_id, device_dir = _device_slot(identity["key"])
            source_path = device_dir / DEVICE_ELOG_FILE
            yield emit(
                {
                    "type": "progress",
                    "stage": "list",
                    "current": 0,
                    "total": 1,
                    "percent": 30,
                    "message": f"正在列出 elog（{serial}）…",
                }
            )
            mode, remote_name = _device_elog_access(adb, serial)
            yield emit(
                {
                    "type": "progress",
                    "stage": "pull",
                    "current": 0,
                    "total": 1,
                    "percent": 50,
                    "message": f"正在拉取 {remote_name} …",
                    "file": remote_name,
                }
            )
            _pull_device_file(adb, serial, mode, remote_name, source_path)
            yield emit(
                {
                    "type": "progress",
                    "stage": "decode",
                    "current": 0,
                    "total": 1,
                    "percent": 75,
                    "message": f"正在解密并覆盖该设备的 {remote_name} …",
                    "file": remote_name,
                }
            )
            results = run_script(script_label, str(source_path))
            if not results:
                yield emit(
                    {
                        "type": "done",
                        "ok": False,
                        "error": "解密失败：未能生成明文日志。请换一个脚本再试。",
                    }
                )
                return
            out_path = Path(results[0])
            _keep_only_latest_pair(device_dir)
            source_meta = _external_meta(source_path, kind="source")
            source_meta["name"] = remote_name
            decoded_meta = _external_meta(out_path, kind="decoded")
            decoded_meta["name"] = remote_name if remote_name.endswith(".log") else remote_name + ".log"
            mode_label = _DEVICE_MODE_LABEL.get(mode, mode)
            who = identity["model"] or identity["key"]
            job = {
                "id": job_id,
                "external": True,
                "created_at": _now_iso(),
                "title": f"{who} · {serial} · {remote_name}"[:120],
                "note": f"该设备单独存放，再次拉取只覆盖这一份 · {mode_label}"[:200],
                "script": script_label,
                "script_name": script_label,
                "uploads": [f"{DEVICE_ABS_DIR}/{remote_name}"],
                "sources": [source_meta],
                "decoded": [decoded_meta],
                "failed": [],
                "zip": None,
                "device_dir": str(device_dir),
                "device_key": identity["key"],
                "device_serial": serial,
                "device_model": identity["model"],
            }
            _upsert_job(job)
            yield emit(
                {
                    "type": "progress",
                    "stage": "done",
                    "current": 1,
                    "total": 1,
                    "percent": 100,
                    "message": "解密完成，已覆盖该设备自己的明文",
                }
            )
            yield emit({"type": "done", "ok": True, "job": job})
        except (RuntimeError, ValueError) as e:
            yield emit({"type": "done", "ok": False, "error": str(e)})
        except subprocess.TimeoutExpired:
            yield emit({"type": "done", "ok": False, "error": "adb 超时"})
        except Exception as e:
            yield emit({"type": "done", "ok": False, "error": "处理失败：" + str(e)})

    return _ndjson_response(generate)


@app.route("/api/pick", methods=["POST"])
def api_pick():
    """Native file/folder dialog so decryption can write beside the real source files."""
    blocked = _reject_cross_site()
    if blocked:
        return jsonify({"ok": False, "error": blocked}), 403
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "files").strip().lower()
    direct = data.get("paths")
    try:
        if isinstance(direct, list) and direct:
            picked = [str(p) for p in direct if isinstance(p, str) and str(p).strip()]
        else:
            picked = _pick_paths(mode)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    if not picked:
        return jsonify({"ok": True, "cancelled": True, "items": []})
    items, truncated = _scan_local_inputs(picked)
    return jsonify(
        {
            "ok": True,
            "cancelled": False,
            "items": items,
            "truncated": truncated,
        }
    )


@app.route("/api/decode-local", methods=["POST"])
def api_decode_local():
    """Decrypt files in place: plaintext is written next to each source .xlog."""
    blocked = _reject_cross_site()
    if blocked:
        return jsonify({"ok": False, "error": blocked}), 403

    data = request.get_json(silent=True) or {}
    script_name = (data.get("script") or default_script()).strip()
    try:
        script_path = resolve_script(script_name)
        input_paths = _coerce_local_paths(data.get("paths") or [])
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    script_label = script_path.name
    job_id = uuid.uuid4().hex

    def generate():
        def emit(payload: dict) -> str:
            return json.dumps(payload, ensure_ascii=False) + "\n"

        work_dir = UPLOAD_ROOT / job_id
        try:
            yield emit(
                {
                    "type": "progress",
                    "stage": "prepare",
                    "current": 0,
                    "total": 1,
                    "percent": 5,
                    "message": "正在源文件目录中查找 .xlog…",
                }
            )
            try:
                all_xlogs = _collect_local_xlogs(input_paths)
            except zipfile.BadZipFile:
                yield emit({"type": "done", "ok": False, "error": "ZIP 文件损坏或格式不正确"})
                return

            if not all_xlogs:
                yield emit({"type": "done", "ok": False, "error": "未找到任何 .xlog 文件"})
                return

            output_files: list[Path] = []
            failed: list[str] = []
            total_xlogs = len(all_xlogs)
            yield emit(
                {
                    "type": "progress",
                    "stage": "decode",
                    "current": 0,
                    "total": total_xlogs,
                    "percent": 30,
                    "message": f"开始解密（{script_label}），明文写在源文件同一目录，共 {total_xlogs} 个 .xlog",
                }
            )
            for i, xlog in enumerate(all_xlogs, start=1):
                pct = 30 + int(60 * i / max(total_xlogs, 1))
                yield emit(
                    {
                        "type": "progress",
                        "stage": "decode",
                        "current": i,
                        "total": total_xlogs,
                        "percent": pct,
                        "message": f"解密中 {i}/{total_xlogs}：{xlog.name} → 同目录",
                        "file": xlog.name,
                    }
                )
                try:
                    results = run_script(script_label, str(xlog))
                except Exception as e:
                    failed.append(f"{xlog.name}（{e}）")
                    continue
                if results:
                    output_files.extend(Path(p) for p in results)
                else:
                    failed.append(xlog.name)

            if not output_files:
                yield emit(
                    {
                        "type": "done",
                        "ok": False,
                        "error": "解密失败：未能生成明文日志。请换一个脚本再试。",
                    }
                )
                return

            zip_path = None
            if len(output_files) > 1:
                yield emit(
                    {
                        "type": "progress",
                        "stage": "pack",
                        "current": 1,
                        "total": 1,
                        "percent": 95,
                        "message": "正在打包一份副本，原文明文仍在源文件目录…",
                    }
                )
                work_dir.mkdir(parents=True, exist_ok=True)
                zip_path = work_dir / "decoded_logs.zip"
                _zip_outputs(output_files, zip_path, _common_dir(output_files))

            if len(input_paths) == 1:
                title = input_paths[0].name
            else:
                parent = _common_dir(input_paths)
                title = (
                    f"{parent.name}/（{len(input_paths)} 个文件）"
                    if parent.name
                    else f"{input_paths[0].name} 等 {len(input_paths)} 个文件"
                )
            job = {
                "id": job_id,
                "external": True,
                "created_at": _now_iso(),
                "title": title[:120],
                "note": "明文在源文件同一目录",
                "script": script_label,
                "script_name": script_label,
                "uploads": [str(p) for p in input_paths],
                "sources": [_external_meta(p) for p in all_xlogs],
                "decoded": [_external_meta(p, kind="decoded") for p in output_files],
                "failed": failed,
                "zip": str(zip_path.resolve()) if zip_path else None,
                "zip_name": zip_path.name if zip_path else None,
            }
            _upsert_job(job)
            yield emit(
                {
                    "type": "progress",
                    "stage": "done",
                    "current": total_xlogs,
                    "total": total_xlogs,
                    "percent": 100,
                    "message": "解密完成，文件已在源文件目录",
                }
            )
            yield emit({"type": "done", "ok": True, "job": job})
        except zipfile.BadZipFile:
            yield emit({"type": "done", "ok": False, "error": "ZIP 文件损坏或格式不正确"})
        except ValueError as e:
            yield emit({"type": "done", "ok": False, "error": str(e)})
        except Exception as e:
            yield emit({"type": "done", "ok": False, "error": "处理失败：" + str(e)})

    return _ndjson_response(generate)


@app.route("/api/decode", methods=["POST"])
def api_decode():
    script_name = (request.form.get("script") or default_script()).strip()
    try:
        script_path = resolve_script(script_name)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    files = [f for f in request.files.getlist("files") if f and f.filename]
    if not files:
        return jsonify({"ok": False, "error": "请选择要上传的文件"}), 400

    # Read uploads into memory/temp first so generator can stream after request body consumed
    job_id = uuid.uuid4().hex
    work_dir = UPLOAD_ROOT / job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        saved_items = []
        for storage in files:
            orig = storage.filename or "file"
            if not _is_xlog_or_zip(orig):
                continue
            rel = _unique_relpath(work_dir, _safe_relpath(orig))
            saved = work_dir / rel
            saved.parent.mkdir(parents=True, exist_ok=True)
            storage.save(saved)
            saved_items.append((orig, saved))
        if not saved_items:
            shutil.rmtree(work_dir, ignore_errors=True)
            return jsonify({"ok": False, "error": "未找到任何 .xlog / .zip 文件"}), 400
    except Exception as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        return jsonify({"ok": False, "error": "保存上传文件失败：" + str(e)}), 500

    script_label = script_path.name

    def generate():
        def emit(payload: dict) -> str:
            return json.dumps(payload, ensure_ascii=False) + "\n"

        try:
            yield emit(
                {
                    "type": "progress",
                    "stage": "prepare",
                    "current": 0,
                    "total": 1,
                    "percent": 5,
                    "message": "正在解析上传文件…",
                }
            )

            upload_names = []
            all_xlogs: list[Path] = []
            total_uploads = len(saved_items)
            for i, (orig_name, saved) in enumerate(saved_items, start=1):
                upload_names.append(orig_name)
                yield emit(
                    {
                        "type": "progress",
                        "stage": "extract",
                        "current": i,
                        "total": total_uploads,
                        "percent": 5 + int(20 * i / max(total_uploads, 1)),
                        "message": f"处理上传 {i}/{total_uploads}：{orig_name}",
                        "file": orig_name,
                    }
                )
                all_xlogs.extend(_extract_xlogs(work_dir, saved))

            uniq = []
            seen = set()
            for p in all_xlogs:
                key = str(p.resolve())
                if key not in seen:
                    seen.add(key)
                    uniq.append(p)
            all_xlogs = uniq

            if not all_xlogs:
                shutil.rmtree(work_dir, ignore_errors=True)
                yield emit({"type": "done", "ok": False, "error": "未找到任何 .xlog 文件"})
                return

            output_files: list[Path] = []
            failed: list[str] = []
            total_xlogs = len(all_xlogs)
            yield emit(
                {
                    "type": "progress",
                    "stage": "decode",
                    "current": 0,
                    "total": total_xlogs,
                    "percent": 30,
                    "message": f"开始解密（{script_label}），共 {total_xlogs} 个 .xlog",
                }
            )

            for i, xlog in enumerate(all_xlogs, start=1):
                pct = 30 + int(60 * i / max(total_xlogs, 1))
                yield emit(
                    {
                        "type": "progress",
                        "stage": "decode",
                        "current": i,
                        "total": total_xlogs,
                        "percent": pct,
                        "message": f"解密中 {i}/{total_xlogs}：{xlog.name}",
                        "file": xlog.name,
                    }
                )
                try:
                    results = run_script(script_label, str(xlog))
                except Exception as e:
                    failed.append(f"{xlog.name}（{e}）")
                    continue
                if results:
                    output_files.extend(Path(p) for p in results)
                else:
                    failed.append(xlog.name)

            if not output_files:
                shutil.rmtree(work_dir, ignore_errors=True)
                yield emit(
                    {
                        "type": "done",
                        "ok": False,
                        "error": (
                            "解密失败：未能生成明文日志。"
                            "解密失败：未能生成明文日志。请换一个脚本再试。"
                        ),
                    }
                )
                return

            zip_path = None
            if len(output_files) > 1:
                yield emit(
                    {
                        "type": "progress",
                        "stage": "pack",
                        "current": 1,
                        "total": 1,
                        "percent": 95,
                        "message": "正在打包解密结果…",
                    }
                )
                zip_path = work_dir / "decoded_logs.zip"
                _zip_outputs(output_files, zip_path, work_dir)

            if len(upload_names) == 1:
                title = upload_names[0]
            else:
                # Prefer folder name when many files share a top-level directory
                tops = []
                for n in upload_names:
                    part = n.replace("\\", "/").split("/", 1)[0]
                    tops.append(part)
                if len(set(tops)) == 1 and any("/" in n.replace("\\", "/") for n in upload_names):
                    title = f"{tops[0]}/（{len(upload_names)} 个文件）"
                else:
                    title = f"{upload_names[0]} 等 {len(upload_names)} 个文件"
            job = {
                "id": job_id,
                "created_at": _now_iso(),
                "title": title[:120],
                "note": "",
                "script": script_label,
                "script_name": script_label,
                "uploads": upload_names,
                "sources": [_file_meta(p, work_dir) for p in all_xlogs],
                "decoded": [_file_meta(p, work_dir) for p in output_files],
                "failed": failed,
                "zip": "decoded_logs.zip" if zip_path else None,
            }
            _upsert_job(job)
            yield emit(
                {
                    "type": "progress",
                    "stage": "done",
                    "current": total_xlogs,
                    "total": total_xlogs,
                    "percent": 100,
                    "message": "解密完成",
                }
            )
            yield emit({"type": "done", "ok": True, "job": job})
        except zipfile.BadZipFile:
            shutil.rmtree(work_dir, ignore_errors=True)
            yield emit({"type": "done", "ok": False, "error": "ZIP 文件损坏或格式不正确"})
        except ValueError as e:
            shutil.rmtree(work_dir, ignore_errors=True)
            yield emit({"type": "done", "ok": False, "error": str(e)})
        except Exception as e:
            shutil.rmtree(work_dir, ignore_errors=True)
            yield emit({"type": "done", "ok": False, "error": "处理失败：" + str(e)})

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

def _decode_line(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").rstrip("\r\n")


def _count_lines(path: Path) -> int:
    total = 0
    with path.open("rb") as fp:
        for _ in fp:
            total += 1
    return total


def _read_tail(path: Path, count: int) -> tuple[list[dict], int, bool, int]:
    """Read last `count` lines in a single pass. Returns (lines, start, has_up, total)."""
    from collections import deque

    count = max(1, min(int(count), 2000))
    buf: deque[bytes] = deque(maxlen=count)
    total = 0
    with path.open("rb") as fp:
        for raw in fp:
            total += 1
            buf.append(raw)
    if not buf:
        return [], 1, False, 0
    start_line = total - len(buf) + 1
    lines = [{"n": start_line + i, "text": _decode_line(raw)} for i, raw in enumerate(buf)]
    return lines, start_line, start_line > 1, total


def _read_range(path: Path, start_line: int, count: int) -> tuple[list[dict], bool]:
    """Read [start_line, start_line+count). Returns (lines, has_more_below)."""
    start_line = max(1, int(start_line))
    count = max(1, min(int(count), 2000))
    lines: list[dict] = []
    has_more = False
    with path.open("rb") as fp:
        for idx, raw in enumerate(fp, start=1):
            if idx < start_line:
                continue
            if len(lines) >= count:
                has_more = True
                break
            lines.append({"n": idx, "text": _decode_line(raw)})
    return lines, has_more


_LEVEL_RE = re.compile(r"^\[([EWIDV])\]")


def _line_level(text: str) -> str | None:
    m = _LEVEL_RE.match(text.lstrip())
    return m.group(1) if m else None


def _build_matcher(query: str, match_mode: str):
    """Return a callable(text) -> bool for search matching."""
    mode = (match_mode or "plain").lower()
    q = (query or "").strip()
    if not q:
        return lambda _t: True

    if mode == "regex":
        try:
            pattern = re.compile(q, re.IGNORECASE)
        except re.error as e:
            raise ValueError("正则无效：" + str(e)) from e
        return lambda text: pattern.search(text) is not None

    # Default box: "a|b" means any, "a&b" means all (matches the placeholder).
    if mode == "plain":
        if "&" in q and "|" not in q:
            mode = "and"
        elif "|" in q and "&" not in q:
            mode = "or"

    if mode == "or":
        parts = [p.strip() for p in re.split(r"\s*\|\s*|\s+OR\s+", q, flags=re.IGNORECASE) if p.strip()]
        if not parts:
            parts = [q]
        lows = [p.lower() for p in parts]
        return lambda text: any(p in text.lower() for p in lows)

    if mode == "and":
        parts = [p.strip() for p in re.split(r"\s*&\s*|\s+AND\s+", q, flags=re.IGNORECASE) if p.strip()]
        if not parts:
            parts = [q]
        lows = [p.lower() for p in parts]
        return lambda text: all(p in text.lower() for p in lows)

    # plain substring
    needle = q.lower()
    return lambda text: needle in text.lower()


def _search_file(
    path: Path,
    query: str,
    max_hits: int = SEARCH_MAX_HITS,
    match_mode: str = "plain",
    level: str = "",
    offset: int = 0,
    from_end: bool = False,
) -> tuple[list[dict], int, bool, int, int, int]:
    """Search the complete file and return one page of matching lines.

    Always scans the whole document. ``max_hits`` only limits how many rows
    are returned in this response. ``first_n`` / ``last_n`` are the line
    numbers of the first and last match in the entire file.

    ``from_end`` returns the last page of matches instead of the page at
    ``offset``. The caller derives that page's offset from ``total - len(hits)``.
    """
    from collections import deque

    matcher = _build_matcher(query, match_mode)
    level = (level or "").strip().upper()
    allowed = set(level.replace(",", "").replace(" ", "")) if level and level not in ("ALL", "*") else set()
    max_hits = max(1, int(max_hits))
    offset = max(0, int(offset))

    hits: list[dict] = []
    tail: deque[dict] = deque(maxlen=max_hits)
    scanned = 0
    matched = 0
    first_n = 0
    last_n = 0
    with path.open("rb") as fp:
        for idx, raw in enumerate(fp, start=1):
            scanned = idx
            text_line = _decode_line(raw)
            if allowed:
                lv = _line_level(text_line)
                if not lv or lv not in allowed:
                    continue
            if matcher(text_line):
                matched += 1
                if first_n == 0:
                    first_n = idx
                last_n = idx
                row = {"n": idx, "text": text_line, "level": _line_level(text_line)}
                if from_end:
                    tail.append(row)
                    continue
                if matched <= offset:
                    continue
                if len(hits) < max_hits:
                    hits.append(row)
    if from_end:
        hits = list(tail)
        has_more = False
    else:
        has_more = matched > offset + len(hits)
    return hits, scanned, has_more, matched, first_n, last_n


@app.route("/api/reveal/<job_id>", methods=["POST"])
def api_reveal(job_id: str):
    """Open the file's folder in the system file manager (Explorer / Finder)."""
    data = request.get_json(silent=True) or {}
    rel_path = (data.get("path") or request.args.get("path") or "").strip()
    if not rel_path:
        return jsonify({"ok": False, "error": "缺少 path"}), 400
    try:
        full = _resolve_job_file(job_id, rel_path)
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    except ValueError:
        return jsonify({"ok": False, "error": "非法路径"}), 400

    import subprocess
    import sys

    target = str(full.resolve())
    folder = str(full.parent.resolve())
    try:
        if os.name == "nt":
            # Select the file in Explorer
            subprocess.Popen(["explorer", "/select,", target], close_fds=True)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", target], close_fds=True)
        else:
            subprocess.Popen(["xdg-open", folder], close_fds=True)
    except OSError as e:
        return jsonify({"ok": False, "error": "无法打开文件夹：" + str(e)}), 500
    return jsonify({"ok": True, "folder": folder, "path": target})


@app.route("/api/file-path/<job_id>", methods=["GET"])
def api_file_path(job_id: str):
    """Return the decrypted file's absolute path so the page can copy it."""
    rel_path = (request.args.get("path") or "").strip()
    if not rel_path:
        return jsonify({"ok": False, "error": "缺少 path"}), 400
    try:
        full = _resolve_job_file(job_id, rel_path)
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    except ValueError:
        return jsonify({"ok": False, "error": "非法路径"}), 400
    return jsonify({"ok": True, "path": str(full.resolve())})


@app.route("/api/file/<job_id>", methods=["GET"])
def api_file(job_id: str):
    rel_path = request.args.get("path", "")
    download = request.args.get("download", "0") == "1"
    if not rel_path:
        return jsonify({"ok": False, "error": "缺少 path"}), 400

    try:
        full = _resolve_job_file(job_id, rel_path)
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    except ValueError:
        return jsonify({"ok": False, "error": "非法路径"}), 400

    if download:
        return send_file(full, as_attachment=True, download_name=full.name)

    mode = (request.args.get("mode") or "range").lower()
    try:
        max_lines = min(int(request.args.get("lines") or PREVIEW_LINES), 2000)
    except ValueError:
        max_lines = PREVIEW_LINES
    try:
        start_line = max(1, int(request.args.get("start") or 1))
    except ValueError:
        start_line = 1

    size = full.stat().st_size
    query = (request.args.get("q") or "").strip()
    match_mode = (request.args.get("match") or "plain").lower()
    level = (request.args.get("level") or "").strip().upper()

    if mode == "search":
        if not query and not level:
            return jsonify({"ok": False, "error": "empty_query"}), 400
        try:
            try:
                search_offset = max(0, int(request.args.get("offset") or 0))
            except ValueError:
                search_offset = 0
            try:
                limit = int(request.args.get("limit") or SEARCH_MAX_HITS)
            except ValueError:
                limit = SEARCH_MAX_HITS
            limit = max(1, min(limit, SEARCH_MAX_HITS))
            from_end = (request.args.get("from_end") or "").lower() in ("1", "true", "yes")
            hits, scanned, has_more, total_hits, first_n, last_n = _search_file(
                full,
                query,
                limit,
                match_mode=match_mode,
                level=level,
                offset=search_offset,
                from_end=from_end,
            )
            if from_end:
                search_offset = max(0, total_hits - len(hits))
                has_more = False
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        effective_mode = match_mode
        if effective_mode == "plain" and query:
            if "&" in query and "|" not in query:
                effective_mode = "and"
            elif "|" in query and "&" not in query:
                effective_mode = "or"
        mode_label = {"plain": "包含", "or": "任一", "and": "全部", "regex": "正则"}.get(
            effective_mode, effective_mode
        )
        level_label = f" · 级别 {level}" if level else ""
        shown_from = search_offset + 1 if hits else 0
        shown_to = search_offset + len(hits)
        shown_q = query if len(query) <= 40 else query[:40] + "…"
        span = f"，分布在 L{first_n}–L{last_n} / 共 {scanned} 行" if first_n else f" · 已扫描 {scanned} 行"
        if total_hits == 0:
            message = f"全文已扫描 {scanned} 行，未找到「{shown_q}」（{mode_label}{level_label}）"
        elif from_end and search_offset > 0:
            message = (
                f"「{shown_q}」全文共 {total_hits} 处（{mode_label}{level_label}）{span}，"
                f"当前列出最后 {len(hits)} 处（第 {shown_from}–{shown_to} 处） · 上滑加载更早匹配"
            )
        elif from_end:
            message = (
                f"「{shown_q}」全文共 {total_hits} 处（{mode_label}{level_label}）{span}，已全部列出 · 已定位到末尾"
            )
        elif has_more:
            message = (
                f"「{shown_q}」全文共 {total_hits} 处（{mode_label}{level_label}）{span}，"
                f"当前列出第 {shown_from}–{shown_to} 处，其余正在继续加载"
            )
        else:
            message = (
                f"「{shown_q}」全文共 {total_hits} 处（{mode_label}{level_label}）{span}，已全部列出"
            )
        try:
            runtime_dir = BASE_DIR / ".runtime"
            runtime_dir.mkdir(exist_ok=True)
            with (runtime_dir / "search.log").open("a", encoding="utf-8") as logf:
                logf.write(
                    f"{_now_iso()}\tq={query!r}\tmode={match_mode}\tlevel={level}\t"
                    f"offset={search_offset}\tfrom_end={from_end}\thits={len(hits)}\ttotal={total_hits}\t"
                    f"scanned={scanned}\tfirst={first_n}\tlast={last_n}\t"
                    f"has_more={has_more}\tfile={full.name}\n"
                )
        except OSError:
            pass
        return jsonify(
            {
                "ok": True,
                "name": full.name,
                "path": rel_path,
                "size": size,
                "mode": "search",
                "query": query,
                "match": match_mode,
                "level": level,
                "lines": hits,
                "hit_count": len(hits),
                "total_hits": total_hits,
                "first_line": first_n,
                "last_line": last_n,
                "offset": search_offset,
                "next_offset": search_offset + len(hits),
                "from_end": from_end,
                "has_more": has_more,
                "scanned_lines": scanned,
                "capped": has_more,
                "has_more_up": False,
                "has_more_down": False,
                "message": message,
            }
        )
    if mode == "tail":
        lines, start_line, has_more_up, total = _read_tail(full, max_lines)
        end_n = lines[-1]["n"] if lines else 0
        return jsonify(
            {
                "ok": True,
                "name": full.name,
                "path": rel_path,
                "size": size,
                "mode": "tail",
                "lines": lines,
                "start": start_line,
                "end": end_n,
                "total_lines": total,
                "has_more_up": has_more_up,
                "has_more_down": False,
                "message": f"末尾 L{start_line}-{end_n}/{total} · 上滑加载更早内容",
            }
        )

    if mode == "head":
        start_line = 1
        report_mode = "head"
    else:
        report_mode = "range"

    lines, has_more_down = _read_range(full, start_line, max_lines)
    end_n = lines[-1]["n"] if lines else start_line - 1
    return jsonify(
        {
            "ok": True,
            "name": full.name,
            "path": rel_path,
            "size": size,
            "mode": report_mode,
            "lines": lines,
            "start": start_line,
            "end": end_n,
            "has_more_up": start_line > 1,
            "has_more_down": has_more_down,
            "message": (
                f"预览 L{start_line}-{end_n}"
                + (" · 下滑继续加载" if has_more_down else " · 已到文件末尾")
                + (" · 上滑加载更早" if start_line > 1 else "")
            ),
        }
    )


if __name__ == "__main__":
    import atexit
    import socket
    import sys
    import threading

    from waitress import serve

    host = "127.0.0.1"
    port = 5000
    lock_path = UPLOAD_ROOT / ".server.lock"
    lock_state = {"fh": None}
    is_windows = os.name == "nt"

    def _lock_file(fh) -> None:
        if is_windows:
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_file(fh) -> None:
        if is_windows:
            import msvcrt

            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _release_lock() -> None:
        fh = lock_state["fh"]
        if fh is None:
            return
        try:
            _unlock_file(fh)
        except OSError:
            pass
        try:
            fh.close()
        except OSError:
            pass
        lock_state["fh"] = None
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass

    # Exclusive lock prevents double-start (port check alone can race)
    fh = None
    try:
        fh = open(lock_path, "a+b")
        _lock_file(fh)
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()).encode("ascii"))
        fh.flush()
        lock_state["fh"] = fh
    except OSError:
        print(f"已有实例在运行: http://{host}:{port}")
        print("不会重复启动。直接打开浏览器即可。")
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass
        sys.exit(0)

    atexit.register(_release_lock)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        in_use = sock.connect_ex((host, port)) == 0
    if in_use:
        print(f"端口 {port} 已被占用，但锁文件可获取 — 请关闭占用进程后重试。")
        _release_lock()
        sys.exit(1)

    threading.Thread(target=_ensure_legacy_scanned, daemon=True).start()
    print(f"Easy Log Watch 已启动: http://{host}:{port}")
    try:
        serve(app, host=host, port=port, threads=6, channel_timeout=120)
    except OSError as e:
        print("启动失败（端口可能被占用）:", e)
        _release_lock()
        sys.exit(1)
    finally:
        _release_lock()

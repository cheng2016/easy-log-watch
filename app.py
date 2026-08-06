# -*- coding: utf-8 -*-
"""Local web UI for Mars/xlog log decryption with history and preview."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import json
import os
import re
import shutil
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file, stream_with_context

from script_runner import default_script, list_scripts, resolve_script, run_script

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / ".uploads"
HISTORY_FILE = UPLOAD_ROOT / "history.json"
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB
PREVIEW_LINES = 400
SEARCH_MAX_HITS = 200

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


def _resolve_job_file(job_id: str, rel_path: str) -> Path:
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


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract zip members without Zip Slip / absolute paths."""
    dest = dest.resolve()
    # Python 3.12+ has built-in filter against path traversal
    try:
        zf.extractall(dest, filter="data")
        return
    except TypeError:
        pass

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
        if not str(target).startswith(str(dest) + os.sep):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)


def _extract_xlogs(work_dir: Path, uploaded_path: Path) -> list[Path]:
    xlogs: list[Path] = []
    suffix = uploaded_path.suffix.lower()
    name_lower = uploaded_path.name.lower()

    if suffix == ".zip":
        extract_dir = work_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(uploaded_path, "r") as zf:
            _safe_extract_zip(zf, extract_dir)
        for root, _, files in os.walk(extract_dir):
            for fname in files:
                if fname.lower().endswith(".xlog") and not fname.lower().endswith(".xlog.log"):
                    xlogs.append(Path(root) / fname)
    elif name_lower.endswith(".xlog") and not name_lower.endswith(".xlog.log"):
        xlogs.append(uploaded_path)
    else:
        # Ignore unrelated files (useful when uploading a whole folder)
        return []

    return xlogs


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
    with _history_lock:
        items = _load_history()
        new_items = [x for x in items if x.get("id") != job_id]
        if len(new_items) == len(items):
            return jsonify({"ok": False, "error": "记录不存在"}), 404
        _save_history(new_items)
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
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
) -> tuple[list[dict], int, bool]:
    matcher = _build_matcher(query, match_mode)
    level = (level or "").strip().upper()
    allowed = set(level.replace(",", "").replace(" ", "")) if level and level not in ("ALL", "*") else set()

    hits: list[dict] = []
    scanned = 0
    capped = False
    with path.open("rb") as fp:
        for idx, raw in enumerate(fp, start=1):
            scanned = idx
            text_line = _decode_line(raw)
            if allowed:
                lv = _line_level(text_line)
                if not lv or lv not in allowed:
                    continue
            if matcher(text_line):
                hits.append({"n": idx, "text": text_line, "level": _line_level(text_line)})
                if len(hits) >= max_hits:
                    capped = True
                    break
    return hits, scanned, capped


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
            hits, scanned, capped = _search_file(
                full,
                query,
                SEARCH_MAX_HITS,
                match_mode=match_mode,
                level=level,
            )
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        mode_label = {"plain": "包含", "or": "任一", "and": "全部", "regex": "正则"}.get(
            match_mode, match_mode
        )
        level_label = f" · 级别 {level}" if level else ""
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
                "scanned_lines": scanned,
                "capped": capped,
                "has_more_up": False,
                "has_more_down": False,
                "message": (
                    f"找到 {len(hits)} 处（{mode_label}{level_label}）"
                    + (f"；已达上限 {SEARCH_MAX_HITS}" if capped else "")
                    + " · 点击行可跳转上下文"
                ),
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

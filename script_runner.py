# -*- coding: utf-8 -*-
"""List and run local decode scripts under scripts/ via subprocess."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
DEFAULT_SCRIPT = "decode_mars_nocrypt_log_file.py"
_RUN_TIMEOUT_SEC = 600

_KNOWN_DESC = {
    "decode_mars_nocrypt_log_file.py": "Mars 未加密 xlog：只做压缩解压（zlib / zstd）",
    "decode_mars_crypt_log_file.py": "Mars 加密 xlog：ECDH + TEA（私钥写在脚本 PRIV_KEY）",
}

_DESC_LINE_RE = re.compile(
    r"^\s*(?:#\s*DESCRIPTION\s*[:=]\s*|DESCRIPTION\s*=\s*[\"'])(.+?)[\"']?\s*$",
    re.IGNORECASE,
)


def _read_head(path: Path, limit: int = 80) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[:limit])


def script_description(path: Path) -> str:
    """Rough one-line note about how the script decrypts."""
    name = path.name
    head = _read_head(path)
    for line in head.splitlines():
        m = _DESC_LINE_RE.match(line)
        if m:
            return m.group(1).strip()[:120]
    if name in _KNOWN_DESC:
        return _KNOWN_DESC[name]
    lower = name.lower()
    head_l = head.lower()
    if "nocrypt" in lower:
        return "Mars 未加密：压缩解压"
    if "crypt" in lower or "priv_key" in head_l or "ecdh" in head_l or "tea" in head_l:
        return "Mars 加密类：ECDH / TEA 等（看脚本内密钥配置）"
    if "zstd" in head_l or "zlib" in head_l:
        return "自定义脚本（含压缩解压逻辑）"
    return "自定义脚本"


def list_scripts() -> list[dict]:
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(SCRIPTS_DIR.glob("*.py")):
        if not path.is_file() or path.name.startswith("_"):
            continue
        items.append(
            {
                "id": path.name,
                "name": path.name,
                "description": script_description(path),
            }
        )
    return items


def default_script() -> str:
    names = {item["id"] for item in list_scripts()}
    if DEFAULT_SCRIPT in names:
        return DEFAULT_SCRIPT
    return next(iter(sorted(names)), DEFAULT_SCRIPT)


def resolve_script(script_name: str) -> Path:
    name = Path(script_name or "").name.strip()
    if not name or not name.endswith(".py") or name.startswith("_"):
        raise ValueError("无效的解密脚本：" + (script_name or ""))
    path = (SCRIPTS_DIR / name).resolve()
    if path.parent != SCRIPTS_DIR.resolve() or not path.is_file():
        raise ValueError("未找到解密脚本：" + name)
    return path


def run_script(script_name: str, xlog_path: str) -> list[str]:
    """Run ``python <script> <xlog>`` (official Mars CLI style).

    Successful decode writes ``<xlog>.log`` next to the input file.
    """
    script = resolve_script(script_name)
    xlog = Path(xlog_path).resolve()
    if not xlog.is_file():
        raise FileNotFoundError("找不到 xlog：" + str(xlog))

    out_path = Path(str(xlog) + ".log")
    if out_path.exists():
        try:
            out_path.unlink()
        except OSError:
            pass

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, "-B", str(script), str(xlog)],
            cwd=str(xlog.parent),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_RUN_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"解密脚本超时（>{_RUN_TIMEOUT_SEC}s）：{script.name}") from e

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        msg = f"解密脚本退出码 {proc.returncode}：{script.name}"
        if detail:
            msg += "\n" + detail[:800]
        raise RuntimeError(msg)

    if out_path.is_file() and out_path.stat().st_size > 0:
        return [str(out_path)]
    return []

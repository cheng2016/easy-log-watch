#!/usr/bin/env bash
# Easy Log Watch — macOS / Linux one-click start
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONDONTWRITEBYTECODE=1

pick_python() {
  if command -v python3 >/dev/null 2>&1; then
    echo python3
  elif command -v python >/dev/null 2>&1; then
    echo python
  else
    echo ""
  fi
}

PY="$(pick_python)"
if [[ -z "$PY" ]]; then
  echo "[ERROR] 未找到 Python 3。请先安装：https://www.python.org/downloads/"
  echo "        macOS 也可用: brew install python"
  exit 1
fi

# Already up? open browser only
if "$PY" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/', timeout=0.6)" >/dev/null 2>&1; then
  echo "Already running. Opening browser..."
  if command -v open >/dev/null 2>&1; then
    open "http://127.0.0.1:5000/"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:5000/" >/dev/null 2>&1 || true
  fi
  exit 0
fi

if ! "$PY" -c "import flask,zstandard,waitress" >/dev/null 2>&1; then
  echo "Checking/installing dependencies..."
  "$PY" -m pip install -r requirements.txt
fi

mkdir -p .runtime
"$PY" -c "import hashlib,pathlib; p=pathlib.Path('requirements.txt'); h=hashlib.sha1((p.read_bytes() if p.exists() else b'')).hexdigest()[:12]; pathlib.Path('.runtime').mkdir(exist_ok=True); pathlib.Path('.runtime/deps_ok').write_text(h, encoding='utf-8')"

echo "Starting server..."
nohup "$PY" app.py >.runtime/server.log 2>&1 &
echo $! >.runtime/server.pid

echo "Waiting for ready..."
if ! "$PY" wait_ready.py; then
  echo "[ERROR] Server did not start in time."
  echo "        查看日志: .runtime/server.log"
  exit 1
fi

echo "Ready. Opening browser..."
if command -v open >/dev/null 2>&1; then
  open "http://127.0.0.1:5000/"
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://127.0.0.1:5000/" >/dev/null 2>&1 || true
else
  echo "请手动打开: http://127.0.0.1:5000/"
fi

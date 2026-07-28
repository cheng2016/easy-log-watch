@echo off
cd /d "%~dp0"
setlocal EnableExtensions

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3 and add it to PATH.
    pause
    exit /b 1
)

REM Already up? open browser only (no second server)
python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/', timeout=0.6)" 1>nul 2>&1
if not errorlevel 1 (
    echo Already running. Opening browser...
    start "" "http://127.0.0.1:5000/"
    exit /b 0
)

REM Soft deps check keyed to requirements.txt hash
python -c "import flask,zstandard,waitress" 1>nul 2>&1
if errorlevel 1 (
    echo Checking/installing dependencies...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
)
if not exist ".runtime" mkdir ".runtime"
python -c "import hashlib,pathlib; p=pathlib.Path('requirements.txt'); h=hashlib.sha1((p.read_bytes() if p.exists() else b'')).hexdigest()[:12]; pathlib.Path('.runtime').mkdir(exist_ok=True); pathlib.Path('.runtime/deps_ok').write_text(h, encoding='utf-8')"

echo Starting server...
start "easy-log-watch" /min python app.py

echo Waiting for ready...
python wait_ready.py
if errorlevel 1 (
    echo [ERROR] Server did not start in time.
    echo Open the minimized easy-log-watch window for details.
    pause
    exit /b 1
)

echo Ready. Opening browser...
start "" "http://127.0.0.1:5000/"
exit /b 0

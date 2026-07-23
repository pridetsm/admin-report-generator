@echo off
REM ===========================================================================
REM  serve.bat  -  start the Django "Report Builder" webapp.
REM
REM  Runs Django's built-in dev server via the project virtualenv, bound to all
REM  interfaces so the LAN can reach it (your firewall/open port is what scopes
REM  access to the same network). If the target port is ALREADY in use, whatever
REM  is listening on it is stopped first, so re-running this always gives you a
REM  fresh server on that port.
REM
REM  Usage:
REM      serve.bat            ->  http://0.0.0.0:8000
REM      serve.bat 8080       ->  listen on port 8080 instead
REM
REM  Stop the server with Ctrl+C. For a production process (auto-restart on boot),
REM  use waitress - see the block at the bottom.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

REM --- port: first argument, default 8000 ---
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8000"

REM --- dev server needs DEBUG on to serve /static/ without collectstatic ---
set "DJANGO_DEBUG=1"

REM --- reclaim the port: stop anything already LISTENING on it (fresh start wins) ---
echo Checking port %PORT% for an existing listener ...
powershell -NoProfile -Command "$p = Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue | Select-Object -Expand OwningProcess -Unique; if ($p) { foreach ($procId in $p) { $n = (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName; Write-Host ('  stopping PID ' + $procId + ' (' + $n + ') on port %PORT%'); taskkill /PID $procId /T /F | Out-Null } } else { Write-Host ('  port %PORT% is free') }"

REM --- give the OS a moment to fully release the socket before we re-bind it ---
timeout /t 1 /nobreak >nul

REM --- interpreter: prefer the project venv, then py launcher, then python ---
set "PY=%~dp0.venv\Scripts\python.exe"
if exist "%PY%" goto :run
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
    echo [x] No Python found: no .venv here and neither py nor python is on PATH.
    echo     Create the venv ^(python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt^)
    echo     or put Python on PATH, then re-run.
    exit /b 9
)

:run
echo Using interpreter: %PY%
"%PY%" --version
echo Starting Django dev server on http://0.0.0.0:%PORT%   (Ctrl+C to stop)
"%PY%" manage.py runserver 0.0.0.0:%PORT%
endlocal

REM ===========================================================================
REM  PRODUCTION (waitress) - swap the runserver line above for these two steps:
REM      "%PY%" -m pip install waitress
REM      "%PY%" -m waitress --listen=0.0.0.0:%PORT% config.wsgi:application
REM  With DEBUG off you must also run:  "%PY%" manage.py collectstatic --noinput
REM  and let a reverse proxy serve webapp\staticfiles\ (see deployment.txt).
REM ===========================================================================

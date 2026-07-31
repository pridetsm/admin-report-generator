@echo off
REM ===========================================================================
REM  System Admin Report — the scheduled daily mailing.
REM  Captures a live Prometheus snapshot ONCE, builds the XLSX report from that
REM  same snapshot, and e-mails the styled preview to the mailing list with the
REM  report attached AND the link to the Grafana Report Generator webapp.
REM  One call does it all (--attach), so the attachment and the summary in the
REM  body can never describe different moments.
REM  Drop --attach for the link-only e-mail; add --theme light for the light
REM  palette. All output is written to mail_last.log so scheduled (no-console)
REM  runs can be diagnosed.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0mail_last.log"

> "%LOG%" echo ===== Mailing run: %DATE% %TIME% (user: %USERNAME%) =====

REM --- locate Python (py launcher preferred, then python on PATH) ---
set "PY="
where py     >nul 2>&1 && set "PY=py"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
    >> "%LOG%" echo [x] Python NOT found on PATH for this account.
    >> "%LOG%" echo     The task probably runs as SYSTEM/another user that cannot see your Python.
    >> "%LOG%" echo     Fix: run the task as your own account ^(Run whether logged on or not^),
    >> "%LOG%" echo          or set the full path to python.exe below.
    type "%LOG%"
    exit /b 9
)
>> "%LOG%" echo Using launcher: %PY%
%PY% --version >> "%LOG%" 2>&1

>> "%LOG%" echo [1/2] Checking requirements...
REM  openpyxl + PIL are needed for the attached XLSX; yaml for the topology.
%PY% -c "import yaml, openpyxl, PIL" >nul 2>&1
if errorlevel 1 (
    >> "%LOG%" echo     installing from requirements.txt ...
    %PY% -m pip install --disable-pip-version-check -r requirements.txt >> "%LOG%" 2>&1
    if errorlevel 1 ( >> "%LOG%" echo [x] Failed to install requirements. & type "%LOG%" & exit /b 1 )
)

>> "%LOG%" echo [2/2] Building the report and e-mailing it to the mailing list...
%PY% mail_report.py --attach --send >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] E-mail send failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

@echo off
REM ===========================================================================
REM  System Admin Report — generate the XLSX and e-mail it to the mailing list.
REM  Two explicit steps, so the report is ALSO left on disk under its config.ini
REM  name ("System Admin Report.xlsx") for anyone/anything that reads it there.
REM  Note: that means two Prometheus captures, a few seconds apart. If you only
REM  want the e-mail with the report attached, use runmailing.bat instead — it
REM  captures once and does both.
REM  All output is written to run_last.log so scheduled (no-console) runs can be
REM  diagnosed. Steps: check requirements -> generate_report.py -> mail_report.py
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_last.log"

> "%LOG%" echo ===== System Admin Report run: %DATE% %TIME% (user: %USERNAME%) =====

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

>> "%LOG%" echo [1/3] Checking requirements...
%PY% -c "import openpyxl, yaml, PIL" >nul 2>&1
if errorlevel 1 (
    >> "%LOG%" echo     installing from requirements.txt ...
    %PY% -m pip install --disable-pip-version-check -r requirements.txt >> "%LOG%" 2>&1
    if errorlevel 1 ( >> "%LOG%" echo [x] Failed to install requirements. & type "%LOG%" & exit /b 1 )
)

>> "%LOG%" echo [2/3] Generating report...
%PY% generate_report.py >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] Report generation failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [3/3] E-mailing report to the mailing list...
%PY% mail_report.py --report "System Admin Report.xlsx" --send >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] E-mail send failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

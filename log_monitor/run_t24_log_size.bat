@echo off
REM ===========================================================================
REM  run_t24_log_size.bat - launch check_log_size_t24.ps1 for Task Scheduler.
REM  Wraps the PowerShell check so the scheduled task is a single .bat entry and
REM  all output lands in run_t24_log_size_last.log for no-console diagnosis.
REM  Any extra args are passed through to the .ps1 (e.g. -FilePath, -TextfileDir).
REM  Deploy: Task Scheduler, every few minutes, as an account that can read the
REM  T24 install path and write the windows_exporter textfile dir.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_t24_log_size_last.log"
set "PS1=%~dp0check_log_size_t24.ps1"

> "%LOG%" echo ===== T24 log size check run: %DATE% %TIME% (user: %USERNAME%) =====

REM --- locate PowerShell ---
set "PWSH="
where powershell >nul 2>&1 && set "PWSH=powershell"
if not defined PWSH (
    >> "%LOG%" echo [x] powershell.exe NOT found on PATH for this account.
    type "%LOG%"
    exit /b 9
)

if not exist "%PS1%" (
    >> "%LOG%" echo [x] Missing script: "%PS1%"
    type "%LOG%"
    exit /b 9
)

>> "%LOG%" echo [*] Running check_log_size_t24.ps1 %*
%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %* >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" (
    >> "%LOG%" echo [OK] Log file found, metrics written. Done: %DATE% %TIME%
) else if "%RC%"=="1" (
    >> "%LOG%" echo [!] Log file MISSING - wrote log_check_success 0. Done: %DATE% %TIME%
) else (
    >> "%LOG%" echo [x] check_log_size_t24.ps1 failed with exit %RC%. Done: %DATE% %TIME%
)

type "%LOG%"
endlocal & exit /b %RC%

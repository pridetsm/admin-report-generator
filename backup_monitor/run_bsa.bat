@echo off
REM ===========================================================================
REM  run_bsa.bat - launch check_backup_bsa.ps1 for Task Scheduler.
REM  Wraps the PowerShell check so the daily task is a single .bat entry and all
REM  output lands in run_bsa_last.log for no-console (scheduled) diagnosis.
REM  Any extra args are passed through to the .ps1 (e.g. -BackupRoot, -TextfileDir).
REM  Deploy: Task Scheduler, daily AFTER the BSA backup window, as an account
REM  that can read E:\BACKUP and write the windows_exporter textfile dir.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_bsa_last.log"
set "PS1=%~dp0check_backup_bsa.ps1"

> "%LOG%" echo ===== BSA backup check run: %DATE% %TIME% (user: %USERNAME%) =====

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

>> "%LOG%" echo [*] Running check_backup_bsa.ps1 %*
%PWSH% -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %* >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" (
    >> "%LOG%" echo [OK] Backup root reachable, metrics written. Done: %DATE% %TIME%
) else if "%RC%"=="1" (
    >> "%LOG%" echo [!] Backup root MISSING/unreadable - wrote backup_check_success 0. Done: %DATE% %TIME%
) else (
    >> "%LOG%" echo [x] check_backup_bsa.ps1 failed with exit %RC%. Done: %DATE% %TIME%
)

type "%LOG%"
endlocal & exit /b %RC%

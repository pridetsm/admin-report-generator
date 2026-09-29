@echo off
REM ===========================================================================
REM  System Admin Report — unattended daily generation + e-mail, single call
REM  to manage.py generate_system_admin_report (no arguments — that command
REM  never takes one, see its own docstring).
REM  Scheduled from folder_exporter.yml's own job scheduler (see
REM  deploy\gms\folder_exporter.yml, job: system_admin_report), same
REM  mechanism as run_active_directory_report.bat/run_alerts.bat/run_events.bat.
REM  Replaces the OLD standalone\systems admin report\run_and_mail.bat job --
REM  see generate_system_admin_report.py's own module docstring for why.
REM  Bare and argument-free directly (folder_exporter's command: field launches
REM  the whole string as ONE literal process path with no argv splitting --
REM  2026-09-11 lesson, see run_automated_report_weekly_trend.bat and siblings).
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install
REM  check) since that venv already has every dependency this needs.
REM  Logs to run_system_admin_report_last.log.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_system_admin_report_last.log"

> "%LOG%" echo ===== System Admin Report run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py generate_system_admin_report >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] generate_system_admin_report failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

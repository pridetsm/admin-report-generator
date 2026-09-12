@echo off
REM ===========================================================================
REM  Active Directory Report — unattended daily generation + e-mail, single
REM  call to manage.py generate_active_directory_report (no arguments — that
REM  command never takes one, see its own docstring).
REM  Scheduled from folder_exporter.yml's own job scheduler (see
REM  deploy\gms\folder_exporter.yml, job: active_directory_report), same
REM  mechanism as run_alerts.bat/run_events.bat/run_system_alerts.bat.
REM  Bare and argument-free directly (no run_automated_report.bat-style
REM  wrapper-of-a-wrapper needed): folder_exporter's command: field launches
REM  the whole string as ONE literal process path with no argv splitting
REM  (2026-09-11 lesson -- see run_automated_report_weekly_trend.bat and
REM  siblings), and this command never takes an argument in the first place.
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install
REM  check) since that venv already has every dependency this needs.
REM  Logs to run_active_directory_report_last.log.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_active_directory_report_last.log"

> "%LOG%" echo ===== Active Directory Report run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py generate_active_directory_report >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] generate_active_directory_report failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

@echo off
REM ===========================================================================
REM  Network Reports (Core Switches, Routers, Wireless Controller, Access
REM  Switches) — unattended daily generation + one bundled e-mail, single call
REM  to manage.py generate_network_reports (no arguments — that command never
REM  takes one, see its own docstring). The four reports run CONCURRENTLY
REM  inside that one process (concurrent.futures.ThreadPoolExecutor) rather
REM  than as four separate scheduled jobs/processes here — see that command's
REM  own module docstring for why.
REM  Scheduled from folder_exporter.yml's own job scheduler (see
REM  deploy\gms\folder_exporter.yml, job: network_reports), same mechanism as
REM  run_active_directory_report.bat/run_system_admin_report.bat.
REM  Bare and argument-free directly: folder_exporter's command: field launches
REM  the whole string as ONE literal process path with no argv splitting
REM  (2026-09-11 lesson -- see run_automated_report_weekly_trend.bat and
REM  siblings), and this command never takes an argument in the first place.
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install
REM  check) since that venv already has every dependency this needs.
REM  Logs to run_network_reports_last.log.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_network_reports_last.log"

> "%LOG%" echo ===== Network Reports run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py generate_network_reports >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] generate_network_reports failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

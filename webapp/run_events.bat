@echo off
REM ===========================================================================
REM  Event poller — single call to reports.events.run_event_cycle via
REM  manage.py run_events. Scheduled from folder_exporter.yml's own job
REM  scheduler (jobs: event_poller), the same mechanism run_alerts.bat uses
REM  for alert_poller — see that file's own header for why (a job inside an
REM  already-running service, not a second Windows Scheduled Task).
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install
REM  check) since that venv already has every dependency this needs.
REM  All output goes to run_events_last.log so a no-console scheduled run can
REM  be diagnosed the same way run_alerts_last.log already is.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_events_last.log"

> "%LOG%" echo ===== Event poll run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py run_events >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] run_events failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

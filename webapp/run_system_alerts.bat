@echo off
REM ===========================================================================
REM  System alert poller — single call to reports.system_alerts.run_system_alert_cycle
REM  via manage.py run_system_alerts. Scheduled from folder_exporter.yml's own job
REM  scheduler (jobs: system_alert_poller), the same mechanism run_alerts.bat/
REM  run_events.bat use — see run_alerts.bat's own header for why (a job inside an
REM  already-running service, not a second Windows Scheduled Task — the exact
REM  failure mode this poller itself exists to catch on OTHER hosts' checkers).
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install check)
REM  since that venv already has every dependency this needs.
REM  All output goes to run_system_alerts_last.log so a no-console scheduled run
REM  can be diagnosed the same way run_alerts_last.log/run_events_last.log already are.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_system_alerts_last.log"

> "%LOG%" echo ===== System alert poll run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py run_system_alerts >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] run_system_alerts failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

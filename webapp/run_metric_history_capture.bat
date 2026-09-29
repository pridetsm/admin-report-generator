@echo off
REM ===========================================================================
REM  Metric history capture — single call to reports.metric_history.capture_now
REM  via manage.py capture_metric_history. Scheduled from folder_exporter.yml's
REM  own job scheduler (jobs: metric_history_capture), the same mechanism
REM  run_alerts.bat uses for alert_poller — see that file's own header for why
REM  (a job inside an already-running service, not a second Windows Scheduled
REM  Task).
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install
REM  check) since that venv already has every dependency this needs.
REM  All output goes to run_metric_history_capture_last.log so a no-console
REM  scheduled run can be diagnosed the same way run_alerts_last.log already is.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_metric_history_capture_last.log"

> "%LOG%" echo ===== Metric history capture run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py capture_metric_history >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] capture_metric_history failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

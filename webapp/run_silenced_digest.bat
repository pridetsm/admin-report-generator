@echo off
REM ===========================================================================
REM  Silenced Alerts digest — single call to reports.alerting.build_silenced_digest
REM  via manage.py run_silenced_digest. Scheduled from folder_exporter.yml's own
REM  job scheduler (see deploy\gms\folder_exporter.yml, jobs: silenced_alerts_digest)
REM  rather than a second Windows Scheduled Task, matching run_alerts.bat/
REM  run_system_alerts.bat's own reasoning — a Task Scheduler entry can drift or
REM  be reset by a GPO baseline / preventive-maintenance sweep; a job inside an
REM  already-running service cannot.
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install check)
REM  since that venv already has every dependency this needs.
REM  All output goes to run_silenced_digest_last.log so a no-console scheduled
REM  run can be diagnosed the same way run_alerts_last.log already is.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_silenced_digest_last.log"

> "%LOG%" echo ===== Silenced Alerts digest run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py run_silenced_digest >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] run_silenced_digest failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

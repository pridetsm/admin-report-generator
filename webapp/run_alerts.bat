@echo off
REM ===========================================================================
REM  Sector alert poller — single call to reports.alerting.run_alert_cycle via
REM  manage.py run_alerts. Scheduled from folder_exporter.yml's own job
REM  scheduler (see deploy\gms\folder_exporter.yml, jobs: alert_poller) rather
REM  than a second Windows Scheduled Task, matching how the daily System Admin
REM  Report job was migrated onto the same mechanism on 2026-08-18 — a Task
REM  Scheduler entry can drift or be reset by a GPO baseline / preventive-
REM  maintenance sweep; a job inside an already-running service cannot.
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install
REM  check) since that venv already has every dependency this needs.
REM  All output goes to run_alerts_last.log so a no-console scheduled run can
REM  be diagnosed the same way run_and_mail.bat's log already is.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "LOG=%~dp0run_alerts_last.log"

> "%LOG%" echo ===== Alert poll run: %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py run_alerts >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] run_alerts failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

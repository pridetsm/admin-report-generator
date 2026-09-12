@echo off
REM ===========================================================================
REM  Automated Reports generator — single call to manage.py generate_automated_report
REM  <report_type>, one call per report type (weekly_trend / monthly_recurring /
REM  quarterly_summary / admin_observations / anomaly_log — NOT system_attention,
REM  which deliberately has no cron, see reports/automated_reports.py's own
REM  REPORT_TYPES entry: it is regenerated on demand from the Automated Reports
REM  screen instead of waiting for a scheduled cycle).
REM  Scheduled from folder_exporter.yml's own job scheduler, same mechanism as
REM  run_alerts.bat/run_events.bat/run_system_alerts.bat — see run_alerts.bat's
REM  own header for why (a job inside an already-running service, not a second
REM  Windows Scheduled Task).
REM  Uses the webapp's OWN venv directly (no PATH lookup, no pip-install check)
REM  since that venv already has every dependency this needs.
REM  %1 is the report_type; each cron entry in folder_exporter.yml passes its own,
REM  so ONE script serves every scheduled report type rather than five near-
REM  identical copies. Logs to run_automated_report_<type>_last.log.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
set "RTYPE=%~1"
if "%RTYPE%"=="" ( echo [x] Usage: run_automated_report.bat ^<report_type^> & exit /b 1 )
set "LOG=%~dp0run_automated_report_%RTYPE%_last.log"

> "%LOG%" echo ===== Automated Report run (%RTYPE%): %DATE% %TIME% (user: %USERNAME%) =====

".venv\Scripts\python.exe" manage.py generate_automated_report %RTYPE% >> "%LOG%" 2>&1
if errorlevel 1 ( >> "%LOG%" echo [x] generate_automated_report %RTYPE% failed. & type "%LOG%" & exit /b 1 )

>> "%LOG%" echo [OK] Done: %DATE% %TIME%
type "%LOG%"
endlocal

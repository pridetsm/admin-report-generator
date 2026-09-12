@echo off
REM Thin, argument-free wrapper for folder_exporter's job scheduler -- see
REM run_automated_report_weekly_trend.bat's own header for why this exists.
call "%~dp0run_automated_report.bat" admin_observations

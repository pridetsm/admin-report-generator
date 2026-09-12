@echo off
REM Thin, argument-free wrapper around run_automated_report.bat for folder_exporter's own
REM job scheduler (2026-09-11 fix). folder_exporter.yml's `command:` field launches the whole
REM string as ONE literal process path -- it does not split on whitespace into argv, so the
REM previous single-job "run_automated_report.bat weekly_trend" entry failed every time with
REM "The system cannot find the file specified" (confirmed: a same-shaped probe job with a
REM trailing argument reproduced the identical error; the argument-free form did not). Every
REM OTHER job in that config already avoids this by taking no arguments at all -- this file
REM (and its siblings run_automated_report_<type>.bat) restore that property for the
REM Automated Reports jobs specifically, without changing run_automated_report.bat itself
REM (still callable by hand as `run_automated_report.bat <type>` for manual/ad-hoc runs).
call "%~dp0run_automated_report.bat" weekly_trend

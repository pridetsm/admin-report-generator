"""Prometheus config management: read the live prometheus.yml for the first-ever edit-screen
load, validate a candidate revision with the REAL promtool (not just a YAML parse) before it's
ever written live, and restart the service.

Prometheus runs as the NSSM-wrapped 'Prometheus' Windows service (LocalSystem — same account
this webapp's own service and Grafana's both run as, so no extra permissions are needed).
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Tuple

PROMETHEUS_DIR = Path(r"C:\metrics\prometheus")
CONFIG_PATH = PROMETHEUS_DIR / "prometheus.yml"
PROMTOOL_PATH = PROMETHEUS_DIR / "promtool.exe"
# Written INSIDE PROMETHEUS_DIR (not a generic system temp dir) — prometheus.yml's rule_files
# entries are relative paths, resolved against the config file's OWN directory, so validating
# from anywhere else would make promtool wrongly report alerts.yml/etc as missing.
CANDIDATE_PATH = PROMETHEUS_DIR / "_candidate_prometheus.yml"
SERVICE_NAME = "Prometheus"

# The three files prometheus.yml's `rule_files:` list references — confirmed via
# `promtool check config` ("3 rule files found"). Each gets its own DB-versioned sub-page,
# reached from the main Prometheus config screen (see prometheus_rule_file in views.py).
RULE_FILES = ["alerts.yml", "t24_services.yml", "folder_exporter_rules.yml"]


def parse_live_config() -> str:
    """The live file's exact text — used ONLY to prefill the edit screen the very first time,
    before any revision exists yet."""
    return CONFIG_PATH.read_text(encoding="utf-8")


def validate(content: str) -> Tuple[bool, str]:
    """Real Prometheus semantics via promtool (catches far more than a bare YAML parse would —
    unknown fields, bad relabel_configs, missing rule files, etc.), not just syntax. Returns
    (ok, captured output) and always cleans up the candidate file it wrote to check with."""
    try:
        CANDIDATE_PATH.write_text(content, encoding="utf-8")
        result = subprocess.run(
            [str(PROMTOOL_PATH), "check", "config", str(CANDIDATE_PATH)],
            capture_output=True, text=True, timeout=30, cwd=str(PROMETHEUS_DIR))
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "promtool check config timed out after 30s."
    except OSError as exc:
        return False, f"Could not run promtool: {exc}"
    finally:
        CANDIDATE_PATH.unlink(missing_ok=True)


def service_status() -> str:
    """'Running' / 'Stopped' / etc, or 'unknown' if the PowerShell call itself fails."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-Service {SERVICE_NAME}).Status"],
            capture_output=True, text=True, timeout=15)
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _restart_service() -> Tuple[bool, str]:
    """Bare Restart-Service call + error handling, shared by the main config and every rule
    file — a rule-file edit needs the same full restart (no --web.enable-lifecycle reload
    endpoint is configured, so this is the one "apply" mechanism used everywhere here)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"Restart-Service {SERVICE_NAME}"],
            capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "the restart command timed out after 30s."
    if result.returncode != 0:
        return False, f"the restart failed: {(result.stderr or result.stdout).strip()}"
    return True, f"{SERVICE_NAME} restarted."


def write_and_restart(content: str) -> Tuple[bool, str]:
    """Validate FIRST — a failing config never touches the live file. Only on success does
    this overwrite prometheus.yml and restart the service. Returns (ok, message)."""
    ok, output = validate(content)
    if not ok:
        return False, f"Rejected — promtool found a problem, nothing was changed:\n{output}"

    try:
        CONFIG_PATH.write_text(content, encoding="utf-8")
    except OSError as exc:
        return False, f"Validation passed, but could not write {CONFIG_PATH}: {exc}"

    ok, detail = _restart_service()
    if not ok:
        return False, f"prometheus.yml was rewritten, but {detail}"
    return True, f"promtool validated the config, prometheus.yml was rewritten, and {detail}"


def rule_file_path(filename: str) -> Path:
    """Raises if `filename` isn't one of the three recognised rule files — closes off
    arbitrary path access before it ever reaches disk I/O."""
    if filename not in RULE_FILES:
        raise ValueError(f"not a recognised rule file: {filename!r}")
    return PROMETHEUS_DIR / filename


def parse_live_rule_file(filename: str) -> str:
    """The live file's exact text — used ONLY to prefill the edit screen the very first time,
    before any revision for this file exists yet."""
    return rule_file_path(filename).read_text(encoding="utf-8")


def validate_rule_file(filename: str, content: str) -> Tuple[bool, str]:
    """`promtool check rules` validates a rule file's syntax standalone — independent of
    prometheus.yml, so (unlike the main config) there's no need to reference or even touch the
    live prometheus.yml to check a candidate edit. Always cleans up the candidate file."""
    candidate = PROMETHEUS_DIR / f"_candidate_{filename}"
    try:
        candidate.write_text(content, encoding="utf-8")
        result = subprocess.run(
            [str(PROMTOOL_PATH), "check", "rules", str(candidate)],
            capture_output=True, text=True, timeout=30, cwd=str(PROMETHEUS_DIR))
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "promtool check rules timed out after 30s."
    except OSError as exc:
        return False, f"Could not run promtool: {exc}"
    finally:
        candidate.unlink(missing_ok=True)


def write_rule_file_and_restart(filename: str, content: str) -> Tuple[bool, str]:
    """Same validate-first guarantee as write_and_restart: a failing rule file never touches
    the live file or restarts anything."""
    ok, output = validate_rule_file(filename, content)
    if not ok:
        return False, f"Rejected — promtool found a problem, nothing was changed:\n{output}"

    path = rule_file_path(filename)
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return False, f"Validation passed, but could not write {path}: {exc}"

    ok, detail = _restart_service()
    if not ok:
        return False, f"{filename} was rewritten, but {detail}"
    return True, f"promtool validated {filename}, it was rewritten, and {detail}"

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

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"Restart-Service {SERVICE_NAME}"],
            capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "prometheus.yml was rewritten, but the restart command timed out after 30s."

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return False, f"prometheus.yml was rewritten, but the restart failed: {detail}"
    return True, f"promtool validated the config, prometheus.yml was rewritten, and {SERVICE_NAME} restarted."

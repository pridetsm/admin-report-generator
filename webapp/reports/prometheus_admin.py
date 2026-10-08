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

import yaml

PROMETHEUS_DIR = Path(r"C:\metrics\prometheus")
CONFIG_PATH = PROMETHEUS_DIR / "prometheus.yml"
PROMTOOL_PATH = PROMETHEUS_DIR / "promtool.exe"
# Written INSIDE PROMETHEUS_DIR (not a generic system temp dir) — prometheus.yml's rule_files
# entries are relative paths, resolved against the config file's OWN directory, so validating
# from anywhere else would make promtool wrongly report alerts.yml/etc as missing.
CANDIDATE_PATH = PROMETHEUS_DIR / "_candidate_prometheus.yml"
SERVICE_NAME = "Prometheus"

# The retention flags this app manages live in NSSM's own AppParameters, NOT prometheus.yml --
# they're process-start CLI flags Prometheus only reads at launch, so changing them always
# needs the same restart as everything else here, never a live reload. Confirmed 2026-09-30:
# NSSM's `Application` for the Prometheus service is prometheus.exe directly (not a wrapping
# .bat), so `nssm set Prometheus AppParameters "..."` is the correct write target -- verify
# this again with `nssm.exe get Prometheus Application` before reusing this code against a
# different host/deployment where that might not hold.
NSSM_PATH = Path(r"C:\nssm\nssm.exe")
DATA_DIR = PROMETHEUS_DIR / "data"

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


def _job_names(text: str) -> set:
    """job_name set from a prometheus.yml's scrape_configs -- used only by write_and_restart's
    own job-preservation guard below. Never raises: a candidate that fails to parse here has
    already failed promtool validation by the time this runs, so an empty set (⊂ any live set)
    just means the guard has nothing of its own to compare and defers to that earlier check."""
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return set()
    return {j.get("job_name") for j in (doc.get("scrape_configs") or []) if j.get("job_name")}


def write_and_restart(content: str, *, allow_job_removal: bool = False) -> Tuple[bool, str]:
    """Validate FIRST — a failing config never touches the live file. Only on success does
    this overwrite prometheus.yml and restart the service. Returns (ok, message).

    `allow_job_removal` (2026-09-22, after a real incident): an edit built from a saved
    PrometheusConfigRevision silently dropped bulawayo_cluster/standalone_servers when applied
    -- both had been added straight to the live file at some point, outside this app's own
    Save flow, so no revision ever recorded them; the next apply through the app, built from
    that now-stale revision, silently reverted the live file to a state missing both,
    de-monitoring an Infrastructure Admin estate as a side effect of an unrelated SNMP edit.
    Default False refuses an apply that would remove any job_name the LIVE file currently has
    but the candidate doesn't, naming exactly which ones -- the same "never silently omit"
    discipline this app already applies to report data, now applied to the one shared document
    every estate's scrape config lives in. A caller that genuinely means to remove a job (a
    real decommission, not a stale source) passes True -- no UI surface exposes this yet, so
    today that means editing prometheus.yml through Configuration > Prometheus, confirming the
    named job(s) really should go, and asking an engineer to run this with the flag if the
    UI's own single-document save (which always sources from the live file at reload) still
    doesn't cover the case.
    """
    ok, output = validate(content)
    if not ok:
        return False, f"Rejected — promtool found a problem, nothing was changed:\n{output}"

    if not allow_job_removal:
        try:
            live_jobs = _job_names(CONFIG_PATH.read_text(encoding="utf-8"))
        except OSError:
            live_jobs = set()
        missing = sorted(live_jobs - _job_names(content))
        if missing:
            return False, (
                "Rejected — nothing was changed. Applying this would silently remove job(s) "
                f"currently live but absent from what you're applying: {', '.join(missing)}. "
                "If this was built from a saved revision rather than the live file, the live "
                "file has likely drifted ahead of it (edited directly, outside this app) -- "
                "reload from the live file and reapply your edit on top of that instead. If "
                "removing these job(s) is genuinely intended, that needs an explicit "
                "allow_job_removal=True (not exposed in the UI yet).")

    try:
        CONFIG_PATH.write_text(content, encoding="utf-8")
    except OSError as exc:
        return False, f"Validation passed, but could not write {CONFIG_PATH}: {exc}"

    ok, detail = _restart_service()
    if not ok:
        return False, f"prometheus.yml was rewritten, but {detail}"
    return True, f"promtool validated the config, prometheus.yml was rewritten, and {detail}"


def get_app_parameters() -> str:
    """The live NSSM AppParameters string, exactly as configured -- e.g.
    '--config.file=C:\\metrics\\prometheus\\prometheus.yml --web.config.file=...'.

    nssm.exe's stdout on this install is genuine UTF-16LE (confirmed live, 2026-09-30: raw
    bytes are '-\\x00-\\x00c\\x00...', one null byte after every ASCII character) -- capturing
    with subprocess's own text=True mis-decodes it via the console's default codepage, which
    does NOT fix this (every other byte still renders as a stray space/control char; a
    whitespace-collapse pass over THAT output is cosmetic and changes nothing, confirmed by
    testing it directly). Capturing raw bytes and decoding as utf-16-le explicitly is the
    actual fix."""
    result = subprocess.run(
        [str(NSSM_PATH), "get", SERVICE_NAME, "AppParameters"],
        capture_output=True, timeout=15)
    return result.stdout.decode("utf-16-le", errors="ignore").strip()


def build_app_parameters(params: str, *, retention_days: int | None,
                         admin_api_enabled: bool = False) -> str:
    """Strip any existing --storage.tsdb.retention.*/--web.enable-admin-api tokens from the
    live AppParameters string and rebuild with the new values, preserving every other flag.
    retention_days=None omits the flag entirely, so Prometheus falls back to its own 15-day
    default -- --storage.tsdb.retention.size is NEVER set here at all (not just conditionally
    omitted): explicit decision, the time window alone is trusted to bound size (see
    PROMETHEUS-RETENTION-PLAN.md's own risk note on this).

    Plain whitespace split, deliberately NOT shlex.split(): confirmed live, 2026-09-30 --
    shlex's default POSIX mode treats backslash as an escape character, silently corrupting
    every Windows path here (C:\\metrics\\prometheus\\prometheus.yml -> C:metricsprometheus
    prometheus.yml). None of these flag values contain spaces, so a plain split needs no
    quoting-awareness at all -- shlex was solving a problem this string doesn't have while
    creating a real one."""
    tokens = [t for t in params.split()
             if not t.startswith("--storage.tsdb.retention.")
             and t != "--web.enable-admin-api"]
    if retention_days is not None:
        tokens.append(f"--storage.tsdb.retention.time={retention_days}d")
    if admin_api_enabled:
        tokens.append("--web.enable-admin-api")
    return " ".join(tokens)


def write_retention_and_restart(retention_days: int) -> Tuple[bool, str]:
    """Apply a new live_window_days to the live service: build the new AppParameters, `nssm
    set`, restart, and re-check service_status() explicitly rather than trusting the restart
    call's own exit code -- this restart is more consequential than a config-file reload (it
    changes what Prometheus itself keeps, not just what it scrapes), so the caller (and the
    PrometheusRetentionRevision row it creates on success) deserves to know Running/Stopped for
    certain, not just "the restart command returned 0"."""
    try:
        current = get_app_parameters()
    except Exception as exc:
        return False, f"Could not read the current service parameters: {exc}"

    new_params = build_app_parameters(current, retention_days=retention_days)
    try:
        result = subprocess.run(
            [str(NSSM_PATH), "set", SERVICE_NAME, "AppParameters", new_params],
            capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False, "nssm set timed out after 15s -- nothing was changed on the service."
    if result.returncode != 0:
        # Same UTF-16LE decoding as get_app_parameters() -- see that function's own comment.
        err = (result.stderr or result.stdout).decode("utf-16-le", errors="ignore").strip()
        return False, f"nssm set failed: {err}"

    ok, detail = _restart_service()
    status = service_status()
    if not ok:
        return False, f"AppParameters updated, but {detail} (service is now: {status})"
    return True, f"Retention set to {retention_days}d and {SERVICE_NAME} restarted (status: {status})."


def disk_usage_snapshot() -> dict:
    """{'data_dir_bytes', 'c_drive_free_bytes', 'c_drive_total_bytes', 'computed_at'} --
    computed on demand (the config screen's own "Refresh disk usage" button), not on every
    page load: walking the block-directory tree is cheap at the tens-of-blocks scale this data
    dir holds, but not something to redo on every GET."""
    import shutil

    import django.utils.timezone as dj_timezone

    data_bytes = 0
    if DATA_DIR.exists():
        for p in DATA_DIR.rglob("*"):
            if p.is_file():
                try:
                    data_bytes += p.stat().st_size
                except OSError:
                    continue
    usage = shutil.disk_usage(str(PROMETHEUS_DIR.anchor))
    return {
        "data_dir_bytes": data_bytes,
        "c_drive_free_bytes": usage.free,
        "c_drive_total_bytes": usage.total,
        "computed_at": dj_timezone.now(),
    }


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

"""Backup policy management: the per-host backup-frequency overrides
generate_report.backup_cutoff() reads (see BACKUP_MAX_AGE_DAYS / reload_backup_policy there)
— how many days old a host's newest backup may be and still count as CURRENT. Almost every
host backs up daily (the engine's own DEFAULT_BACKUP_MAX_AGE_DAYS = 1); a host on a slower
cycle needs an override here, otherwise the gap between its runs reads as a missing backup —
e.g. BSA's database, whose MSSQL full backup runs every 3rd day.

"Frequency" (frequency_days) was the only field a host's entry carried at first. Kept as
{field: value} per host, not a bare int, specifically so a second component could be added
later without reshaping what is already stored — the same reasoning
webapp/reports/snmp_admin.py's profiles dict follows for its own per-item fields. That
happened: "off weekdays" (off_weekdays) is a SEPARATE dimension from frequency, for a host
that simply doesn't run a backup on a given day of the week at all (RTGS/CSD, Sundays) —
distinct from a slower fixed cycle like BSA's, see generate_report.backup_cutoff's own
docstring for why a flat frequency override can't express "skip Sunday" without also
loosening every other day's window.

BACKUP_POLICY_PATHS are the LIVE files generate_report.capture() reads fresh on every
report — no restart, no service: the very next capture (webapp, mail_report.py, or the
scheduled CLI run) picks up an edit. Two paths because there are two independently-running
copies of the engine (this webapp's own send_report/, and the scheduled deployment under
C:\\metrics\\prometheus\\send_report) — both are written together so the interactive report
and the e-mailed daily one never disagree about a host's policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

import generate_report as gr

BACKUP_POLICY_PATHS = [
    Path(r"C:\Users\Administrator\Desktop\admin-report-generator\send_report\backup_policy.json"),
    Path(r"C:\metrics\prometheus\send_report\backup_policy.json"),
]

FREQUENCY_FIELD = "frequency_days"
DEFAULT_FREQUENCY_DAYS = gr.DEFAULT_BACKUP_MAX_AGE_DAYS   # 1 — daily

OFF_WEEKDAYS_FIELD = "off_weekdays"
# Monday=0 .. Sunday=6 (Python's own date.weekday(), what generate_report.backup_cutoff
# compares against) — the order this module and the config screen always present them in.
WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def parse_live_policy() -> Dict[str, dict]:
    """{instance: {"frequency_days": N, "off_weekdays": [...]}, ...} — the live file if this
    webapp has ever saved one, else generate_report's own hardcoded defaults (BSA's 3-day
    override, RTGS/CSD's Sunday-off policy), so the very first edit-screen load shows real
    current behaviour rather than an empty form."""
    path = BACKUP_POLICY_PATHS[0]
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    merged: Dict[str, dict] = {inst: {FREQUENCY_FIELD: days} for inst, days in gr.BACKUP_MAX_AGE_DAYS.items()}
    for inst, off_days in gr.BACKUP_OFF_WEEKDAYS.items():
        merged.setdefault(inst, {})[OFF_WEEKDAYS_FIELD] = sorted(off_days)
    return merged


def write_policy(policy: Dict[str, dict]) -> Tuple[bool, str]:
    """Write `policy` to every live location. Returns (ok, message) — ok only if EVERY
    location wrote successfully, so a partial failure (e.g. the scheduled deployment's disk
    unreachable) is never reported as a clean apply."""
    text = json.dumps(policy, indent=2, sort_keys=True)
    failures: List[str] = []
    for path in BACKUP_POLICY_PATHS:
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    if failures:
        return False, "Written to some locations, but failed on:\n" + "\n".join(failures)
    return True, ("backup_policy.json rewritten at every location — takes effect on the "
                  "next report, no restart needed.")

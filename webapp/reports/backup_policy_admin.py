"""Backup policy management: the per-host backup-frequency overrides
generate_report.backup_cutoff() reads (see BACKUP_MAX_AGE_DAYS / reload_backup_policy there)
— how many days old a host's newest backup may be and still count as CURRENT. Almost every
host backs up daily (the engine's own DEFAULT_BACKUP_MAX_AGE_DAYS = 1); a host on a slower
cycle needs an override here, otherwise the gap between its runs reads as a missing backup —
e.g. BSA's database, whose MSSQL full backup runs every 3rd day.

"Frequency" (frequency_days) is the only field a host's entry carries today. Kept as
{field: value} per host, not a bare int, so a second component (e.g. an expected
time-of-day, once that becomes something worth alerting on) can be added later without
reshaping what is already stored — the same reasoning webapp/reports/snmp_admin.py's
profiles dict follows for its own per-item fields.

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


def parse_live_policy() -> Dict[str, dict]:
    """{instance: {"frequency_days": N}, ...} — the live file if this webapp has ever saved
    one, else generate_report's own hardcoded defaults (BSA's 3-day override today), so the
    very first edit-screen load shows real current behaviour rather than an empty form."""
    path = BACKUP_POLICY_PATHS[0]
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {inst: {FREQUENCY_FIELD: days} for inst, days in gr.BACKUP_MAX_AGE_DAYS.items()}


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

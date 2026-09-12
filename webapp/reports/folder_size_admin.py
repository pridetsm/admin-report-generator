"""Size Monitoring's own threshold -- generate_report.FOLDER_EXPECTED_PCT (folder_exporter
target name -> (volume it lives on, expected size as a fraction of that volume's own total
capacity), "T24 Log File" being the only entry today). A watched folder over this share of
its volume feeds the Folders table's own "over expected size" banner AND
reports.alerting._folder_flags_by_system's "folder" category -- ONE number, used by both, so
this is the single place that number lives.

FOLDER_SIZE_POLICY_PATHS are the LIVE files generate_report.capture() reads fresh on every
report (via reload_folder_expected_pct(), called the same way reload_backup_policy() already
is) -- no restart. Two paths because there are two independently-running copies of the
engine (this webapp's own send_report/, and the scheduled deployment under
C:\\metrics\\prometheus\\send_report) -- both are written together, the exact same sync
boundary reports/backup_policy_admin.py already uses for backup_policy.json.

Stored on disk as a 0-100 percentage (how the config screen talks about it, and how an admin
would say it out loud) -- generate_report.py's own reload_folder_expected_pct() divides by
100 into the 0-1 fraction folder_expected_gb's math expects.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

import generate_report as gr

FOLDER_SIZE_POLICY_PATHS = [
    Path(r"C:\Users\Administrator\Desktop\admin-report-generator\send_report\folder_size_policy.json"),
    Path(r"C:\metrics\prometheus\send_report\folder_size_policy.json"),
]


def parse_live_policy() -> Dict[str, dict]:
    """{folder_name: {"mount": "F:", "pct": 80}, ...} -- the live file if this webapp has
    ever saved one, else generate_report's own hardcoded default (T24 Log File, 80% of F:),
    converted from the in-memory 0-1 fraction to the 0-100 percentage the form shows, so the
    very first edit-screen load shows real current behaviour rather than an empty form."""
    path = FOLDER_SIZE_POLICY_PATHS[0]
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {name: {"mount": mount, "pct": round(frac * 100, 2)}
           for name, (mount, frac) in gr.FOLDER_EXPECTED_PCT.items()}


def write_policy(policy: Dict[str, dict]) -> Tuple[bool, str]:
    """Write `policy` to every live location. Returns (ok, message) — ok only if EVERY
    location wrote successfully, so a partial failure is never reported as a clean apply."""
    text = json.dumps(policy, indent=2, sort_keys=True)
    failures = []
    for path in FOLDER_SIZE_POLICY_PATHS:
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    if failures:
        return False, "Written to some locations, but failed on:\n" + "\n".join(failures)
    return True, ("folder_size_policy.json rewritten at every location — takes effect on the "
                  "next report, no restart needed.")

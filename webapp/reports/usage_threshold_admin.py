"""Disk / RAM / CPU usage thresholds -- generate_report.py's own chip_amber/chip_red
(75%/90% by default), the SAME shared pair the daily/interactive report's disk, RAM and CPU
tables, KPI counts and banners already use throughout (see generate_report.Config's own
chip_amber/chip_red fields, and every call site that reads them). These are ONE shared number
today, not three independently configurable ones -- chip_amber/chip_red are threaded through
dozens of call sites across the whole report engine (disk tables, RAM tables, CPU tables,
banners, KPI counts), not just alerting, so splitting Disk/RAM/CPU into independent
thresholds would mean touching that entire engine (mirrored across three identical copies --
this webapp's own, the scheduled C:\\metrics one, and the standalone Systems Admin Report
tool) rather than one config value. This module exposes the one number that genuinely IS
just a value today; RAM's own per-instance exceptions (generate_report.RAM_THRESHOLD_OVERRIDES,
e.g. T24 DB's own wider band) are untouched by this and keep working exactly as before.

Lives in config.ini's [report] section, read fresh by generate_report.load_config() on every
capture/report -- already hot, no restart needed. Written here via a TARGETED line
substitution, not configparser's own writer, because config.ini carries hand-written
commentary throughout (including this app's own SMTP password) that a generic
configparser.write() would silently discard -- the same reasoning GrafanaConfigRevision /
PrometheusConfigRevision treat their own files as raw text rather than re-serializing them.

Synced to the same TWO locations reports/backup_policy_admin.py already writes
backup_policy.json to -- this webapp's own send_report/config.ini and the scheduled
C:\\metrics\\prometheus\\send_report\\config.ini -- so the live dashboard and the scheduled
daily e-mail agree. The standalone report tools' own config.ini copies are NOT included,
matching backup_policy.json's own existing sync boundary.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Tuple

import generate_report as gr

USAGE_THRESHOLD_PATHS = [
    Path(r"C:\Users\Administrator\Desktop\admin-report-generator\send_report\config.ini"),
    Path(r"C:\metrics\prometheus\send_report\config.ini"),
]

_AMBER_RE = re.compile(r"(?m)^chip_amber\s*=\s*\d+\s*$")
_RED_RE = re.compile(r"(?m)^chip_red\s*=\s*\d+\s*$")

DEFAULT_AMBER_PCT = 75
DEFAULT_RED_PCT = 90


def read_live() -> Tuple[int, int]:
    """The CURRENT chip_amber/chip_red, read the exact same way the live app already trusts
    (generate_report.load_config()) -- never re-parsed by hand here, so this can never
    disagree with what a report or alert actually uses."""
    cfg = gr.load_config()
    return cfg.chip_amber, cfg.chip_red


def write_live(amber: int, red: int) -> Tuple[bool, str]:
    """Rewrite chip_amber/chip_red in place at every synced config.ini, leaving every other
    line (including every comment) untouched. Returns (ok, message) -- ok only if EVERY
    location wrote successfully, so a partial failure is never reported as a clean apply."""
    failures = []
    for path in USAGE_THRESHOLD_PATHS:
        try:
            text = path.read_text(encoding="utf-8")
            new_text, n_amber = _AMBER_RE.subn(f"chip_amber = {amber}", text)
            new_text, n_red = _RED_RE.subn(f"chip_red = {red}", new_text)
            if n_amber == 0 or n_red == 0:
                failures.append(f"{path}: chip_amber/chip_red line not found -- not written")
                continue
            path.write_text(new_text, encoding="utf-8")
        except OSError as exc:
            failures.append(f"{path}: {exc}")
    if failures:
        return False, "Written to some locations, but failed on:\n" + "\n".join(failures)
    return True, "config.ini rewritten at every location — takes effect on the next report or poll, no restart needed."

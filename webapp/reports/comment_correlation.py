"""Phase 2 of the Automated Reports spec ("New Promt.txt"): administrator comment
structuring / linkage.

Phase 1's own data audit found that reports.models.ReportSubmission.annotations already
carries genuine, human-typed operational commentary, per system, per report run -- entered
through the existing report form, not machine-generated. The open question Phase 2 exists to
resolve was HOW to link a comment back to the specific finding(s) it concerns.

FIRST DESIGN (validated 2026-09-07, then discarded): join a comment's answered flag_keys
against `AlertFinding` by (system, flag_key). This looked reasonable but is UNRELIABLE for
historical correlation, because AlertFinding is a MUTABLE CURRENT-STATE table -- one row per
(group, system, flag_key), overwritten in place every time a finding resolves and reopens
(see AlertFinding's own docstring: "A resolved row that reappears is treated as brand-new:
its timestamps AND its reminder schedule reset on the SAME row"). A comment written during an
EARLIER open/resolve cycle would silently get attributed to whatever the CURRENT cycle's
first_seen_at/resolved_at happen to be, which can be a completely different incident with
different duration/severity if the flag_key has cycled more than once. Validating the join
against real data (985 real per-system comments, spanning back to July) surfaced this risk
directly, even though the specific sample checked (RTGS disk:Database:/u01) happened to be
one continuous, never-resolved incident where the join was accidentally correct.

CORRECTED DESIGN: `ReportSubmission.report_content` is the real append-only incident ledger
this spec's trend/recurrence analysis (sections 5-6) needs, and it requires NO JOIN AT ALL --
each submission's own JSON snapshot already merges every flagged item (key/text/band/
category) with the admin's own answer AND the system's own free-text comment for THAT EXACT
run (see webapp/reports/views.py's own report_content construction). A new ReportSubmission
row is created fresh on every report run and never mutated afterward, so walking the
SEQUENCE of submissions over time gives a genuinely reliable historical record: how many
times has this flag_key actually recurred, with what the admin said about it each time.

`AlertFinding` remains useful as a SEPARATE, clearly-labelled cross-reference for "is this
finding CURRENTLY open, and what does its live reminder history look like right now" --
current-state questions it answers correctly -- but this module does not use it for
historical frequency/recurrence, which is exactly the question it cannot reliably answer.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ObservedFlag:
    """One flagged item from one historical report submission -- the append-only, per-moment
    unit trend/recurrence analysis is built on. Self-contained: no join needed to know what
    was flagged, at what severity, on which system, in which run, together with whatever the
    admin recorded about it AT THAT TIME."""
    submission_id: int
    created_at: object       # datetime, the submission's own created_at
    system: str
    flag_key: str
    text: str
    band: str
    category: str
    answer: str               # "Yes" / "No" / "" -- the admin's own answer for THIS flag, THIS run
    system_comment: str       # the system's own free-text comment for THIS run (not per-flag)


def observed_flags(start=None, end=None, system: Optional[str] = None) -> list[ObservedFlag]:
    """Every flagged item across ReportSubmission.report_content history (optionally
    windowed by [start, end) on created_at, optionally scoped to one system) -- the real,
    reliable historical incident ledger for this spec's trend/recurrence analysis. See this
    module's own docstring for why AlertFinding itself is NOT used here."""
    from .models import ReportSubmission

    qs = ReportSubmission.objects.all()
    if start is not None:
        qs = qs.filter(created_at__gte=start)
    if end is not None:
        qs = qs.filter(created_at__lt=end)

    out: list[ObservedFlag] = []
    for sub in qs.order_by("created_at"):
        for sysd in (sub.report_content or {}).get("systems", []):
            sysname = sysd.get("name", "")
            if system is not None and sysname != system:
                continue
            comment = sysd.get("comment", "")
            for f in sysd.get("flags", []):
                out.append(ObservedFlag(
                    submission_id=sub.pk, created_at=sub.created_at, system=sysname,
                    flag_key=f.get("key", ""), text=f.get("text", ""), band=f.get("band", ""),
                    category=f.get("category", ""), answer=f.get("answer", ""),
                    system_comment=comment,
                ))
    return out


def current_finding_state(system: str, flag_key: str):
    """The LIVE AlertFinding row for (system, flag_key), if any -- deliberately a separate,
    narrowly-scoped lookup for "is this open right now, and what's its current reminder
    history" (a question AlertFinding answers correctly), never used for historical
    frequency/recurrence counting -- see this module's own docstring for why that join is
    unreliable across multiple resolve/reopen cycles. Returns None if there is no current
    row (never seen, or the row was for a different group)."""
    from .models import AlertFinding

    return AlertFinding.objects.filter(system=system, flag_key=flag_key).first()

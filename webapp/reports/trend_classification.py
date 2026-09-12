"""Phase 3 of the Automated Reports spec ("New Promt.txt"), sections 5-6: classify each
distinct (system, flag_key) issue observed in reports.comment_correlation.observed_flags()
history as Recurring / Persistent / One-off / (Potential Fluke), with a confidence level
(section 14), before any report template is built on top of it (section 12/Phase 4).

Built on the CORRECTED Phase 2 data source (ReportSubmission.report_content's own
append-only per-run snapshots, not AlertFinding's mutable current-state rows -- see
reports.comment_correlation's own docstring for why).

CLASSIFICATION RULE (agreed 2026-09-07): occurrence-count + gap-based, operating on DISTINCT
CALENDAR DAYS an issue was observed within a rolling window, not raw report-RUN count --
real report-run frequency varies a lot day to day (a scheduled daily run plus however many
ad-hoc ones an admin happens to trigger), so counting runs would make a flag_key look more
"recurring" purely because someone ran the report five times on a Tuesday. Counting distinct
days is the closest reliable proxy for "does this come and go" that the agreed rule actually
intends.

  ONE_OFF     -- observed on exactly 1 distinct day in the window, no other occurrence.
  RECURRING   -- observed on 3+ distinct days, with GAPS between them (comes and goes) --
                measured as day-coverage (distinct days / the span they're spread across)
                below the PERSISTENT threshold.
  PERSISTENT  -- observed on 3+ distinct days, continuously or near-continuously across the
                whole span it's been appearing in (high day-coverage) -- "never really
                clears."
  BORDERLINE  -- observed on exactly 2 distinct days -- not enough to call Recurring with
                confidence yet, but more than a one-off. Always LOW confidence.

EMERGING is a separate, additive flag (not a replacement label): the occurrence rate in the
most recent third of the window is meaningfully higher than the rest of it -- a pattern that
may not be severe yet but is accelerating (section: "Emerging trends").

Confidence (section 14) is a function of HOW MUCH evidence exists, independent of which
label was assigned -- a Recurring classification from 3 occurrences is real but weaker
evidence than one from 15.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional

from django.utils import timezone

from .comment_correlation import ObservedFlag, observed_flags

ONE_OFF = "One-off"
RECURRING = "Recurring"
PERSISTENT = "Persistent"
BORDERLINE = "Potential fluke"

HIGH = "High confidence"
MEDIUM = "Medium confidence"
LOW = "Low confidence"

# Day-coverage (distinct days observed / days spanned) at or above this reads as "never
# really clears" rather than "comes and goes" -- see module docstring.
_PERSISTENT_COVERAGE = 0.7
# The occurrence rate in the most recent third of the window must be at least this many
# times the rate in the rest of it, AND the recent slice must have a minimum absolute count,
# before "Emerging" is added -- guards against a single extra occurrence in a short recent
# slice reading as a dramatic acceleration.
_EMERGING_RATIO = 2.0
_EMERGING_MIN_RECENT = 2


@dataclass
class IssueClassification:
    """One (system, flag_key) issue's classification over the analysis window -- the
    evidence is carried alongside the verdict so a report template (Phase 4) or a human
    reviewer can see exactly why, not just trust the label."""
    system: str
    flag_key: str
    category: str
    latest_text: str
    label: str
    confidence: str
    emerging: bool
    distinct_days: int
    span_days: int
    coverage: float
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    worst_band: str            # "red" if it was ever red in-window, else "amber"
    occurrences: list = field(default_factory=list)   # ObservedFlag rows, chronological
    comments: list = field(default_factory=list)       # non-empty (created_at, comment) pairs

    @property
    def significance(self) -> tuple:
        """Sort key for ranking (section 5: "frequency + duration + severity + persistence +
        operational impact", explicitly NOT raw alert count alone). Persistent issues rank
        above Recurring above Borderline above One-off; within a label, more days and a
        wider span rank higher; red beats amber."""
        label_rank = {PERSISTENT: 3, RECURRING: 2, BORDERLINE: 1, ONE_OFF: 0}[self.label]
        return (label_rank, self.worst_band == "red", self.distinct_days, self.span_days)


def _classify_series(flags: list) -> tuple:
    """(label, confidence, emerging, distinct_days, span_days, coverage) for one issue's
    already-chronological ObservedFlag list. Pure function, no DB access, so it's directly
    testable against a hand-built list of dates."""
    days = sorted({f.created_at.date() for f in flags})
    distinct_days = len(days)
    span_days = (days[-1] - days[0]).days + 1 if days else 0
    coverage = distinct_days / span_days if span_days else 0.0

    if distinct_days <= 1:
        label, confidence = ONE_OFF, LOW
    elif distinct_days == 2:
        label, confidence = BORDERLINE, LOW
    else:
        label = PERSISTENT if coverage >= _PERSISTENT_COVERAGE else RECURRING
        confidence = HIGH if distinct_days >= 5 else MEDIUM

    emerging = False
    if distinct_days >= 3:
        third = max(1, span_days // 3)
        cutoff = days[-1] - datetime.timedelta(days=third)
        recent = sum(1 for d in days if d > cutoff)
        earlier = distinct_days - recent
        earlier_rate = earlier / max(1, span_days - third)
        recent_rate = recent / third
        if recent >= _EMERGING_MIN_RECENT and earlier_rate > 0 and recent_rate >= earlier_rate * _EMERGING_RATIO:
            emerging = True

    return label, confidence, emerging, distinct_days, span_days, coverage


def classify_all(window_days: int = 30, now=None) -> list[IssueClassification]:
    """Every distinct (system, flag_key) issue observed in the last `window_days`, classified
    and ranked by significance (highest first) -- the Phase 3 deliverable: a testable module
    producing Trend/Recurring/One-off/Fluke + confidence + evidence, kept deliberately
    decoupled from any report template (Phase 4 wires this in, not this module)."""
    now = now or timezone.now()
    start = now - datetime.timedelta(days=window_days)

    grouped: dict = {}
    for f in observed_flags(start=start, end=now):
        grouped.setdefault((f.system, f.flag_key), []).append(f)

    results = []
    for (system, flag_key), flags in grouped.items():
        flags.sort(key=lambda f: f.created_at)
        label, confidence, emerging, distinct_days, span_days, coverage = _classify_series(flags)
        comments = [(f.created_at, f.system_comment.strip()) for f in flags if f.system_comment.strip()]
        results.append(IssueClassification(
            system=system, flag_key=flag_key, category=flags[-1].category,
            latest_text=flags[-1].text, label=label, confidence=confidence, emerging=emerging,
            distinct_days=distinct_days, span_days=span_days, coverage=round(coverage, 2),
            first_seen=flags[0].created_at, last_seen=flags[-1].created_at,
            worst_band="red" if any(f.band == "red" for f in flags) else "amber",
            occurrences=flags, comments=comments,
        ))

    results.sort(key=lambda r: r.significance, reverse=True)
    return results

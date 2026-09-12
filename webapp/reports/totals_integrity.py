"""Phase 3, item 9 of the Automated Reports spec ("New Promt.txt"): "Validate both modules
against known historical cases... Use the console's own already-documented data-integrity
issues (metrics that should be monotonic but fluctuate, e.g. total tracked backups, total
services, expired certs) as test cases -- if the engine can't correctly flag a totals metric
moving in both directions as at minimum 'worth investigating', it isn't ready for Phase 4."

This is a SEPARATE, narrower check from reports.trend_classification: that module classifies
per-(system, flag_key) issues drawn from ReportSubmission.report_content["systems"], which
never included the report's own aggregate TOTALS (total services, total tracked-backup hosts,
total certs monitored, currently-expired cert count) -- those live only in
report_content["overview"] (see reports.services.build_overview for the exact shape each
value is built from). A totals metric moving in both directions across report runs (e.g. the
count of tracked backup hosts going 40 -> 38 -> 41) is exactly the kind of "should generally
only grow, or at least not silently reverse" signal item 9 asks the engine to catch, and
nothing before this module could see it at all.

Deliberately narrow: this flags a metric as LOW confidence "worth investigating" (section 14)
whenever it decreases anywhere in the window, never claims to explain WHY -- a legitimate
cause (a host decommissioned, a cert renewed and dropping out of the "expiring" count) is
just as possible as a data-integrity bug. Section 14 exists precisely so a low-confidence
flag is never mistaken for a certainty.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from django.utils import timezone

from .models import ReportSubmission


def _find(overview: dict, section: str, label: str):
    for row in overview.get(section, []) or []:
        if row.get("label") == label:
            return row.get("value")
    return None


def _digits(s) -> int | None:
    if s is None:
        return None
    digits = "".join(ch for ch in str(s) if ch.isdigit())
    return int(digits) if digits else None


def _second_half(value) -> int | None:
    """'3 | 56' -> 56 (the 'total' half of an 'affected | total' tile). Bare '56' -> 56."""
    if value is None:
        return None
    s = str(value)
    return _digits(s.split("|", 1)[1]) if "|" in s else _digits(s)


def _first_half(value) -> int | None:
    """'3 | 56' -> 3 (the 'affected' half). Bare '56' -> 56."""
    if value is None:
        return None
    s = str(value)
    return _digits(s.split("|", 1)[0]) if "|" in s else _digits(s)


# key -> (label shown to a reader, extractor(overview) -> int|None). Each is a TOTAL that
# should generally only grow (a host/service/cert being added) or at least never reverse
# without a real, explainable cause -- the spec's own three named examples, matched to the
# exact overview tiles reports.services.build_overview already produces (see that function's
# glance/immediate lists for the "affected | total" shape these tiles use).
TOTALS_WATCHED = {
    "total_services": (
        "Total services monitored",
        lambda ov: _digits(_find(ov, "glance", "Services"))),
    "total_tracked_backups": (
        "Total backup-tracked hosts",
        lambda ov: _second_half(_find(ov, "immediate", "Missing backups"))),
    "total_certs_monitored": (
        "Total certificates monitored",
        lambda ov: _second_half(_find(ov, "immediate", "Expired certs"))),
    "expired_certs_count": (
        "Currently-expired certificates",
        lambda ov: _first_half(_find(ov, "immediate", "Expired certs"))),
}


@dataclass
class TotalsAnomaly:
    metric: str
    label: str
    confidence: str
    occurrences: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    min_value: int
    max_value: int
    latest_value: int
    example_drop: dict   # {"from": int, "to": int, "at": isoformat str}
    series: list = field(default_factory=list)   # [(isoformat, value), ...] -- full evidence


def _series_for(window_days: int, now) -> dict:
    start = now - datetime.timedelta(days=window_days)
    subs = (ReportSubmission.objects
            .filter(created_at__gte=start, created_at__lte=now)
            .order_by("created_at")
            .only("created_at", "report_content"))
    series: dict = {key: [] for key in TOTALS_WATCHED}
    for sub in subs:
        overview = (sub.report_content or {}).get("overview") or {}
        for key, (_label, extractor) in TOTALS_WATCHED.items():
            try:
                value = extractor(overview)
            except Exception:   # noqa: BLE001 -- a malformed/older overview shape just skips this point
                value = None
            if value is not None:
                series[key].append((sub.created_at, value))
    return series


def all_totals_series(window_days: int = 30, now=None) -> dict:
    """Every WATCHED total's own full [(isoformat, value), ...] series across the window,
    regardless of whether it ever dropped -- 2026-09-10, item 14: "showing the actual 7-day
    series instead of a single before→after snippet." detect_totals_anomalies only returns
    metrics that actually decreased at least once (that's its own, narrower job -- flagging a
    real anomaly); the sparkline chart wants ALL of them, decreased or not, since "how has this
    number moved" is worth showing even for a total that stayed perfectly monotonic. No new
    storage -- computed fresh from the same ReportSubmission history _series_for already reads,
    same "single-window dataset, no cross-run infrastructure" principle §3a's own note uses.
    Returns {metric_key: {"label":, "series": [(isoformat, value), ...]}}."""
    now = now or timezone.now()
    series = _series_for(window_days, now)
    return {key: {"label": TOTALS_WATCHED[key][0], "series": [(at.isoformat(), v) for at, v in points]}
           for key, points in series.items() if points}


def detect_totals_anomalies(window_days: int = 30, now=None) -> list:
    """Every watched total that decreased at least once in the window -- "moved in both
    directions" per item 9's own phrasing, since a decrease can only exist alongside an
    earlier higher value. Returns TotalsAnomaly objects, most-occurrences first."""
    now = now or timezone.now()
    series = _series_for(window_days, now)

    anomalies = []
    for key, points in series.items():
        if len(points) < 2:
            continue
        label, _extractor = TOTALS_WATCHED[key]
        drops = []
        prev = points[0]
        for point in points[1:]:
            if point[1] < prev[1]:
                drops.append((prev, point))
            prev = point
        if not drops:
            continue
        values = [v for _at, v in points]
        first_drop = drops[0]
        anomalies.append(TotalsAnomaly(
            metric=key, label=label, confidence="Low confidence", occurrences=len(drops),
            first_seen=points[0][0], last_seen=points[-1][0],
            min_value=min(values), max_value=max(values), latest_value=values[-1],
            example_drop={"from": first_drop[0][1], "to": first_drop[1][1],
                         "at": first_drop[1][0].isoformat()},
            series=[(at.isoformat(), v) for at, v in points],
        ))
    anomalies.sort(key=lambda a: a.occurrences, reverse=True)
    return anomalies


def totals_anomaly_to_dict(a: TotalsAnomaly) -> dict:
    return {
        "metric": a.metric, "label": a.label, "confidence": a.confidence,
        "occurrences": a.occurrences, "first_seen": a.first_seen.isoformat(),
        "last_seen": a.last_seen.isoformat(), "min_value": a.min_value,
        "max_value": a.max_value, "latest_value": a.latest_value,
        "example_drop": a.example_drop, "series": a.series,
    }

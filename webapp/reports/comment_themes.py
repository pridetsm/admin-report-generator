"""Deterministic theme tagging for administrator comments (Automated Reports spec, section 3,
and the Administrator Observations Digest in section 17).

Deliberately NOT NLP/theme-clustering: Phase 2 item 6 says not to attempt that until comments
are structurally linked to (system, timestamp, flag) -- which they now are, via
reports.comment_correlation.observed_flags -- but full topic modelling is still more than a
deterministic, no-ML fallback path needs or can responsibly do without a human reviewing the
clusters it invents. Instead: a curated keyword-bucket classifier. Section 3's own instruction
("do not simply count keywords... interpret the operational meaning") is honoured by pairing
each theme's count with the systems it touches and real example quotes, so a reader always
sees the evidence a count alone would hide -- not by pretending keyword matching is NLP.
"""
from __future__ import annotations

import datetime
from collections import defaultdict

from django.utils import timezone

from .comment_correlation import observed_flags

# Keyword -> theme. Matched as a case-insensitive substring against each comment. Order in
# THEMES doesn't matter; a single comment can (and often should) match more than one theme.
THEMES = {
    "cob": ["cob", "close of business", "end of day", "eod run", "eod process"],
    "manual_intervention": ["manually", "manual intervention", "had to restart", "restarted the",
                            "cleared manually", "manual workaround", "manual fix"],
    "network": ["network", "connectivity", "link down", "unreachable", "vpn", "firewall", "switch"],
    "database": ["database", "tablespace", " db ", "db)", "sql server", "oracle"],
    "capacity": ["archiving", "disk space", "utilization", "utilisation", "capacity",
                "expected to reduce", "growing", "running out of space"],
    "backup_policy": ["backup policy", "no backup is expected", "backup window",
                      "backup schedule", "not expected on"],
    "configuration": ["configuration", "config change", "misconfigured", "setting change"],
    "external_dependency": ["vendor", "third-party", "third party", "external provider", "upstream"],
    "investigation_pending": ["investigating", "investigation underway", "looking into",
                              "pending review", "under investigation"],
}

THEME_LABELS = {
    "cob": "Close-of-business / end-of-day processing",
    "manual_intervention": "Manual intervention",
    "network": "Network / connectivity",
    "database": "Database",
    "capacity": "Capacity / archiving",
    "backup_policy": "Backup policy / scheduling",
    "configuration": "Configuration",
    "external_dependency": "External / third-party dependency",
    "investigation_pending": "Investigation still pending",
}

# Themes that describe an OPERATIONAL PROCESS rather than an infrastructure fault (section 3:
# "surfaces operational-process patterns... separately from infrastructure ones").
PROCESS_THEMES = {"cob", "manual_intervention", "backup_policy", "investigation_pending"}


def theme_digest(window_days: int = 30, now=None) -> list:
    """One entry per theme matched at least once in the window: theme key, label, whether it's
    process-vs-infrastructure, match count, distinct systems touched, and up to 3 example
    (system, flag_key, quote) rows so every count stays traceable back to a real comment
    (section 4's traceability requirement). Returns plain JSON-safe dicts, ranked by count."""
    now = now or timezone.now()
    start = now - datetime.timedelta(days=window_days)

    by_theme = defaultdict(list)
    for f in observed_flags(start=start, end=now):
        text = f.system_comment.strip()
        if not text:
            continue
        lowered = text.lower()
        for key, keywords in THEMES.items():
            if any(kw in lowered for kw in keywords):
                by_theme[key].append(f)

    results = []
    for key, flags in by_theme.items():
        systems = sorted({f.system for f in flags})
        examples = []
        seen_quotes = set()
        for f in flags:
            q = f.system_comment.strip()
            if q in seen_quotes:
                continue
            seen_quotes.add(q)
            examples.append({"system": f.system, "flag_key": f.flag_key, "quote": q[:220]})
            if len(examples) >= 3:
                break
        results.append({
            "theme": key,
            "label": THEME_LABELS[key],
            "kind": "process" if key in PROCESS_THEMES else "infrastructure",
            "count": len(flags),
            "systems": systems,
            "examples": examples,
        })
    results.sort(key=lambda r: r["count"], reverse=True)
    return results

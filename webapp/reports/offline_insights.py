"""Deterministic, literature-grounded heuristics for the offline (no-LLM) narrative
fallback (reports.ai_narrative.OfflineNarrativeProvider). Explicit instruction (2026-09-07):
the offline report "can't just be completely devoid of any valuable insights" -- it must
still say something worth reading, not merely restate counts.

Rather than invent ad-hoc rules, each heuristic below is a named, established practice from
monitoring/ITSM/SRE/safety literature, applied deterministically to
reports.trend_classification.IssueClassification data. Same inputs always produce the same
output -- no network call, no randomness, cannot fail or hallucinate:

  - Pareto concentration        -- ITIL Problem Management / Juran's 80-20 rule: prioritise
    by where issues concentrate, not by raw issue count.
  - Root-cause fan-in           -- Ishikawa (fishbone) reasoning: several symptoms on the
    same host are more likely one shared cause than independent faults.
  - Stale-acknowledgement       -- "normalization of deviance" (Vaughan, "The Challenger
    Launch Decision"), echoed in SRE alert-fatigue writing: an unchanged explanation
    repeated across cycles while the condition persists is itself a signal, not evidence of
    resolution.
  - Unacknowledged persistence  -- SRE/ITSM alerting hygiene: a persistent or recurring issue
    with no recorded response is a triage gap, independent of its severity.
  - Coincident onset            -- temporal-clustering / correlation analysis (used in AIOps
    root-cause correlation): independent systems developing new issues within the same short
    window are worth checking for a shared dependency before being treated as unrelated.
  - Category concentration      -- capacity-trend framing (Google SRE book, capacity-planning
    chapter): track which resource category (disk/ram/backup/...) dominates the estate's
    active load, not just which host.
"""
from __future__ import annotations

import datetime
from collections import Counter, defaultdict
from difflib import SequenceMatcher

ACTIVE_LABELS = {"Persistent", "Recurring"}
STALE_COMMENT_MIN = 3        # need at least this many comments to call a pattern "stale"
STALE_SIMILARITY = 0.85      # SequenceMatcher ratio at/above this counts as "unchanged"
COINCIDENT_WINDOW_DAYS = 2
COINCIDENT_MIN_SYSTEMS = 3
# A window must hold at least this share of ALL systems that saw any new (non-Persistent)
# issue in the whole analysis run before it's flagged -- an absolute count alone (e.g. "3
# systems in 2 days") is met by chance almost every week once there are more than a handful
# of systems and issues in play; requiring a large share of that week's total activity to
# land in one short window is what actually distinguishes a real cluster from background
# noise (the same "is this surprising relative to the base rate" logic control charts and
# burst-detection heuristics use, kept here as a simple proportion rather than a full
# statistical test).
COINCIDENT_SHARE = 0.5
FANIN_MIN_METRICS = 3


def pareto_concentration(issues: list):
    """Smallest set of systems covering >=80% of active (Persistent/Recurring) issues.
    Returns (systems, share) or None if there are fewer than 2 systems involved (nothing to
    concentrate)."""
    active = [i for i in issues if i.label in ACTIVE_LABELS]
    if not active:
        return None
    ranked = Counter(i.system for i in active).most_common()
    if len(ranked) < 2:
        return None
    target = len(active) * 0.8
    running = 0
    top = []
    for system, n in ranked:
        top.append(system)
        running += n
        if running >= target:
            break
    return top, running / len(active)


def root_cause_fanin(issues: list) -> dict:
    """Systems where >= FANIN_MIN_METRICS distinct flag_keys are simultaneously
    Persistent/Recurring -- more likely one shared host-level cause than independent
    per-metric faults."""
    by_system = defaultdict(list)
    for i in issues:
        if i.label in ACTIVE_LABELS:
            by_system[i.system].append(i)
    return {s: items for s, items in by_system.items() if len(items) >= FANIN_MIN_METRICS}


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


def stale_acknowledgements(issues: list) -> list:
    """Active issues whose last STALE_COMMENT_MIN comments are near-identical -- the same
    reassurance repeated while the condition remains open, rather than a comment reflecting a
    change in diagnosis or an updated timeline."""
    out = []
    for i in issues:
        if i.label not in ACTIVE_LABELS or len(i.comments) < STALE_COMMENT_MIN:
            continue
        recent = [_norm(c) for _dt, c in i.comments[-STALE_COMMENT_MIN:]]
        base = recent[0]
        if all(SequenceMatcher(None, base, c).ratio() >= STALE_SIMILARITY for c in recent[1:]):
            out.append(i)
    return out


def unacknowledged_persistent(issues: list) -> list:
    """Persistent/Recurring issues with zero recorded admin comments -- a triage gap under
    standard alerting-hygiene practice, independent of severity."""
    return [i for i in issues if i.label in ACTIVE_LABELS and not i.comments]


def coincident_onsets(issues: list) -> list:
    """Groups of >= COINCIDENT_MIN_SYSTEMS distinct systems whose issues first appeared
    within the same COINCIDENT_WINDOW_DAYS-day window -- worth checking for a shared
    dependency (power/network/hypervisor) before treating as unrelated coincidences.

    Deliberately excludes "Persistent" issues: classify_all() only looks back window_days,
    so an issue that was already continuously present before the window even started still
    gets a first_seen clipped to the window's first day -- indistinguishable, by timestamp
    alone, from a genuine new onset. Onset clustering is only meaningful for issues that
    actually started within the window (Recurring/Potential fluke/One-off), not ones merely
    clipped by where the window happens to begin."""
    by_day = defaultdict(set)
    all_systems = set()
    for i in issues:
        if i.label == "Persistent":
            continue
        by_day[i.first_seen.date()].add(i.system)
        all_systems.add(i.system)
    if len(all_systems) < COINCIDENT_MIN_SYSTEMS:
        return []
    threshold = max(COINCIDENT_MIN_SYSTEMS, len(all_systems) * COINCIDENT_SHARE)

    days = sorted(by_day)
    clusters = []
    used_days = set()
    for d in days:
        if d in used_days:
            continue
        window = [d + datetime.timedelta(days=k) for k in range(COINCIDENT_WINDOW_DAYS)]
        systems = set()
        for w in window:
            systems |= by_day.get(w, set())
        if len(systems) >= threshold:
            clusters.append((d, systems))
            used_days.update(window)
    return clusters


def category_concentration(issues: list):
    """Share of active issues held by their single most common category. Returns
    (category, share) or None."""
    active = [i for i in issues if i.label in ACTIVE_LABELS]
    if not active:
        return None
    category, n = Counter(i.category for i in active).most_common(1)[0]
    return category, n / len(active)

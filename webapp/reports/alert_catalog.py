"""Aggregation layer for the Alert Dashboard (management_dashboard_alerts) -- reads
IssueOccurrence/AlertSilence directly. No Prometheus ALERTS metric, no Alertmanager, anywhere
in this module or the screen it backs -- this app has its own bespoke alerting engine (see
IssueOccurrence's own docstring for why Prometheus's native ALERTS metric was tried once and
explicitly abandoned: 5 Temenos-only rules, no CPU/RAM/disk/service coverage at all).

Severity here is the dashboard's own FOUR-tier scheme (Imminent/Critical/Warning/Note) -- a
superset of alert_email_templates._severity()'s 3-tier NOTIFICATION vocabulary, extended with
the "note" band that is real and live today (network.py's node_net_disc, band="note", flows
into IssueOccurrence completely unfiltered -- record_occurrences has no band allowlist) but
was never surfaced anywhere the notification pipeline itself renders, since amber/red were
the only bands that pipeline ever needed to color.

Domain comes straight off IssueOccurrence.domain (set at write time by alerting.py's own
record_occurrences callers) -- see that field's own comment for why this is never re-derived
here from category/flag_key.
"""
from __future__ import annotations

import datetime
import re

# "Self" (2026-10-01, on request: "increase domain to include another domain we can call it
# something like Self") -- this app watching its OWN monitoring pipeline (reports.system_alerts'
# checker/exporter staleness findings), not a business system/estate -- a genuinely different
# thing being monitored than Systems/Network/Infrastructure, so it gets its own column rather
# than being folded into one of those. Unlike Security, it has a real data source from day one
# (see system_alerts.run_system_alert_cycle's own record_occurrences call), so it is never a
# placeholder the way Security still is.
DOMAINS = ["Systems", "Network", "Infrastructure", "Self", "Security"]
SECURITY_PLACEHOLDER = {"name": "Security", "note": "No monitoring data source yet."}

TIER_ORDER = ["imminent", "critical", "warning", "note"]
TIER_LABEL = {"imminent": "Imminent", "critical": "Critical", "warning": "Warning", "note": "Note"}

# One place holding every per-tier CSS value the template needs -- built here, not as if/elif
# chains in the template (Django templates can't index a dict by a variable key at all, and a
# chain repeated for every colour reference on every panel is exactly the kind of duplication
# that drifts out of sync with itself over time).
TIER_STYLE = {
    # Both "heat" and "imminent"'s header_bg/header_fg are CSS var *references* (resolved in
    # .adk's own stylesheet, with light+dark values), not literal colours -- (2026-10-01 fix:
    # "light themed version is not visible properly"). They used to be literal hex/RGB-triplet
    # strings of .adk's DARK palette only, baked straight into the server-rendered inline
    # style, so they never responded to the light/dark toggle at all. That was invisible for
    # critical/warning/note (their header_bg was already a theme-reactive var(--xx-bg) paired
    # with the same theme-reactive fg), but "imminent" paired a hardcoded-black header_bg with
    # the theme-reactive fg -- in light mode fg resolves to the LIGHT --rd (tuned for contrast
    # on a pale card, not on a near-black bar), giving dark-red-on-near-black text on exactly
    # the one panel meant to be the most visible. header_fg now points at a dedicated
    # --imm-bar-fg var (always bright, paired with --imm-bar-bg) instead of reusing fg.
    "imminent": {"css": "rd", "fg": "var(--rd)", "bg": "var(--rd-bg)", "border": "var(--rd-b)",
                "header_bg": "var(--imm-bar-bg)", "header_fg": "var(--imm-bar-fg)",
                "subtitle": "immediate action required", "heat": "var(--heat-imminent)"},
    "critical": {"css": "rd2", "fg": "var(--rd2)", "bg": "var(--rd2-bg)", "border": "var(--rd2-b)",
                "header_bg": "var(--rd2-bg)", "header_fg": "var(--rd2)",
                "subtitle": "needs attention within the hour", "heat": "var(--heat-critical)"},
    "warning": {"css": "am", "fg": "var(--am)", "bg": "var(--am-bg)", "border": "var(--am-b)",
               "header_bg": "var(--am-bg)", "header_fg": "var(--am)",
               "subtitle": "monitor · not yet urgent", "heat": "var(--heat-warning)"},
    "note": {"css": "pu", "fg": "var(--pu)", "bg": "var(--pu-bg)", "border": "var(--pu-b)",
            "header_bg": "var(--pu-bg)", "header_fg": "var(--pu)",
            "subtitle": "informational · no action required", "heat": "var(--heat-note)"},
                                         # ("note" heat is unused today -- Note has no matrix --
                                         # kept here so this dict stays complete.)
}

# Same idea for domains -- pill CSS class + segment colour, one lookup instead of an if/elif
# chain wherever a domain name needs to become a pill/segment colour.
DOMAIN_STYLE = {
    "Systems": "dsy", "Network": "dn", "Infrastructure": "di", "Self": "dself", "Security": "dsc",
}


def _tier(band: str, category: str) -> str:
    """Extends alert_email_templates._severity()'s exact red+category rule with the one
    branch that pipeline never needed: band=="note" (currently only network.py's
    node_net_disc). Keep this in step with that function if the red+category rule ever
    changes -- deliberately not imported from there since that module has its own
    no-Django-models constraint (alerting.py is the only place meant to touch the ORM) and
    this one is ORM-heavy by design.

    Imminent category list (2026-10-01, on request: "for disk usage there is one that is
    imminent and a version of it that is critical... transaction queue drainage is always
    imminent"): "disk" ITSELF no longer reaches Imminent -- split out into "very_high_disk"
    (>=95%, see that category's own comment in models.py) for exactly that; "disk" now tops
    out at Critical. "queue_stuck" (payment/interface queue drainage gone red -- see
    alerting._undrained_folder_flags_by_system's own docstring) is here instead of
    "undrained_folders": those queues are expected to self-drain, so a genuinely stuck one is
    as urgent as a lost connection, but "undrained_folders" itself stays amber-only (2026-10-01,
    "do not name them the exact same thing across severities" -- the two severities needed
    two different category names, not one name spanning both).
    "very_high_cpu"/"very_high_ram" (same date, "cpu usage is also between 2 severities" /
    "rename ram usage across severities") -- same split, same reasoning, same 95% line as
    very_high_disk, just CPU/RAM instead of disk; each also gained a middle "high_*" Critical
    tier (disk/cpu/ram amber=Warning, high_*=Critical, very_high_*=Imminent) for the same
    "do not name them the exact same thing" reason. "very_high_folder" (same date, "same
    split for folder size too") -- "folder" has no percentage reading, so its own severe line
    is a RATIO of actual to expected size instead (see alerting.FOLDER_IMMINENT_RATIO's own
    comment). "unreachable" now means ONLY Imminent, no Warning case at all (same date, on
    request: "component unreachable belongs only to imminent severity remove it from
    [warning]") -- the "not yet configured for SNMP" case that used to stay amber was
    reclassified to red at its own network.py call site (snmp_unconfigured), so there is no
    longer any amber-unreachable finding anywhere in this app; this exception list only needs
    the red branch."""
    if band == "red" and category in ("unreachable", "very_high_disk", "very_high_cpu",
                                      "very_high_ram", "very_high_folder", "queue_stuck"):
        return "imminent"
    if band == "red":
        return "critical"
    if band == "amber":
        return "warning"
    return "note"


# Display name for a category -- COSMETIC only (a slightly-off name is low-stakes, unlike
# domain, which is never a hand-maintained guess -- see IssueOccurrence.domain's own comment).
# Same labels AlertGroup.CATEGORY_CHOICES/alert_email_templates._METRIC_KEY already carry,
# duplicated as a plain dict for the same reason alert_email_templates.py does: keeps this
# lookup a one-line fallback away from ever silently dropping a category nobody's named yet.
_CATEGORY_NAME = {
    "disk": "Disk usage", "ram": "RAM usage", "cpu": "CPU usage",
    "service": "Service down", "degraded": "Degraded", "degrading": "Degrading",
    "potentially_degrading": "Potentially degrading", "temperature": "Temperature",
    "backup": "Backup missing",
    "unreachable": "Component unreachable", "untracked": "Backup untracked",
    "untracked_metrics": "Untracked metrics",
    "backup_uncleared": "Backup & log drainage", "folder": "Folder size",
    "undrained_folders": "Drainage monitoring",
    # "staleness" (2026-10-01, on request: "just add a staleness issue category... use
    # existing design") -- reports.system_alerts.run_system_alert_cycle's own
    # record_occurrences() call, category="staleness", domain="Self" always. See DOMAINS'
    # own comment for why "Self" instead of folding this into an existing domain.
    "staleness": "Staleness",
    # "very_high_disk"/"backup_overdue"/"very_high_cpu"/"very_high_ram"/"very_high_folder"/
    # "high_disk"/"high_cpu"/"high_ram"/"queue_stuck" (2026-10-01) -- see each one's own
    # comment in models.py's CATEGORY_CHOICES for the full split history.
    "very_high_disk": "Very high disk usage",
    "backup_overdue": "Backup & log drainage overdue",
    "very_high_cpu": "Very high CPU usage",
    "very_high_ram": "Very high RAM usage",
    "very_high_folder": "Folder far over expected size",
    "high_disk": "High disk usage", "high_cpu": "High CPU usage", "high_ram": "High RAM usage",
    "queue_stuck": "Queue not draining",
}

# Which band(s) a category's own real call sites ever actually assign -- grounded in reading
# each one's source (generate_report.py/network.py/alerting.py/system_alerts.py), NOT "all
# three are theoretically possible" (2026-10-01 fix, on request: "staleness belongs only to
# the critical severity matrix" -- found the same over-inclusion affected several OTHER
# categories too, e.g. "Degrading" was showing a permanently-0 Critical row despite
# network.py's own degrading-category call sites being hardcoded band="amber" always, never
# red; same latent bug, just the one the requester happened to notice first). Confirmed
# against real IssueOccurrence history (`IssueOccurrence.objects.values_list("category",
# "band").distinct()`) where history exists; for brand-new categories with no history yet
# (staleness, folder) this is instead the literal band each one's OWN FlagVM/Flag call site
# hardcodes -- see _CATEGORY_NAME's own per-category comments above for exactly which.
# "unreachable" is red-ONLY now (2026-10-01, on request: "component unreachable belongs only
# to imminent severity remove it from [warning]") -- the "snmp_unconfigured"/not-yet-
# configured-for-SNMP case that used to stay amber was reclassified to red at its own
# network.py call site, so no amber-unreachable finding exists anywhere any more ("note" was
# removed the same day: confirmed no CURRENT code path ever writes unreachable+note, a stray
# historical row from before some earlier fix, not a real possibility). "temperature"
# collapsed to red-only 2026-10-01 ("temperature is always only critical" -- see temp_high's
# own comment in network.py).
_CATEGORY_BANDS = {
    # "disk"/"ram"/"cpu" are amber-ONLY now (2026-10-01, "do not name them the exact same
    # thing across severities") -- red split out into "high_*" (Critical, <95%) and
    # "very_high_*" (Imminent, >=95%); see those categories' own comments below.
    "disk": {"amber"}, "ram": {"amber"}, "cpu": {"amber"},
    "service": {"red"}, "degraded": {"red"}, "degrading": {"amber"},
    "potentially_degrading": {"note"}, "temperature": {"red"},
    "backup": {"red"}, "unreachable": {"red"},
    "untracked": {"amber"}, "untracked_metrics": {"amber"},
    "folder": {"red"},
    # "backup_uncleared" is amber-only now (2026-10-01) -- its own escalated state is the
    # separate "backup_overdue" category, not the same one turning red; see
    # backup_uncleared_folder_flags_by_system's own docstring for the full split.
    "backup_uncleared": {"amber"}, "backup_overdue": {"red"},
    # "undrained_folders" is amber-ONLY now too (same reasoning as disk/ram/cpu above) --
    # its red case is the separate "queue_stuck" category (Imminent); see _tier()'s own
    # category exception and alerting._undrained_folder_flags_by_system's own docstring.
    "undrained_folders": {"amber"}, "queue_stuck": {"red"}, "staleness": {"red"},
    # "very_high_disk"/"very_high_cpu"/"very_high_ram": always red by construction (>=95%,
    # see each one's own comment in models.py).
    "very_high_disk": {"red"}, "very_high_cpu": {"red"}, "very_high_ram": {"red"},
    # "high_disk"/"high_cpu"/"high_ram": always red by construction too (the <95% red range,
    # Critical tier) -- the NEW middle category between the amber base and the very_high_*
    # Imminent sibling.
    "high_disk": {"red"}, "high_cpu": {"red"}, "high_ram": {"red"},
    # "very_high_folder": always red by construction (see alerting.FOLDER_IMMINENT_RATIO's
    # own comment) -- "folder" keeps {"red"} above too (it was ALREADY always-red, single
    # severity, before this split; very_high_folder is the new Imminent sibling, not a
    # second band of the same category).
    "very_high_folder": {"red"},
}


def _display_name(category: str, flag_key: str) -> str:
    if category in _CATEGORY_NAME:
        return _CATEGORY_NAME[category]
    prefix = flag_key.split(":", 1)[0]
    return prefix.replace("_", " ").title() or "Unnamed check"


def _muted_scope(now=None) -> tuple:
    """({(system,flag_key)}, {(system,category)}) -- every currently-active AlertSilence's own
    exact-component or whole-category scope (2026-10-01, on request: "the system... should
    reference actual alert groups and alert configs to see overrides and whether or not that
    particular alert has been muted"). Shared by current_state()/severity_matrix() so a muted
    finding is excluded from the live severity picture the SAME way alerting._silenced()
    already excludes it from triggering a notification -- a muted finding is known about and
    expected to clear on its own, not absent, so it belongs in the Muted panel's own count
    (alert_catalog.muted_matrix), not double-counted as still-unaddressed in Critical/Warning/
    etc. too.

    ONE source of truth now, real AlertSilence rows only (2026-10-02, on request: "muted
    should mean the same thing we cant have a muted unmuted transient state... when i tell
    you to pause a notification... this should translate to a mute") -- pausing a Monitoring
    AlertGroup used to be a SEPARATE, live-computed condition folded in here alongside real
    silences (_compute_paused_scope, now removed); AlertGroup.save() itself now writes real
    whole-category AlertSilence rows the moment a group is paused (and releases them the
    moment it's reactivated), so this function needs nothing extra to see them -- they're
    just silences, same as any other."""
    from django.utils import timezone as dj_timezone

    from .alerting import _FLAG_SIBLINGS
    from .models import AlertSilence

    if now is None:
        now = dj_timezone.now()
    exact, by_category = set(), set()
    for s in AlertSilence.objects.filter(active=True, expires_at__gt=now).values("system", "flag_key", "category"):
        if s["flag_key"]:
            exact.add((s["system"], s["flag_key"]))
            # A silence on one side of a known degraded/degrading flag pair (e.g. the discard
            # or link-saturation thresholds) also counts as muting the other side here, same
            # reasoning and same source of truth as alerting._active_silences' own sibling
            # expansion (2026-10-03, "network discard (degrades v degrading) alerts still
            # sneak through the mute") -- otherwise the dashboard would keep showing a finding
            # as live/Firing even though the real notification pipeline has already stopped
            # e-mailing about it, which is its own, separate lie worth avoiding.
            sibling = _FLAG_SIBLINGS.get(s["flag_key"])
            if sibling:
                exact.add((s["system"], sibling))
        elif s["category"]:
            by_category.add((s["system"], s["category"]))
    return exact, by_category


def _is_muted(system: str, flag_key: str, category: str, exact: set, by_category: set) -> bool:
    return (system, flag_key) in exact or (system, category) in by_category


def current_state() -> dict:
    """Stat tiles + domain bars.
    {"total_rules": int, "firing": {"imminent":n,...,"note":n,"total":n}, "muted": int,
     "last_30d_total": int, "last_30d_avg_per_day": float,
     "domains": [{"name","tiers":{...},"total"} x3, SECURITY_PLACEHOLDER]}

    `firing` EXCLUDES currently-muted occurrences (see _muted_scope's own comment) -- a
    finding covered by an active AlertSilence no longer counts toward Currently Firing or a
    tier panel's own badge; it counts in the Muted panel instead. `domains` does NOT exclude
    them (2026-10-02, on request: "alert domain and severity treds panels should read all
    alerts not just the unmuted ones" -- matches severity_trend(), which never filtered by
    mute state at all; Alert Domains was the one outlier still doing so) -- it's a read of the
    estate's real shape, same spirit as muted_matrix()'s own "no empty cells for a monitored
    thing" reasoning, not a worklist of what needs attention right now (that's what the tier
    panels and the Muted panel are each already for)."""
    from django.utils import timezone as dj_timezone

    from .models import AlertSilence, IssueOccurrence

    now = dj_timezone.now()
    exact_muted, category_muted = _muted_scope(now)
    open_rows = list(IssueOccurrence.objects.filter(resolved_at__isnull=True)
                     .values("system", "domain", "band", "category", "flag_key"))

    firing = {t: 0 for t in TIER_ORDER}
    domain_counts = {d: {t: 0 for t in TIER_ORDER} for d in ("Systems", "Network", "Infrastructure", "Self")}
    for r in open_rows:
        tier = _tier(r["band"], r["category"])
        if r["domain"] in domain_counts:
            domain_counts[r["domain"]][tier] += 1
        if _is_muted(r["system"], r["flag_key"], r["category"], exact_muted, category_muted):
            continue
        firing[tier] += 1
    firing["total"] = sum(firing[t] for t in TIER_ORDER)

    muted = AlertSilence.objects.filter(active=True, expires_at__gt=now).count()

    since_30d = now - datetime.timedelta(days=30)
    last_30d_total = IssueOccurrence.objects.filter(started_at__gte=since_30d).count()

    # Self-updating, not a hand-counted constant -- matches this app's own established "derive
    # from what actually happened" discipline (see metric_registry.py's own reasoning).
    total_rules = (IssueOccurrence.objects.filter(started_at__gte=since_30d)
                  .values("category", "flag_key").distinct().count())

    domains = [{"name": name, "tiers": domain_counts[name], "total": sum(domain_counts[name].values())}
              for name in ("Systems", "Network", "Infrastructure", "Self")]
    domains.append(dict(SECURITY_PLACEHOLDER))

    return {
        "total_rules": total_rules,
        "firing": firing,
        "muted": muted,
        "last_30d_total": last_30d_total,
        "last_30d_avg_per_day": round(last_30d_total / 30, 1),
        "domains": domains,
    }


def severity_tables(days: int = 30) -> dict:
    """{"imminent": [row, ...], "critical": [...], "warning": [...], "note": [...]}. One row
    per (category, domain) pair that fired within `days`, in whichever tier its band+category
    currently maps to. `count` = distinct (system, flag_key) incidents in the window;
    `trend_pct` = this-week vs last-week incident-count delta, None if last week had zero (no
    baseline to compare against, not a 0% or infinite change)."""
    from django.utils import timezone as dj_timezone

    from .models import IssueOccurrence

    now = dj_timezone.now()
    since = now - datetime.timedelta(days=days)
    week_ago = now - datetime.timedelta(days=7)
    two_weeks_ago = now - datetime.timedelta(days=14)

    rows = (IssueOccurrence.objects.filter(started_at__gte=since)
           .values("system", "flag_key", "category", "band", "domain", "started_at", "resolved_at"))

    groups: dict = {}
    for r in rows:
        tier = _tier(r["band"], r["category"])
        key = (tier, r["category"], r["domain"])
        g = groups.setdefault(key, {
            "name": _display_name(r["category"], r["flag_key"]),
            "domain": r["domain"], "firing": False,
            "keys_30d": set(), "keys_this_week": set(), "keys_last_week": set(),
        })
        ident = (r["system"], r["flag_key"])
        g["keys_30d"].add(ident)
        if r["resolved_at"] is None:
            g["firing"] = True
        if r["started_at"] >= week_ago:
            g["keys_this_week"].add(ident)
        elif r["started_at"] >= two_weeks_ago:
            g["keys_last_week"].add(ident)

    out = {t: [] for t in TIER_ORDER}
    for (tier, _category, _domain), g in groups.items():
        this_week, last_week = len(g["keys_this_week"]), len(g["keys_last_week"])
        trend_pct = round(100 * (this_week - last_week) / last_week) if last_week else None
        out[tier].append({
            "name": g["name"], "domain": g["domain"], "firing": g["firing"],
            "count": len(g["keys_30d"]), "trend_pct": trend_pct,
        })

    for t in TIER_ORDER:
        out[t].sort(key=lambda r: (-r["count"], r["name"]))
    return out


def muted_alerts() -> list:
    """[{"name","domain","reason"}, ...] -- every currently-active AlertSilence, real or
    pause-materialized (2026-10-02: a paused Monitoring group's own AlertGroup.save() writes
    real whole-category silences now, so there's nothing separate to fold in here any more --
    this function only ever reads AlertSilence, same as it would for any other silence). A
    specific-component silence (flag_key set) resolves name/domain from the most recent
    matching IssueOccurrence. A whole-category silence (flag_key blank -- see
    AlertSilence.is_category_wide) resolves domain the same way but keyed on category instead
    of one flag_key, and its name is suffixed " (all)" so the muted table visibly distinguishes
    "one mount silenced" from "every mount, current and future, silenced". Falls back to a bare
    category-derived name/"Systems" if no matching occurrence exists yet (a silence created
    ahead of the first real incident)."""
    from django.utils import timezone as dj_timezone

    from .models import AlertSilence, IssueOccurrence

    now = dj_timezone.now()
    silences = list(AlertSilence.objects.filter(active=True, expires_at__gt=now)
                    .values("system", "flag_key", "category", "reason"))
    out = []
    for s in silences:
        if s["flag_key"]:
            occ = (IssueOccurrence.objects.filter(system=s["system"], flag_key=s["flag_key"])
                  .order_by("-started_at").values("category", "domain").first())
            name = _display_name(occ["category"] if occ else s["category"], s["flag_key"])
        else:
            occ = (IssueOccurrence.objects.filter(system=s["system"], category=s["category"])
                  .order_by("-started_at").values("domain").first())
            name = _display_name(s["category"], "") + " (all)"
        domain = (occ["domain"] if occ else "") or "Systems"
        out.append({"name": name, "domain": domain, "reason": s["reason"]})
    return out


def severity_trend(days: int = 7) -> dict:
    """{"days": [date, ...], "series": {"imminent": [n,...], ...}} -- one point per DAY, same
    overlap-window technique alert_spikes.hourly_alert_series uses (fetch the window once,
    bucket in Python), bucketed by severity TIER across the whole estate instead of
    per-system."""
    from django.db.models import Q
    from django.utils import timezone as dj_timezone

    from .models import IssueOccurrence

    now = dj_timezone.now()
    end = now.replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)
    start = end - datetime.timedelta(days=days)
    day_starts = [start + datetime.timedelta(days=d) for d in range(days)]

    series = {t: [0] * days for t in TIER_ORDER}
    rows = (IssueOccurrence.objects.filter(started_at__lt=end)
           .filter(Q(resolved_at__isnull=True) | Q(resolved_at__gt=start))
           .values("band", "category", "started_at", "resolved_at"))
    for r in rows:
        tier = _tier(r["band"], r["category"])
        active_from = max(r["started_at"], start)
        active_to = min(r["resolved_at"] or end, end)
        if active_to <= active_from:
            continue
        i0 = int((active_from - start).total_seconds() // 86400)
        i1 = -(-int((active_to - start).total_seconds()) // 86400)  # ceil division
        for i in range(i0, min(i1, days)):
            series[tier][i] += 1

    return {"days": day_starts, "series": series}


def hourly_distribution(days: int = 30) -> dict:
    """{"hours": [0..23], "avg": [float,...], "peak": [bool,...]} -- average number of open
    incidents per hour-of-day, averaged across `days` days. `peak` flags hours whose average
    is a statistical outlier (mean + k*stdev across the 24 hourly averages) -- the same
    spike_mask technique alert_spikes.py already uses for per-system daily spikes, reused
    here across hours-of-day instead."""
    from django.db.models import Q
    from django.utils import timezone as dj_timezone

    from .alert_spikes import spike_mask
    from .models import IssueOccurrence

    now = dj_timezone.now()
    end = now.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)
    start = end - datetime.timedelta(days=days)

    hour_totals = [0] * 24
    rows = (IssueOccurrence.objects.filter(started_at__lt=end)
           .filter(Q(resolved_at__isnull=True) | Q(resolved_at__gt=start))
           .values("started_at", "resolved_at"))
    for r in rows:
        active_from = max(r["started_at"], start)
        active_to = min(r["resolved_at"] or end, end)
        if active_to <= active_from:
            continue
        cur = active_from.replace(minute=0, second=0, microsecond=0)
        while cur < active_to:
            hour_totals[cur.hour] += 1
            cur += datetime.timedelta(hours=1)

    avg = [round(t / days, 2) for t in hour_totals]
    peak = spike_mask(avg, k=1.5)
    return {"hours": list(range(24)), "avg": avg, "peak": peak}


def notification_activity() -> dict:
    """{"total": int, "fired": int, "resolved": int} -- REAL notification e-mails successfully
    sent TODAY (local calendar day), derived from AlertFinding/SystemAlertFinding's own
    send-bookkeeping fields, since this app keeps no separate send log at all.

    "fired" = one per (group, last_notified_at) pair stamped today. alerting.run_alert_cycle
    and system_alerts.run_system_alert_cycle both stamp EVERY row in one group's successful
    send with the exact same shared `now`, and each increments its own emails_sent counter
    exactly once per such batch (confirmed by reading both call sites) -- so counting distinct
    (group, timestamp) pairs reproduces the real sent-email count, not an approximation. A
    failed send never stamps anything, so a delivery failure is correctly excluded, not
    undercounted as a decision.

    "resolved" = one per (group, resolved_at) pair stamped today on AlertFinding rows that HAD
    been notified (mirrors alerting._collect_and_resolve's own gate: a finding nobody was ever
    told about doesn't get a "resolved" e-mail). SystemAlertFinding has NO resolved e-mail at
    all -- staleness clearing is stamped silently (confirmed live in system_alerts.py: no
    second send_email call exists there) -- so it never contributes to this half.

    Deliberately excludes the once-daily Silenced Alerts digest (alerting.build_silenced_digest)
    -- that function keeps no record of its own past sends anywhere, so "was a digest actually
    sent today" is not derivable from stored data. Left out entirely rather than guessed, same
    as the Security domain's own placeholder."""
    from django.utils import timezone as dj_timezone

    from .models import AlertFinding, SystemAlertFinding

    today = dj_timezone.localtime(dj_timezone.now()).date()

    fired = (AlertFinding.objects.filter(last_notified_at__date=today)
            .values("group_id", "last_notified_at").distinct().count()
            + SystemAlertFinding.objects.filter(last_notified_at__date=today)
              .values("group_id", "last_notified_at").distinct().count())
    resolved = (AlertFinding.objects.filter(resolved_at__date=today, last_notified_at__isnull=False)
               .values("group_id", "resolved_at").distinct().count())

    return {"total": fired + resolved, "fired": fired, "resolved": resolved}


def avg_resolve_time(days: int = 30) -> dict:
    """{"hours": float|None} -- mean (resolved_at - started_at) across IssueOccurrence rows
    resolved in the last `days` days, across every domain. None when nothing resolved in the
    window -- no baseline to average, not a fabricated 0."""
    from django.db.models import Avg, F
    from django.utils import timezone as dj_timezone

    from .models import IssueOccurrence

    since = dj_timezone.now() - datetime.timedelta(days=days)
    agg = (IssueOccurrence.objects.filter(resolved_at__gte=since)
          .annotate(duration=F("resolved_at") - F("started_at"))
          .aggregate(avg=Avg("duration")))
    dur = agg["avg"]
    return {"hours": round(dur.total_seconds() / 3600, 1) if dur else None}


# ---------------------------------------------------------------------------------------------
# Alert Matrix (2026-10-01, on request: a dropped-in spec/mockup, "replace Imminent/Critical/
# Warning tables with the alert matrix"). Rows = alert type (category), columns = domain,
# fixed Network/Systems/Infrastructure/Security order per the spec -- a DIFFERENT order from
# this module's own DOMAINS above (Systems-first), which stays exactly as it is everywhere
# else on the page; this order is scoped to the matrix only.
#
# Real gaps confirmed against live IssueOccurrence data before writing any of this (the spec's
# own "Before you start" step, and this session's established discipline -- never invent a
# value a label gap can't actually support):
#   - No host/instance field is persisted anywhere. `system` is a BUSINESS name ("RTGS",
#     "CEBAS") for Systems/Infrastructure domains, and happens to already BE the device
#     hostname for Network domain rows. `system` is reused as the popup's "host" field
#     everywhere -- the most specific identifier this app actually keeps, not a fabricated one.
#   - flag_key only decomposes into "component[:resource]" for the categories that are WRITTEN
#     as "category:component[:resource]" (disk/ram/cpu/backup/untracked) -- confirmed live.
#     service/unreachable/network-interface categories use opaque check names
#     ("iface_discards_heavy", "temp_high", "metrics_missing") with no such structure; for
#     those _parse_component returns ("", "") and the popup path is system-only.
#   - No separate numeric "value" field exists -- Flag.text follows a consistent
#     "label · detail" shape across every category (confirmed live), parsed by
#     _value_context() below; a percentage inside `detail` becomes the headline value when
#     present, otherwise the whole detail does.
# ---------------------------------------------------------------------------------------------

MATRIX_DOMAINS = ["Network", "Systems", "Infrastructure", "Self", "Security"]
# Security is the one place this module deliberately deviates from the spec's own "every slot
# gets a tile, no empty cells" rule (rule 2) -- that rule assumes every column is at least
# MONITORED, just possibly quiet. Security has no real data source anywhere in this app (see
# SECURITY_PLACEHOLDER above) -- showing it as "0, OK" would claim it was checked and found
# clear, which is false. It renders as a genuinely empty tile (the mockup's own, already-
# styled-but-unused `.empty` CSS) instead, consistent with how Security is treated everywhere
# else on this dashboard.
_MATRIX_NO_DATA_DOMAIN = "Security"

_PCT_RE = re.compile(r"(\d{1,3})%")


def _matrix_duration_str(start, end) -> str:
    """Same shape as alerting._duration_str ("3h 10m", "9d 4h") -- duplicated rather than
    imported: alert_catalog is the ORM-heavy aggregation layer, alerting.py is the notification
    pipeline, and this is an 8-line utility, not worth a cross-module dependency for."""
    total_min = max(0, int((end - start).total_seconds() // 60))
    if total_min < 60:
        return f"{total_min}m"
    h, m = divmod(total_min, 60)
    if h < 24:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"


def _parse_component(category: str, flag_key: str) -> tuple:
    """(component, resource) best-effort from flag_key's own "category:component[:resource]"
    convention -- see this section's own module-level comment for exactly which categories
    this does and doesn't work for. Returns ("", "") rather than guessing when the flag_key
    doesn't follow that shape."""
    prefix = category + ":"
    if not flag_key.startswith(prefix):
        return "", ""
    rest = flag_key[len(prefix):]
    if ":" in rest:
        component, _, resource = rest.partition(":")
        return component, resource
    return rest, ""


def _value_context(text: str) -> tuple:
    """(value, context) best-effort split of a Flag.text "label · detail" sentence -- see this
    section's own module-level comment. A percentage inside `detail` becomes the headline
    value (matching the mockup's own "94%" style); otherwise `detail` itself is the value and
    `label` becomes the supporting context line."""
    label, sep, detail = text.partition(" · ")
    if not sep:
        return text, ""
    m = _PCT_RE.search(detail)
    if m:
        return f"{m.group(1)}%", ""
    return detail, label


def _meter_pct(value: str, band: str) -> int:
    """Meter-bar fill, 0-100. A real percentage drives it directly; otherwise a red (down/
    never-backed-up-style) finding fills the bar fully, matching the mockup's own treatment of
    its non-percentage examples ("Down", "Never"), and an amber one half-fills it -- a labelled
    fallback, never a fabricated precise number."""
    if value.endswith("%"):
        try:
            return int(value[:-1])
        except ValueError:
            pass
    return 100 if band == "red" else 55


def _affected_item(row: dict, now, reason: str = "", configured: bool = True) -> dict:
    component, resource = _parse_component(row["category"], row["flag_key"])
    value, context = _value_context(row["text"])
    path = [row["system"]]
    # A single-host system's own flag_key often names the component after itself (e.g.
    # "backup:Voice Recorder" on system "Voice Recorder") -- skip the repeat rather than
    # show "Voice Recorder › Voice Recorder".
    if component and component != row["system"]:
        path.append(component)
    if resource:
        path.append(resource)
    if context == path[-1]:
        context = ""   # same redundancy as the component-dedup above, one line down
    item = {
        "path": path, "host": row["system"], "v": value, "s": context,
        "pct": _meter_pct(value, row["band"]),
        "since": _matrix_duration_str(row["started_at"], now),
        # (system, flag_key) -- the SAME stable identity comment_correlation.observed_flags()
        # and AutomatedFindingAction already key on -- lets the popup's own drill-down look up
        # this exact finding's admin comment history (2026-10-01, on request: a clickable
        # "third screen" showing the last 10 admin comments for a clicked item).
        "fk": row["flag_key"],
        # category travels alongside flag_key (2026-10-01, on request: "mute alert and use one
        # of their comments as mute reason") -- AlertSilence.category is a required field (see
        # that model's own docstring on why) and this is the one place that already has it on
        # hand without re-deriving it from flag_key's own "category:component[:resource]" shape.
        "cat": row["category"],
        # Whether ANY Monitoring AlertGroup covers this (system, category) at all (2026-10-02,
        # on request: "a way to show alerts that are configured vs those that are not
        # configured....some are just issues from issue occurance" -- IssueOccurrence is
        # written for every system/category combination unconditionally, see that model's own
        # docstring, regardless of whether any admin ever set up a group to notify on it).
        # Always present (not conditional like `reason`) since a single matrix cell can mix
        # configured and unconfigured systems -- severity_matrix()'s own cell-level
        # "unconfigured" state only applies when EVERY item in it is uncovered; a mixed cell
        # still needs this per item so the popup can flag just the uncovered ones.
        "configured": configured,
    }
    if row["band"] == "red":
        item["sev"] = "var(--up)"
    # `reason` (2026-10-01, Muted matrix only): the AlertSilence's own free-text reason, shown
    # per item rather than once per cell -- two systems can share a (category, domain) cell
    # under two DIFFERENT silences with different reasons, so this is never a single cell-level
    # value. Plain "" (not passed) for every ordinary severity_matrix() item, which the popup
    # JS already treats as "no reason line" via a truthy check.
    if reason:
        item["reason"] = reason
    return item


def _walk_comment_history(system: str, flag_keys: set, limit: int = 10) -> list[dict]:
    """The actual comprehensive historical walk, across every flag_key in `flag_keys` at once
    (2026-10-01 fix: "i find it extremely hard to believe that we dont have any comment on
    rtgs's high disk usage ... your search is not comprehensive enought ... search all db
    records" -- see models.CommentIndexEntry's own docstring for why a single exact flag_key
    was never enough: a finding's category prefix changes across a severity escalation, and
    the OLD version of this function only ever matched the one flag_key the clicked tile
    happened to carry RIGHT NOW). Only called when CommentIndexEntry has no cached answer yet
    -- every future call for this (system, suffix) is served from that cache instead, not
    this walk again (the "better mechanism for new reports" half of the same request).

    Uses models.comment_relevant_flag_keys, not "any flag present that day", to decide whether
    a submission's comment actually belongs to one of `flag_keys`, AND to narrow a genuinely
    multi-topic comment down to just the line(s) about THIS finding -- a same-day-but-unrelated
    flag used to pull in a plainly irrelevant comment, or a real comment covering two real
    findings at once leaked the OTHER one's own detail into this one (2026-10-01, confirmed
    real: "are you sure the targetted comments are relevant to the exact issue" / "comments
    picked for sc corporate actions service being down are talking about ram", then "this is
    the disk usage issue yet it also picked a comment related to no backup" -- see that
    function's own comment for all three confirmed cases)."""
    from .models import ReportSubmission, comment_relevant_flag_keys

    out: list[dict] = []
    qs = ReportSubmission.objects.only("created_at", "author", "generated_by", "report_content")
    for sub in qs.order_by("-created_at").iterator():
        for sysd in (sub.report_content or {}).get("systems", []):
            if sysd.get("name") != system:
                continue
            if not (sysd.get("comment") or "").strip():
                break
            relevant = comment_relevant_flag_keys(sysd)
            matched = next((k for k in relevant if k in flag_keys), None)
            if not matched:
                break
            author = sub.author or (sub.generated_by.get_username() if sub.generated_by_id else "")
            out.append({"created_at": sub.created_at.isoformat(), "comment": relevant[matched],
                       "author": author, "flag_key": matched})
            break
        if len(out) >= limit:
            break
    return out


def comment_history(system: str, flag_key: str, category: str = "", limit: int = 10) -> list[dict]:
    """Up to the most recent `limit` admin comments on record for this real-world finding --
    the "third screen" drill-down from a clicked matrix item (2026-10-01, on request: "the
    detailed alert on the second screen must also be clickable opening another popup that
    shows the last 10 comments given by admins for that particular issue"), later corrected
    the same day (see models.CommentIndexEntry's own docstring) to follow the finding across a
    severity-tier category change instead of matching one exact flag_key.

    Served from models.CommentIndexEntry when that (system, suffix) has been looked up before
    -- a single indexed row read. On a genuine first-ever lookup, falls back to
    `_walk_comment_history` across every sibling flag_key (models.sibling_flag_keys) this
    finding could have been recorded under at any severity tier, THEN persists that result so
    every later lookup -- including a NEW comment arriving on a different tier later -- never
    repeats the full walk (models._index_new_report_submission keeps the cache current from
    then on, for every report type, with no further changes needed here).

    `category` is optional only for backward compatibility with an old cached page's JS (no
    sibling expansion without it -- falls back to the exact-flag_key behaviour this function
    started with). The real UI always sends it (see _affected_item's own "cat" comment).
    """
    from .models import CommentIndexEntry, comment_index_suffix, sibling_flag_keys

    suffix = comment_index_suffix(category, flag_key) if category else flag_key
    entry = CommentIndexEntry.objects.filter(system=system, suffix=suffix).first()
    if entry is None:
        flag_keys = sibling_flag_keys(category, flag_key) if category else {flag_key}
        comments = _walk_comment_history(system, flag_keys, limit)
        CommentIndexEntry.objects.get_or_create(system=system, suffix=suffix, defaults={"comments": comments})
        return comments
    return list(entry.comments or [])[:limit]


def monitoring_groups_for(system: str, category: str) -> list[dict]:
    """Every active Monitoring AlertGroup that would actually notify for a Flag of this
    category on this system -- i.e. the real, allowed choices for "whose digest does this
    silence roll into" (AlertSilence.group's own docstring: "normally the SAME group that
    would otherwise have been notified for it"). SAME matching rule
    alerting._evaluate_for_groups() uses for real notification eligibility
    (`system in group.systems` and `group.category_matches(system, category)`) -- deliberately
    reused rather than re-derived, so "which groups can this be muted into" can never silently
    drift from "which groups would otherwise be notified" (2026-10-01, on request: "mute alert
    and use one of their comments as mute reason" -- the drill-down popup's own quick-mute
    action needs this same list config_alerts' own silence form already offers via a free
    group picker, just narrowed to the ones that are actually relevant here)."""
    from .models import AlertGroup

    out = []
    for g in AlertGroup.objects.filter(alert_type=AlertGroup.ALERT_TYPE_MONITORING, active=True):
        if system in (g.systems or []) and g.category_matches(system, category):
            out.append({"id": g.pk, "name": g.name})
    return out


# Auto-mute (2026-10-01, on request: after manually muting CRB's and RTGS's own recurring
# high-disk-usage explanations -- "i think the comments fully explayn what is going on look
# for recuring comments....in future set up a mechanism where if an issue occurs and has 3 or
# more duplicate comments on different report runs automatically mute alert").
#
# TOKEN OVERLAP, not byte-identical, and not a character-sequence ratio either (2026-10-01
# follow-up, on request: "tokenise these comments and compare them to each other as tokens...
# acceptance rate of say 92 percent... tokenisation as used in rag"). True RAG-style
# embeddings were considered and rejected: these are short, templated, repetitive operational
# notes, not open-ended language needing semantic understanding, and embeddings would mean
# either a heavy new dependency (sentence-transformers/torch) or sending internal operational
# text to an external API -- not justified for this problem.
#
# Plain Jaccard (intersection / union) was tried first and rejected too, grounded against the
# SAME real CRB/RTGS data this whole feature started from: CRB's two genuine phrasings of one
# explanation ("Log files retention" vs "Log files are retained and maintained on a rolling
# basis") only score 0.36-0.42 Jaccard, because the longer sentence pulls extra words into the
# union and punishes the length difference -- a 92% (or even 80%) Jaccard threshold would have
# missed the exact case this feature was built for.
#
# OVERLAP COEFFICIENT (intersection / size of the SMALLER token set) instead: CRB's two
# phrasings consistently score 0.83, RTGS's own (which drifts less: "&" vs "and", a trailing
# "process") scores 0.93-1.00, and a genuinely unrelated control comment scored 0.0 -- clean
# separation. 92% was the user's own first guess, but real data doesn't support it: CRB's
# confirmed-correct case tops out at 0.83, so 92% would have rejected it. 80% is the real,
# data-grounded threshold -- catches both known-good cases with room to spare, while the 0.0
# control shows it isn't so loose it would start matching unrelated text.
_AUTO_MUTE_MIN_DUPLICATES = 3
_AUTO_MUTE_SIMILARITY = 0.80
_AUTO_MUTE_EXPIRES_DAYS = 60


def _tokenize_comment(text: str) -> set:
    return set(re.findall(r"[a-z0-9%]+", text.lower()))


def _comment_similarity(a: str, b: str) -> float:
    """Token overlap coefficient -- see this section's own module-level comment for why this
    metric and this threshold, chosen against real data rather than guessed."""
    ta, tb = _tokenize_comment(a), _tokenize_comment(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / min(len(ta), len(tb))


def _is_recurring_comment(comments: list, min_count: int = _AUTO_MUTE_MIN_DUPLICATES,
                          threshold: float = _AUTO_MUTE_SIMILARITY) -> bool:
    """Whether `comments` (same shape comment_history()/CommentIndexEntry.comments use) holds
    a cluster of `min_count`+ comments that are near-identical to EACH OTHER (not just to the
    single newest one -- confirmed necessary against CRB's real data, where the newest comment
    happens to sit in the SMALLER of two near-identical phrasing clusters; comparing only
    against it would have missed the dominant, 7-strong cluster entirely)."""
    texts = [(c.get("comment") or "").strip() for c in comments]
    for i, t in enumerate(texts):
        if not t:
            continue
        count = 1 + sum(1 for j, u in enumerate(texts)
                        if i != j and u and _comment_similarity(t, u) >= threshold)
        if count >= min_count:
            return True
    return False


def _recurring_mute_candidate(system: str, category: str, flag_key: str, comments: list = None) -> dict:
    """Would (system, category, flag_key) qualify for the recurring-comment auto-mute right
    now -- the shared decision logic behind maybe_auto_mute (which acts on a candidate
    immediately) and run_recurring_auto_mute's own dry-run preview (which just reports
    candidates for the dashboard's own confirmation dialog, 2026-10-02, on request: "the mute
    recurring button should also open a confirmation dialog where it shows the results of its
    assessments... and a confirmation button"). Returns None when already muted, not
    recurring, or the covering group is missing/ambiguous (see monitoring_groups_for's own
    comment on why that's never guessed) -- a dict
    {"system","category","flag_key","label","reason","group_id","group_name"} otherwise.
    Never writes anything -- callers that want to act on it do so themselves."""
    from .models import AlertSilence

    if AlertSilence.objects.filter(system=system, category=category, flag_key=flag_key, active=True).exists():
        return None
    if comments is None:
        comments = comment_history(system, flag_key, category=category)
    if not comments or not _is_recurring_comment(comments):
        return None
    groups = monitoring_groups_for(system, category)
    if len(groups) != 1:
        return None
    newest = (comments[0].get("comment") or "").strip()
    reason = (f"Auto-muted: the same explanation has been recorded "
             f"{_AUTO_MUTE_MIN_DUPLICATES}+ times across different report runs — "
             f"“{newest}”")
    return {"system": system, "category": category, "flag_key": flag_key,
           "label": _display_name(category, flag_key), "reason": reason,
           "group_id": groups[0]["id"], "group_name": groups[0]["name"]}


def _create_silence_from_candidate(candidate: dict) -> None:
    from .models import AlertGroup, AlertSilence
    from django.utils import timezone as dj_timezone

    AlertSilence.objects.create(
        system=candidate["system"], category=candidate["category"], flag_key=candidate["flag_key"],
        group=AlertGroup.objects.get(pk=candidate["group_id"]),
        reason=candidate["reason"], created_by=None,
        expires_at=dj_timezone.now() + datetime.timedelta(days=_AUTO_MUTE_EXPIRES_DAYS))


def maybe_auto_mute(system: str, category: str, flag_key: str, comments: list) -> bool:
    """Create an AlertSilence automatically once an issue's own admin comments show the same
    explanation recorded _AUTO_MUTE_MIN_DUPLICATES+ times across different report runs (see
    this section's own comment above for the request this implements). Returns True if a
    silence now exists for this exact (system, category, flag_key) -- whether created just now
    or already there from before, so a caller never needs a second existence check of its own.
    `created_by` stays null (no human acted) -- this is the fully-automatic path (the
    ReportSubmission signal); see run_recurring_auto_mute's own docstring for the on-demand,
    human-confirmed dashboard path, which shares this exact same candidate logic."""
    from .models import AlertSilence

    if AlertSilence.objects.filter(system=system, category=category, flag_key=flag_key, active=True).exists():
        return True
    candidate = _recurring_mute_candidate(system, category, flag_key, comments)
    if candidate is None:
        return False
    _create_silence_from_candidate(candidate)
    return True


def run_recurring_auto_mute(dry_run: bool = False, user=None) -> dict:
    """On-demand sweep of every CURRENTLY OPEN finding against _recurring_mute_candidate's own
    criteria (2026-10-01, on request: a "Mute recurring" button on the dashboard "that
    triggers the mechanism we just defined"). The normal path
    (_index_new_report_submission, a signal on ReportSubmission) only ever checks whatever
    flag_key a JUST-SUBMITTED report touched -- this covers findings that already qualify
    RIGHT NOW but haven't had a new report run since the mechanism existed, or since their
    comment history last grew past the threshold.

    `dry_run=True` (2026-10-02, on request: the button "should also open a confirmation
    dialog where it shows the results of its assessments... and a confirmation button") -- the
    SAME candidate evaluation, but creates nothing; returns
    {"checked": N, "candidates": [...]} for the dashboard to show BEFORE anything is muted.
    `dry_run=False` (the real action, fired only after the admin confirms) creates a real
    AlertSilence per qualifying candidate and returns {"checked": N, "muted": [...]} -- the
    same shape the button's own success path already expects. One evaluation per row either
    way, so confirming never re-walks comment history or re-decides anything the preview
    already showed -- what you confirm is exactly what you saw.

    `user` (2026-10-02, on request: muting "would have to filter through the permissions you
    have as per your designated alert group") -- when given and not a full Administrator, the
    sweep is scoped to findings whose own covering group roles.can_edit_alert_group approves
    for THIS user; a full admin (or the signal-driven automatic path, user=None) keeps the
    whole-estate sweep unchanged. `checked` still counts every open finding examined, same as
    always -- only which ones can QUALIFY narrows, so the admin sees an honest "how many did I
    actually have rights over" rather than a number that silently differs by who's logged in."""
    from .models import AlertGroup, IssueOccurrence
    from .roles import can_edit_alert_group, is_role_admin

    editable_group_ids = None
    if user is not None and not is_role_admin(user):
        editable_group_ids = {g.pk for g in AlertGroup.objects.filter(alert_type=AlertGroup.ALERT_TYPE_MONITORING)
                              if can_edit_alert_group(user, g)}

    rows = (IssueOccurrence.objects.filter(resolved_at__isnull=True)
           .values("system", "category", "flag_key").distinct())
    checked = 0
    results = []
    for r in rows:
        system, category, flag_key = r["system"], r["category"], r["flag_key"]
        if not (system and category and flag_key):
            continue
        checked += 1
        candidate = _recurring_mute_candidate(system, category, flag_key)
        if candidate is None:
            continue
        if editable_group_ids is not None and candidate["group_id"] not in editable_group_ids:
            continue
        if not dry_run:
            _create_silence_from_candidate(candidate)
        results.append(candidate)
    return {"checked": checked, "candidates" if dry_run else "muted": results}


def severity_matrix(tier: str, days: int = 30) -> dict:
    """Matrix data for ONE tier panel (Imminent/Critical/Warning): {"data": [[alert, domain,
    state, count_now, count_prev], ...], "affected": {"alert|domain": [item, ...]}} -- shaped
    to match alert-matrix-mockup.html's own `data`/`affected` JS consts exactly, so the ported
    component JS needs no reshaping, only the sample arrays replaced with this. A cell's state
    is "unconfigured" (2026-10-02, "a way to show alerts that are configured vs those that are
    not configured") rather than "firing" when every open item in it lacks ANY AlertGroup
    coverage -- IssueOccurrence is written for every system/category unconditionally (see that
    model's own docstring), so a real finding can exist with nobody ever having configured an
    AlertGroup to notice it. Rendered calm (the SAME green as "ok", no pulse) rather than
    alarming, since nothing is actually firing a real notification for it -- a cell with even
    one COVERED item stays "firing" as normal, real pulsing red, since genuine notification is
    still happening for part of it.

    ROWS (alert types) are never a hand-maintained list, but ALSO never gated on having
    actually fired (2026-10-01, on request -- staleness had zero real occurrences ever, so it
    was silently absent from every panel despite being correctly wired; "should it show 0 like
    all the other issues... why is it missing" -> "show everything we do not need to adhere to
    this limitation"): every category in AlertGroup.CATEGORY_CHOICES (plus "staleness", which
    deliberately isn't in that list -- see its own comment) that CAN mechanically reach this
    tier via _tier() shows as a row, real history or not. "Can reach" is computed from _tier()
    itself, not a hand-maintained per-category tier map, so it never drifts if _tier()'s own
    rule changes -- e.g. "disk"/"unreachable" are the only two categories that ever reach
    "imminent" (red collapses everything else straight to "critical"), so those are the only
    two rows there; every other category can reach "critical" (red), "warning" (amber), and
    "note" (band="note"), whether or not any real code path has ever actually produced that
    combination -- a category that structurally never emits red (e.g. "degrading") will show a
    permanently-0 Critical row rather than being hidden, by the same explicit choice.

    count_now = CURRENTLY OPEN right now, not a `days`-window event count (the spec's own
    correction: "if the current tables count firing events rather than currently firing
    alerts, switch to currently firing"). count_prev = the same currently-open snapshot taken
    exactly 24h earlier ("the previous alert window", confirmed with the requester 2026-10-01
    -- this app's own day-boundary notification-cycle concept, see AlertFinding's own docstring
    on why a day is this app's one established "window" unit), computed via the same overlap-
    window technique severity_trend/hourly_distribution already use (was this row open AT that
    point in time, not merely started before it).

    count_now/count_prev/`affected` EXCLUDE anything currently covered by an active AlertSilence
    (2026-10-01, on request: "the system... should reference actual alert groups and alert
    configs to see overrides and whether or not that particular alert has been muted" -- see
    _muted_scope's own comment). The ROW and CELL themselves still appear if the category/
    domain combination has EVER produced a finding in the window, muted or not -- muting hides
    the finding from this panel's counts (it belongs in the Muted panel's own count instead),
    it does not make the combination stop being a real, monitored thing."""
    from django.utils import timezone as dj_timezone

    from .models import AlertGroup, IssueOccurrence

    now = dj_timezone.now()
    since = now - datetime.timedelta(days=days)
    prev_point = now - datetime.timedelta(hours=24)
    exact_muted, category_muted = _muted_scope(now)
    # Fetched once per call, not once per row (2026-10-02, "configured vs not configured") --
    # a Monitoring group's own systems/categories don't change mid-request, and this matrix
    # evaluates on the order of a hundred rows per tier, never thousands.
    monitoring_groups = list(AlertGroup.objects.filter(alert_type=AlertGroup.ALERT_TYPE_MONITORING))
    covered_cache: dict = {}

    def is_configured(system: str, category: str) -> bool:
        key = (system, category)
        if key not in covered_cache:
            covered_cache[key] = any(system in (g.systems or []) and g.category_matches(system, category)
                                     for g in monitoring_groups)
        return covered_cache[key]

    recent = list(IssueOccurrence.objects.filter(started_at__gte=since)
                 .values("category", "domain", "band", "flag_key", "text", "system",
                        "started_at", "resolved_at"))

    # "staleness" isn't in AlertGroup.CATEGORY_CHOICES on purpose (see that choice's own
    # comment in models.py) -- it's not a Monitoring-alert category a group can pick/silence
    # through config_alerts, just a dashboard-visible finding type, so it's added here only.
    # Each category's row only shows in the tier(s) it can ACTUALLY reach -- _CATEGORY_BANDS'
    # own comment on why "any of red/amber/note is possible" was wrong for several categories.
    all_categories = [k for k, _ in AlertGroup.CATEGORY_CHOICES] + ["staleness"]
    categories = sorted({cat for cat in all_categories
                        for band in _CATEGORY_BANDS.get(cat, {"red", "amber", "note"})
                        if _tier(band, cat) == tier})
    if not categories:
        return {"data": [], "affected": {}}

    ever_pairs = set()
    now_counts: dict = {}
    prev_counts: dict = {}
    affected_now: dict = {}

    for r in recent:
        if r["category"] not in categories or _tier(r["band"], r["category"]) != tier:
            continue
        key = (r["category"], r["domain"])
        ever_pairs.add(key)
        if _is_muted(r["system"], r["flag_key"], r["category"], exact_muted, category_muted):
            continue   # a real, monitored combination -- just not counted as still-unaddressed
                       # here while an admin has it muted (see this function's own docstring)
        is_open_now = r["resolved_at"] is None
        was_open_prev = (r["started_at"] <= prev_point
                         and (r["resolved_at"] is None or r["resolved_at"] > prev_point))
        if is_open_now:
            now_counts[key] = now_counts.get(key, 0) + 1
            affected_now.setdefault(key, []).append(r)
        if was_open_prev:
            prev_counts[key] = prev_counts.get(key, 0) + 1

    data = []
    affected = {}
    for cat in categories:
        name = _display_name(cat, "")
        for d in MATRIX_DOMAINS:
            if d == _MATRIX_NO_DATA_DOMAIN:
                data.append([name, d, "empty", 0, 0])
                continue
            key = (cat, d)
            n = now_counts.get(key, 0)
            p = prev_counts.get(key, 0)
            rows = sorted(affected_now.get(key, []), key=lambda r: r["started_at"]) if n else []
            configured_flags = [is_configured(r["system"], r["category"]) for r in rows]
            # "unconfigured" (2026-10-02, "a way to show alerts that are configured vs those
            # that are not configured....perhaps we can make it the same exact color as the
            # green zero tile and not give it a puls animation as all the live alerts") -- only
            # when EVERY item in the cell lacks AlertGroup coverage; a cell with even one
            # covered system is real, notified-on firing and keeps that state, same pulsing
            # red it always had (muting this down would hide a genuine active alert behind a
            # calm colour). The individual uncovered items still carry their own `configured:
            # False` either way, so a MIXED cell's popup can flag just those.
            if n and all(not c for c in configured_flags):
                state = "unconfigured"
            else:
                state = "firing" if n > 0 else "ok"
            data.append([name, d, state, n, p])
            if n:
                affected[f"{name}|{d}"] = [_affected_item(r, now, configured=c)
                                          for r, c in zip(rows, configured_flags)]

    return {"data": data, "affected": affected}


# Muted panel's own grey accent -- a CSS var reference (--heat-muted, themed in .adk itself),
# matching the EXACT pattern TIER_STYLE's own "heat" keys already use for the four severity
# panels (see that dict's own comment). Not added to TIER_STYLE itself -- Muted is not a
# severity tier, _tier() has no "muted" branch and never will (muting is an admin DECISION
# layered on top of a real severity, not a severity of its own).
MUTED_HEAT = "var(--heat-muted)"


def muted_matrix(days: int = 30) -> dict:
    """Matrix data for the Muted panel (2026-10-01, on request: "apply matrix to muted alerts
    table"), SAME {"data": [...], "affected": {...}} shape severity_matrix() returns, so it is
    rendered by the identical ported JS -- only the semantics of a cell differ:

    Rows = category of an ACTIVE AlertSilence. count_now/count_prev = how many
    IssueOccurrence rows are CURRENTLY/previously OPEN under that silence's own scope (the
    real suppressed volume, not a count of silences -- almost always 1-3, far less useful).
    EVERY covered cell gets state "muted" regardless of its count (including 0 -- a silence
    created ahead of the first real incident, or one whose incident has since cleared, is
    still an active administrative decision worth seeing, the same "no empty cells for a
    monitored thing" reasoning severity_matrix's own "ok" state uses) -- "firing"/"ok" never
    apply here, this panel is never about current severity. Security is still "empty": no
    occurrence can ever carry that domain, so no silence can ever cover it either, same as
    every other panel.

    Each affected item carries its OWN `reason` (AlertSilence.reason, or the synthesized
    pause reason below) -- two systems can share one (category, domain) cell under two
    different silences with two different reasons, so reason is never a single cell-level
    value (see _affected_item's own comment).

    A paused Monitoring group's own findings are already represented here with no extra code
    (2026-10-02): AlertGroup.save() writes real whole-category AlertSilence rows the moment a
    group pauses (see that method's own docstring), so they're just silences like any other by
    the time this function runs -- nothing synthetic to fold in."""
    from django.utils import timezone as dj_timezone

    from .alerting import _FLAG_SIBLINGS
    from .models import AlertSilence, IssueOccurrence

    now = dj_timezone.now()
    since = now - datetime.timedelta(days=days)
    prev_point = now - datetime.timedelta(hours=24)

    silences = list(AlertSilence.objects.filter(active=True, expires_at__gt=now)
                    .values("system", "flag_key", "category", "reason"))
    if not silences:
        return {"data": [], "affected": {}}

    recent = list(IssueOccurrence.objects.filter(started_at__gte=since)
                 .values("system", "flag_key", "category", "domain", "band", "text",
                        "started_at", "resolved_at"))
    by_system_category: dict = {}
    by_system_flagkey: dict = {}
    for r in recent:
        by_system_category.setdefault((r["system"], r["category"]), []).append(r)
        by_system_flagkey.setdefault((r["system"], r["flag_key"]), []).append(r)

    categories = set()
    ever_pairs = set()
    now_counts: dict = {}
    prev_counts: dict = {}
    affected_now: dict = {}   # (category, domain) -> [(row, reason), ...]

    def _fold(rows: list, reason: str) -> None:
        # rows always share one real category (they all came from one by_system_flagkey or
        # by_system_category bucket) -- each call here builds/extends exactly one cell, never
        # relabels a row's own category, so a degraded row always lands in the degraded row
        # and a degrading one in degrading, even when borrowed in via a sibling below.
        category = rows[0]["category"]
        categories.add(category)
        domain = rows[0]["domain"] or "Systems"
        key = (category, domain)
        ever_pairs.add(key)
        for r in rows:
            is_open_now = r["resolved_at"] is None
            was_open_prev = (r["started_at"] <= prev_point
                             and (r["resolved_at"] is None or r["resolved_at"] > prev_point))
            if is_open_now:
                now_counts[key] = now_counts.get(key, 0) + 1
                affected_now.setdefault(key, []).append((r, reason))
            if was_open_prev:
                prev_counts[key] = prev_counts.get(key, 0) + 1

    # Real silences only ever silence their OWN (system, flag_key) -- used below so a sibling
    # that already has its own dedicated silence is never ALSO borrowed in a second time.
    real_flag_keys = {(s["system"], s["flag_key"]) for s in silences if s["flag_key"]}

    for s in silences:
        if s["flag_key"]:
            rows = by_system_flagkey.get((s["system"], s["flag_key"]), [])
        else:
            rows = by_system_category.get((s["system"], s["category"]), [])
        if rows:
            _fold(rows, s["reason"])
        # Known degraded/degrading sibling pair (e.g. discards, link saturation -- see
        # alerting._FLAG_SIBLINGS' own comment): when the sibling flag_key has NO silence of
        # its own, the real notification pipeline suppresses it anyway (alerting.
        # _active_silences' own sibling expansion), so show it here too, under its OWN
        # category/cell, using this silence's reason -- otherwise a device that only ever
        # crossed into the un-named side in this window would vanish from both Firing
        # (correctly excluded, see alert_catalog._muted_scope) and this Muted panel at once
        # (2026-10-03, "network discard (degrades v degrading) alerts still sneak through the
        # mute"). Skipped whenever the sibling has its own real silence row -- that row's own
        # turn through this same loop already folds it in, once, with its own real reason.
        sibling = _FLAG_SIBLINGS.get(s["flag_key"]) if s["flag_key"] else None
        if sibling and (s["system"], sibling) not in real_flag_keys:
            sib_rows = by_system_flagkey.get((s["system"], sibling), [])
            if sib_rows:
                _fold(sib_rows, s["reason"])

    data = []
    affected = {}
    for cat in sorted(categories):
        name = _display_name(cat, "")
        for d in MATRIX_DOMAINS:
            if d == _MATRIX_NO_DATA_DOMAIN:
                data.append([name, d, "empty", 0, 0])
                continue
            key = (cat, d)
            if key not in ever_pairs:
                data.append([name, d, "empty", 0, 0])
                continue
            n = now_counts.get(key, 0)
            p = prev_counts.get(key, 0)
            data.append([name, d, "muted", n, p])
            rows = sorted(affected_now.get(key, []), key=lambda rr: rr[0]["started_at"])
            affected[f"{name}|{d}"] = [_affected_item(r, now, reason=reason) for r, reason in rows]

    return {"data": data, "affected": affected}

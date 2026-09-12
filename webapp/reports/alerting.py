"""Sector-based alerting engine.

Gathers live data the same way services.capture_snapshot does (same config/topology/capture
calls) but works directly with generate_report.flagged_for_system's Flag objects instead of
building the report-builder's SystemVM/FlagVM view-models -- this module has no UI to serve,
only AlertGroup policy to evaluate against the estate's current findings.

Reuses flagged_for_system for ALL per-system policy (RAM_THRESHOLD_OVERRIDES, backup policy
exemptions, etc.) and mail_report.send_email for ALL SMTP -- neither is reimplemented here.
Only the run_alerts management command calls run_alert_cycle(); nothing else in the webapp
imports this module.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from django.utils import timezone

import generate_report as gr   # send_report/ is on sys.path, same mechanism services.py uses

from . import alert_email_templates
from . import folders

# One (system, flag_key) pair per suppressed ALERT, not a whole category -- 2026-09-08, on
# request: "disable the rtgs database disk usage alert", confirmed scoped to just that one
# mount (RTGS's Reverse Proxy and Backend disk alerts keep firing normally). Matches
# generate_report.BACKUP_UNTRACKED_EXEMPT's own shape/spirit (a small, named, commented
# exemption list) but keyed finer -- AlertGroup.categories can only exclude a whole category
# per system, which would have silenced all three of RTGS's disk alerts to suppress just one.
# Deliberately NOT applied to record_occurrences (see run_alert_cycle's own call site) -- this
# suppresses the NOTIFICATION only; the underlying incident still shows up in the System Admin
# Report and Automated Reports exactly as before, so it doesn't silently vanish from history,
# it just stops paging anyone.
ALERT_FLAG_SUPPRESSED = {
    ("RTGS", "disk:Database:/u01"),   # 2026-09-08: known/accepted, not to be re-alerted
}


def _flag_suppressed(system: str, flag_key: str) -> bool:
    return (system, flag_key) in ALERT_FLAG_SUPPRESSED


@dataclass
class AlertRunResult:
    """What one run_alert_cycle() call did, for the management command to report and for
    tests to assert against."""
    groups_evaluated: int = 0
    systems_captured: int = 0
    new_count: int = 0
    reminder_count: int = 0
    resolved_count: int = 0
    emails_sent: int = 0
    resolved_emails_sent: int = 0
    emails_preview: List[dict] = field(default_factory=list)   # populated only when dry_run


def severity_meets(band: str, category: str | None = None) -> bool:
    """Whether a Flag's band is even alertable at all -- "red" is still the internal value (see
    AlertGroup.MIN_SEVERITY_CHOICES' own comment on why the DISPLAY labels are Imminent/
    Critical instead). No group can opt into amber/Warning any more (on request, 2026-09-04:
    "there are no expected alerts for warning severity...only imminent and critical
    thresholds") -- amber findings are real (still shown on the Folder Watch dashboard etc.)
    but never reach an AlertGroup's notification pipeline.

    ONE deliberate, narrow exception (2026-09-07, on request: "let it be one of the few
    alerts that fires as a WARNING Alert Notification"): "backup_uncleared" (backup/log
    folder drainage -- see backup_uncleared_folder_flags_by_system's own docstring) is a MANUAL
    process, so an admin wants a gentle amber heads-up the moment it's overdue, escalating to
    a real red/Critical only once it's been neglected for days. Every other category is
    unaffected -- this is not a reopening of Warning severity generally."""
    if band == "red":
        return True
    return category == "backup_uncleared" and band == "amber"


def _capture(system_names: Optional[set]):
    """cfg + topology + a live Prometheus capture, scoped to exactly the given systems --
    `None` means every business system, no filter (used by run_alert_cycle since 2026-09-07:
    the occurrence log it now also records must be comprehensive, independent of which systems
    any AlertGroup happens to cover -- see record_occurrences' own docstring). Same three calls
    services.capture_snapshot makes (gr.load_config, the SystemConfig override,
    gr.load_topology, gr.Prometheus/prom.ping, gr.capture) -- kept separate from that function
    because this module has no Snapshot/view-model to build."""
    from .models import SystemConfig

    cfg = gr.load_config()
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url
    if sc.grafana_url:
        cfg.grafana = sc.grafana_url
    systems = [s for s in gr.load_topology(cfg.prometheus_yml, scope="business")
              if system_names is None or s.name in system_names]
    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    prom.ping()
    store = gr.capture(prom, systems, cfg)
    return store, systems, cfg


def folder_size_flags_by_system(store, systems) -> Dict[str, list]:
    """Synthetic Flag objects for every currently-over-expected watched folder, grouped by
    owning system. Shared by run_alert_cycle and send_test_alert so the "repackage
    folder_over_expected_detail as a Flag" logic (see run_alert_cycle's own comment on why it
    lives here rather than in generate_report.py) exists in exactly one place.

    band="red" (2026-09-04: since severity_meets now only ever admits red -- "no expected
    alerts for warning severity, only imminent and critical" -- an amber-only category would
    otherwise be permanently unalertable). This category still never escalates further; it is
    simply reported at the one severity that can actually reach anyone now, not two."""
    out: Dict[str, list] = {}
    for sysname, fname, expected, actual in gr.folder_over_expected_detail(store, systems):
        out.setdefault(sysname, []).append(gr.Flag(
            key=f"folder:{fname}",
            text=f"{fname} over expected size: {actual:.1f}GB (expected {expected:.1f}GB)",
            band="red", category="folder"))
    return out


def undrained_folder_flags_by_system(cfg, covered_systems: set) -> Dict[str, list]:
    """Synthetic Flag objects for every payment-queue folder currently NOT draining --
    files waiting whose oldest has aged past its amber/red limit, per reports.folders'
    own live verdict (folders.verdict: red/amber both imply files>0 and an aged-out oldest
    file; "idle" -- files<=0 -- is the healthy drained state and never flags here).

    A SEPARATE live Prometheus query from _capture's own store (reports.folders.snapshot()
    calls generate_report.Prometheus itself, independently) -- same reasoning as
    folder_size_flags_by_system's own comment on why this lives here rather than in
    generate_report.py, just a different underlying screen/exporter reading. Skipped entirely
    (no extra query at all) when no covered system is even eligible to produce this category,
    same T24-only gating as "folder" -- see folders.folder_watch_systems."""
    eligible = folders.folder_watch_systems(cfg.prometheus_yml) & covered_systems
    if not eligible:
        return {}
    try:
        data = folders.snapshot()
    except folders.FolderWatchUnavailable:
        return {}
    out: Dict[str, list] = {}
    for f in data["folders"]:
        if f["state"] not in ("red", "amber"):
            continue
        # A "logfiles" watch_type folder (e.g. T24 Log File) is judged by SIZE, not by
        # anything draining -- an amber verdict there means "over its expected share of the
        # volume", already reported as its own "folder" (Size Monitoring) Flag via
        # folder_size_flags_by_system/folder_over_expected_detail. Flagging it AGAIN here as
        # "undrained_folders" would be the same underlying fact under the wrong category.
        #
        # "backup"/"logs" watch_type (2026-09-07): the Temenos Backup & Log Folders now get
        # their OWN category, "backup_uncleared" (see backup_uncleared_folder_flags_by_system) --
        # a manual, admin-owned clearing process with a deliberately gentler Warning-first
        # escalation, not the immediate Critical-only rule every payment/interface queue
        # folder gets here. Excluded here so the same folder is never flagged under BOTH
        # categories at once.
        if f["watch_type"] in ("logfiles", "backup", "logs"):
            continue
        flag = gr.Flag(
            key=f"undrained:{f['key']}",
            text=f"{f['name']} on {f['host']} not draining: {f['files']} file(s) waiting, oldest {f['age_text']} old",
            band=f["state"], category="undrained_folders")
        for sysname in eligible:
            out.setdefault(sysname, []).append(flag)
    return out


# How long a backup/log folder may sit past its own due date (folders.backup_drain_limits'
# per-system red_seconds) before "backup_uncleared" escalates from Warning to Critical
# (2026-09-07, on request: "until perhaps a period of about 3 days overdue then have it fire
# as a CRITICAL Alert Notification"). This is ON TOP OF the due date itself, not instead of
# it -- a folder becomes eligible to flag (Warning) the moment it passes its own due date,
# then Critical 3 more days after that.
MAX_BACKUP_OVERDUE_SECONDS = 3 * 86400


def backup_uncleared_folder_flags_by_system(cfg, covered_systems: set) -> Dict[str, list]:
    """Synthetic Flag objects for Temenos Backup & Log Folders that are overdue to be
    cleared -- category "backup_uncleared" (2026-09-07, on request: "perhaps we need a
    custom notification for backup and log drainage... this is a manual drainage type and we
    simply want to remind people first").

    DELIBERATELY separate from "undrained_folders" (payment/interface queues) even though
    both read the very same folders.snapshot(): a payment queue is expected to drain itself
    automatically within minutes, so any queue backlog is a genuine, immediate problem --
    Critical only, no grace period, matches every other alert category. A backup/log folder
    is cleared out by a HUMAN on a schedule; going a little past its own due date is routine,
    not an emergency, so this category gets the gentlest possible first notice (Warning --
    one of the few categories severity_meets lets through at amber) and only escalates to
    Critical once it's been neglected for MAX_BACKUP_OVERDUE_SECONDS (3 days) past due.

    Reuses each folder's own `red_seconds` (folders.backup_drain_limits' per-system,
    admin-overridable cadence -- the SAME number Per Alert Config's "Backup drainage
    monitoring" table already shows) as the due date, rather than introducing a second
    threshold to configure: "overdue" starts at exactly the point that already meant
    something to an admin looking at that screen."""
    eligible = folders.backup_drainage_systems() & covered_systems
    if not eligible:
        return {}
    try:
        data = folders.snapshot()
    except folders.FolderWatchUnavailable:
        return {}
    out: Dict[str, list] = {}
    for f in data["folders"]:
        if f["watch_type"] not in ("backup", "logs"):
            continue
        if f["age"] is None:
            continue   # nothing waiting -- fully cleared, the healthy state
        overdue = f["age"] - f["red_seconds"]
        if overdue < 0:
            continue   # not yet past its own due date
        band = "red" if overdue >= MAX_BACKUP_OVERDUE_SECONDS else "amber"
        flag = gr.Flag(
            key=f"backup_uncleared:{f['key']}",
            text=f"{f['name']} on {f['host']} not cleared: {f['files']} file(s) waiting, oldest {f['age_text']} old",
            band=band, category="backup_uncleared")
        for sysname in eligible:
            out.setdefault(sysname, []).append(flag)
    return out


def _decide(existing, band: str, now, schedule: List[int], *, imminent: bool = False,
           imminent_minutes: int = 10) -> tuple:
    """('new'|'renew'|'remind'|'skip', reminder_number) -- reminder_number is the ordinal
    (1..len(schedule)) this would be if it fires as 'remind', else None. A pure function of
    the existing AlertFinding row (or None), the flag's CURRENT band, and the CURRENT reminder
    schedule (the owning group's own AlertGroup.effective_reminder_minutes -- group-specific,
    2026-09-04 -- fetched once per group per run_alert_cycle call, not per finding, so every
    finding evaluated for the same group in the same poll is judged against the same schedule
    even if an admin saves a change mid-poll).

    Reopening (resolved_at was set) and a first-ever sighting both read as 'new'. An
    escalation (existing.band was amber, current band is red) also always reads as 'new' --
    see AlertFinding's own docstring for why this resets the schedule rather than continuing
    it.

    `imminent=True` (component unreachable -- see alert_email_templates._severity's own
    IMMINENT mapping) takes over ENTIRELY at this point and ignores everything below: no
    daily cap, no schedule list, just "remind" every `imminent_minutes` minutes since the
    LAST reminder, for as long as the finding stays open (on request, 2026-09-04: "treat all
    component down alerts as imminent... we need to be made aware of it... willing to have a
    persistent notification until resolved"). Anchored to last_notified_at, not
    first_notified_at like the capped schedule below -- a genuine repeating interval, not a
    fixed list of offsets from one anchor.

    Otherwise, the reminder cap is PER CALENDAR DAY (local time, on request 2026-09-04: "3
    reminders on that particular day then reset on next day"), not for the finding's whole
    lifetime -- a finding still open once local midnight has passed since its CURRENT cycle's
    first_notified_at reads as 'renew': the caller treats this exactly like 'new' for
    notifying and for resetting first_notified_at/reminder_count, but -- unlike a genuine
    'new' -- does NOT touch first_seen_at, since this is still the same ongoing incident, not
    a fresh one (see run_alert_cycle's own handling and AlertFinding.first_seen_at's own
    docstring). Without this, a finding open for a week would get its 3 reminders on day one
    and then go silent for the other six.

    Otherwise: once len(schedule) reminders have already gone out TODAY, stays silent for the
    rest of today (not a repeating interval); before the cap, fires 'remind' once at least
    schedule[reminder_count] minutes have passed since first_notified_at -- "at least",
    because resolution and re-notification are both only ever checked when the poller
    actually runs, so the schedule can't fire any faster than the poller's own cadence."""
    if existing is None or existing.resolved_at is not None or existing.last_notified_at is None:
        return "new", None
    if existing.band == "amber" and band == "red":
        return "new", None
    if existing.first_notified_at is None:
        return "skip", None
    if imminent:
        if now - existing.last_notified_at >= datetime.timedelta(minutes=imminent_minutes):
            return "remind", existing.reminder_count + 1
        return "skip", None
    if timezone.localtime(now).date() != timezone.localtime(existing.first_notified_at).date():
        return "renew", None
    if existing.reminder_count >= len(schedule):
        return "skip", None
    due_after = schedule[existing.reminder_count]
    if now - existing.first_notified_at >= datetime.timedelta(minutes=due_after):
        return "remind", existing.reminder_count + 1
    return "skip", None


def record_occurrences(system: str, flags: list, now) -> None:
    """IssueOccurrence's only writer -- see that model's own docstring for why it exists
    separately from AlertFinding. Called once per system, every run_alert_cycle poll (~5
    minutes), for that system's ENTIRE fresh flags list -- not filtered by any AlertGroup's
    category/severity selection, since "is this eligible for notification" and "did this
    actually happen" are different questions, and this table only ever answers the second one.

    A flag_key with a still-open row gets that row refreshed in place (band/text/last_seen_at)
    -- the same incident continuing, not a new one. A flag_key that HAD an open row but is no
    longer in this poll's fresh flags gets that row closed (resolved_at = now) -- the same
    "vanished from this poll = resolved" rule run_alert_cycle's own AlertFinding cleanup
    already uses, applied here independently since this table's set of open keys is its own,
    not derived from AlertFinding's. A flag_key with no open row is a brand new incident."""
    from .models import IssueOccurrence

    current = {f.key: f for f in flags}
    open_rows = {r.flag_key: r for r in
                IssueOccurrence.objects.filter(system=system, resolved_at__isnull=True)}

    stale_pks = [r.pk for key, r in open_rows.items() if key not in current]
    if stale_pks:
        IssueOccurrence.objects.filter(pk__in=stale_pks).update(resolved_at=now)

    for key, f in current.items():
        row = open_rows.get(key)
        if row is None:
            IssueOccurrence.objects.create(
                system=system, flag_key=f.key, category=f.category, band=f.band, text=f.text,
                started_at=now, last_seen_at=now)
        elif row.band != f.band or row.text != f.text:
            IssueOccurrence.objects.filter(pk=row.pk).update(
                band=f.band, text=f.text, last_seen_at=now)
        else:
            IssueOccurrence.objects.filter(pk=row.pk).update(last_seen_at=now)


def run_alert_cycle(*, dry_run: bool = False) -> AlertRunResult:
    """One poll: capture live data, evaluate every active group against its own systems, send
    (or, if dry_run, only preview) one digest e-mail per group with anything new/due, and
    record what happened in AlertFinding so the next run knows what's already been said.

    A group with no active systems mapped is skipped entirely (nothing to capture for it); a
    group with findings but no resolvable stakeholder e-mail is skipped at send time (logged
    via the result, not raised -- one misconfigured group must never stop every other group's
    alerts from going out)."""
    from .models import AlertFinding, AlertGroup

    result = AlertRunResult()
    now = timezone.now()
    local_now = timezone.localtime(now)
    # Monitoring Alert groups only (2026-09-05: AlertGroup now also carries System Alert
    # groups -- reports.system_alerts' own concern, filtered there by alert_type instead --
    # see AlertGroup's own docstring on why one model now serves both classifications).
    #
    # A group outside its own schedule (2026-09-07: "people are asking for these alerts to
    # be schedulable... enable them at a certain time and disable them at a certain time,
    # even in terms of days") is filtered out here, in Python rather than the DB query, since
    # in_schedule's own day/time-of-day/overnight-wrap logic isn't a clean SQL WHERE clause --
    # this reads EXACTLY like `active=False` for this poll: no new findings evaluated, no
    # reminders sent, no stale-resolution processing either, since it never reaches the
    # per-group loop below at all. Unscheduled groups (schedule_enabled=False, the default)
    # always pass through unaffected.
    groups = [g for g in AlertGroup.objects.filter(
                 active=True, alert_type=AlertGroup.ALERT_TYPE_MONITORING).prefetch_related("users")
             if g.in_schedule(local_now)]
    result.groups_evaluated = len(groups)
    # Per-group, not global (2026-09-04: "notification reminder schedule should be group
    # specific") -- fetched once per group here, not per Flag inside the loop below, so every
    # finding evaluated for the same group in the same poll agrees on the same schedule even if
    # an admin saves a change mid-poll (same reasoning the old single global schedule used).
    schedules: Dict[int, list] = {g.pk: g.effective_reminder_minutes for g in groups}

    # (system, band, text, first_seen_at, flag_key) per group, for the "Resolved" digest below
    # -- populated ONLY for rows that were actually notified (last_notified_at is not None): a
    # finding that appeared and cleared between two polls, without anyone ever being told it
    # existed, must not generate a "resolved" e-mail about something nobody knew was wrong.
    # flag_key rides along so the e-mail can show the same category icon/label a fired finding
    # gets -- AlertFinding has no separate category column, but every Flag.key this app ever
    # writes is "category:..." (or "category:sub:..."), so the prefix before the first colon
    # IS the category, the same convention alert_email_templates.py's own category-icon lookup
    # already assumes.
    per_group_resolved: Dict[int, list] = {g.pk: [] for g in groups}

    def _collect_and_resolve(qs):
        rows = list(qs)
        for row in rows:
            if row.last_notified_at is not None:
                per_group_resolved[row.group_id].append(
                    (row.system, row.band, row.text, row.first_seen_at, row.flag_key))
        if rows:
            AlertFinding.objects.filter(pk__in=[r.pk for r in rows]).update(resolved_at=now)
        return len(rows)

    # A system dropped from a group's OWN scope (edited in Configuration, not just missing
    # from this poll's capture) is resolved here unconditionally, before the capture-scoped
    # loop below even runs -- that loop only ever sees systems that are STILL covered by some
    # active group, so a system removed from every group that used to cover it would otherwise
    # never be captured again and its old findings would dangle open forever.
    if not dry_run:
        for g in groups:
            stale = (AlertFinding.objects
                    .filter(group=g, resolved_at__isnull=True)
                    .exclude(system__in=(g.systems or [])))
            result.resolved_count += _collect_and_resolve(stale)

    covered = {s for g in groups for s in (g.systems or [])}

    # Full topology, not just `covered` (2026-09-07, on request): the occurrence log recorded
    # below must be comprehensive, independent of which systems any AlertGroup happens to
    # cover -- see IssueOccurrence's own docstring. `covered` remains exactly what it was for
    # everything BELOW this capture (which systems get evaluated for NOTIFICATION purposes);
    # only the capture scope widened. One live Prometheus read either way, not two.
    store, systems, cfg = _capture(None)
    result.systems_captured = len(systems)
    if not systems:
        return result
    all_names = {s.name for s in systems}

    # Folder-over-expected-size is a real generate_report finding (see
    # folder_over_expected_detail's own docstring), just never routed through
    # flagged_for_system -- it's a report-level banner there, not a per-system Flag. Reused
    # exactly as-is (not reimplemented) and re-packaged into genuine Flag namedtuples here,
    # entirely inside this module, so the rest of this function (severity_meets,
    # category_matches, _decide, the AlertFinding bookkeeping, the digest e-mail) treats a
    # folder finding identically to any other -- no separate code path to keep in sync.
    # Always "red" (see folder_size_flags_by_system's own docstring: never escalated, however far
    # over expected a folder grows -- just reported at the one severity that can alert at all),
    # category "folder" (see AlertGroup.CATEGORY_CHOICES' own comment on why this category
    # exists only here, not in generate_report.py itself).
    folder_flags_by_system = folder_size_flags_by_system(store, systems)
    # A SEPARATE live check (see undrained_folder_flags_by_system's own docstring on why it
    # queries independently of `store`) for payment-queue folders that have files waiting past
    # their drain-time limit -- category "undrained_folders", distinct from "folder" above
    # (that one is disk-size overflow; this one is a queue backlog, different exporter).
    # `all_names`, not `covered` -- same reasoning as the capture above.
    undrained_flags_by_system = undrained_folder_flags_by_system(cfg, all_names)
    # Backup/log folder drainage (2026-09-07) -- category "backup_uncleared", deliberately a
    # SEPARATE check from undrained_flags_by_system above even though both read the same
    # folders.snapshot() (see backup_uncleared_folder_flags_by_system's own docstring: a manual,
    # human-cleared process gets a gentler Warning-first ladder, not the immediate
    # Critical-only rule payment/interface queues get).
    backup_uncleared_flags_by_system = backup_uncleared_folder_flags_by_system(cfg, all_names)

    # [(system, Flag, action)] per group -- collected in the capture pass below, then either
    # previewed (dry_run) or turned into one digest e-mail per group afterward. The rows this
    # loop writes track CURRENT TRUTH (band/text/first_seen_at/last_seen_at) unconditionally,
    # but deliberately do NOT set last_notified_at yet -- that only happens once send_email
    # actually succeeds, below, so a transient SMTP failure leaves the row looking exactly
    # like "not yet notified" and the NEXT cycle tries again immediately rather than waiting
    # out a "daily" group's full 24h window for something nobody was actually told.
    per_group_items: Dict[int, list] = {g.pk: [] for g in groups}
    per_group_rows: Dict[int, list] = {g.pk: [] for g in groups}   # AlertFinding rows to stamp
    # Genuinely still-open findings that AREN'T themselves due for a new/reminder event this
    # poll -- collected from the SAME live `eligible` pass (fresh band/text, not whatever an
    # AlertFinding row was last stamped with) so that IF some other finding in this group DOES
    # go out this cycle, its digest can show the complete current picture rather than just
    # what happened to be due (2026-09-04, on request: "if ram is high for system x and... for
    # system y, the ram alert notification should contain all systems with high ram usage").
    # Deliberately does NOT touch reminder_count/first_notified_at/last_notified_at for these
    # -- appearing here is pure context, never a notification event in its own right.
    per_group_still_open: Dict[int, list] = {g.pk: [] for g in groups}

    for sysm in systems:
        flags = (gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
                 + undrained_flags_by_system.get(sysm.name, [])
                 + backup_uncleared_flags_by_system.get(sysm.name, []))

        # Comprehensive occurrence log (see IssueOccurrence's own docstring): every system,
        # every category, regardless of whether any AlertGroup below even covers this system
        # let alone has this category ticked. Skipped in dry_run for the same reason AlertFinding
        # is untouched then -- a preview must not write real incident history.
        if not dry_run:
            record_occurrences(sysm.name, flags, now)

        if sysm.name not in covered:
            continue   # no active group cares about this system for NOTIFICATION purposes
        for g in groups:
            if sysm.name not in (g.systems or []):
                continue
            matches = [f for f in flags
                      if severity_meets(f.band, f.category)
                      and g.category_matches(sysm.name, f.category)]
            # eligible_keys (below) comes from `matches`, NOT the suppression-filtered
            # `eligible` -- a suppressed flag that's still genuinely present must not fall out
            # of eligible_keys, or the stale-resolution pass right below would mark its
            # existing AlertFinding resolved and fire a false "resolved" e-mail (the disk usage
            # hasn't gone away, it's just been told not to page anyone -- see
            # ALERT_FLAG_SUPPRESSED's own docstring). `eligible` itself (the new/reminder loop
            # below) DOES exclude it -- that's the actual suppression.
            eligible = [f for f in matches if not _flag_suppressed(sysm.name, f.key)]
            eligible_keys = {f.key for f in matches}

            if not dry_run:
                stale = (AlertFinding.objects
                        .filter(group=g, system=sysm.name, resolved_at__isnull=True)
                        .exclude(flag_key__in=eligible_keys))
                result.resolved_count += _collect_and_resolve(stale)

            for f in eligible:
                existing = None if dry_run else AlertFinding.objects.filter(
                    group=g, system=sysm.name, flag_key=f.key).first()
                # IMMINENT (component unreachable, or disk near full) findings bypass the
                # capped daily schedule entirely -- persistent reminders every group.
                # effective_imminent_reminder_minutes until resolved (2026-09-04: "treat all
                # component down alerts as imminent... willing to have a persistent
                # notification until resolved"; disk added 2026-09-07: "treat disk near full
                # alerts... as IMMINENT Alert Notifications" -- the same chip_red threshold
                # the daily report's own DISK NEAR-FULL banner already uses, see
                # alert_email_templates._severity's own docstring on why no new threshold was
                # needed for this).
                is_imminent = f.band == "red" and f.category in ("unreachable", "disk")
                action, reminder_number = _decide(
                    existing, f.band, now, schedules[g.pk],
                    imminent=is_imminent, imminent_minutes=g.effective_imminent_reminder_minutes)
                if action == "skip":
                    # existing is never None here (see _decide: existing is None always
                    # decides 'new') -- a genuinely still-open finding, just not due for its
                    # own event this poll.
                    per_group_still_open[g.pk].append((sysm.name, f))
                    continue
                # 'renew' (a new calendar day's first notification for a still-open finding
                # -- see _decide's own docstring) reads exactly like 'new' for the digest
                # e-mail and the new/reminder counts; only the first_seen_at bookkeeping below
                # tells the two apart.
                email_action = "new" if action in ("new", "renew") else "remind"
                # None total (only ever for an imminent 'remind') tells the renderer this
                # reminder has no "final" -- it repeats forever until resolved, so labelling
                # it "final reminder" the moment reminder_number reaches the group's own
                # UNRELATED capped-schedule length would be actively wrong.
                item_total = None if is_imminent and email_action == "remind" else len(schedules[g.pk])
                per_group_items[g.pk].append((sysm.name, f, email_action, reminder_number, item_total))
                if email_action == "new":
                    result.new_count += 1
                else:
                    result.reminder_count += 1
                if not dry_run:
                    row, created = AlertFinding.objects.get_or_create(
                        group=g, system=sysm.name, flag_key=f.key,
                        defaults={"band": f.band, "text": f.text,
                                  "first_seen_at": now, "last_seen_at": now})
                    if not created and action == "new":
                        row.first_seen_at = now
                        # A fresh incident (reopen or amber->red escalation) restarts the
                        # reminder schedule from zero -- see AlertFinding's own docstring.
                        # first_notified_at is set below only once THIS send succeeds.
                        row.first_notified_at = None
                        row.reminder_count = 0
                    elif not created and action == "renew":
                        # Still the SAME ongoing incident -- only the notification cycle
                        # restarts for the new day (see _decide's own docstring); first_seen_at
                        # is left untouched so a resolved digest still reports how long the
                        # finding has REALLY been open, not just since today's first reminder.
                        row.first_notified_at = None
                        row.reminder_count = 0
                    row.band, row.text, row.last_seen_at = f.band, f.text, now
                    row.resolved_at = None
                    row.save()
                    per_group_rows[g.pk].append((row, email_action))

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    mailcfg["from_name"] = "System Alerts"

    for g in groups:
        items = per_group_items[g.pk]
        resolved = per_group_resolved[g.pk]
        if not items and not resolved:
            continue
        recipients = g.recipient_emails()
        if not recipients:
            continue   # misconfigured group: no stakeholders -- skip, don't crash the run

        if items:
            subject, text_body, html_body, inline_images = _render_fired_email(
                g, items, total_reminders=len(schedules[g.pk]),
                still_open=per_group_still_open[g.pk])
            if dry_run:
                result.emails_preview.append({"group": g.name, "kind": "fired", "to": recipients,
                                              "subject": subject, "text_body": text_body})
            elif mailcfg.get("host"):
                try:
                    mr.send_email(mailcfg, recipients, subject, html_body, text_body,
                                  inline_images=inline_images)
                    result.emails_sent += 1
                    # Per-row, not a bulk .update(): a "new" row gets its schedule anchor set
                    # for the first time, a "remind" row advances its count by exactly one --
                    # two different field changes on the same batch, only ever applied once
                    # THIS send has actually succeeded (see the loop above's own comment on
                    # why first_notified_at/reminder_count aren't touched any earlier).
                    for row, action in per_group_rows[g.pk]:
                        if action == "new":
                            row.first_notified_at = now
                        else:
                            row.reminder_count += 1
                        row.last_notified_at = now
                        row.save(update_fields=["first_notified_at", "reminder_count", "last_notified_at"])
                except Exception:  # noqa: BLE001 -- one group's SMTP failure must not stop the rest
                    pass

        if resolved:
            subject, text_body, html_body, inline_images = _render_resolved_email(g, resolved, now)
            if dry_run:
                result.emails_preview.append({"group": g.name, "kind": "resolved", "to": recipients,
                                              "subject": subject, "text_body": text_body})
            elif mailcfg.get("host"):
                try:
                    mr.send_email(mailcfg, recipients, subject, html_body, text_body,
                                  inline_images=inline_images)
                    result.resolved_emails_sent += 1
                except Exception:  # noqa: BLE001 -- one group's SMTP failure must not stop the rest
                    pass
    return result


def send_test_alert(group, *, to: str | None = None) -> tuple[bool, str]:
    """Manually triggered from the group's own edit screen -- always a REAL send, never a dry
    run, because the whole point is to answer "does this actually reach my stakeholders right
    now" (SMTP config, recipient addresses) which a preview can't tell you.

    `to`, if given, MUST already be one of group.recipient_emails() (the caller validates --
    see config_alert_group_test) -- narrows delivery to that one stakeholder instead of the
    whole group, so iterating on a test doesn't re-notify everyone every time. None sends to
    every current stakeholder, same as before this parameter existed.

    Deliberately never touches AlertFinding: a test firing must not consume a group's real
    once-only notify slot or shift its renotify clock, or running one could cause a genuine
    finding to go silently unreported later because the test already "used up" that finding's
    turn. It reads the group's CURRENT saved systems/categories/severity (whatever's actually
    in the database), not any unsaved edits sitting in the form.

    If the group has real eligible findings right now they're included (still marked [TEST]
    throughout) so this doubles as a live check that detection still works; if there are none,
    the e-mail says so explicitly rather than going out empty and unexplained. Exceptions are
    surfaced to the caller as the failure message, not swallowed, since seeing the actual SMTP
    error is the point of clicking this button."""
    recipients = [to] if to else group.recipient_emails()
    if not recipients:
        return False, "This group has no stakeholders yet — add at least one before testing."
    if not group.systems:
        return False, "This group covers no systems yet — add at least one before testing."

    try:
        store, systems, cfg = _capture(set(group.systems))
    except Exception as exc:      # noqa: BLE001 -- shown to the admin, not swallowed
        return False, f"Could not capture live data: {exc}"

    folder_flags_by_system = folder_size_flags_by_system(store, systems)
    undrained_flags_by_system = undrained_folder_flags_by_system(cfg, set(group.systems))
    backup_uncleared_flags_by_system = backup_uncleared_folder_flags_by_system(cfg, set(group.systems))
    items = []
    for sysm in systems:
        flags = (gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
                 + undrained_flags_by_system.get(sysm.name, [])
                 + backup_uncleared_flags_by_system.get(sysm.name, []))
        eligible = [f for f in flags
                   if severity_meets(f.band, f.category)
                   and group.category_matches(sysm.name, f.category)
                   and not _flag_suppressed(sysm.name, f.key)]
        items += [(sysm.name, f, "new", None, None) for f in eligible]

    subject, text_body, html_body, inline_images = _render_fired_email(group, items)
    subject = f"[TEST] {subject}"
    if items:
        preamble = "This is a manually triggered TEST alert — not a real notification cycle.\n\n"
    else:
        preamble = ("This is a manually triggered TEST alert — not a real notification cycle.\n"
                   "No current findings for this group; sent purely to confirm delivery.\n\n")
    text_body = preamble + text_body
    html_body = "<pre>" + preamble.replace("\n", "<br>") + "</pre>" + html_body

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        return False, "No SMTP host configured (send_report/config.ini [smtp])."
    mailcfg["from_name"] = "System Alerts (test)"
    try:
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, inline_images=inline_images)
    except Exception as exc:      # noqa: BLE001 -- shown to the admin, that's the point of testing
        return False, f"Send failed: {exc}"
    return True, f"Test alert sent to {', '.join(recipients)}."


def _duration_str(start, end) -> str:
    """Human-readable elapsed time for a resolved digest's "open for" column."""
    total_min = max(0, int((end - start).total_seconds() // 60))
    if total_min < 60:
        return f"{total_min}m"
    h, m = divmod(total_min, 60)
    if h < 24:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"


def _render_fired_email(group, items, *, total_reminders: int | None = None,
                        for_browser: bool = False, still_open: list | None = None) -> tuple:
    """items: [(system, Flag, action, reminder_number, item_total), ...] for ONE group --
    action is 'new' or 'remind', reminder_number is 1..item_total (which of the scheduled
    reminders this is) when action is 'remind', else None. `item_total` travels WITH each
    item (2026-09-04) rather than being one shared value, since a persistent IMMINENT
    reminder (component unreachable -- see _decide's own imminent branch) carries
    item_total=None ("no final reminder, repeats until resolved") which must never be
    overwritten by some OTHER, unrelated finding's own capped schedule length in the same
    digest. `total_reminders` (this function's own parameter) is now used only to pass a
    caller-supplied fallback through to the renderer for items that never got a real one
    (e.g. send_test_alert's synthetic 'new' items, which never show a reminder label at all
    anyway) -- defaults to this group's own current schedule length.

    Uses alert_email_templates.render_fired for the HTML -- the same branded shell every other
    alert e-mail this feature sends (navy gradient header, white "Alert notification" title,
    card per finding, each tagged NEW or an ordinal reminder tag from
    alert_email_templates.reminder_label() so a recipient can tell at a glance how many times
    they've already been told about this exact finding), not the older mail_report-styled
    "SYSTEM ALERT" digest this used to build via _email_shell, which is what a real recipient's
    screenshot showed was still going out for real production alerts even after
    render_resolved was migrated (2026-09-04) -- only the fired path had been missed."""
    if total_reminders is None:
        total_reminders = len(group.effective_reminder_minutes)
    new_items = [(s, f) for s, f, a, _n, _t in items if a == "new"]
    reminders = [(s, f, n, t) for s, f, a, n, t in items if a == "remind"]
    subject = f"[Alerts] {group.name} — {len(new_items)} new, {len(reminders)} reminder(s)"

    lines = []
    if new_items:
        lines.append("NEW:")
        lines += [f"  [{f.band.upper()}] {s} — {f.text}" for s, f in new_items]
    if reminders:
        lines.append("STILL OPEN:")
        lines += [f"  [{f.band.upper()}] {s} — {f.text} "
                 f"({alert_email_templates.reminder_label(n, t)})"
                 for s, f, n, t in reminders]
    if still_open:
        # NOT the same as the "STILL OPEN:" reminders section above -- these are OTHER,
        # currently-open findings in this group that simply aren't due for their own
        # reminder this poll, included purely for situational awareness (2026-09-05, on
        # request: a RAM alert for system Y shouldn't hide that system X's RAM is also
        # still high just because X's own reminder isn't due yet). Own label to avoid
        # colliding with the real "STILL OPEN:" (=reminder) section above.
        lines.append("ALSO OPEN (not due for a reminder yet):")
        lines += [f"  [{f.band.upper()}] {s} — {f.text}" for s, f in still_open]
    text_body = "\n".join(lines)

    html_body, inline_images = alert_email_templates.render_fired(
        items, group_name=group.name, min_severity=group.min_severity,
        total_reminders=total_reminders, for_browser=for_browser, still_open=still_open)
    return subject, text_body, html_body, inline_images


def _render_resolved_email(group, resolved_items, now, *, for_browser: bool = False) -> tuple:
    """resolved_items: [(system, band, text, first_seen_at, flag_key), ...] for ONE group --
    findings that WERE notified and have now cleared (see run_alert_cycle's own filtering: a
    finding never successfully notified never reaches here). flag_key rides along purely so
    the e-mail can recover the category for its icon/label (see alert_email_templates.
    _category_from_flag_key's own docstring) -- AlertFinding has no separate category column.

    Uses alert_email_templates.render_resolved for the HTML -- the same branded shell every
    other alert e-mail this feature sends now uses (navy gradient header, white "Alert
    resolved" title matching "Alert notification"'s own styling, green banner) -- not the
    older mail_report-styled digest this used to build via _email_shell, which is what a real
    recipient flagged as visibly mismatched from the rest of the feature (2026-09-04)."""
    subject = f"[Resolved] {group.name} — {len(resolved_items)} finding(s) cleared"
    lines = [f"  {s} — {text} (was {band.upper()}, open for {_duration_str(first_seen, now)})"
            for s, band, text, first_seen, _flag_key in resolved_items]
    text_body = "RESOLVED:\n" + "\n".join(lines)
    items = [(s, band, text, _duration_str(first_seen, now), flag_key)
            for s, band, text, first_seen, flag_key in resolved_items]
    html_body, inline_images = alert_email_templates.render_resolved(
        items, group_name=group.name, min_severity=group.min_severity, for_browser=for_browser)
    return subject, text_body, html_body, inline_images


def _synthetic_flag(category: str, band: str):
    """A fabricated Flag for test/preview purposes only -- never derived from a live capture,
    so these buttons always produce the same example regardless of what Prometheus actually
    reports right now. Text says so explicitly, so nobody mistakes a test e-mail for a real
    incident or a real resolution.

    Shaped to match what THIS category's real wording actually looks like (on request,
    2026-09-04: a preview showing "97%" for Drainage monitoring -- "that is not a type of
    alert" -- a percentage is real for disk/ram/cpu, but drainage is about how long a file
    has been waiting, not a percentage of anything). See generate_report.flagged_for_system's
    own Flag() call sites for disk/ram/cpu/unreachable/service/backup/untracked's real
    wording, and alerting.folder_size_flags_by_system/undrained_folder_flags_by_system/
    backup_uncleared_folder_flags_by_system's own Flag() calls for folder/undrained_folders/
    backup_uncleared -- every branch below mirrors one of those exactly (same units, same
    presence/absence of a number) rather than inventing new wording."""
    from .models import AlertGroup

    label = dict(AlertGroup.CATEGORY_CHOICES).get(category, category)
    if category in ("disk", "ram", "cpu"):
        # "{component} · {word} {pct}%" -- generate_report.flagged_for_system's own real
        # shape (e.g. "Eagle DB · E: 92%"), component and drive/word BEFORE the percent, so
        # the preview actually demonstrates alert_email_templates._row_detail's extraction of
        # them instead of hiding behind a shape real disk/ram/cpu alerts never have (on
        # request, 2026-09-04: alerts "were not specifying the system components as well as
        # the drive which is important for this alert").
        sample = "97%" if band == "red" else "88%"
        word = {"disk": "E:", "ram": "RAM", "cpu": "CPU"}[category]
        text = f"Primary DB · {word} {sample} (synthetic test reading, fabricated for preview)"
    elif category == "unreachable":
        text = f"{label} — synthetic test event (fabricated for preview, not a real outage): component unreachable"
    elif category == "service":
        text = f"{label} — synthetic test event (fabricated for preview, not a real outage): SERVICE DOWN"
    elif category == "backup":
        text = f"{label} — synthetic test event (fabricated for preview, not a real gap): NO BACKUP found"
    elif category == "untracked":
        text = f"{label} — synthetic test event (fabricated for preview): no backup check configured on any host"
    elif category == "backup_uncleared":
        waiting, age = ("6", "4d 2h") if band == "red" else ("3", "1d 4h")
        text = (f"BACKUP on Temenos/T24 Backup & Log Folders not cleared (fabricated for preview): "
               f"{waiting} file(s) waiting, oldest {age} old")
    elif category == "folder":
        actual, expected = ("48.2", "32.0") if band == "red" else ("38.5", "32.0")
        text = f"{label} — synthetic test folder over expected size: {actual}GB (expected {expected}GB, fabricated for preview)"
    elif category == "undrained_folders":
        waiting, age = ("4", "6m") if band == "red" else ("2", "1m")
        text = f"{label} — synthetic test folder not draining (fabricated for preview): {waiting} file(s) waiting, oldest {age} old"
    else:
        sample = "97%" if band == "red" else "88%"
        text = f"{label} — synthetic test reading {sample} (fabricated for preview, not a real measurement)"
    return gr.Flag(key=f"synthetic:{category}", text=text, band=band, category=category)


def render_test_email(group, *, kind: str, system: str, category: str, band: str,
                      for_browser: bool = False) -> tuple:
    """Builds (subject, text_body, html_body, inline_images) from a FABRICATED example --
    'positive' (a fired finding) or 'resolved' (that finding clearing). Used by both the
    in-browser preview endpoint and send_test_email, so preview and send can never disagree
    about what a recipient would actually see, and so a "Preview" click always shows EXACTLY
    the compact digest design a real alert actually goes out as (2026-09-04, on request:
    reproducing a hand-built reference sample) -- both kinds go through the same
    render_fired/render_resolved a real run_alert_cycle poll uses. The separate
    single-category hero-visual alert_email_templates.render() (gauge/ring/grid/bar) is no
    longer called from anywhere as of this change -- the "Alert templates" gallery
    (config_alert_template_preview) serves its own static sample files directly, never that
    function."""
    flag = _synthetic_flag(category, band)
    inline_images: dict = {}
    if kind == "resolved":
        opened_at = timezone.now() - datetime.timedelta(hours=3, minutes=17)
        subject, text_body, html_body, inline_images = _render_resolved_email(
            group, [(system, band, flag.text, opened_at, flag.key)], timezone.now(), for_browser=for_browser)
    else:
        subject, text_body, html_body, inline_images = _render_fired_email(
            group, [(system, flag, "new", None, None)], for_browser=for_browser)
    return f"[SYNTHETIC TEST] {subject}", text_body, html_body, inline_images


def send_test_email(group, *, kind: str, system: str, category: str, band: str,
                    to: str | None = None) -> tuple[bool, str]:
    """Sends the fabricated preview e-mail (see render_test_email) to the group's current
    stakeholders -- a real send, clearly marked [SYNTHETIC TEST] throughout so nobody mistakes
    it for a real incident. Never touches AlertFinding, same reasoning as send_test_alert.

    `to`, if given, MUST already be one of group.recipient_emails() (the caller validates --
    see config_alert_group_test) -- narrows delivery to that one stakeholder instead of the
    whole group. None sends to every current stakeholder."""
    recipients = [to] if to else group.recipient_emails()
    if not recipients:
        return False, "This group has no stakeholders yet — add at least one before testing."

    subject, text_body, html_body, inline_images = render_test_email(
        group, kind=kind, system=system, category=category, band=band, for_browser=False)
    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        return False, "No SMTP host configured (send_report/config.ini [smtp])."
    mailcfg["from_name"] = "System Alerts (test)"
    try:
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, inline_images=inline_images)
    except Exception as exc:      # noqa: BLE001 -- shown to the admin, that's the point of testing
        return False, f"Send failed: {exc}"
    return True, f"Synthetic {kind} test sent to {', '.join(recipients)}."

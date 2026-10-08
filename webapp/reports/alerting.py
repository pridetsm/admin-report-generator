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

# Kill switch for IMMINENT's own persistent-reminder behaviour (2026-09-14, on request:
# "disable persistent alerts for the time being, just have these have the original alert
# count") -- False makes run_alert_cycle's own `is_imminent` computation below always False,
# so unreachable/disk-near-full findings fall back to the SAME capped daily schedule every
# other red/critical finding already uses ("the original alert count"), instead of repeating
# every group.effective_imminent_reminder_minutes forever until resolved. The underlying
# mechanism (_decide's own `imminent=`/`imminent_minutes=` branch, AlertGroup.
# effective_imminent_reminder_minutes) is untouched -- flip this back to True to restore it
# exactly as it was, no other code changes needed.
IMMINENT_REMINDERS_ENABLED = False


def _flag_suppressed(system: str, flag_key: str) -> bool:
    return (system, flag_key) in ALERT_FLAG_SUPPRESSED


# Silenced Alerts (2026-09-19, on request: "reduce the intrusiveness of alerts" for findings
# "not being actioned at all by admins... that self resolve and then start again given times
# of the day or week") -- an admin-managed alternative to ALERT_FLAG_SUPPRESSED above: same
# (system, flag_key) scope, but batched into ONE digest e-mail a day (see
# build_silenced_digest) rather than dropped from notification entirely. See AlertSilence's
# own docstring for the full design and why it expires rather than lasting forever.
#
# A silence exists because a finding is EXPECTED to clear on its own; if one particular
# incident stops doing that and just stays open, it no longer matches that pattern, so normal
# immediate alerting resumes for it rather than trusting a rule that assumed a shorter-lived
# one. Chosen well above a single poll cycle (a transient blip must never escalate) but
# comfortably below the shortest genuinely-self-resolving pattern seen so far in this estate
# (the HCI staleness findings that DID heal on their own ran 1.5-2 days; this is a fraction of
# that) -- long enough that a real flap-and-heal cycle is never mistaken for "stuck", short
# enough that something that stopped healing doesn't hide in a digest for long.
#
# Does NOT apply to _NEVER_ESCALATE_CATEGORIES (degraded/degrading/untracked, 2026-10-08) --
# see _silenced's own comment for the two real leaks this exempted: congestion/saturation
# legitimately stays open for hours as its normal shape, and "untracked" is a permanent
# structural fact rather than anything expected to clear -- neither means "still open after
# 4h" the "stopped clearing" signal this constant is meant to catch for every other category.
SILENCE_ESCALATE_AFTER = datetime.timedelta(hours=4)

# Reopen debounce (2026-10-02, on request: "discard values change so high discards will
# always register as a new issue what can we do to make alerts regarding this as minimally
# invasive as possible" -- confirmed against real data first: RBZ-DR-CORE-SW-9300 alone
# produced 86 separate IssueOccurrence rows in 24h, its discard rate crossing network.py's own
# DISCARD_RED=1000 cutover back and forth, each crossing flipping it between the red
# "iface_discards_heavy"/degraded flag and the amber "iface_discards"/degrading one -- two
# DIFFERENT flag_keys, so each crossing reads as "flag resolved" + "a different flag is new"
# to AlertFinding, which notifies immediately on every reopen). Scoped to the WHOLE
# degraded/degrading family, not just discards specifically -- interface saturation, OSPF
# adjacency, temperature and the rest of that category pair share the identical "impaired but
# reachable, naturally fluctuating around a hard threshold" shape (see AlertGroup.
# CATEGORY_CHOICES' own comment on what "degraded"/"degrading" covers), so the same flapping
# risk applies to all of them, not only the case that prompted this.
#
# Deliberately a NOTIFICATION-layer fix only, not a report_generation/network.py threshold
# change: IssueOccurrence keeps recording every flip exactly as before (dashboards, Severity
# Trends, the Silenced Alerts Digest all stay just as accurate/granular as they are today) --
# this only delays the FIRST e-mail for a REOPENED finding in this family until it has
# survived one full extra poll cycle (_decide's own call site, below, checks the current open
# IssueOccurrence's own started_at). A genuinely new problem still notifies on its very first
# sighting, same as always -- only a REOPEN (which is what a threshold-crossing flap produces)
# is held back, and only by one cycle, so a real, sustained new incident is still reported
# within two poll intervals, never silently dropped.
_REOPEN_DEBOUNCE_CATEGORIES = {"degraded", "degrading"}
_REOPEN_DEBOUNCE_MINUTES = 8   # just over one 5-minute poll cycle -- requires 2 consecutive

# Categories exempt from SILENCE_ESCALATE_AFTER entirely -- see _silenced's own comment.
# degraded/degrading: naturally fluctuating, covered above for the reopen-debounce too.
# untracked (2026-10-08, on real complaint: "stop tracking the backups untracked backups in
# managerial dashboards" -> "this is not true that metric still triggers domain alerts" --
# confirmed live: Standalone Servers' own "untracked" mute had been open 20 days straight,
# escalating past it daily) is exempt for a DIFFERENT reason: it's not a fluctuating signal at
# all, it's a permanent, structural fact -- a system either has a backup check configured or
# it doesn't, and that doesn't change hour to hour. Muting it is a deliberate, indefinite
# policy choice (the admin's own AlertSilence.expires_at is the only thing that should ever
# end it), never a "give it a few hours to self-heal" bet the way every other category's mute
# genuinely is.
_NEVER_ESCALATE_CATEGORIES = _REOPEN_DEBOUNCE_CATEGORIES | {"untracked"}

# Sibling flag_keys (2026-10-03, on request: "network discard (degrades v degrading) alerts
# still sneak through the mute"). Confirmed against real AlertSilence data: an admin (or the
# auto-mute sweep) had silenced ONLY "iface_discards"/degrading (amber) for ~25 Network Team
# devices, not the "iface_discards_heavy"/degraded (red) sibling -- so the moment one of those
# devices' discard rate crossed DISCARD_RED, it flipped to the red flag_key, which carries NO
# silence of its own, and fired a real notification. This is the same threshold-crossing shape
# _REOPEN_DEBOUNCE_CATEGORIES already exists for (network.py's own comment there: the flag_key
# PREFIX deliberately changes at the boundary so IssueOccurrence/dashboard history always sees
# a clean close+reopen) -- but a debounce only delays the first e-mail of a reopen by one poll
# cycle, it does not know about an admin's own explicit mute. An admin silencing "the discards
# on this switch" plainly means both readings of the identical physical congestion, not
# whichever one flag_key happened to be open the moment they clicked mute.
#
# Deliberately NOT extended to disk/ram/cpu's own tiered flag_keys (very_high_disk/high_disk/
# disk etc.) -- generate_report.py's own comment on those is explicit that crossing a usage
# threshold is meant to read as a genuinely NEW incident each time, not two views of one
# ongoing episode, so folding those together would undo that design rather than fix a leak.
_FLAG_SIBLINGS: Dict[str, str] = {
    "iface_discards_heavy": "iface_discards",
    "iface_discards": "iface_discards_heavy",
    "links_saturated_critical": "links_saturated",
    "links_saturated": "links_saturated_critical",
}
_BAND_RANK = {"red": 2, "amber": 1, "note": 0}   # worst-of-window label, see _FLAG_SIBLINGS use


def _active_silences() -> tuple[Dict[tuple, object], Dict[tuple, object]]:
    """Two lookups over currently-active AlertSilence rows: EXACT (system, flag_key) for a
    single silenced component, and CATEGORY (system, category) for a whole-category silence
    (flag_key left blank -- matches every current AND FUTURE component under that category for
    that system, see AlertSilence's own docstring).

    A silence on one side of a known _FLAG_SIBLINGS pair also populates the OTHER side's exact
    key (via setdefault, so a genuine silence on that other side -- processed in either order
    -- always wins over the borrowed one): see _FLAG_SIBLINGS' own comment for why."""
    from .models import AlertSilence
    now = timezone.now()
    exact: Dict[tuple, object] = {}
    by_category: Dict[tuple, object] = {}
    for s in AlertSilence.objects.filter(active=True, expires_at__gt=now):
        if s.flag_key:
            exact[(s.system, s.flag_key)] = s
            sibling = _FLAG_SIBLINGS.get(s.flag_key)
            if sibling:
                exact.setdefault((s.system, sibling), s)
        elif s.category:
            by_category[(s.system, s.category)] = s
    return exact, by_category


def _silenced(system: str, flag_key: str, category: str, exact_silences: Dict[tuple, object],
             category_silences: Dict[tuple, object],
             open_started_by_key: Dict[str, "datetime.datetime"], now) -> bool:
    """True if this flag is covered by either an exact (system, flag_key) silence or a whole-
    category (system, category) one, AND it hasn't escalated back to normal alerting (see
    SILENCE_ESCALATE_AFTER's own comment). `open_started_by_key` is a one-query-per-system
    prefetch (started_at of THIS system's own open IssueOccurrence rows, keyed by flag_key)
    built by the caller right after record_occurrences -- not a per-flag query here.

    degraded/degrading (discards, saturation, OSPF, temperature) are EXEMPT from
    SILENCE_ESCALATE_AFTER entirely (2026-10-08, on real complaint: "discard errors are muted
    by networks team yet some still sneak past[.] how is this possible" -- traced to a real
    leak, confirmed against live history: RBZ-HRE-LEVEL14-SW1's iface_discards_heavy mute was
    active, correctly keyed, and non-expired the whole time, yet a real notification fired at
    12:25:12 on 2026-10-07 -- EXACTLY 4 hours after that occurrence's own started_at of
    08:25:10. This family's own module-level comment already explains why: congestion/
    saturation/temperature are expected to fluctuate around a hard threshold and can
    legitimately stay open for hours at a stretch (this exact device did, repeatedly, across
    weeks of real history) -- that is the NORMAL shape for this family, not evidence the
    finding "stopped clearing on its own" the way SILENCE_ESCALATE_AFTER assumes for every
    other category. Same family _REOPEN_DEBOUNCE_CATEGORIES already special-cases for the
    identical reason (network.py's own comment: "naturally fluctuating around a hard
    threshold"), reused here rather than a second constant. A mute on this family now holds
    for its full admin-set duration (AlertSilence.expires_at) -- the only thing that should
    ever end it is the admin's own choice, not an internal timer silently working against them.

    "untracked" (2026-10-08, see _NEVER_ESCALATE_CATEGORIES' own comment) is exempt for a
    related but distinct reason: not a fluctuating signal, a permanent structural fact (no
    backup check configured at all) that was never going to clear on its own in the first
    place, so "still open after 4h" proves nothing here either."""
    silence = exact_silences.get((system, flag_key)) or category_silences.get((system, category))
    if silence is None:
        return False
    if category in _NEVER_ESCALATE_CATEGORIES:
        return True
    started = open_started_by_key.get(flag_key)
    return started is None or (now - started) <= SILENCE_ESCALATE_AFTER


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
    # Always 0 now (2026-10-03) -- resolved findings no longer get their own real-time e-mail;
    # see run_alert_cycle's own "No separate 'Alert resolved' e-mail any more" comment. Kept
    # as a field, not removed, so a caller/test keying on it sees an honest zero rather than
    # an AttributeError.
    resolved_emails_sent: int = 0
    emails_preview: List[dict] = field(default_factory=list)   # populated only when dry_run


@dataclass
class SilencedDigestResult:
    """What one build_silenced_digest() call did, for the management command to report and
    for tests to assert against."""
    silences_evaluated: int = 0
    groups_notified: int = 0
    emails_sent: int = 0
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


# A folder at/beyond this multiple of its own expected size is "very_high_folder" (Imminent),
# not "folder" (Critical) -- same "two alert types, not one that varies" shape as
# very_high_disk/very_high_cpu/very_high_ram (2026-10-01, on request: "same split for folder
# size too"). "folder" has no percentage-of-capacity reading the way disk/CPU/RAM do (a size-
# over-expected check is unbounded, not 0-100%), so the equivalent severe line is a RATIO of
# actual to expected rather than an absolute percent -- 2x (actual at or past DOUBLE its
# expected size) chosen as a clear, easily-understood line, not derived from an existing
# precedent the way DISK_IMMINENT_PCT borrowed flash_storage's own 95% -- there isn't one for
# this check. Adjust if this turns out too sensitive/not sensitive enough in practice.
FOLDER_IMMINENT_RATIO = 2.0


def folder_size_flags_by_system(store, systems) -> Dict[str, list]:
    """Synthetic Flag objects for every currently-over-expected watched folder, grouped by
    owning system. Shared by run_alert_cycle and send_test_alert so the "repackage
    folder_over_expected_detail as a Flag" logic (see run_alert_cycle's own comment on why it
    lives here rather than in generate_report.py) exists in exactly one place.

    band="red" (2026-09-04: since severity_meets now only ever admits red -- "no expected
    alerts for warning severity, only imminent and critical" -- an amber-only category would
    otherwise be permanently unalertable). "folder" itself still never escalates beyond
    Critical; a folder at/past FOLDER_IMMINENT_RATIO times its expected size becomes the
    separate "very_high_folder" category (Imminent) instead -- see that constant's own
    comment."""
    out: Dict[str, list] = {}
    for sysname, fname, expected, actual in gr.folder_over_expected_detail(store, systems):
        text = f"{fname} over expected size: {actual:.1f}GB (expected {expected:.1f}GB)"
        if expected > 0 and actual >= expected * FOLDER_IMMINENT_RATIO:
            out.setdefault(sysname, []).append(gr.Flag(
                key=f"very_high_folder:{fname}", text=text,
                band="red", category="very_high_folder"))
        else:
            out.setdefault(sysname, []).append(gr.Flag(
                key=f"folder:{fname}", text=text, band="red", category="folder"))
    return out


def undrained_folder_flags_by_system(cfg, covered_systems: set) -> Dict[str, list]:
    """Synthetic Flag objects for every payment-queue folder currently NOT draining --
    files waiting whose oldest has aged past its amber/red limit, per reports.folders'
    own live verdict (folders.verdict: red/amber both imply files>0 and an aged-out oldest
    file; "idle" -- files<=0 -- is the healthy drained state and never flags here).

    TWO categories now, not one varying band (2026-10-01, on request: "do not name them the
    exact same thing across severities"): amber -> "undrained_folders" ("Drainage
    monitoring", Warning), red -> "queue_stuck" (Imminent) -- see _tier()'s own category
    exception for why red reaches Imminent at all ("transaction queue drainage is always
    imminent": a payment/interface queue is expected to self-drain, so a genuinely stuck one
    is as urgent as a lost connection).

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
        text = f"{f['name']} on {f['host']} not draining: {f['files']} file(s) waiting, oldest {f['age_text']} old"
        # Imminent (red) gets its OWN category, "queue_stuck", not "undrained_folders"
        # turning red (2026-10-01, on request: "do not name them the exact same thing
        # across severities") -- "undrained_folders"/"Drainage monitoring" (amber/Warning,
        # a queue running a little behind) and "queue_stuck" (red/Imminent, a queue that has
        # genuinely stopped draining) are two different alert types now, same "two alert
        # types" shape as every other split today.
        if f["state"] == "red":
            flag = gr.Flag(key=f"queue_stuck:{f['key']}", text=text,
                           band="red", category="queue_stuck")
        else:
            flag = gr.Flag(key=f"undrained:{f['key']}", text=text,
                           band="amber", category="undrained_folders")
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
    Imminent, no grace period (2026-10-01: upgraded from Critical-only to Imminent, on
    request: "transaction queue drainage is always imminent" -- see _tier()'s own category
    exception). A backup/log folder is cleared out by a HUMAN on a schedule; going a little
    past its own due date is routine, not an emergency, so this category gets the gentlest
    possible first notice (Warning -- one of the few categories severity_meets lets through
    at amber) and only escalates once it's been neglected for MAX_BACKUP_OVERDUE_SECONDS (3
    days) past due -- escalating now means a DIFFERENT category, "backup_overdue"
    (Critical), not "backup_uncleared" turning red (2026-10-01, on request: "one issue with
    multiple alerts depending on severity" -- see that category's own comment in models.py).
    "backup_uncleared" itself never reaches Critical any more.

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
        # Escalation becomes a DIFFERENT category/flag_key, not the same one turning red
        # (2026-10-01, on request: "one issue with multiple alerts depending on severity" --
        # see "backup_overdue"'s own comment in models.py) -- the 3-day trigger itself
        # (MAX_BACKUP_OVERDUE_SECONDS) is unchanged, only how it's represented is. Changing
        # the flag_key prefix too (not just category) means the normal "vanished from this
        # poll's current flags -> resolved" machinery closes the Warning finding and opens a
        # genuinely new Critical one on its own -- a real resolved + a real new notification,
        # exactly the "two alert types" the request asked for, no special-cased transition
        # logic needed.
        escalated = overdue >= MAX_BACKUP_OVERDUE_SECONDS
        band = "red" if escalated else "amber"
        category = "backup_overdue" if escalated else "backup_uncleared"
        flag = gr.Flag(
            key=f"{category}:{f['key']}",
            text=f"{f['name']} on {f['host']} not cleared: {f['files']} file(s) waiting, oldest {f['age_text']} old",
            band=band, category=category)
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


def record_occurrences(system: str, flags: list, now, domain: str = "") -> None:
    """IssueOccurrence's only writer -- see that model's own docstring for why it exists
    separately from AlertFinding. Called once per system, every run_alert_cycle poll (~5
    minutes), for that system's ENTIRE fresh flags list -- not filtered by any AlertGroup's
    category/severity selection, since "is this eligible for notification" and "did this
    actually happen" are different questions, and this table only ever answers the second one.

    `domain` ("Systems" | "Infrastructure" | "Network") is the caller's own estate -- see
    IssueOccurrence.domain's own comment on why this is passed in, not inferred later. Written
    on every touch (create AND refresh), not just create, so a row backfilled blank by the
    one-time migration self-heals the next time this same key is next seen, no re-run needed.

    A flag_key with a still-open row gets that row refreshed in place
    (band/text/domain/category/last_seen_at) -- the same incident continuing, not a new one.
    A flag_key that HAD an open row but is no longer in this poll's fresh flags gets that row
    closed (resolved_at = now) -- the same "vanished from this poll = resolved" rule
    run_alert_cycle's own AlertFinding cleanup already uses, applied here independently since
    this table's set of open keys is its own, not derived from AlertFinding's. A flag_key with
    no open row is a brand new incident.

    `category` is refreshed, not just set at creation (2026-10-01 fix, found while moving
    network.py's interface/hardware findings from category="service" to the new "degraded"
    split -- see AlertGroup.CATEGORY_CHOICES' own comment): without this, an occurrence that
    had already been open since before a category reclassification would carry the OLD
    category forever, since nothing ever revisited it after creation -- the exact same
    staleness `domain` would have had if it hadn't been added to this same refresh check when
    IT was introduced (see 0059_backfill_issueoccurrence_domain's own docstring: "even
    pre-existing OPEN rows self-heal on their next touch"). category now self-heals the same
    way, no migration needed for currently-open rows -- the next poll fixes them."""
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
                domain=domain, started_at=now, last_seen_at=now)
        elif (row.band != f.band or row.text != f.text or row.domain != domain
              or row.category != f.category):
            IssueOccurrence.objects.filter(pk=row.pk).update(
                band=f.band, text=f.text, domain=domain, category=f.category, last_seen_at=now)
        else:
            IssueOccurrence.objects.filter(pk=row.pk).update(last_seen_at=now)


def _evaluate_for_groups(system: str, flags: list, *, groups, covered: set, now, schedules: dict,
                         exact_silences, category_silences, silenced_systems: set,
                         result: "AlertRunResult", dry_run: bool, per_group_items: dict,
                         per_group_rows: dict, per_group_still_open: dict,
                         collect_and_resolve, domain: str = "") -> None:
    """Match one system's fresh flags against every active group's own scope (systems,
    categories, severity, silencing) and queue whatever's eligible for this poll's digest --
    AlertFinding bookkeeping, per_group_items/per_group_still_open for the e-mail renderer,
    exactly ONE outcome per (group, flag) this cycle (new/renew/remind/skip/resolved), same as
    always.

    `domain` (2026-10-02, on request: "alerts should collect each other by domain... kinda
    like what is currently set up for systems alerts we have the still open") -- the SAME
    "Systems"/"Network"/"Infrastructure" value record_occurrences is called with right next to
    this (the caller already knows it; nothing new to derive), threaded through into
    per_group_items/per_group_still_open so render_fired can group a digest that spans more
    than one domain into its own labelled sections instead of one flat list -- see that
    function's own docstring.

    Extracted (2026-10-01, on request: "they are not yet sending to these teams... this is
    something we should be able to know immediately") from what used to be ONLY the business-
    "Systems" loop's own inline per-system block in run_alert_cycle -- found, while answering
    why the new Network Team/Infrastructure Team AlertGroups showed a healthy green halo but
    had sent exactly zero notifications ever, that the "kind" loop (Infrastructure/AD/
    Switches & Routers, added 2026-09-18) only ever called record_occurrences() for the
    dashboard's IssueOccurrence log -- it never touched AlertFinding, severity_meets,
    category_matches, or silencing at all, so NO AlertGroup could ever notify for a system in
    those three estates, regardless of how correctly it was configured. This function is that
    shared logic, now called from BOTH loops so the two behave identically; the Systems loop's
    own inline version was a byte-for-byte match before this refactor, verified via a dry-run
    diff against the pre-refactor output (same new/reminder/resolved counts, same preview
    text) before the kind loop below was ever wired to call it."""
    from .models import AlertFinding, IssueOccurrence

    # One query per system (not per silenced flag) -- built right after record_occurrences'
    # own call (by the caller, just before this) so it reflects an already-fresh
    # IssueOccurrence.started_at for THIS poll. Only queried when this system actually has a
    # silence to check, since most systems have none at all.
    open_started_by_key = {}
    if not dry_run and system in silenced_systems:
        open_started_by_key = {
            r.flag_key: r.started_at for r in
            IssueOccurrence.objects.filter(system=system, resolved_at__isnull=True)}

    if system not in covered:
        return   # no active group cares about this system for NOTIFICATION purposes

    for g in groups:
        if system not in (g.systems or []):
            continue
        matches = [f for f in flags
                  if severity_meets(f.band, f.category)
                  and g.category_matches(system, f.category)]
        # eligible_keys (below) comes from `matches`, NOT the suppression/silence-filtered
        # `eligible` -- a suppressed or silenced flag that's still genuinely present must not
        # fall out of eligible_keys, or the stale-resolution pass right below would mark its
        # existing AlertFinding resolved and fire a false "resolved" e-mail (the finding
        # hasn't gone away, it's just been told not to page anyone this way -- see
        # ALERT_FLAG_SUPPRESSED's/AlertSilence's own docstrings). `eligible` itself (the
        # new/reminder loop below) DOES exclude both -- that's the actual suppression.
        eligible = [f for f in matches
                   if not _flag_suppressed(system, f.key)
                   and not _silenced(system, f.key, f.category, exact_silences,
                                    category_silences, open_started_by_key, now)]
        eligible_keys = {f.key for f in matches}

        if not dry_run:
            stale = (AlertFinding.objects
                    .filter(group=g, system=system, resolved_at__isnull=True)
                    .exclude(flag_key__in=eligible_keys))
            result.resolved_count += collect_and_resolve(stale)

        for f in eligible:
            existing = None if dry_run else AlertFinding.objects.filter(
                group=g, system=system, flag_key=f.key).first()
            # IMMINENT (component unreachable, disk/CPU/RAM at/above 95%, a folder at/past 2x
            # its expected size, or a genuinely stuck payment/interface queue) findings bypass
            # the capped daily schedule entirely -- persistent reminders every group.
            # effective_imminent_reminder_minutes until resolved. "disk"/"cpu"/"ram"/"folder"
            # themselves no longer qualify (2026-10-01: each split into its own "very_high_*"
            # -- see those categories' own comments in models.py); "queue_stuck" is here
            # instead of "undrained_folders" (same date, "do not name them the exact same
            # thing across severities" -- the two severities needed two different category
            # names) -- keep this tuple in step with _tier()'s and alert_email_templates.
            # _severity()'s own identical category lists if it ever changes again.
            is_imminent = (IMMINENT_REMINDERS_ENABLED
                          and f.band == "red"
                          and f.category in ("unreachable", "very_high_disk", "very_high_cpu",
                                             "very_high_ram", "very_high_folder",
                                             "queue_stuck"))
            action, reminder_number = _decide(
                existing, f.band, now, schedules[g.pk],
                imminent=is_imminent, imminent_minutes=g.effective_imminent_reminder_minutes)
            # Reopen debounce (see _REOPEN_DEBOUNCE_CATEGORIES' own module-level comment) --
            # only a REOPEN (existing already on file, just previously resolved) in a
            # flap-prone category, and only while the reopened incident hasn't yet survived a
            # full extra poll cycle. A true first-ever sighting (existing is None) is never
            # debounced -- this is about threshold flapping on an already-known check, not
            # about delaying real new problems.
            if (action == "new" and existing is not None and existing.resolved_at is not None
                    and f.category in _REOPEN_DEBOUNCE_CATEGORIES):
                started_at = (IssueOccurrence.objects
                             .filter(system=system, flag_key=f.key, resolved_at__isnull=True)
                             .values_list("started_at", flat=True).first())
                if started_at and now - started_at < datetime.timedelta(minutes=_REOPEN_DEBOUNCE_MINUTES):
                    continue   # too soon to tell this isn't just another flap -- say nothing
                              # yet; AlertFinding stays untouched so next poll re-checks fresh
            if action == "skip":
                # existing is never None here (see _decide: existing is None always decides
                # 'new') -- a genuinely still-open finding, just not due for its own event
                # this poll.
                per_group_still_open[g.pk].append((system, f, domain))
                continue
            # 'renew' (a new calendar day's first notification for a still-open finding --
            # see _decide's own docstring) reads exactly like 'new' for the digest e-mail and
            # the new/reminder counts; only the first_seen_at bookkeeping below tells the two
            # apart.
            email_action = "new" if action in ("new", "renew") else "remind"
            # None total (only ever for an imminent 'remind') tells the renderer this
            # reminder has no "final" -- it repeats forever until resolved, so labelling it
            # "final reminder" the moment reminder_number reaches the group's own UNRELATED
            # capped-schedule length would be actively wrong.
            item_total = None if is_imminent and email_action == "remind" else len(schedules[g.pk])
            per_group_items[g.pk].append((system, f, email_action, reminder_number, item_total, domain))
            if email_action == "new":
                result.new_count += 1
            else:
                result.reminder_count += 1
            if not dry_run:
                row, created = AlertFinding.objects.get_or_create(
                    group=g, system=system, flag_key=f.key,
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
                    # Still the SAME ongoing incident -- only the notification cycle restarts
                    # for the new day (see _decide's own docstring); first_seen_at is left
                    # untouched so a resolved digest still reports how long the finding has
                    # REALLY been open, not just since today's first reminder.
                    row.first_notified_at = None
                    row.reminder_count = 0
                row.band, row.text, row.last_seen_at = f.band, f.text, now
                row.resolved_at = None
                row.save()
                per_group_rows[g.pk].append((row, email_action))


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
    # per-group loop below at all. A group with no schedule of its own (schedule_enabled=False)
    # now falls back to SystemConfig's own default window instead of passing through
    # unconditionally (2026-10-02, on request: "have a default alert window set for each and
    # every alert... subject to any specific change from the admins" -- see in_schedule's own
    # comment for the full reasoning, including why System Alert groups stay exempt).
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
    # Read once per poll, not once per flag -- see _silenced's own docstring for how this is
    # used below.
    exact_silences, category_silences = _active_silences()
    silenced_systems = {sysname for sysname, _ in exact_silences} | {sysname for sysname, _ in category_silences}

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
    # NOTE-band only, dashboard cache display ONLY -- never merged into `flags` below, so it
    # never reaches record_occurrences or _evaluate_for_groups (2026-10-07, on request:
    # "managerial dashboard still not telling us which folder did not drain" -- see
    # services.queue_waiting_folder_flags_by_system's own docstring for the full "why": the
    # dashboard's own "Undrained queues" tile counts ANY non-idle queue folder, including
    # folders.py's own healthy "green" state, but no per-system Flag existed for green state
    # at all until now, so the tile's click-to-expand detail could show a real non-zero count
    # with an empty popup. A green/healthy folder must never become a real alert-pipeline
    # finding -- that is the whole reason this is a SEPARATE dict, merged only into
    # cached_flags a few lines down, not into `flags` itself.
    from . import services as _services
    queue_waiting_flags_by_system = _services.queue_waiting_folder_flags_by_system(cfg, all_names)

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

    # System Admin's own half of the LiveEstateOverview cache (see that model's docstring) --
    # built alongside the notification loop below from the SAME flags it already computes per
    # system, so caching costs nothing extra beyond the one build_overview() call after the loop.
    live_systems_json: List[dict] = []

    # Down web links also count toward the "Services down" tile (gr.services_down sums BOTH
    # PromQL service checks and link probes -- see that function's own docstring) but
    # flagged_for_system's own Flag list never gets one for a down LINK -- web links are a
    # parallel concept, rendered straight from store.links by the report/xlsx builder, never
    # folded into the Flag system. That left the dashboard's own "which service" drill-down
    # (views._exception_detail, word-matching "service" against each system's cached flags)
    # structurally unable to ever find a down link, even though the aggregate count included
    # it (2026-10-05, confirmed live after the user reported: "we have one service down yet the
    # row on the managerial dashboard does not open to show use which service" -- that
    # particular case turned out to be a transient blip already cleared by the next poll, but
    # the underlying gap is real and would reproduce on any future down link). Built here, into
    # a SEPARATE synthetic entry added only to this cache's own "flags" list below -- NOT into
    # `flags` itself, which still feeds record_occurrences/_evaluate_for_groups just below
    # unchanged, so this stays a display-only fix and never starts notifying for link outages
    # that were never part of the real alerting pipeline before. category="service" so it's
    # found by the exact same word-match a down PromQL service already is; owner attribution
    # reuses gr._link_owner_name, the SAME function services_down_detail's own list (the
    # banner naming "which service" everywhere else) is already built from, so this can never
    # disagree with that about which system a down link belongs to.
    down_links_by_system: Dict[str, list] = {}
    for url, d in store.links.items():
        if not d.get("up", False):
            owner = gr._link_owner_name(url, systems)
            down_links_by_system.setdefault(owner, []).append(gr._link_display(url))

    for sysm in systems:
        flags = (gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
                 + undrained_flags_by_system.get(sysm.name, [])
                 + backup_uncleared_flags_by_system.get(sysm.name, []))
        cached_flags = [{"key": f.key, "text": f.text, "band": f.band, "category": f.category}
                        for f in flags]
        cached_flags += [{"key": f"service:link:{label}", "text": f"{label} DOWN",
                         "band": "red", "category": "service"}
                        for label in down_links_by_system.get(sysm.name, [])]
        # NOTE-band, display-only -- see queue_waiting_flags_by_system's own comment above for
        # why this is appended to cached_flags specifically, never to `flags` itself.
        cached_flags += [{"key": f.key, "text": f.text, "band": f.band, "category": f.category}
                        for f in queue_waiting_flags_by_system.get(sysm.name, [])]
        live_systems_json.append({
            "name": sysm.name, "hosts": len(sysm.components), "flags": cached_flags,
        })

        # Comprehensive occurrence log (see IssueOccurrence's own docstring): every system,
        # every category, regardless of whether any AlertGroup below even covers this system
        # let alone has this category ticked. Skipped in dry_run for the same reason AlertFinding
        # is untouched then -- a preview must not write real incident history.
        if not dry_run:
            record_occurrences(sysm.name, flags, now, domain="Systems")

        _evaluate_for_groups(
            sysm.name, flags, groups=groups, covered=covered, now=now, schedules=schedules,
            exact_silences=exact_silences, category_silences=category_silences,
            silenced_systems=silenced_systems, result=result, dry_run=dry_run,
            per_group_items=per_group_items, per_group_rows=per_group_rows,
            per_group_still_open=per_group_still_open, collect_and_resolve=_collect_and_resolve,
            domain="Systems")

    # LiveEstateOverview cache (see that model's own docstring) -- System Admin's half, built
    # from the SAME store/systems/cfg this cycle already captured above, so this costs one
    # extra (cheap, in-process) build_overview() call, not another Prometheus round trip.
    if not dry_run:
        from .models import LiveEstateOverview
        from . import services as _services

        LiveEstateOverview.objects.update_or_create(
            kind="system_admin",
            defaults={"captured_at": now,
                     "overview": _services.build_overview(store, systems, cfg),
                     "systems": live_systems_json})

    # Infrastructure's HCI clusters, Active Directory's domain controllers, and (2026-09-22)
    # the Switches & Routers estate, recorded into the SAME comprehensive occurrence log the
    # business-system loop above already writes to (2026-09-18, on request: "broaden alert
    # poller to cover infrastructure and network metrics and just use this as default poller
    # to feed both alerts and live dashboards") -- these estates never had a poller of their
    # own before this; the only source of truth for their state used to be whatever the LAST
    # GENERATED REPORT for that estate happened to say (see the exec dashboard's own former
    # live-capture-per-pageview workaround, which the LiveEstateOverview cache below replaced).
    # The old bare "network" entry (only=None, the whole DEVICES pool) was retired the same
    # day the core switch moved into Switches & Routers -- by then it was 100% redundant with
    # infrastructure + active_directory + switches_routers combined, not a distinct estate.
    #
    # DOES now touch `covered`/groups/AlertFinding/notifications (2026-10-01, on request:
    # "they are not yet sending to these teams... this is something we should be able to know
    # immediately") -- it never used to: an admin who created a group covering one of these
    # systems (e.g. Network Team/Infrastructure Team) found it already had real occurrence
    # history to alert on, per the ORIGINAL version of this comment, but that was ONLY ever
    # true for dashboard history. No AlertGroup could ever actually NOTIFY for a system in
    # these three estates -- this loop only called record_occurrences(), never
    # _evaluate_for_groups() (then inlined, Systems-loop-only) -- found when Network Team/
    # Infrastructure Team showed a healthy green config halo (see _alert_group_health) but had
    # sent exactly zero notifications ever despite real, matching IssueOccurrence history.
    # Fixed by calling the SAME shared _evaluate_for_groups() the Systems loop above uses, per
    # system, right after record_occurrences -- same severity_meets/category_matches/
    # silencing/AlertFinding/reminder-schedule behavior, no separate code path to drift.
    #
    # Capture + evaluation now run regardless of dry_run (same as the Systems loop's own
    # `_capture()` above, which was never gated either) so a preview can show what WOULD be
    # sent for these estates too; only the WRITES (record_occurrences, LiveEstateOverview) stay
    # gated, same convention _evaluate_for_groups() itself already uses internally. Each
    # estate's own capture is wrapped separately (not one shared try/except) so SNMP being
    # briefly unreachable never also skips Infrastructure/AD, and vice versa -- the same "one
    # estate's own hiccup must never take the others down with it" principle the exec
    # dashboard's own per-domain fallback already uses. The same capture also feeds
    # LiveEstateOverview for this estate -- one live read serving alerts, occurrence history,
    # and the dashboard cache all at once.
    from . import network as _network

    # Infrastructure and Active Directory merge into one "Infrastructure" domain on the
    # Alert Dashboard/Executive Dashboard, same 2026-09-16 merge decision both already use
    # (views._management_dashboard_context's own Infrastructure+AD combination) -- kept as
    # a map right here, not a separate module, since this loop is the only place `kind`
    # and "which domain owns it" are both already in scope together.
    _KIND_DOMAIN = {
        "infrastructure": "Infrastructure",
        "active_directory": "Infrastructure",
        "switches_routers": "Network",
    }

    for kind, capture in (
        ("infrastructure", lambda: _network.capture_snapshot(
            "alert-poller", only=_network.infra_device_keys(), infra=True)),
        ("active_directory", lambda: _network.capture_snapshot(
            "alert-poller", only=_network.ad_device_keys(), infra=True)),
        # Switches & Routers Report (2026-09-22) -- same "own LiveEstateOverview row" split
        # as infrastructure/active_directory just above, using mode= (not the infra= alias)
        # so it gets _switches_routers_overview's own correct per-device CPU/RAM/temp
        # tiles rather than _network_overview's single-scalar ones -- see capture_snapshot's
        # own docstring.
        ("switches_routers", lambda: _network.capture_snapshot(
            "alert-poller", only=_network.switches_routers_device_keys(),
            mode="switches_routers")),
    ):
        try:
            snap = capture()
        except Exception:   # noqa: BLE001 -- see this block's own comment above
            continue
        for sysvm in snap.systems:
            if not dry_run:
                record_occurrences(sysvm.name, sysvm.flags, now, domain=_KIND_DOMAIN[kind])
            _evaluate_for_groups(
                sysvm.name, sysvm.flags, groups=groups, covered=covered, now=now,
                schedules=schedules, exact_silences=exact_silences,
                category_silences=category_silences, silenced_systems=silenced_systems,
                result=result, dry_run=dry_run, per_group_items=per_group_items,
                per_group_rows=per_group_rows, per_group_still_open=per_group_still_open,
                collect_and_resolve=_collect_and_resolve, domain=_KIND_DOMAIN[kind])
        if not dry_run:
            from .models import LiveEstateOverview
            LiveEstateOverview.objects.update_or_create(
                kind=kind,
                defaults={"captured_at": now, "overview": snap.overview,
                         "systems": [{"name": s.name, "hosts": s.hosts,
                                     "flags": [{"key": f.key, "text": f.text, "band": f.band,
                                                "category": f.category} for f in s.flags]}
                                    for s in snap.systems]})

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

        # No separate "Alert resolved" e-mail any more (2026-10-03, on request: "do not send
        # emails for resolved alerts just pump this into the combined notification digest
        # instead" -- the same intrusiveness-reduction reasoning the Silenced Alerts Digest
        # was already built on, 2026-09-19: "reduce the intrusiveness of alerts"). `resolved`
        # is still collected above and AlertFinding.resolved_at is still stamped by
        # _collect_and_resolve regardless -- that bookkeeping is what
        # build_silenced_digest()'s own "Resolved Today" section reads fresh once a day, the
        # SAME self-contained "query AlertFinding directly" pattern it already uses for
        # silences, not a hand-off from this loop. `resolved` itself is now unused here beyond
        # the dry-run preview below, kept only so a preview run can still show what WOULD have
        # resolved, for parity with the fired-items preview just above.
        if resolved and dry_run:
            result.emails_preview.append({
                "group": g.name, "kind": "resolved (now folded into the daily digest)",
                "to": recipients, "subject": f"{len(resolved)} finding(s) cleared",
                "text_body": "\n".join(f"  [{band.upper()}] {s} — {text}"
                                       for s, band, text, _fsa, _fk in resolved)})
    return result


def build_silenced_digest(*, dry_run: bool = False, to: str | None = None) -> SilencedDigestResult:
    """Once a day (see run_silenced_digest.bat / folder_exporter.yml's own
    silenced_alerts_digest job, 10:30am), roll up everything that happened under an active
    AlertSilence over roughly the last 24 hours into ONE combined digest e-mail covering every
    AlertGroup at once (2026-10-02, on request: "combine all silenced alerts digests into one
    and send it to everyone in the groups concerned" -- replaces the original one-e-mail-per-
    group version, which meant a stakeholder on 3 groups got 3 separate e-mails every morning),
    in place of the individual new/reminder e-mails run_alert_cycle's own _silenced() check
    above already withholds for these (system, flag_key) pairs.

    Needs no bookkeeping of its own: IssueOccurrence (record_occurrences, run_alert_cycle's
    own writer, every ~5 minutes) already tracks every system/flag's own occurrence history
    regardless of AlertGroup coverage or silencing -- this just asks "what happened for each
    silenced pair in roughly the last day" and reports it. A group with NOTHING that happened
    in the window is left out of the combined digest's own body entirely -- a quiet day for an
    already-known-noisy check isn't itself news. Recipients are the UNION of every group-with-
    activity's own recipient_emails() -- "everyone in the groups concerned", not everyone on
    every group regardless of whether their own group had anything to report today.

    `to` (2026-10-02, "send a sample to me so i see") -- same narrowing send_test_alert's own
    `to` parameter already does: a REAL send (never a dry run even if dry_run=True is also
    passed -- a sample needs to actually land in an inbox to answer "so i see"), to just this
    one address instead of the real distribution, so a one-off preview never also reaches the
    genuine 8 stakeholders."""
    from .models import AlertFinding, AlertSilence, IssueOccurrence

    result = SilencedDigestResult()
    now = timezone.now()
    today = timezone.localtime(now).date()
    cutoff = now - datetime.timedelta(hours=24)

    silences = list(AlertSilence.objects.filter(active=True, expires_at__gt=now)
                    .select_related("group"))
    result.silences_evaluated = len(silences)

    # Resolved-today findings, folded into this SAME digest instead of their own real-time
    # e-mail (2026-10-03, on request: "do not send emails for resolved alerts just pump this
    # into the combined notification digest instead" -- run_alert_cycle no longer sends
    # render_resolved's own e-mail at all; see that function's own "No separate 'Alert
    # resolved' e-mail any more" comment). Queried fresh here, the SAME self-contained pattern
    # the silenced half already uses, not handed off from run_alert_cycle's own in-memory
    # state -- `last_notified_at__isnull=False` is the same "nobody was ever told this was
    # wrong" gate run_alert_cycle's own resolved-email code used to apply, reused via
    # alert_catalog.notification_activity()'s own identical filter for its "resolved" stat.
    resolved_findings = list(AlertFinding.objects.filter(
        resolved_at__date=today, last_notified_at__isnull=False).select_related("group"))

    if not silences and not resolved_findings:
        return result

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    mailcfg["from_name"] = "Silenced Alerts Digest"

    by_group_silences: Dict[int, list] = {}
    for s in silences:
        by_group_silences.setdefault(s.group_id, []).append(s)
    by_group_resolved: Dict[int, list] = {}
    for af in resolved_findings:
        by_group_resolved.setdefault(af.group_id, []).append(af)

    # [(group_name, recipients, silenced_entries, resolved_entries), ...] -- silenced_entries:
    # {"system","category","flag_key","count","open","is_category_wide"}, resolved_entries:
    # {"system","category","flag_key","band","duration"}, both fed straight to
    # render_silenced_digest_combined (2026-10-02: redesigned from flat (label, detail,
    # still_open) strings into structured data so the template can group/badge by check TYPE
    # -- see digest-redesign-package.zip's own GROUP_DIGEST_REDESIGN_PROMPT.md). ONE group
    # card either way -- a group with both silenced AND resolved activity today gets one card
    # with two sections, not two separate cards for the same group.
    total_resolved = 0
    group_rows: list = []
    recipients: set = set()
    for gid in set(by_group_silences) | set(by_group_resolved):
        group_silences = by_group_silences.get(gid, [])
        group_resolved = by_group_resolved.get(gid, [])
        group = (group_silences[0] if group_silences else group_resolved[0]).group
        entries = []
        # Sibling flag_keys silenced TWICE over (one AlertSilence row per side, the common
        # real-data shape) must still produce only ONE digest row, not two near-duplicates of
        # the same physical congestion -- track which exact flag_keys this group's entries
        # already cover (see _FLAG_SIBLINGS' own comment).
        covered_flag_keys: set = set()
        for s in group_silences:
            if s.flag_key:
                if s.flag_key in covered_flag_keys:
                    continue
                sibling = _FLAG_SIBLINGS.get(s.flag_key)
                flag_keys = [s.flag_key, sibling] if sibling else [s.flag_key]
                occurrences = list(IssueOccurrence.objects
                                  .filter(system=s.system, flag_key__in=flag_keys, last_seen_at__gte=cutoff)
                                  .order_by("-started_at"))
                if not occurrences:
                    continue   # silenced, but nothing actually happened in the window -- no row
                covered_flag_keys.update(flag_keys)
                # Label the merged row by whichever side reached the WORST severity in the
                # window, not just the most recent reading -- a device that spiked red then
                # settled back to amber before this ran should still show as having been red.
                worst = max(occurrences, key=lambda o: _BAND_RANK.get(o.band, 0))
                entries.append({"system": s.system, "category": worst.category, "flag_key": s.flag_key,
                               "count": len(occurrences),
                               "open": any(o.resolved_at is None for o in occurrences),
                               "is_category_wide": False})
            else:
                # Whole-category silence (AlertSilence.is_category_wide) -- roll up EVERY
                # component under this category that fired in the window into ONE entry,
                # rather than one per mount, since the admin silenced the category as a unit;
                # `count` is the number of DISTINCT COMPONENTS that fired, not raw occurrence
                # events (confirmed against real data: CRB's own disk(all) silence -- 2 fired
                # mounts in the window -- is the "×2" the redesign's own reference mockup
                # shows, not a larger per-event tally).
                occurrences = list(IssueOccurrence.objects
                                  .filter(system=s.system, category=s.category, last_seen_at__gte=cutoff)
                                  .order_by("-started_at"))
                if not occurrences:
                    continue
                by_component: Dict[str, list] = {}
                for o in occurrences:
                    by_component.setdefault(o.flag_key, []).append(o)
                entries.append({"system": s.system, "category": s.category, "flag_key": "",
                               "count": len(by_component),
                               "open": any(o.resolved_at is None for o in occurrences),
                               "is_category_wide": True})
        resolved_entries = [
            {"system": af.system, "category": alert_email_templates._category_from_flag_key(af.flag_key),
            "flag_key": af.flag_key, "band": af.band,
            "duration": _duration_str(af.first_seen_at, af.resolved_at)}
            for af in group_resolved]
        total_resolved += len(resolved_entries)
        if not entries and not resolved_entries:
            continue
        group_recipients = group.recipient_emails()
        group_rows.append((group.name, group_recipients, entries, resolved_entries))
        recipients.update(group_recipients)
        result.groups_notified += 1

    if not group_rows:
        return result

    total_checks = sum(len(entries) for _name, _recip, entries, _resolved in group_rows)
    group_names = ", ".join(name for name, _recip, _entries, _resolved in group_rows)
    subject = f"[Silenced Alerts] Daily Digest — {total_checks} silenced check(s)"
    if total_resolved:
        subject += f", {total_resolved} resolved finding(s)"
    subject += f" across {len(group_rows)} group(s)"
    text_lines = []
    for name, _recip, entries, resolved_entries in group_rows:
        text_lines.append(f"{name}:")
        for e in entries:
            scope = e["category"] + (" (all)" if e["is_category_wide"] else "")
            text_lines.append(f"  {e['system']} · {scope} ×{e['count']} — "
                              f"{'open' if e['open'] else 'clear'}")
        for r in resolved_entries:
            text_lines.append(f"  RESOLVED: {r['system']} · {r['category']} — "
                              f"was {r['band'].upper()}, open for {r['duration']}")
    text_body = "\n".join(text_lines)
    recipients = sorted(recipients)

    if to:
        recipients = [to]
        subject = f"[SAMPLE] {subject}"
    elif dry_run:
        result.emails_preview.append({"group": group_names, "to": recipients,
                                      "subject": subject, "text_body": text_body})
        return result
    if not recipients:
        return result   # no group-with-activity has any stakeholders -- nothing to send

    html_body, inline_images = alert_email_templates.render_silenced_digest_combined(
        group_rows, total_silences=result.silences_evaluated, generated_at=now)
    if mailcfg.get("host"):
        try:
            mr.send_email(mailcfg, recipients, subject, html_body, text_body,
                         inline_images=inline_images)
            result.emails_sent = 1
        except Exception:  # noqa: BLE001
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
    exact_silences, category_silences = _active_silences()
    silenced_systems = {sysname for sysname, _ in exact_silences} | {sysname for sysname, _ in category_silences}
    items = []
    for sysm in systems:
        flags = (gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
                 + undrained_flags_by_system.get(sysm.name, [])
                 + backup_uncleared_flags_by_system.get(sysm.name, []))
        open_started_by_key = {}
        if sysm.name in silenced_systems:
            from .models import IssueOccurrence
            open_started_by_key = {
                r.flag_key: r.started_at for r in
                IssueOccurrence.objects.filter(system=sysm.name, resolved_at__isnull=True)}
        eligible = [f for f in flags
                   if severity_meets(f.band, f.category)
                   and group.category_matches(sysm.name, f.category)
                   and not _flag_suppressed(sysm.name, f.key)
                   and not _silenced(sysm.name, f.key, f.category, exact_silences,
                                    category_silences, open_started_by_key, timezone.now())]
        items += [(sysm.name, f, "new", None, None, "") for f in eligible]

    subject, text_body, html_body, inline_images = _render_fired_email(group, items)
    subject = f"[TEST] {subject}"
    if items:
        preamble = "This is a manually triggered TEST alert — not a real notification cycle.\n\n"
    else:
        preamble = ("This is a manually triggered TEST alert — not a real notification cycle.\n"
                   "No current findings for this group; sent purely to confirm delivery.\n\n")
    text_body = preamble + text_body
    html_body = ('<div style="font-family:monospace;white-space:normal;overflow-wrap:anywhere;">'
                 + preamble.replace("\n", "<br>") + "</div>" + html_body)

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
    new_items = [(s, f) for s, f, a, _n, _t, _d in items if a == "new"]
    reminders = [(s, f, n, t) for s, f, a, n, t, _d in items if a == "remind"]
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
        lines += [f"  [{f.band.upper()}] {s} — {f.text}" for s, f, _d in still_open]
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
    if category in ("disk", "ram", "cpu", "high_disk", "high_ram", "high_cpu",
                    "very_high_disk", "very_high_ram", "very_high_cpu"):
        # "{component} · {word} {pct}%" -- generate_report.flagged_for_system's own real
        # shape (e.g. "Eagle DB · E: 92%"), component and drive/word BEFORE the percent, so
        # the preview actually demonstrates alert_email_templates._row_detail's extraction of
        # them instead of hiding behind a shape real disk/ram/cpu alerts never have (on
        # request, 2026-09-04: alerts "were not specifying the system components as well as
        # the drive which is important for this alert"). Sample % reflects which of the
        # three tiers this category actually is (2026-10-01 split) rather than just red/amber.
        sample = "97%" if category.startswith("very_high_") else "92%" if category.startswith("high_") else "88%"
        base = category.replace("very_high_", "").replace("high_", "")
        word = {"disk": "E:", "ram": "RAM", "cpu": "CPU"}[base]
        text = f"Primary DB · {word} {sample} (synthetic test reading, fabricated for preview)"
    elif category == "unreachable":
        text = f"{label} — synthetic test event (fabricated for preview, not a real outage): component unreachable"
    elif category == "service":
        text = f"{label} — synthetic test event (fabricated for preview, not a real outage): SERVICE DOWN"
    elif category == "degraded":
        text = (f"{label} — synthetic test event (fabricated for preview, not a real fault): "
               f"4150 discard(s) across 1 interface(s) (reachable device, impaired operation)")
    elif category == "degrading":
        text = (f"{label} — synthetic test event (fabricated for preview, not a real fault): "
               f"17 discard(s) across 1 interface(s) (reachable device, impaired operation)")
    elif category == "potentially_degrading":
        text = (f"{label} — synthetic test event (fabricated for preview, not a real fault): "
               f"6 discard(s) in the last 5m (reachable device, early signal only)")
    elif category == "temperature":
        sample = "78" if band == "red" else "66"
        text = f"Hottest sensor reading {sample}°C (synthetic test reading, fabricated for preview)"
    elif category == "backup":
        text = f"{label} — synthetic test event (fabricated for preview, not a real gap): NO BACKUP found"
    elif category == "untracked":
        text = f"{label} — synthetic test event (fabricated for preview): no backup check configured on any host"
    elif category == "untracked_metrics":
        text = (f"{label} — synthetic test event (fabricated for preview): 4 of 19 requested "
               f"metrics are not collected: PoE power draw, BGP sessions, Active connections, "
               f"Connected devices (Wi-Fi)")
    elif category == "backup_uncleared":
        text = (f"BACKUP on Temenos/T24 Backup & Log Folders not cleared (fabricated for preview): "
               f"3 file(s) waiting, oldest 1d 4h old")
    elif category == "backup_overdue":
        text = (f"BACKUP on Temenos/T24 Backup & Log Folders not cleared (fabricated for preview): "
               f"6 file(s) waiting, oldest 4d 2h old")
    elif category == "folder":
        text = f"{label} — synthetic test folder over expected size: 38.5GB (expected 32.0GB, fabricated for preview)"
    elif category == "very_high_folder":
        text = f"{label} — synthetic test folder over expected size: 68.0GB (expected 32.0GB, fabricated for preview)"
    elif category == "undrained_folders":
        text = f"{label} — synthetic test folder not draining (fabricated for preview): 2 file(s) waiting, oldest 1m old"
    elif category == "queue_stuck":
        text = f"{label} — synthetic test folder not draining (fabricated for preview): 4 file(s) waiting, oldest 6m old"
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
            group, [(system, flag, "new", None, None, "")], for_browser=for_browser)
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

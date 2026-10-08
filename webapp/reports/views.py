"""Report Builder views.

Flow:
    GET  /            -> capture a live snapshot, cache it under a token, render the form
    POST /generate    -> reload the SAME snapshot, bake the admin's answers in, build the
                         .xlsx, save an audit row, and stream it back as a download
    GET  /history     -> past submissions (audit trail)

The snapshot is cached between the two requests so the admin's answers stay married to the
exact numbers they reviewed (Prometheus could drift in the seconds between form and submit).
"""
from __future__ import annotations

import datetime
import io
import re
import time
import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.cache import cache
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.safestring import mark_safe
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

import generate_report as gr   # to show the config.ini defaults on the settings page

from pathlib import Path

from . import (alert_email_templates, alerting, backup_policy_admin, connect, crypto,
               folder_exporter_admin, folder_size_admin, folders, grafana_admin, network,
               network_sod, promconfig, prometheus_admin, scripts, snmp_admin, system_alerts,
               usage_threshold_admin)
from . import keycloak as keycloak_mod
from .directory import search_directory
from .forms import (GrafanaConfigForm, PrometheusConfigForm, ProfileForm, SystemConfigForm,
                    UserAccountForm)
from .models import (AlertGroup, AlertSilence, AutomatedReportGroup, AutomatedReportInstance,
                     BackupPolicyRevision, DrainageThresholdConfig, EventGroup, FreshnessCheck,
                     GeneratedScript, GrafanaConfigRevision, PrometheusConfigRevision,
                     PrometheusRuleFileRevision, ReportSubmission, RoleRequest, RoleScope,
                     SnmpConfigRevision, SystemConfig, UserProfile)
from .roles import (ALL_ROLES, ALL_ROLES_DESCRIPTION, ALL_ROLES_ICON, ALL_ROLES_LABEL,
                    ROLE_DESCRIPTIONS, ROLE_HOME, ROLE_NAMES, ROLE_PAGES,
                    SESSION_KEY as ROLE_SESSION_KEY, SYSTEM_ADMIN_ROLE, roles_without_screens,
                    active_role, can_view_alert_dashboard, held_roles, is_infra_admin,
                    is_management, is_network_admin,
                    is_role_admin, effective_roles, is_security_admin, reports_for,
                    role_icon, role_screens,
                    is_superuser, is_system_admin,
                    can_edit_alert_group, can_delete_alert_group, can_reach_my_alert_groups,
                    SELECTABLE_ROLE_NAMES)
from .automated_reports import REPORT_TYPES, generate_automated_report, report_to_dict
from .scheduled_xlsx_reports import XLSX_REPORT_TYPES
from .automated_reports_mail import send_automated_report
from .services import (
    OsInventoryUnavailable,
    build_os_inventory,
    default_os_inventory_filename,
    BackupHistoryUnavailable,
    build_backup_history_report,
    default_backup_history_filename,
    earliest_backup_history_date,
    mark_xlsx_download,
    EmailNotConfigured,
    PrometheusUnavailable,
    build_report,
    capture_snapshot,
    default_recipients,
    default_report_filename,
    email_report,
    list_systems,
    recipient_options,
)

_CACHE_PREFIX = "snapshot:"

# A system counts as "recently reported" (heads-up badge on the selection dialog) if it
# appeared in any report generated within this window. Advisory only — never blocks.
_RECENT_REPORT_HOURS = 3


def _cache_key(token: str) -> str:
    return f"{_CACHE_PREFIX}{token}"


def _recently_reported(hours: int = _RECENT_REPORT_HOURS) -> dict:
    """Which systems were included in a report within the last `hours` — a non-blocking
    heads-up so an admin can avoid unknowingly re-reporting the same system. Returns
    {system_name: {"at": datetime, "by": username}} for the MOST RECENT such report.

    Submissions are ordered newest-first (Meta.ordering), so the first time a system name is
    seen while iterating is its latest appearance.
    """
    since = timezone.now() - datetime.timedelta(hours=hours)
    recent: dict = {}
    for sub in (ReportSubmission.objects
                .filter(created_at__gte=since).select_related("generated_by")):
        names = [s.get("name") for s in (sub.report_content or {}).get("systems", []) if s.get("name")]
        if not names:                       # legacy rows: fall back to annotation keys
            names = list((sub.annotations or {}).keys())
        who = sub.generated_by.get_username() if sub.generated_by else (sub.author or "")
        for name in names:
            recent.setdefault(name, {"at": sub.created_at, "by": who})
    return recent


#: How each platform is named to a human. The picker's glyph is decorative, so this supplies
#: the accessible name and the tooltip — a screen reader announcing "R, RTGS, 4 hosts" learned
#: nothing about the estate, and a penguin alone doesn't say "Linux" to everyone.
PLATFORM_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "hybrid": "Mixed Windows and Linux",
    "": "Platform not identified",
}


def _mono_hue(name: str) -> int:
    """A stable, well-spread hue (0-359) for a system's monogram tile, keyed by its FIRST LETTER
    so the same initial always gets the same colour. The golden-angle stride keeps neighbouring
    letters visually distinct; the template pins saturation/lightness so every hue reads as one
    cohesive palette (varied colour, same family)."""
    ch = (name or "?").strip()[:1].upper()
    idx = (ord(ch) - 65) if "A" <= ch <= "Z" else (ord(ch) if ch else 0)
    return int((idx * 137.508) % 360)


def _profile_author(user) -> str:
    """The report's "Signed by / By" name, self-populated from the user's profile.

    We never invent report fields — this only fills an EXISTING field (the master author
    line) so the person who generated the report and stands behind the comments is
    attributed automatically, without the admin having to type it.
    """
    name = (user.get_full_name() or "").strip() or user.get_username()
    prof = getattr(user, "profile", None)
    title = (getattr(prof, "job_title", "") or "").strip() if prof else ""
    return f"{name}, {title}" if title else name


@never_cache
@login_required
def role_empty(request):
    """The landing screen for a role that exists but owns nothing yet.

    Shared by every such role rather than written once per role: they differ only in their
    name, and a copy per role would drift the moment one of them gained a screen.

    The way out depends on whether there IS one. Someone who holds other roles goes back to
    the picker; someone who holds only this one would be bounced straight back here by that
    same picker (it auto-applies a single role), so they are offered sign-out instead of a
    button that loops.
    """
    roles = held_roles(request.user)
    empty = [r for r in roles if r in roles_without_screens()]
    if not empty:
        return redirect("report_form")
    # Name the role they are actually acting as, falling back to the first empty one they
    # hold — arriving here by URL without a selection should still say something true.
    current = active_role(request)
    role = current if current in empty else empty[0]
    return render(request, "reports/role_empty.html", {
        "role": role,
        "description": ROLE_DESCRIPTIONS.get(role, ""),
        "can_go_back": len(roles) > 1,
    })


# Domains with no report/data source at all -- shown honestly as such (on request, matching
# design_prompt.md's own explicit instruction), not silently omitted or fabricated a "clean"
# reading from data that doesn't exist. Module-level (2026-10-07, on request, incident
# calendar package: "Derive it from the same source Domain Health uses; do not hard-code if
# that source exists") so build_incident_calendar_context can reuse the EXACT same list
# _management_dashboard_context's own no_data_domains is built from, rather than a second,
# driftable copy of "Security" typed out twice.
NO_DATA_DOMAIN_NAMES = ["Security"]


def _live_report_sections() -> list:
    """The SAME shape report_sections has always had ({"kind", "label", "generated_at",
    "author", "overview", "systems"}), now read from LiveEstateOverview -- the alert poller's
    own cache (2026-09-18, on request: "broaden alert poller to cover infrastructure and
    network metrics and just use this as default poller to feed both alerts and live
    dashboards"). This is the SECOND half of that request: the poller side
    (reports.alerting.run_alert_cycle) already writes a fresh, fully-computed overview/systems
    row per domain on every ~5-minute poll (see LiveEstateOverview's own docstring); this is
    just a plain DB read of what it last wrote, replacing the live-capture-per-pageview
    approach an earlier pass of this same request used as an interim fix (a real Prometheus/
    SNMP round trip on every single dashboard view, ~6s combined even parallelized -- now a
    handful of indexed reads).

    "Real-time" now means "as of the last poll" (≤5 minutes stale) rather than instantaneous,
    the tradeoff inherent in reading a poller's cache instead of capturing live -- the same
    tradeoff IssueOccurrence-based alerting has always made for the estates it already covered.

    Falls back to the last SAVED ReportSubmission for any ONE domain with no cache row yet
    (e.g. immediately after this deploy, before the poller's first run since) -- a dashboard
    that goes blank the moment one estate hasn't been polled yet would be a worse regression
    than the staleness this replaces.
    """
    from .models import LiveEstateOverview

    def _fallback(kind):
        sub = (ReportSubmission.objects.filter(report_content__kind=kind)
              .order_by("-created_at").first())
        if not sub:
            return None
        return {"generated_at": sub.created_at, "author": sub.author,
                "overview": sub.report_content.get("overview", {}),
                "systems": sub.report_content.get("systems", [])}

    def _from_cache(row):
        return {"generated_at": row.captured_at, "author": "Live",
                "overview": row.overview, "systems": row.systems}

    specs = [
        ("system_admin", "System Admin Report"),
        ("infrastructure", "Cluster Health Report"),
        ("active_directory", "Active Directory Report"),
        # "Network" (2026-09-24, on request: "wire in this network report cluster to the
        # management dashboards as the network domain") -- reads the SAME combined,
        # whole-estate "switches_routers" LiveEstateOverview row the alert poller has always
        # written (see network.switches_routers_device_keys' own comment on why that combined
        # view stays separate from the four report-picker screens split out of it); this
        # dashboard section was never about which report screen an admin opens, only about
        # having one live reading for the whole network estate, so nothing else here needed
        # to change once the picker itself split into four.
        ("switches_routers", "Network"),
    ]
    cached = {row.kind: row for row in LiveEstateOverview.objects.filter(
        kind__in=[k for k, _ in specs])}

    sections = []
    for kind, label in specs:
        row = cached.get(kind)
        data = _from_cache(row) if row else _fallback(kind)
        if data:
            sections.append({"kind": kind, "label": label, **data})
    return sections


def _incident_device_label(occurrence) -> str:
    """"RTGS — Database" from an IssueOccurrence's own (system, flag_key) -- flag_key is
    "backup:{component}" (generate_report.Flag.key's own convention for this category), and
    the system name alone is ambiguous once two different business systems both have a
    component named e.g. "Database" -- the spec's own example devices ("T24-APP01") assumed
    per-host identifiers this estate's real backup check doesn't have at component
    granularity; "System — Component" is the same disambiguating shape every other flagged-
    item list in this app already uses (see submission_detail.html's own "CRB — DB" rows)."""
    component = occurrence.flag_key.split(":", 1)[1] if ":" in occurrence.flag_key else occurrence.flag_key
    return f"{occurrence.system} — {component}"


def _admin_comment_for_incident_day(system: str, category: str, flag_key: str,
                                    day: "datetime.date") -> tuple:
    """The administrator's own real comment explaining why an incident happened, found the
    SAME way alert_catalog._walk_comment_history already does for the Alert Dashboard's own
    comment drill-down -- reused, not reinvented, so the two can never disagree about what
    counts as a genuinely relevant comment (2026-10-08, on request: "we need the
    administrator's comments on why the incident happened in the incident calendar[.] check
    issues that happened on the day and find one that included that system then check if
    there is a comment").

    Scoped to the exact day the incident started, rather than walking all history the way the
    Alert Dashboard's own version does -- the calendar already knows precisely which day to
    look at, so there's no need for a running multi-comment search. Checks every REAL report
    submitted that day (earliest first), for a system-level comment that
    models.comment_relevant_flag_keys can confidently attribute to this exact finding or one
    of its severity-tier siblings (models.sibling_flag_keys) -- same precision-over-recall
    rule that already prevents a comment about one mount/component being wrongly attributed to
    another. Returns (comment_text, author) or (None, None) when no report that day mentioned
    this system with a comment that's actually about this finding."""
    from .models import ReportSubmission, comment_relevant_flag_keys, sibling_flag_keys

    flag_keys = sibling_flag_keys(category, flag_key)
    for sub in (ReportSubmission.objects
               .filter(created_at__date=day)
               .only("created_at", "author", "generated_by", "report_content")
               .order_by("created_at")):
        for sysd in (sub.report_content or {}).get("systems", []):
            if sysd.get("name") != system:
                continue
            relevant = comment_relevant_flag_keys(sysd)
            matched = next((k for k in relevant if k in flag_keys), None)
            if matched:
                author = sub.author or (sub.generated_by.get_username() if sub.generated_by_id else "")
                return relevant[matched], author
    return None, None


def build_incident_calendar_context(today: datetime.date, include_security: bool = True) -> dict:
    """Incident Calendar panel data (2026-10-07, incident-calendar.zip package). Deliberately
    reuses IssueOccurrence -- the existing, real, already-unconditionally-written (system,
    flag_key) occurrence ledger (reports.alerting.record_occurrences, every ~5 minutes, for
    every category including "backup") -- as the incident source, rather than a new model: it
    already has everything the spec's own suggested Incident model would need (system, domain,
    category, started_at, resolved_at), already reliably populated, with no new lifecycle-
    writing code to keep in sync. "Create (or extend, if a suitable one exists)" -- the spec's
    own wording -- confirmed live, 2026-10-07: a suitable one already exists.

    One incident entry per (domain, day) -- every IssueOccurrence row whose RED/"bad" band
    started on that calendar day is merged into one entry, its affected components collected
    into `devices` (section 3.2 point 1: "one incident per domain per day per type, merging
    all affected devices"). `resolved` is True only once EVERY merged occurrence has its own
    resolved_at set; if any one is still open the whole day's entry reads unresolved, matching
    the three-colour rule the template's own JS applies (only-unresolved / mixed / only-
    resolved). `note` is an honest, non-fabricated status line -- IssueOccurrence carries no
    human-authored resolution comment at all (unlike the spec's own hypothetical Incident
    model, which assumed one pulled from admin report comments); inventing one would misattribute
    real commentary no one wrote.

    "Missing backups" is the only tracked type today, and real data confirms it is ALWAYS
    domain="Systems" (reports.alerting.record_occurrences' own Systems-loop call hardcodes
    this) -- Network/Infrastructure/Security rows will always read clear for this type until a
    second type exists; this is real estate shape, not a gap in the query.

    include_security (2026-10-07, on request: "remove the domain for which we have nothing
    monitored i.e security domain" for the landing-page variant specifically) drops "Security"
    from `domains` and from each month's own `nodata` list entirely -- the caller just never
    asked for that column, not a domain that exists but renders empty. Defaults True so every
    OTHER caller (management_dashboard_pretty_analytical, the reference copy this request was
    split off from) is unaffected.
    """
    import calendar as _calendar

    from .models import IssueOccurrence

    def month_key(d: datetime.date) -> str:
        return f"{d.year:04d}-{d.month:02d}"

    cur_key = month_key(today)
    prev_key = month_key(today.replace(day=1) - datetime.timedelta(days=1))
    domains = ["Systems", "Network", "Infrastructure"] + (["Security"] if include_security else [])
    types = ["Missing backups"]

    months = {}
    for key, is_current in ((prev_key, False), (cur_key, True)):
        year, mon = (int(x) for x in key.split("-"))
        days_in_month = _calendar.monthrange(year, mon)[1]
        month_start = datetime.date(year, mon, 1)
        month_end = datetime.date(year, mon, days_in_month)

        occurrences = (IssueOccurrence.objects
                      .filter(category="backup", band__in=("red", "bad"),
                             started_at__date__gte=month_start, started_at__date__lte=month_end)
                      .order_by("started_at"))

        grouped = {}
        for occ in occurrences:
            k = (occ.domain or "Systems", occ.started_at.date().day)
            grouped.setdefault(k, []).append(occ)

        incidents = []
        for (domain, day), occs in sorted(grouped.items()):
            resolved = all(o.resolved_at is not None for o in occs)
            devices = sorted({_incident_device_label(o) for o in occs})
            desc = (f"No recent backup found for {devices[0]}." if len(devices) == 1 else
                   f"No recent backup found for {len(devices)} component(s).")
            # The real administrator's own comment, when one exists, in place of the honest
            # but generic fallback (2026-10-08, see _admin_comment_for_incident_day's own
            # docstring for the request and the reused Alert-Dashboard-drill-down mechanism).
            # Checked per UNDERLYING occurrence, not once per merged incident -- a multi-device
            # incident can have a real comment for one device and none for another, and each
            # must be attributed to the right one rather than a single blended guess.
            real_comments = []
            seen_occ = set()
            for o in occs:
                if o.pk in seen_occ:
                    continue
                seen_occ.add(o.pk)
                comment, author = _admin_comment_for_incident_day(
                    o.system, o.category, o.flag_key, o.started_at.date())
                if comment:
                    device = _incident_device_label(o)
                    prefix = f"{device} — " if len(devices) > 1 else ""
                    real_comments.append(f"{prefix}{comment}" + (f" ({author})" if author else ""))
            if real_comments:
                note = " | ".join(real_comments)
            else:
                note = ("Backup check found a fresh backup again — cleared automatically."
                        if resolved else "Awaiting resolution.")
            incidents.append({"domain": domain, "day": day, "type": "Missing backups",
                             "desc": desc, "devices": devices, "resolved": resolved, "note": note})

        months[key] = {"today": today.day if is_current else days_in_month,
                      "nodata": [d for d in NO_DATA_DOMAIN_NAMES if include_security or d != "Security"],
                      "incidents": incidents}

    # Banner colour, averaged across EVERY day this panel holds (both tabs combined), not
    # just whichever month tab is open (2026-10-07, on request: "average out the banner color
    # in a way that is significant [over] all monthly data thus far... it needs to have a
    # wholistic look"). FIRST version of this scored resolved/total incidents (17 of 18
    # resolved -> 94% green) and was rightly rejected on request: "he have recorded an
    # incident every single day thus far exept for one[,] yes some are resolved but
    # still...how does this tranlate to a green" -- resolved/total measures whether a backup
    # miss eventually got fixed, not whether the estate was actually quiet; a failure that
    # recurs daily and gets cleared same-day every time is a chronic problem, not health, and
    # scoring it by resolution rate alone painted it green. The real signal for "how healthy
    # has this been" is day COVERAGE: of every calendar day elapsed in this panel's own
    # two-month window, what fraction had zero incidents anywhere (confirmed live, 2026-10-07:
    # only 19 of 37 elapsed days were actually clear). A currently-open incident additionally
    # hard-caps the score at 40% green -- "still broken right now" can never read as mostly
    # green no matter how clean the history is.
    window_start = (today.replace(day=1) - datetime.timedelta(days=1)).replace(day=1)
    window_days = (today - window_start).days + 1
    incident_days = set()
    for key, m in months.items():
        year, mon = (int(x) for x in key.split("-"))
        for inc in m["incidents"]:
            incident_days.add(datetime.date(year, mon, inc["day"]))
    clear_days = window_days - len(incident_days)
    clear_pct = round(100 * clear_days / window_days) if window_days else 100

    all_incidents = [inc for m in months.values() for inc in m["incidents"]]
    total_n = len(all_incidents)
    resolved_n = sum(1 for i in all_incidents if i["resolved"])
    open_n = total_n - resolved_n
    green_pct = min(clear_pct, 40) if open_n else clear_pct

    return {"domains": domains, "types": types, "months": months,
            "health": {"green_pct": green_pct, "clear_pct": clear_pct,
                      "window_days": window_days, "clear_days": clear_days,
                      "incident_days": len(incident_days),
                      "total": total_n, "resolved": resolved_n, "open": open_n}}


def _management_dashboard_context(request, exclude_labels: frozenset = frozenset(),
                                  include_security: bool = True):
    """Shared context builder behind both Executive Dashboard pages -- Full and Focused
    (2026-09-16, on request: "save current dashboard as is well move it to a page... called
    Executive - Full... add another such page and make it the landing page... called
    Executive - Focused"). Every number either page shows comes from here; the two templates
    then just choose which sections to lay out and how wide (see management_dashboard_full.html
    / management_dashboard_focused.html), rather than this function knowing about either page's
    own layout.

    Pulls each estate's own "At a glance / Needs immediate attention / Needs attention" tiles
    VERBATIM from the alert poller's own LiveEstateOverview cache (2026-09-18, on request:
    "shouldn't it be fed by the pollers not the reports[,] because this is set to be a realtime
    system", then "broaden alert poller... use this as default poller to feed both alerts and
    live dashboards" -- see _live_report_sections' own docstring) -- the exact same overview
    dict form.html's own review screen renders (snapshot.overview.glance/immediate/watch),
    rather than deriving any new metric of its own. Each section is labelled with which estate
    it came from and when it was last polled (2026-09-12, on request, after an earlier version
    invented its own "estate health"/icon tiles instead: "pull all tiles as is from every
    report we generate so far... clearly labelled where they came from" -- "generated" now
    means "as of the poller's last run", not "whenever someone last submitted a report", but
    the same verbatim-tiles promise holds). Falls back to the last SAVED ReportSubmission, per
    estate, only if that estate has no poller cache row yet -- see _live_report_sections' own
    docstring.

    Attention Items (oldest unresolved, what admins are saying) is the one section that was
    NEVER pulled from a report even before this -- it was asked for directly, sourced from
    live IssueOccurrence/AutomatedFindingAction rows, and labelled as live activity rather
    than dressed up as a report section it is not. (The Alert Activity fired/resolved/still-
    firing-today tiles that used to sit alongside SWIFT/COB here were removed 2026-09-18, on
    request: "remove the alert table from both exec dashboards" -- SWIFT and COB's own charts
    took their place.)

    Returns None when the viewer isn't Management -- callers redirect on that themselves,
    same as the single view function did before this was split into Full/Focused.

    `exclude_labels` (2026-10-03, on request: "remove heavy discards unencripted links and
    some discards from the focused managerial dashboard" -- management_dashboard_focused's own
    caller passes its own trim set; Full/Analytical pass nothing, so their own callers are
    completely unaffected). Applied at the SAME three places a tile's label can surface here --
    _domain_pill (so an excluded tile can never leave behind an unexplained warn/bad pill with
    nothing visible underneath it), _domain_bars, and the exceptions loop below -- not a late
    filter on the finished lists, which would have left the Domain Health card's own severity
    pill still reacting to a tile the page no longer shows a reason for. Does NOT touch the
    underlying report's own glance/immediate/watch tiles themselves (System Admin Report,
    Network Report, etc. still show every tile as always) or report_sections -- this only
    changes what THIS summary view, specifically, chooses to surface.
    """
    if not is_management(request.user):
        return None

    import re

    from . import report_charts
    from .models import AutomatedFindingAction, IssueOccurrence

    report_sections = _live_report_sections()

    # ---- Exception-based domain view (2026-09-14, on request: "go into the executive
    # dashboard zip file and execute this" -- rbz_executive_dashboard.zip's own
    # design_prompt.md/exec_dashboard.html). Every number below still comes verbatim from
    # each report's own overview.glance/immediate/watch tiles (the same "pull tiles as is,
    # clearly labelled where they came from" rule the original version of this page was
    # built under, 2026-09-12) -- this only changes how those SAME tiles are grouped and
    # drawn (domain cards + bars instead of a flat KPI wall), it never invents a new metric.
    def _ratio(value):
        """'N | Total' -> (n, total, pct), else None -- never fabricate a ratio for a tile
        that isn't genuinely one (on request, matching design_prompt.md's own rule)."""
        m = re.match(r"^\s*(\d+)\s*\|\s*(\d+)\s*$", str(value))
        if not m:
            return None
        n, total = int(m.group(1)), int(m.group(2))
        return (n, total, round(n / total * 100)) if total > 0 else None

    def _domain_pill(sec):
        """Takes the whole report section now, not just its overview (2026-10-08, on request:
        "it has already expired from the needs attention now banner why is it still active in
        individual domain banners") -- needs `sec["systems"]` to apply the SAME 2-hour
        freshness override _domain_bars already does below, so a card's own pill can never
        again claim "bad" off a stale Missing-backups reading with no bad bar left to explain
        it (confirmed live: Full's own Systems card read pill="bad" with ZERO bad bars
        underneath, once the bars themselves were fixed -- the pill had its own, separate,
        still-unfixed copy of the same raw-state bug)."""
        overview = sec["overview"]
        immediate = [i for i in overview.get("immediate", []) if i["label"] not in exclude_labels]
        watch = [i for i in overview.get("watch", []) if i["label"] not in exclude_labels]
        states = [_fresh_backup_miss_override(sec, i)[1] for i in immediate + watch]
        if "bad" in states:
            return "bad"
        if "warn" in states:
            return "warn"
        return "ok"

    # Click an exception to see its exact source -- which system, which component (2026-09-16,
    # on request: "clicking it should reveal the exact source of that error which system,
    # system component is giving that error"). The exception rows above are DOMAIN-level
    # aggregates ("Missing backups: 1 | 12"); the actual per-system detail already lives in
    # report_content["systems"][*]["flags"] (every report kind stores this the same way -- see
    # e.g. generate_active_directory_report.py's own report_content dict), just one level down
    # from what the aggregate tiles read. There's no shared key to join the two on precisely
    # (the aggregate's own "label" is free text, a flag's "category" is a coarse bucket several
    # unrelated labels can share -- Network's own links_failed/iface_discards_heavy are BOTH
    # category "service"), so this matches on significant words the label and a flag's own
    # key/category/text have in common. A best-effort hint, not a guaranteed join -- a label
    # with no real per-system counterpart (Expired certs, Undrained queues -- rollups that
    # were never recorded as a per-system flag) simply shows no detail, rather than a wrong one.
    # A length>=4 floor originally dropped "cpu"/"ram" outright (2026-09-16, on request: "High
    # CPU and High RAM tiles do not open these boxes" -- both boiled down to just the word
    # "high", too generic to match anything, since "cpu"/"ram" are only 3 letters). A stopword
    # list instead of a length floor keeps short-but-specific words like these.
    #
    # Moved up ahead of _domain_bars (2026-10-06, on request: "make the domain tiles in
    # managerial dashboard make their bar graphs clickable just li[k]e the tiles in needs
    # attention now so we see the actual error") -- _domain_bars now calls this SAME join for
    # every bar it builds, not just the flat exceptions table further down, so a Domain
    # Health mini-bar opens the identical per-system detail a Needs Attention Now row already
    # does. Had to move: a nested function can only reference an enclosing-scope name that's
    # already bound by the time it's actually CALLED, and _domain_bars is called by the
    # domain_cards loop immediately below, well before this used to be defined.
    _DETAIL_STOPWORDS = {"high", "down", "total", "with", "that", "this"}

    # A flag's own text is free-form prose, sometimes with a comma-separated tail bolted on
    # (a device list, a metric list) that reads as a wall of jargon once several wrap across a
    # narrow box (2026-09-16, on request: "is there too much text data, if yes can data be
    # tabulated"). This splits "headline — a, b, c" or "headline: a, b, c" into a plain
    # headline plus a real list of items the template renders as small wrapped tags instead of
    # one long run-on sentence -- text with no such tail (most flags: "RAM 95%") is left alone.
    def _split_detail_text(text):
        for sep in (" — ", ": "):
            if sep in text:
                head, _, tail = text.partition(sep)
                if "," in tail:
                    items = [i.strip() for i in tail.split(",") if i.strip()]
                    return head.strip(), items
        return text, None

    def _exception_detail(sec, label):
        words = {w[:-1] if w.endswith("s") and len(w) > 4 else w
                 for w in re.findall(r"[a-z]{3,}", label.lower())
                 if w not in _DETAIL_STOPWORDS}
        if not words:
            return []
        # "Missing backups" popup stays consistent with its own tile's 2-hour freshness rule
        # (2026-10-07, see _fresh_backup_miss_override's own comment) -- otherwise the tile
        # could read "0" while clicking it still listed stale, >2h-old entries.
        backup_cutoff = None
        if label == "Missing backups":
            from .models import IssueOccurrence

            backup_cutoff = timezone.now() - datetime.timedelta(hours=2)
            backup_started = {
                (o.system, o.flag_key): o.started_at
                for o in IssueOccurrence.objects.filter(category="backup", resolved_at__isnull=True)
            }
        found = []
        for s in sec["systems"]:
            for f in s.get("flags", []):
                # category="untracked" ("no backup check configured at all") is explicitly
                # excluded from every detail popup here, never just the ones it's actually
                # about (2026-10-08, on request: "the untracked backup metric is not a
                # relevant enough kpi to be showing to management" -- found while investigating
                # a real cross-contamination bug: GTMS's own untracked finding's text contains
                # the word "backup", so it was word-matching into "Missing backups"' own
                # popup too, even while that row itself read "ok" -- clicking a tile that
                # claimed to be healthy showed GTMS as if something there was wrong. No label
                # in this app's own managerial displays is actually ABOUT "untracked" (it has
                # no row of its own in _MATRIX_ROW_LABELS/_STANDING_LABELS), so excluding it
                # here removes a no-legitimate-home bleed risk everywhere, not just this one
                # instance of it.
                if f.get("category") == "untracked":
                    continue
                # "Backup tracking" (whether a system has a backup check CONFIGURED at all)
                # and "Missing backups" (category="backup" -- a configured check that found no
                # fresh file) are two different questions that happen to share the word
                # "backup" -- found live, 2026-10-08, on request "why do we get a missing
                # backup from this tile": RTGS's real category="backup" NO BACKUP finding was
                # word-matching into "Backup tracking"'s own popup too. Scoped the same
                # explicit way "Missing backups" already is below, rather than trusting the
                # word-match to keep two lexically-overlapping categories apart. In practice
                # this now leaves "Backup tracking"'s own popup always empty (its one real
                # subject, category="untracked", is excluded everywhere just above) -- correct
                # and intentional, not a bug: the tile itself stays visible only on Executive -
                # Full, with nothing further to drill into, consistent with "not a relevant
                # enough kpi to be showing to management" applying to the whole category.
                if label == "Backup tracking" and f.get("category") != "untracked":
                    continue
                if backup_cutoff is not None and f.get("category") == "backup":
                    started = backup_started.get((s["name"], f.get("key")))
                    if started is None or started < backup_cutoff:
                        continue
                # "note" (2026-10-07, on request: "managerial dashboard still not telling us
                # which folder did not drain") -- a genuinely healthy finding (e.g. a queue
                # folder with fresh files waiting, services.queue_waiting_folder_flags_by_
                # system's own output) that a standing tile's own count still includes. Shown
                # with the popup's real "ok" (green) severity, never "warn" -- it would be
                # dishonest to paint a healthy reading amber just because it shares a category
                # with real problems.
                if f.get("band") not in ("red", "amber", "bad", "warn", "note"):
                    continue
                haystack = f"{f.get('key', '')} {f.get('category', '')} {f.get('text', '')}".lower()
                if any(w in haystack for w in words):
                    headline, items = _split_detail_text(f.get("text", ""))
                    band = ("bad" if f.get("band") in ("red", "bad") else
                           "ok" if f.get("band") == "note" else "warn")
                    found.append({"system": s["name"], "headline": headline, "items": items,
                                  "band": band})
        return found

    def _fresh_backup_miss_override(sec, item):
        """Needs Attention Now shows a missing-backup finding for its first 2 hours only
        (2026-10-07, incident calendar package, on request: "keep both occurances, just stop
        firing in needs attention now after 2 hours") -- past that it's a known, tracked,
        recurring issue better reviewed in the Incident Calendar (build_incident_calendar_
        context) than repeated in the urgent panel every poll. Recomputes the REAL value/state
        from the real per-system flags (category="backup") cross-referenced against
        IssueOccurrence's own real started_at -- NEVER touches services.build_overview's own
        nmiss (the System Admin Report's own form/xlsx tile keeps showing the TRUE, full,
        un-time-filtered count; see that function's own "Totals... must stay based on the
        fixed register" comment) -- this only overrides what THIS panel displays. Returns
        (value, state) for "Missing backups", the item's own (value, state) unchanged for
        every other label.

        Moved ahead of _domain_bars (2026-10-08, on request: "it has already expired from the
        needs attention now banner why is it still active in individual domain banners") --
        _domain_bars now calls this SAME override too, so Domain Health's own "Missing
        backups" bar can never again disagree with its own popup: before this, the bar's
        colour read the tile's raw, un-gated state directly while _exception_detail (building
        that same bar's own alerts list) already silently applied this exact 2-hour cutoff --
        a stale (>2h) finding painted the bar red with an EMPTY popup underneath it, no
        visible reason at all ("its no longer showing the actual reason which is why I had to
        ask you"). Had to move for the same reason _domain_bars itself once did: a nested
        function can only reference an enclosing-scope name that's already bound by the time
        it's actually CALLED, and _domain_bars is invoked (building domain_cards) well before
        this used to be defined."""
        if item["label"] != "Missing backups":
            return item["value"], item.get("state", "good")
        from .models import IssueOccurrence

        cutoff = timezone.now() - datetime.timedelta(hours=2)
        open_started = {
            (o.system, o.flag_key): o.started_at
            for o in IssueOccurrence.objects.filter(category="backup", resolved_at__isnull=True)
        }
        fresh = 0
        for s in sec["systems"]:
            for f in s.get("flags", []):
                if f.get("category") != "backup" or f.get("band") not in ("red", "bad"):
                    continue
                started = open_started.get((s["name"], f.get("key")))
                if started is not None and started >= cutoff:
                    fresh += 1
        raw_value = str(item["value"])
        total = raw_value.split("|", 1)[1].strip() if "|" in raw_value else ""
        value = f"{fresh} | {total}" if total else str(fresh)
        state = "bad" if fresh else "good"
        return value, state

    # Each bar now carries its own "id" (clicked to open its own popup, same pattern as
    # _needs_attention_matrix's own cells) and "detail" (via _exception_detail above, same
    # best-effort word-match join the flat exceptions table already used) -- takes `sec`, not
    # just its own `overview`, since _exception_detail needs the section's real per-system
    # flags, one level down from overview.immediate/watch. sec["kind"] (a stable, always-unique
    # report kind like "system_admin") anchors the id instead of a domain display name, since
    # _domain_bars itself has no idea yet whether it's building Systems' own card or one of
    # Infrastructure's two merged components.
    def _domain_bars(sec):
        overview = sec["overview"]
        bars = []
        for idx, item in enumerate(overview.get("immediate", []) + overview.get("watch", [])):
            if item["label"] in exclude_labels:
                continue
            item_value, item_state = _fresh_backup_miss_override(sec, item)
            if item_state not in ("bad", "warn"):
                continue
            ratio = _ratio(item_value)
            # Same {sev, system, desc, time, pills} shape _needs_attention_matrix's own cells
            # build their "alerts" list in (2026-10-05) -- template reuses that identical
            # alert-row partial verbatim for a bar's own popup, rather than inventing a second
            # shape/template block to render one detail row.
            alerts = [{"sev": "red" if d["band"] in ("red", "bad") else "amb",
                      "system": d["system"], "desc": d["headline"],
                      "time": sec["generated_at"], "pills": d.get("items") or []}
                     for d in _exception_detail(sec, item["label"])]
            bars.append({"label": item["label"], "value": item_value,
                        "band": item_state, "pct": ratio[2] if ratio else None,
                        "id": _matrix_slug(f"bar-{sec['kind']}-{item['label']}-{idx}"),
                        "alerts": alerts})
        return bars

    # Shorter domain names in the exception-based view only (2026-09-14, on request: "drop
    # the admin in estate banner names just network not network admin systems not systems
    # admin") -- report_sections' own "label" stays the full "System Admin Report" etc. (still
    # used to look reports up by kind), this only renames what gets DISPLAYED as a domain.
    # Infrastructure/Active Directory get a "Infrastructure · <component>" form (2026-09-16, on
    # request: "infrastructure is the domain not active directory, active directory is one of
    # the components of the infrastructure domain, the other component... is clusters") -- used
    # by the flat per-row lists below (exceptions, compliance) that still need to name which
    # COMPONENT a finding came from; domain_cards itself merges the two into one card further
    # down, where "Infrastructure" alone is the right label (see that merge's own comment).
    _DOMAIN_DISPLAY_NAMES = {"System Admin": "Systems", "Network Admin": "Network",
                             "Cluster Health": "Infrastructure · Clusters",
                             "Active Directory": "Infrastructure · Active Directory"}

    def _domain_display_name(label):
        base = label.replace(" Report", "")
        return _DOMAIN_DISPLAY_NAMES.get(base, base)

    sections_by_kind = {s["kind"]: s for s in report_sections}

    domain_cards = []
    for kind, name in (("system_admin", "Systems"), ("switches_routers", "Network")):
        sec = sections_by_kind.get(kind)
        if not sec:
            continue
        ov = sec["overview"]
        domain_cards.append({
            "name": name, "pill": _domain_pill(sec), "glance": ov.get("glance", []),
            "bars": _domain_bars(sec), "components": [], "generated_at": sec["generated_at"],
        })

    # Infrastructure is the domain; Clusters (the report still tagged "infrastructure" --
    # HCI cluster hardware, not a general infrastructure catch-all) and Active Directory are
    # its two components, merged into ONE card rather than two separate domain-level entries
    # (2026-09-16, on request -- confirmed via the "one merged domain card, worst-of status
    # wins" option: Estate at a Glance, the Overview donut/domain tally, and Domain Health all
    # now treat this as a single domain; a component's own bars are prefixed with its name so
    # a merged card's mini-bar list still says which component an issue belongs to).
    infra_components = []
    for kind, comp_name in (("infrastructure", "Clusters"), ("active_directory", "Active Directory")):
        sec = sections_by_kind.get(kind)
        if not sec:
            continue
        ov = sec["overview"]
        infra_components.append({
            "name": comp_name, "pill": _domain_pill(sec), "glance": ov.get("glance", []),
            "bars": _domain_bars(sec), "generated_at": sec["generated_at"],
        })
    if infra_components:
        combined_bars = [{**b, "label": f"{comp['name']} — {b['label']}"}
                         for comp in infra_components for b in comp["bars"]]
        infra_pill = ("bad" if any(c["pill"] == "bad" for c in infra_components) else
                     "warn" if any(c["pill"] == "warn" for c in infra_components) else "ok")
        domain_cards.append({
            "name": "Infrastructure", "pill": infra_pill,
            "glance": [g for c in infra_components for g in c["glance"]],
            "bars": combined_bars, "components": infra_components,
            "generated_at": max(c["generated_at"] for c in infra_components),
        })

    # Grouped by severity, worst first (2026-09-14, on request: "add a group by severity
    # feature for domain banners... will make the presentation cleaner") -- same "bad before
    # warn" ordering `exceptions` below already uses, so a degraded domain is never buried
    # after several clean ones just because of report-generation order. Stable sort: domains
    # tied on severity keep report_sections' own relative order.
    _PILL_RANK = {"bad": 0, "warn": 1, "ok": 2}
    domain_cards.sort(key=lambda c: _PILL_RANK.get(c["pill"], 2))

    # Domain Health split into its own two sub-sub-sections, clean domains first (2026-09-14,
    # on request: "get all greens...no faults detected in their own sub sub section then
    # another sub section for those that have issues") -- domain_cards itself stays the single
    # full list Overview's own donut/bar chart still reads.
    domain_cards_ok = [c for c in domain_cards if c["pill"] == "ok"]
    domain_cards_issues = [c for c in domain_cards if c["pill"] != "ok"]

    # Two domains with no report/data source at all -- shown honestly as such (on request,
    # matching design_prompt.md's own explicit instruction), not silently omitted or
    # fabricated a "clean" reading from data that doesn't exist.
    # include_security (2026-10-07, "remove the domain for which we have nothing monitored i.e
    # security domain" -- the landing-page variant specifically, see management_dashboard_
    # pretty's own docstring) drops Security from here entirely rather than showing an empty
    # "nodata" card for it -- the caller asked for a domain that doesn't exist on this page at
    # all, not one that exists and renders blank.
    no_data_domains = [
        {"name": name, "note": "No monitoring data source yet."} for name in NO_DATA_DOMAIN_NAMES
        if include_security or name != "Security"
    ]
    excluded_domain_note = ("Government Systems isn't included yet -- no monitoring data "
                            "is available for that domain.")

    exceptions = []
    for sec in report_sections:
        ov = sec["overview"]
        for tier in ("immediate", "watch"):
            for item in ov.get(tier, []):
                if item["label"] in exclude_labels:
                    continue
                # "Storage at capacity" no longer exists as its own tile at all (2026-09-18,
                # on request -- see network._infra_overview's own comment on its own removal),
                # so there's nothing left to filter out here; "Storage critical" alone covers
                # this table's own storage row now, same as it always has for every other
                # caller of _infra_overview.
                item_value, item_state = _fresh_backup_miss_override(sec, item)
                if item_state in ("bad", "warn"):
                    exceptions.append({"domain": _domain_display_name(sec["label"]),
                                       "label": item["label"], "value": item_value,
                                       "band": item_state,
                                       "generated_at": sec["generated_at"],
                                       "detail": _exception_detail(sec, item["label"])})
    # Standing status rows -- ALWAYS shown, unlike every row above (2026-09-18, on request:
    # "one of the most important metrics to add... is the unreachable components, even if
    # things are reachable we still need that green [not] showing that all is well"; "Services
    # down" added to this same set 2026-10-03, on request: "add services down permanantly to
    # that dashboard if its zero make it green like unreachable components" -- identical
    # reasoning, just a second label; then, same day, "if we can have Unreachable components
    # for other domains also show up in the needs attention now panel if clean leave it green"
    # -- Network's own "Not responding" and Infrastructure's/Active Directory's own "Components
    # down" each got their own standing row here too, at the time under their OWN original
    # label text, since "Unreachable components" was a System Admin Report-only label back
    # then. Same day, once all three were already behaving identically: "can we rename all not
    # responding or component down to be Unreachable components just to standardise things" --
    # network.py's own three tile definitions were renamed to match (see each one's own
    # comment there), so this list collapses back down to the two real label STRINGS now in
    # use; the per-domain row count is unaffected -- Infrastructure · Clusters and
    # Infrastructure · Active Directory (both fed by network._infra_overview, called once per
    # device scope -- see alerting.run_alert_cycle's own _KIND_DOMAIN map) still produce two
    # separate standing rows, each reading its own real count, not one shared between them --
    # only the text displayed changed, not which sections contribute a row. "Undrained queues"
    # added 2026-10-05, on request: "add the queue clearing metric to the managerial dashboard
    # permanantly is there is no issues make it 0/5 green" -- already the identical "good" at
    # 0/warn otherwise two-state shape every other standing label uses (see services.py's own
    # comment on this tile: "0 undrained of 5" is deliberately the healthy reading), so it
    # needed nothing extra beyond joining this same set. "Missing backups" added the same day,
    # after the Voice Recorder backup checker fix cleared it and the row simply vanished from
    # the page (its own normal behaviour -- the main exceptions loop above only ever shows
    # bad/warn rows) -- on request: "why has the missing backups flag disappeared keep it
    # there". Same "good" at 0/bad-or-warn otherwise shape as every other standing label (see
    # generate_report.backup_missing_band's own docstring: "No misses -> good (green)"), so
    # again nothing extra needed beyond joining this set. Every other row here is a pure
    # problem list, silently absent when nothing's wrong; these are standing status lines
    # instead, so none of these is ever a metric you have to infer from its own ABSENCE. Reuses
    # each report's own existing immediate tile rather than inventing a second, parallel
    # definition of any of them. Skipped per (domain, label) if the main loop above already
    # added that exact row (its own state was bad/warn) -- never duplicated.
    _STANDING_LABELS = ("Unreachable components", "Services down", "Undrained queues", "Missing backups")
    _standing_shown = {(e["domain"], e["label"]) for e in exceptions if e["label"] in _STANDING_LABELS}
    for sec in report_sections:
        domain = _domain_display_name(sec["label"])
        for item in sec["overview"].get("immediate", []):
            if item["label"] not in _STANDING_LABELS:
                continue
            if (domain, item["label"]) in _standing_shown:
                continue
            item_value, item_state = _fresh_backup_miss_override(sec, item)
            exceptions.append({"domain": domain,
                               "label": item["label"], "value": item_value,
                               "band": "ok" if item_state == "good" else item_state,
                               "generated_at": sec["generated_at"],
                               "detail": _exception_detail(sec, item["label"])})
    exceptions.sort(key=lambda r: {"bad": 0, "warn": 1}.get(r["band"], 2))

    donut = {"ok": (1 if include_security else 0) + sum(1 for c in domain_cards if c["pill"] == "ok"),
            "warn": sum(1 for c in domain_cards if c["pill"] == "warn"),
            "bad": sum(1 for c in domain_cards if c["pill"] == "bad")}

    if any(c["pill"] == "bad" for c in domain_cards):
        banner_tier = "bad"
    elif any(c["pill"] == "warn" for c in domain_cards):
        banner_tier = "warn"
    else:
        banner_tier = "ok"

    swift_kpis = [g for sec in report_sections if sec["label"] == "System Admin Report"
                 for g in sec["overview"].get("glance", [])
                 if "swift" in g["label"].lower() or "cob" in g["label"].lower()]

    # A splash of color on the numbers themselves (2026-09-14, on request: "add a splash of
    # alert colours as there perhaps in the numbers eg 0|13 can be green if this is healthy" --
    # later corrected: every reading in this section is already filtered to state == "good",
    # so it's ALWAYS the healthy one, not just when its value happens to parse as an "N | Total"
    # ratio with N==0 -- the first cut only tinted domains whose good values were ratio-shaped
    # (Infrastructure/Active Directory), silently leaving Network/Systems' equally-clean plain
    # readings untinted, which is what "tint the other [domain]s' metrics green too" was
    # flagging). No per-item health check needed at all -- membership in `good` already means it.
    compliance_rows = []
    for sec in report_sections:
        ov = sec["overview"]
        good = [i for i in ov.get("immediate", []) + ov.get("watch", []) if i.get("state") == "good"]
        total = len(ov.get("immediate", [])) + len(ov.get("watch", []))
        if good:
            clean_count = len(good)
            compliance_rows.append({
                "domain": _domain_display_name(sec["label"]), "good": good,
                "clean_count": clean_count, "total": total, "fully_clean": clean_count == total,
            })

    open_issues = IssueOccurrence.objects.filter(resolved_at__isnull=True)

    # Attention Items coloured by how long each issue has been open (2026-09-14, on request:
    # "a splash of colour in the attention items section perhaps as it relates to how long the
    # issues have remained open") -- same 3-day red threshold backup/log drainage already uses
    # elsewhere in this app for "this has been overdue too long", not a new number invented
    # for this section.
    now = timezone.now()
    oldest_open = []
    for o in open_issues.order_by("started_at")[:5]:
        days_open = (now - o.started_at).days
        age_band = "bad" if days_open >= 3 else ("warn" if days_open >= 1 else "ok")
        oldest_open.append({"system": o.system, "text": o.text, "flag_key": o.flag_key,
                            "started_at": o.started_at, "age_band": age_band})

    recent_comments = (AutomatedFindingAction.objects.exclude(comment="")
                       .select_related("updated_by").order_by("-updated_at")[:5])

    return {
        "report_sections": report_sections,
        "domain_cards": domain_cards,
        "domain_cards_ok": domain_cards_ok,
        "domain_cards_issues": domain_cards_issues,
        "no_data_domains": no_data_domains,
        "excluded_domain_note": excluded_domain_note,
        "exceptions": exceptions,
        "donut": donut,
        "banner_tier": banner_tier,
        "swift_kpis": swift_kpis,
        "compliance_rows": compliance_rows,
        "oldest_open": oldest_open,
        "recent_comments": recent_comments,
        # days=30 (2026-09-18, on request: same scrollable/zoomable treatment as the Weekly
        # Trend report's own SWIFT chart -- see automated_report_download.html's "Cluster
        # zoom+pan+scroll" block, mirrored below for this page's single swiftLine2 canvas).
        "swift_chart": report_charts.swift_transaction_line_data(days=30),
        # cob_chart (2026-09-18, on request: "add the superimposed one for cob time same
        # style") -- same days=30 window as swift_chart, same reason.
        "cob_chart": report_charts.cob_time_line_data(days=30),
        "generated_at": timezone.localtime(),
        "incident_data": build_incident_calendar_context(timezone.localtime().date(),
                                                         include_security=include_security),
    }


@never_cache
@login_required
def management_dashboard_full(request):
    """Executive - Full: the original Executive Dashboard, unchanged, now reachable from the
    Management drawer rather than being the only screen the role has (2026-09-16, on request:
    "save current dashboard as is well move it to a page accessible through the management
    roles drawer navigation panel called Executive - full"). See management_dashboard_focused
    for the trimmed landing-page variant and _management_dashboard_context for the shared data.
    """
    ctx = _management_dashboard_context(request)
    if ctx is None:
        return redirect("report_form")
    return render(request, "reports/management_dashboard_full.html", ctx)


# Needs Attention Now drops a handful of tiles on the two trimmed dashboards specifically
# (2026-09-18, on request: "remove ram and cpu usage even disk usage from the smaller
# dashboard's needs attention banner", then "remove metric not collected too and links shut")
# -- Full keeps every exception unfiltered, only these narrow. Matched by label PREFIX ("High
# disk", not the trailing "≥85%" threshold text; "Links shut" alone matches Network's own
# "Links shut / unclear") so this doesn't silently stop working if wording/thresholds are ever
# retuned. "Storage critical" (Infrastructure's own cluster storage capacity -- "Storage at
# capacity" no longer exists as a separate tile at all, see network._infra_overview's own
# comment) and "Links failed" (a real outage, not a collection gap) are deliberately untouched
# -- only usage-noise and collection-gap tiles are hidden here. Shared by both
# management_dashboard_focused and management_dashboard_analytical (2026-09-19: Analytical is
# the former Focused page, kept verbatim under a new name/URL when Focused itself was redesigned
# into a plain 2x2 domain grid -- see management_dashboard_focused's own docstring) so the two
# pages can never quietly drift apart on which tiles this hides.
_HIDDEN_EXCEPTION_PREFIXES = ("High CPU", "High RAM", "High disk",
                              "Metrics not collected", "Links shut")


def _trimmed_dashboard_exceptions(ctx):
    return [e for e in ctx["exceptions"] if not e["label"].startswith(_HIDDEN_EXCEPTION_PREFIXES)]


def _pill_from_bars(bars) -> str:
    if any(b["band"] == "bad" for b in bars):
        return "bad"
    if any(b["band"] == "warn" for b in bars):
        return "warn"
    return "ok"


def _trimmed_domain_cards(domain_cards):
    """Domain Health's own bars, trimmed to the SAME set _trimmed_dashboard_exceptions already
    hides from Needs Attention Now, with each card's pill RECOMPUTED from what's left
    (2026-10-05, on request: "now the domain panels must reflect only the metrics from the
    needs attention now section not their own..things like cpu usage is not needed at this
    dashboard its for managers").

    Before this, Domain Health's mini-bars were built straight from _domain_bars -- every bad/
    warn immediate+watch tile except this page's own `exclude_labels` -- a DIFFERENT, wider
    set than what Needs Attention Now actually shows (that table also drops
    _HIDDEN_EXCEPTION_PREFIXES: High CPU/RAM/disk, Metrics not collected, Links shut -- "usage-
    noise and collection-gap tiles", see that constant's own comment). Confirmed live: Systems
    was showing "High CPU"/"High RAM"/"High disk ≥85%" bars that never appeared in the
    exceptions table at all -- the two panels disagreeing about what counts as worth a
    manager's attention.

    Only `c["bars"]` is touched -- the one list the template actually renders as mini-bars, for
    every card including the merged Infrastructure one (`components` exists only to drive each
    component's own 3-line glance text above the bars; `comp["bars"]` is never itself rendered,
    see management_dashboard_focused.html's own domain-grid2 loop). Infrastructure's own bars
    are each pre-prefixed with their component's name ("Clusters — High CPU", see
    _management_dashboard_context's own combined_bars) -- stripped back off before the prefix
    match so it's matched by the SAME rule as every other domain's unprefixed bars, not left
    exempt by accident.

    Pill is NOT just inherited -- recomputing it from the trimmed bars is what the "Needs
    Attention Now banner colour blend"/.ok-banner-contrast fixes earlier this session already
    established as the rule: a card's own severity pill must never claim something's wrong (or
    hide that something's wrong) with no visible bar underneath it to explain why. "nodata"
    (Security) is left completely untouched -- it never had bars to begin with."""
    component_names = {c["name"] for card in domain_cards for c in card.get("components", [])}

    def visible(bars):
        kept = []
        for b in bars:
            label = b["label"]
            for name in component_names:
                prefix = f"{name} — "
                if label.startswith(prefix):
                    label = label[len(prefix):]
                    break
            if not label.startswith(_HIDDEN_EXCEPTION_PREFIXES):
                kept.append(b)
        return kept

    trimmed = []
    for c in domain_cards:
        c = dict(c)
        c["bars"] = visible(c["bars"])
        if c.get("pill") != "nodata":
            c["pill"] = _pill_from_bars(c["bars"])
        trimmed.append(c)
    return trimmed


@never_cache
@login_required
def management_dashboard_analytical(request):
    """Executive - Analytical: the ORIGINAL Executive - Focused page, kept verbatim under a new
    name/URL (2026-09-19, on request: "save the current variation of the focused dashboard as
    -analytical instead of -focused... for -focused dashboard which will become our landing
    page[, redesign it]") -- management_dashboard_focused.html was cloned byte-for-byte into
    management_dashboard_analytical.html BEFORE that redesign touched it, so this page is
    exactly what "Executive - Focused" used to render: the exception-grouped (clean/issues)
    Domain Health cards and the two SWIFT/COB week-over-week comparison charts. See
    management_dashboard_focused for what replaced it as the landing page.

    "Backup tracking" excluded (2026-10-08, on request: "stop tracking the backups untracked
    backups in managerial dashboards") -- Focus/Pretty/Pretty Analytical already had this
    hidden via _focus_style_context's own _FOCUSED_EXCLUDE_LABELS (2026-10-03, "even backup
    tracking"), but Analytical was cloned from Focused on 2026-09-19 -- BEFORE that request
    existed -- so it never inherited it; this was a backport gap, not a deliberate difference.
    Passed as exclude_labels (not just _trimmed_dashboard_exceptions' own narrower post-hoc
    filter below, which only touches the flat exceptions list) so it also disappears from
    Domain Health's own bars/pill, same complete removal Focus/Pretty already get -- see
    _management_dashboard_context's own exclude_labels docstring for the three places this
    applies. Executive - Full deliberately keeps this (and everything else) unfiltered, by its
    own long-standing design -- not touched here."""
    ctx = _management_dashboard_context(request, exclude_labels=frozenset({"Backup tracking"}))
    if ctx is None:
        return redirect("report_form")
    ctx = dict(ctx, exceptions=_trimmed_dashboard_exceptions(ctx))
    return render(request, "reports/management_dashboard_analytical.html", ctx)


def _weighted_color_blend(exceptions) -> tuple:
    """(green_pct, red_vs_amber_pct) -- the robust, continuous colour-blend algorithm built
    2026-10-03 for the Needs Attention Now banner (see _focus_style_context's own "Needs
    Attention Now banner colour blend" comment for the full history/reasoning), factored out
    here 2026-10-06 so it has exactly ONE implementation shared by every banner that wants a
    "how healthy is this panel, right now" colour instead of a flat per-row vote or a discrete
    3-way state switch: weighted by each row's own "N | total" ratio (a metric affecting 20 of
    59 pulls far harder toward red than one affecting 1 of 59), never a flat count of how many
    rows are which colour. green_pct is the MEAN of every row's own greenness
    (1 - affected/total, so a clean "0 | N" row always contributes full 1.0); red_vs_amber_pct
    is red's own share of the red+amber "problem" mass specifically, both weighted the same
    way. 50/100 are the neutral fallbacks for an empty or fully-clean `exceptions` list."""
    ratio_re = re.compile(r"^\s*(\d+)\s*\|\s*(\d+)\s*$")
    greenness_sum = 0.0
    red_mass = 0.0
    amber_mass = 0.0
    n_rows = len(exceptions)
    for e in exceptions:
        m = ratio_re.match(str(e["value"]))
        # Falls back to the old all-or-nothing reading only for the rare row whose value isn't
        # itself an "N | total" ratio (none exist on this page today -- every tile here follows
        # that shape -- but this keeps a non-conforming row from crashing the blend outright).
        ratio = (int(m.group(1)) / int(m.group(2)) if m and int(m.group(2)) > 0
                else (0.0 if e["band"] == "ok" else 1.0))
        greenness_sum += 1 - ratio
        if e["band"] == "bad":
            red_mass += ratio
        elif e["band"] == "warn":
            amber_mass += ratio
    green_pct = round(100 * greenness_sum / n_rows) if n_rows else 100
    problem_mass = red_mass + amber_mass
    red_vs_amber_pct = round(100 * red_mass / problem_mass) if problem_mass else 50
    return green_pct, red_vs_amber_pct


def _focus_style_context(request, include_security: bool = True):
    """Shared setup behind BOTH "Focused-style" landing pages -- management_dashboard_focus
    (the original exception-first 2x2-grid design) and management_dashboard_pretty (2026-10-05,
    the cosmetic matrix redesign of its own Needs Attention Now panel that replaced it as the
    landing page, see management_dashboard_pretty's own docstring) -- everything through
    building domain_grid/banner_tier/banner_blend_style is IDENTICAL between the two; only the
    Needs Attention Now panel's own markup (and, for Pretty, its own separate matrix data --
    see _needs_attention_matrix) differs. Extracted here so the two views, and their own
    templates' Domain Health/Live Activity sections, can never quietly drift apart on what
    "the focused view" actually shows. Returns None when the viewer isn't Management, same
    contract as _management_dashboard_context itself.

    Trims a handful of lower-signal tiles entirely off this page specifically (2026-10-03, on
    request: "remove heavy discards unencripted links and some discards from the focused
    managerial dashboard" -> "even backup tracking" -> "metrics not collected doesnt matter"
    -> "remove high temperature here" -- a standing exposure/known-QoS-noise/tracking-coverage/
    data-coverage-gap/watch-tier environmental reading, not an active incident, so it's judged
    too granular for the exception-first landing page; Full/Analytical still show all of these,
    unchanged, for whoever wants the complete picture). See _management_dashboard_context's own
    `exclude_labels` docstring for exactly where this is applied.

    include_security (2026-10-07, see management_dashboard_pretty's own docstring) is passed
    straight through to _management_dashboard_context and additionally drops "Security" out of
    the fixed 2x2 domain_grid order below -- Focus and Pretty Analytical both leave it True
    (unchanged, Security still shown as its own "no data" card); only Pretty itself passes
    False now that it's the landing page and the domain never had a real monitoring source.
    """
    _FOCUSED_EXCLUDE_LABELS = frozenset({
        "Heavy discards", "Some discards", "Unencrypted links", "Backup tracking",
        "Metrics not collected", "High Temperature",
    })
    ctx = _management_dashboard_context(request, exclude_labels=_FOCUSED_EXCLUDE_LABELS,
                                       include_security=include_security)
    if ctx is None:
        return None
    ctx = dict(ctx, exceptions=_trimmed_dashboard_exceptions(ctx))
    # Domain Health's own bars, trimmed to match Needs Attention Now exactly -- see
    # _trimmed_domain_cards' own docstring (2026-10-05, "the domain panels must reflect only
    # the metrics from the needs attention now section not their own").
    ctx["domain_cards"] = _trimmed_domain_cards(ctx["domain_cards"])
    # banner_tier RECOMPUTED from the now-trimmed cards' own pills, same worst-of formula
    # _management_dashboard_context used for its own (pre-trim) value -- that original value is
    # now stale: it could still say "warn" off a High CPU pill this page no longer shows a
    # single bar for, which would make the Needs Attention Now heading claim a problem exists
    # with nothing underneath it to point to (the exact inconsistency the .ok-banner-contrast
    # fix earlier this session already ruled out for the pill/bar relationship -- this is the
    # same rule applied one level up, to the heading text itself).
    if any(c["pill"] == "bad" for c in ctx["domain_cards"]):
        ctx["banner_tier"] = "bad"
    elif any(c["pill"] == "warn" for c in ctx["domain_cards"]):
        ctx["banner_tier"] = "warn"
    else:
        ctx["banner_tier"] = "ok"

    # Needs Attention Now banner colour blend (2026-10-03, on request: "establish a color
    # system for the top banner pick an appropriate green color that matches the current
    # theme...for every green metric recorde on this panel shift hue by a set ammount towards
    # green....for every red or amber metric shift hue by a set amount towards the current
    # color"). The banner used to be a hard 3-way switch (all-red/all-amber/all-green) keyed
    # only off banner_tier -- worst-of-ANY-domain, so a single stray finding against 20 clean
    # rows painted the whole banner solid red. This computes a CONTINUOUS blend instead, over
    # the exact rows the panel itself renders (ctx["exceptions"], post-trim -- "recorded on
    # this panel", not the wider estate) toward --ehgreen (this theme's own established green
    # token -- the SAME one status-pill2.ok/sev2.ok already use, not a new invented colour) or
    # --ehred/--ehamber. banner_tier (worst-of) is UNCHANGED and still decides the heading's
    # own wording (Critical/Warning/Healthy) -- a factual classification, not a cosmetic one;
    # only the background colour becomes this continuous read instead of matching 1:1 with
    # that text.
    #
    # Weighted by each row's OWN "N | total" ratio, not a flat per-row vote (corrected same
    # day, on request: "blindly counting a metric as green or red is ineffective we should
    # weigh how many green bricks to add based on the percentage of how red it is[,] 1/59 is
    # different from 20/59" -- the first version counted "Missing backups: 2 | 27" and
    # "Unreachable components: 0 | 59" as equally-sized red/green votes, when the first is
    # really ~93% healthy on its own and the second is 100% healthy; averaging raw row counts
    # instead of each row's own severity badly understated how clean the estate actually was).
    # Every tile on this page already reads "affected | total" (see services.py/network.py's
    # own "a count can never be mistaken for the whole estate" comment), so each row's own
    # greenness is 1 - (affected/total) -- an "ok" row's affected is always 0, so this still
    # gives it full greenness(1.0) under the exact same formula, no separate ok/not-ok branch
    # needed. The final blend is the MEAN of every row's own greenness, i.e. a metric affecting
    # 20 of 59 pulls the banner far harder toward red than one affecting 1 of 59, matching the
    # weight a reader would actually give each finding.
    #
    # Factored into _weighted_color_blend (2026-10-06) so management_dashboard_pretty's own
    # matrix banner can reuse this EXACT same algorithm against its own colour palette, rather
    # than the discrete 3-state (healthy/warning/critical) switch the cosmetic matrix redesign
    # had replaced it with outright -- on request: "this change was meant to be cosmetic only
    # we designed a robust color change algorithm that has since been set asside... we designed
    # an algorithim to change colors as things happen". See that function's own docstring.
    _green_pct, _red_vs_amber_pct = _weighted_color_blend(ctx["exceptions"])
    # Two chained color-mix() calls, not a server-computed hex/hsl string -- stays theme-
    # reactive (recomputes under :root[data-theme="dark"] for free, since it reads the live
    # custom properties) the same way --grad-red/--grad-amber/--grad-green already do. The
    # dark gradient stop reuses THEIR OWN "88% colour, 12% black" darkening ratio for visual
    # consistency with those three. Built once here (not per-branch in the template) since all
    # three banner_tier branches apply the identical blend -- only the heading text differs.
    _blend = (f"color-mix(in srgb, var(--ehgreen) {_green_pct}%, "
             f"color-mix(in srgb, var(--ehred) {_red_vs_amber_pct}%, var(--ehamber)))")
    ctx["banner_blend_style"] = mark_safe(
        f"--banner-blend:{_blend}; background:linear-gradient(135deg, var(--banner-blend), "
        f"color-mix(in srgb, var(--banner-blend) 88%, black 12%));")

    # Fixed 2x2 order regardless of status or which domains happen to have real data this poll
    # (2026-09-19, on request: "starting with security then infrastructure then networks then
    # systems"; Systems/Security swapped 2026-10-05, on request: "swap the system and security
    # domain tile together in managerial dashboard" -- Systems now leads, top-left, Security
    # moves to bottom-right; Infrastructure/Network stay exactly where they were). Security has
    # no monitoring source at all (see _management_dashboard_context's own no_data_domains), so
    # it's normalised into the SAME card shape as a real domain here, with a distinct "nodata"
    # pill/band the template styles neutrally rather than green/amber/red. Went green->neutral-
    # >green->neutral over three quick rounds on 2026-09-19 ("you removed green coloring from
    # security domain", then "i think i like no data source better") -- neutral is the settled
    # choice; a Security card that's never actually measured anything shouldn't look identical
    # to one that measured everything and found it healthy.
    _domain_by_name = {c["name"]: c for c in ctx["domain_cards"]}
    _no_data_by_name = {nd["name"]: nd for nd in ctx["no_data_domains"]}
    domain_grid = []
    _grid_names = (("Systems", "Infrastructure", "Network", "Security") if include_security else
                   ("Systems", "Infrastructure", "Network"))
    for name in _grid_names:
        if name in _domain_by_name:
            domain_grid.append(_domain_by_name[name])
        elif name in _no_data_by_name:
            domain_grid.append({"name": name, "pill": "nodata", "glance": [], "bars": [],
                                "components": [], "note": _no_data_by_name[name]["note"]})
    ctx["domain_grid"] = domain_grid

    return ctx


@never_cache
@login_required
def management_dashboard_focus(request):
    """Executive - Focus: the exception-first 2x2-grid design, kept verbatim under a new
    name/URL (2026-10-05, on request: "added a new zip to apply cosmatic changes to the
    managerial dashboard needs attention now panel....save the current dashboard as -focus....
    then this new one call it -pretty and make it the landing page" -- the SAME "preserve the
    outgoing landing page under its own new name" move already used once before, 2026-09-19,
    when this page's own former content became Executive - Analytical; see
    management_dashboard_pretty for what replaced THIS page as the landing page this time).
    management_dashboard_focused.html was cloned byte-for-byte into
    management_dashboard_focus.html before the new page's own template was built, so this is
    exactly what "Executive - Focused" rendered the moment before this change -- including
    every Needs Attention Now/Domain Health fix made earlier on 2026-10-03 through 2026-10-05
    (the colour blend, the domain-panel/exceptions-table consistency fix, the Systems/Security
    swap, all still live here, unchanged)."""
    ctx = _focus_style_context(request)
    if ctx is None:
        return redirect("report_form")
    return render(request, "reports/management_dashboard_focus.html", ctx)


# Needs Attention Now matrix rows -- the SAME 4 standing labels _STANDING_LABELS already
# established (2026-10-05, reused rather than re-picked: "domains on X axis, issue types on Y
# axis" needed some fixed, small set of real issue types, and these 4 are already this app's
# own settled definition of "always-shown, managerial-relevant" metrics -- see
# _management_dashboard_context's own `_STANDING_LABELS` docstring for why each one earned
# that status). No Tabler icon font (the redesign package's own reference HTML loads one from
# a public CDN) -- this app vendors every other script/library locally (see
# management_dashboard_focused.html's own chart.umd.min.js) and has no existing dependency on
# an external icon CDN, so row labels are plain text here instead of adding a first one just
# for this.
_MATRIX_ROW_LABELS = ("Missing backups", "Unreachable components", "Services down", "Undrained queues")

# Needs Attention Now matrix columns -- the real domain names _management_dashboard_context's
# own exceptions already carry, each mapped to the underlying exception "domain" string(s) it
# draws from. Infrastructure's two sub-domains (Clusters/Active Directory) are now ONE merged
# column (2026-10-06, on request: "combine infra clusters and infra ad into one infrastructure
# domain leave delineation to the pop up when clicked add all components" -- reversing the
# 2026-10-05 decision to keep them separate columns, same "one merged domain, worst-of status
# wins" treatment _management_dashboard_context's own domain_cards merge already applies to
# Domain Health/Estate at a Glance -- see that merge's own comment). The per-component
# delineation this drops from the column header moves into each alert row instead (see the
# loop below, which prefixes a merged cell's own alerts with their source component's name) --
# nothing is actually lost, it just lives one level deeper, behind the cell's own popup, same
# as the brief asked. Security is still included as its own column, all dashes (no matching
# exceptions rows exist for it, since it has no monitoring source at all) -- shown honestly as
# a real, always-present column rather than silently dropped, matching how Domain Health
# already treats it (see that section's own "nodata" card).
_MATRIX_COLUMNS = (
    ("Systems", "Systems", ("Systems",)),
    ("Network", "Network", ("Network",)),
    ("Infrastructure", "Infrastructure",
     ("Infrastructure · Clusters", "Infrastructure · Active Directory")),
    ("Security", "Security", ("Security",)),
)


def _matrix_slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _needs_attention_matrix(ctx, include_security: bool = True):
    """The Needs Attention Now panel's own domain x issue-type matrix (2026-10-05, see
    management_dashboard_pretty's own docstring for the request this implements) --
    {"rows": [{"label","cells":[cell_or_None, ...]}, ...], "columns": [...], "state":
    "ok"/"amb"/"red", "n_domains", "n_domains_affected", "n_issue_types",
    "n_issue_types_affected", "health_pct", "n_errors", "n_checked"}.

    Built entirely from ctx["exceptions"] -- the SAME already-trimmed, already-detail-attached
    rows the existing flat Needs Attention Now table reads (see _exception_detail, called once
    per row when _management_dashboard_context first builds that list) -- not a second,
    parallel query. A cell is None (rendered as an empty "—" dash) whenever no exceptions row
    exists for that exact (domain, label) pair -- the same "not applicable here" meaning the
    reference design's own empty cells carry, e.g. "Undrained queues" has no Network/
    Infrastructure/Security equivalent tile at all. Each cell's own `alerts` list IS
    _exception_detail's own `detail` list, reshaped into the popup's row shape -- never
    fabricated: a clean cell's alerts list is genuinely empty, shown as "0 alerts" rather than
    a made-up success message, since this app has no real per-finding "all clear" text to show.

    include_security=False (2026-10-07, see management_dashboard_pretty's own docstring) drops
    the Security column out of _MATRIX_COLUMNS entirely for this call -- it was always every
    cell showing a dash anyway (Security has no monitoring source at all), so dropping it
    changes nothing about what the matrix actually SAYS, only removes a column that could never
    say anything."""
    _columns_src = (_MATRIX_COLUMNS if include_security else
                    tuple(c for c in _MATRIX_COLUMNS if c[0] != "Security"))
    by_domain_label = {(e["domain"], e["label"]): e for e in ctx["exceptions"]}
    ratio_re = re.compile(r"^\s*(\d+)\s*\|\s*(\d+)\s*$")
    band_map = {"ok": "ok", "warn": "amb", "bad": "red"}
    rows = []
    n_errors = 0
    n_checked = 0
    worst = "ok"
    domains_affected = set()
    issue_types_affected = set()
    for label in _MATRIX_ROW_LABELS:
        cells = []
        for col, _col_label, source_domains in _columns_src:
            # One or more underlying exception rows feed this column -- exactly one for every
            # plain column (source_domains is just (col,) itself), two for the merged
            # Infrastructure column. Looping uniformly over source_domains, rather than special-
            # casing the merge, means a single-source column and a multi-source one build their
            # cell the exact same way -- the only thing that changes is whether anything ever
            # gets prefixed with a component name below.
            matched = []
            for dom in source_domains:
                e = by_domain_label.get((dom, label))
                if e is not None:
                    comp = dom.split(" · ", 1)[1] if " · " in dom else None
                    matched.append((comp, e))
            if not matched:
                cells.append(None)
                continue
            errors = total = 0
            band = "ok"
            alerts = []
            for comp, e in matched:
                m = ratio_re.match(str(e["value"]))
                e_errors, e_total = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
                e_band = band_map.get(e["band"], "ok")
                errors += e_errors
                total += e_total
                if e_band == "red":
                    band = "red"
                elif e_band == "amb" and band != "red":
                    band = "amb"
                for d in e["detail"]:
                    # Delineation moved here from the column header (2026-10-06, see
                    # _MATRIX_COLUMNS' own comment) -- a merged cell's alert rows are
                    # prefixed with their source component's name so clicking into a combined
                    # "Infrastructure" cell still tells Clusters and Active Directory findings
                    # apart; a single-source column's own comp is None, so its alerts render
                    # exactly as before.
                    system = f"{comp} · {d['system']}" if comp else d["system"]
                    alerts.append({
                        "sev": "red" if d["band"] in ("red", "bad") else "amb",
                        "system": system, "desc": d["headline"],
                        "time": e["generated_at"], "pills": d.get("items") or [],
                    })
            if band == "red":
                worst = "red"
            elif band == "amb" and worst != "red":
                worst = "amb"
            if band != "ok":
                domains_affected.add(col)
                issue_types_affected.add(label)
            n_errors += errors
            n_checked += total
            cells.append({
                "id": f"{_matrix_slug(label)}--{_matrix_slug(col)}",
                "domain": col, "label": label,
                "errors": errors, "total": total, "band": band, "alerts": alerts,
                "health_pct": round(100 * (total - errors) / total) if total else 100,
            })
        rows.append({"label": label, "cells": cells})
    n_domains = sum(1 for col, _lbl, source_domains in _columns_src
                    if any(by_domain_label.get((dom, lbl))
                           for dom in source_domains for lbl in _MATRIX_ROW_LABELS))
    n_issue_types = len(_MATRIX_ROW_LABELS)
    n_domains_affected = len(domains_affected)
    n_issue_types_affected = len(issue_types_affected)
    # Item-weighted again, NOT the whole-domain-affected ratio (2026-10-06, reverted on request:
    # "75 percent is also wrong because it assumes one whole domain all its services and kpis
    # are down" -- the (n_domains - n_domains_affected) / n_domains version this replaced was
    # its own overcorrection: 1 dead service out of Systems' own 91 made the ENTIRE Systems
    # domain count as 0% healthy, understating things just as badly as the original bug
    # overstated them. Back to the real proportion of individually-checked items that are
    # clean (n_errors/n_checked) -- 1 of 251 here, a genuinely small, honest fraction -- but
    # with the ORIGINAL bug's actual defect fixed directly instead of worked around: never
    # ROUND UP to a flat "100%" while a real error exists. 99.6% floors to 99%, not 100%, so
    # the stat can never again claim "all clear" in the same breath the banner above it says
    # "Critical". n_errors==0 is the only path that ever shows literal 100.
    if n_checked == 0:
        health_pct = 100
    elif n_errors == 0:
        health_pct = 100
    else:
        health_pct = min(99, round(100 * (n_checked - n_errors) / n_checked))
    columns = [{"key": col, "label": lbl} for col, lbl, _src in _columns_src]
    return {
        "rows": rows, "columns": columns, "state": worst,
        "n_domains": n_domains, "n_domains_affected": n_domains_affected,
        "n_issue_types": n_issue_types, "n_issue_types_affected": n_issue_types_affected,
        "health_pct": health_pct, "n_errors": n_errors, "n_checked": n_checked,
    }


def _matrix_scoped_domain_grid(domain_grid):
    """Domain Health's bars on the Pretty page specifically, narrowed to EXACTLY the labels
    its own Needs Attention Now matrix shows -- _MATRIX_ROW_LABELS, the fixed 4 rows (Missing
    backups/Unreachable components/Services down/Undrained queues) -- not the broader "every
    bad/warn tile except the 5 usage-noise prefixes" _trimmed_domain_cards already applied
    further up in _focus_style_context (2026-10-06, on request: "we said only the errors
    monitored in needs attention now should appear in domain tiles not every error").

    Focus's own Needs Attention Now is a flat table of every bad/warn exception (minus the
    hidden usage-noise prefixes) -- _trimmed_domain_cards' existing scope is already the right
    match for it, so Focus/Full/Analytical (which all reuse that same function, unchanged)
    keep showing any such bar. Pretty's own Needs Attention Now is narrower -- a fixed 4-row
    matrix, nothing else, ever -- so a Domain Health card here showing a bar for, say,
    "Expired certs" (a real bad/warn tile, not hidden-prefix-trimmed, but not one of the 4 rows
    either) would be showing the manager something Needs Attention Now right above it never
    displays, the exact disagreement-between-panels problem the original 2026-10-05 trim was
    built to prevent in the first place -- just one level narrower here than there.

    Applied ON TOP OF the existing trim (domain_grid arrives here already past
    _trimmed_domain_cards), not instead of it -- this only ever REMOVES bars the broader trim
    already let through, never adds any back. Same component-prefix-strip-before-matching and
    pill-recompute-from-what's-left pattern _trimmed_domain_cards itself established, reused
    verbatim rather than re-invented: a card's own DEGRADED/NORMAL pill must never claim
    something's wrong with no visible bar left to explain why, and now must never disagree with
    the matrix sitting directly above it either."""
    component_names = {c["name"] for card in domain_grid for c in card.get("components", [])}
    scoped = []
    for card in domain_grid:
        card = dict(card)
        kept = []
        for b in card.get("bars", []):
            label = b["label"]
            for name in component_names:
                prefix = f"{name} — "
                if label.startswith(prefix):
                    label = label[len(prefix):]
                    break
            if label in _MATRIX_ROW_LABELS:
                kept.append(b)
        card["bars"] = kept
        if card.get("pill") != "nodata":
            card["pill"] = _pill_from_bars(kept)
        scoped.append(card)
    return scoped


@never_cache
@login_required
def management_dashboard_pretty(request):
    """Executive - Pretty: Management's landing page (2026-10-05, on request: "added a new zip
    to apply cosmatic changes to the managerial dashboard needs attention now panel....save the
    current dashboard as -focus....then this new one call it -pretty and make it the landing
    page" -- needs-attention-package.zip's own NEEDS_ATTENTION_REDESIGN_PROMPT.md, a cosmetic/
    structural redesign of JUST the Needs Attention Now panel: a domain x issue-type matrix
    instead of a flat list, a state-driven animated banner, and clickable cells that open a
    scrollable popup of the real underlying findings -- see that package's own 3 reference HTML
    files, built directly from, same "follow the reference file" precedent the digest redesign
    already established). Domain Health and Live Activity (the SWIFT chart) are UNCHANGED from
    Executive - Focus -- the redesign package's own request was scoped to the Needs Attention
    Now panel specifically, not the whole page -- so this view reuses the exact same
    _focus_style_context every other field in ctx comes from; only the matrix (
    _needs_attention_matrix) is new.

    include_security=False below (2026-10-07, on request: "rename this one to Pretty Analytical
    then duplicate it and remove the domain for which we have nothing monitored i.e security
    domain...this duplicate make it landing page") -- this page's own prior, unmodified content
    (Security domain included) is preserved verbatim as management_dashboard_pretty_analytical
    instead; THIS view/URL/template keep their original name and the landing-page slot, but now
    render the Security-free variant. Security never had a real monitoring source to begin with
    (NO_DATA_DOMAIN_NAMES) -- every one of its cells across Domain Health/the matrix/the
    Incident Calendar was always an honest "no data" placeholder, never a real reading, so
    dropping the column changes what's SHOWN, never what's actually being measured."""
    ctx = _focus_style_context(request, include_security=False)
    if ctx is None:
        return redirect("report_form")
    ctx["domain_grid"] = _matrix_scoped_domain_grid(ctx["domain_grid"])
    ctx["matrix"] = _needs_attention_matrix(ctx, include_security=False)
    # The SAME continuous weighted blend _focus_style_context already computes for the old
    # Focus-style banner (ctx["banner_blend_style"], against --ehgreen/--ehred/--ehamber) --
    # reused here against the matrix redesign's own dark palette instead (2026-10-06, on
    # request: "this change was meant to be cosmetic only we designed a robust color change
    # algorithm that has since been set asside... yes i like the new colors but we desined al
    # algorithim to change colors as things happen" -- the cosmetic redesign had swapped this
    # real, continuous computation out for a discrete 3-state healthy/warning/critical switch
    # on the banner's own background/glow; the state classification itself -- matrix["state"],
    # driving the heading text/badge wording -- stays discrete on purpose, same "text is
    # factual, colour is the continuous nuance" split the original algorithm already used).
    # Literal hex anchors, not var(--eh*) tokens -- this palette was never tied to the page's
    # own light/dark theme toggle (the matrix panel is intentionally always-dark), so there are
    # no matching custom properties to blend against here the way the Focus banner has.
    _na_green_pct, _na_red_vs_amber_pct = _weighted_color_blend(ctx["exceptions"])
    _na_blend = (f"color-mix(in srgb, #10b981 {_na_green_pct}%, "
                f"color-mix(in srgb, #ef4444 {_na_red_vs_amber_pct}%, #f59e0b))")
    ctx["na_blend_style"] = mark_safe(f"--na-blend:{_na_blend};")
    return render(request, "reports/management_dashboard_pretty.html", ctx)


@never_cache
@login_required
def management_dashboard_pretty_analytical(request):
    """Executive - Pretty Analytical: the reference copy of Executive - Pretty kept exactly as
    it was before 2026-10-07's Security-domain removal (see management_dashboard_pretty's own
    docstring) -- same matrix/banner/Incident Calendar/SWIFT content, Security domain included,
    just no longer the landing page. Deliberately a near-duplicate of the view above rather than
    a parameterised single view the URLconf dispatches on: these two are allowed to actually
    diverge over time (e.g. if Pretty itself gets Security-shaped changes later that Pretty
    Analytical has no reason to inherit), where a single shared view would quietly couple them
    again. include_security defaults True on every helper below -- unchanged behaviour."""
    ctx = _focus_style_context(request)
    if ctx is None:
        return redirect("report_form")
    ctx["domain_grid"] = _matrix_scoped_domain_grid(ctx["domain_grid"])
    ctx["matrix"] = _needs_attention_matrix(ctx)
    _na_green_pct, _na_red_vs_amber_pct = _weighted_color_blend(ctx["exceptions"])
    _na_blend = (f"color-mix(in srgb, #10b981 {_na_green_pct}%, "
                f"color-mix(in srgb, #ef4444 {_na_red_vs_amber_pct}%, #f59e0b))")
    ctx["na_blend_style"] = mark_safe(f"--na-blend:{_na_blend};")
    return render(request, "reports/management_dashboard_pretty_analytical.html", ctx)


def _alert_dashboard_context(request):
    """The Alert Dashboard's own context -- deliberately NOT built on
    _management_dashboard_context (that function's whole contract is verbatim glance/
    immediate/watch tiles pulled from LiveEstateOverview; this screen needs a different
    shape entirely: a severity-tiered incident catalog, muted list, and trend charts, all
    sourced from IssueOccurrence/AlertSilence via reports.alert_catalog). Returns None when
    the viewer can't view it (roles.can_view_alert_dashboard -- 2026-10-01, moved off
    Management onto the five estate/admin roles, see that function's own docstring), same
    contract as _management_dashboard_context, so the caller redirects the same way every
    other role-gated screen does."""
    if not can_view_alert_dashboard(request.user):
        return None

    from . import alert_catalog
    from django.utils import timezone

    state = alert_catalog.current_state()
    notif = alert_catalog.notification_activity()
    resolve_time = alert_catalog.avg_resolve_time()

    # Every dict below carries its own pre-resolved CSS bits (a "css"/"fg"/"bg" style key,
    # already looked up from alert_catalog.TIER_STYLE/DOMAIN_STYLE) rather than a bare tier/
    # domain NAME -- Django templates cannot index a dict by a variable ({{ d[tier] }} isn't
    # valid template syntax), so resolving colour/class lookups here, once, keeps the template
    # to plain dot-lookups only and avoids a same-lookup if/elif chain repeated at every one
    # of the mockup's many colour references.

    # Domain bars: flex-grow proportional to each tier's raw count within that domain's own
    # row (mockup's own `style="flex:N"` convention) -- 0 special-cased to a hairline sliver
    # so an empty tier still renders as a visible (colourless) gap, not collapse the row's
    # total width the way flex:0 silently would.
    domain_rows = []
    for d in state["domains"]:
        css = alert_catalog.DOMAIN_STYLE[d["name"]]
        if "tiers" not in d:            # Security placeholder -- no bars at all
            domain_rows.append({"name": d["name"], "css": css, "note": d["note"]})
            continue
        # `label`/`title` (2026-10-01, on request: "make alert domains... interactive a bit")
        # -- a native title="" tooltip needs the tier's own display name on the segment itself;
        # TIER_LABEL/TIER_STYLE are keyed by the same tier string, so this is a plain lookup,
        # not new data.
        segments = [{"css": alert_catalog.TIER_STYLE[t]["css"], "count": d["tiers"][t],
                    "flex": d["tiers"][t] or 0.001, "label": alert_catalog.TIER_LABEL[t],
                    "title": f"{alert_catalog.TIER_LABEL[t]}: {d['tiers'][t]}"}
                   for t in alert_catalog.TIER_ORDER]
        domain_rows.append({"name": d["name"], "css": css, "total": d["total"], "segments": segments})

    # Severity trend: the mockup's bars assume a fixed 0-40 scale, meaningless at this app's
    # real volumes (a single day's "warning" count alone can run into the thousands, confirmed
    # live) -- compute the axis max from the ACTUAL window instead, four evenly-spaced y-axis
    # labels under it, same shape the mockup's own <div class="yax"> expects.
    trend = alert_catalog.severity_trend(days=7)
    trend_max = max((max(series) for series in trend["series"].values()), default=0) or 1
    trend_days = []
    for i, day in enumerate(trend["days"]):
        day_label = day.strftime("%a")
        trend_days.append({
            "label": day_label,
            # `title` (2026-10-01, interactivity) -- the bar's own height is a PERCENTAGE of
            # this chart's own max (meaningless on its own, see this block's own comment
            # above), so the tooltip needs the real count, not pct, to be useful on hover.
            "bars": [{"css": alert_catalog.TIER_STYLE[t]["css"],
                     "pct": round(100 * trend["series"][t][i] / trend_max, 1),
                     "title": f"{day_label} · {alert_catalog.TIER_LABEL[t]}: {trend['series'][t][i]}"}
                    for t in alert_catalog.TIER_ORDER],
        })
    trend_yaxis = [round(trend_max * f) for f in (1, 0.75, 0.5, 0.25, 0)]

    # Severity panels: one per tier, each already carrying its own label/style/firing count/
    # matrix -- so the template's own {% for panel in tier_panels %} never needs to look
    # anything up by the loop variable. Grid DISPLAY order only -- originally matched the
    # supplied mockup's own panel layout (Critical before Imminent, 2026-09-30), swapped
    # 2026-10-02 on request ("swap imminent and and critical matrix panels on dashboard") to
    # now match alert_catalog.TIER_ORDER's own imminent-first severity ranking instead (the
    # same order the legends/domain-bar segments/trend bars already use) -- still kept as its
    # own separate list rather than importing TIER_ORDER directly, since this is the grid's
    # own left-to-right arrangement and the two happening to agree now is not a guarantee
    # they must stay coupled if either changes again later.
    #
    # Every tier uses the Alert Matrix now (2026-10-01: Imminent/Critical/Warning from the
    # original spec, Note added on explicit follow-up request) -- severity_tables()/the classic
    # per-row table markup this loop used to also build are gone, not just unused: the
    # template's own {% else %} branch for a non-matrix tier is dead code with nothing left to
    # reach it. Muted stays OUT of this loop entirely (the requester separately confirmed "do
    # not apply matrix to muted alerts table") -- it isn't a severity tier at all (no band/
    # category to classify by), so severity_matrix(), keyed on alert_catalog._tier(), has no
    # equivalent for it anyway; it gets its own muted_matrix() below instead.
    PANEL_GRID_ORDER = ["imminent", "critical", "warning", "note"]
    tier_panels = []
    for t in PANEL_GRID_ORDER:
        tier_panels.append({
            "tier": t, "label": alert_catalog.TIER_LABEL[t], "style": alert_catalog.TIER_STYLE[t],
            "firing_count": state["firing"][t],
            "matrix": alert_catalog.severity_matrix(t), "matrix_id": f"mxData_{t}",
        })

    # Alert Matrix popup footer's second button (2026-10-01, on request: "instead of open in
    # grafana button put open alert groups button, this should open the alert groups that the
    # user has access to"). ALWAYS my_alert_groups, never config_alerts (2026-10-02 fix, on
    # request: "the open alert groups panel navigates to the main alerting configuration
    # screen and not the alert groups config page at each admin's side nav panel this is a
    # risk") -- config_alerts is the ENTIRE Alerting hub (thresholds, templates, System
    # Alerting config too), while my_alert_groups is the focused screen the side nav itself
    # links to and already shows every group to a full Administrator (its own docstring: "A
    # full Administrator sees every group, same as the hub's own list, since nothing here is
    # a restriction for them") -- there is no viewer for whom config_alerts was ever the
    # right target from this button specifically. Anyone who can't reach even that screen
    # gets no button at all rather than one that goes nowhere -- same "don't offer a tile
    # that does nothing when picked" discipline SELECTABLE_ROLE_NAMES already applies to Sub
    # Admin itself.
    alert_groups_url = reverse("my_alert_groups") if can_reach_my_alert_groups(request.user) else None

    muted = [dict(m, css=alert_catalog.DOMAIN_STYLE.get(m["domain"], "dsy")) for m in alert_catalog.muted_alerts()]
    # Muted matrix (2026-10-01, on request: "apply matrix to muted alerts table") -- `muted`
    # above still drives the panel's own "N silenced" badge/footer count (a count of SILENCES);
    # muted_matrix is a completely separate, matrix-shaped view of the SUPPRESSED VOLUME those
    # silences cover -- see alert_catalog.muted_matrix's own docstring for why the two numbers
    # are deliberately different things.
    muted_matrix_data = alert_catalog.muted_matrix()
    # The top MUTED stat tile originally showed state.muted (the rule count, same "3" as the
    # panel badge) -- reported twice (2026-10-01) as a confusing mismatch against the matrix's
    # own "4". Every OTHER top-row tile counts things actually HAPPENING (Currently Firing,
    # Total Firings, ...), not configuration rows, so the tile now matches that pattern instead
    # of re-explaining the distinction again: its big number is the SAME suppressed-volume
    # total the matrix shows, and the rule count moves to the subtitle, where its different
    # meaning is explicit rather than implied by two tiles disagreeing.
    muted_suppressed_total = sum(row[3] for row in muted_matrix_data["data"])

    generated_at = timezone.localtime()
    return {
        "state": state,
        "notif": notif,
        "resolve_hours": resolve_time["hours"],
        "domain_rows": domain_rows,
        "tier_panels": tier_panels,
        "muted": muted,
        "muted_matrix": muted_matrix_data,
        "muted_suppressed_total": muted_suppressed_total,
        "trend_days": trend_days,
        "trend_yaxis": trend_yaxis,
        "generated_at": generated_at,
        # The matrix panels' own "previous alert window" (severity_matrix()'s own docstring:
        # count_prev is the same currently-open snapshot taken exactly 24h earlier) -- was
        # labelled just "(24h)" on every panel, a real duration but not an actual clock range
        # (2026-10-01, on request: "all alerts have an alert window which is an actual time
        # from what time to what time go check" -- the SAME real 24h-rolling window
        # severity_matrix() already computes, not a separately invented one).
        "prev_window_start": generated_at - datetime.timedelta(hours=24),
        # The estate-wide default notification window (2026-10-02, on request: "make every
        # alert share Innocent Nyama Alert group alert window and have this reflect cleanly
        # on our alert dashboard") -- SystemConfig.default_alert_window_*, see
        # AlertGroup.in_schedule's own docstring for exactly when this applies (a Monitoring
        # group with no schedule of its own).
        "default_window": SystemConfig.get(),
        "alert_groups_url": alert_groups_url,
        "comment_history_url": reverse("alert_comment_history"),
        "mute_url": reverse("alert_mute_from_comment"),
        "mute_bulk_url": reverse("alert_mute_bulk"),
        "unmute_url": reverse("alert_unmute"),
        # Page-level "can this viewer ever mute anything from here" gate for the "Mute
        # recurring" button (2026-10-02, on request: broaden mute access beyond full admins,
        # "filter through the permissions you have as per your designated alert group") -- a
        # full Administrator, or any Sub-Admin-shaped user who is a stakeholder on at least
        # one Alert Group (same roles.can_reach_my_alert_groups the side nav's own "My Alert
        # Groups" link uses). The PER-FINDING mute-with-comment button has its own, narrower,
        # per-group check (see alert_comment_history's own comment) -- this flag only governs
        # the estate-wide sweep button, which run_recurring_auto_mute itself further scopes to
        # this user's own editable groups when they're not a full admin.
        "can_mute": is_role_admin(request.user) or can_reach_my_alert_groups(request.user),
        "mute_recurring_url": reverse("alert_mute_recurring"),
    }


@never_cache
@login_required
def management_dashboard_alerts(request):
    """Executive - Alerts: a NEW, standalone 4th Management view (2026-09-30, on request,
    correcting an externally-supplied design spec that assumed raw Prometheus ALERTS/
    Alertmanager -- neither exists in this app; see reports.alert_catalog's own docstring).
    Deliberately does NOT touch or replace Full/Analytical/Focused -- those three had their
    own alert tiles removed on 2026-09-18 at the team's own request ("remove the alert table
    from both exec dashboards"), a decision this screen respects rather than reverses. Reached
    the same way as the other three: same is_management() gate, same nav drawer."""
    ctx = _alert_dashboard_context(request)
    if ctx is None:
        return redirect("report_form")
    return render(request, "reports/management_dashboard_alerts.html", ctx)


@never_cache
@login_required
def alert_comment_history(request):
    """AJAX drill-down for the Alert Dashboard's matrix popup (2026-10-01, on request: a
    clickable "third screen" from an affected item showing the last 10 admin comments on
    record for that exact issue). Same role gate as the dashboard itself -- this is purely a
    deeper look into data that screen already shows, not a new surface of its own.

    Also returns the candidate Monitoring groups for a quick "mute with this reason" action
    (2026-10-01, on request: "for those issues where admins affirm normal behaviour mute alert
    and use one of their comments as mute reason") when the caller passes `category` -- folded
    into this same response rather than a separate round-trip, since both need nothing more
    than `system` to look up, and computing the group list is cheap (AlertGroup is a small
    table; see monitoring_groups_for's own docstring).

    Permission-filtered PER FINDING, not just gated on a role (2026-10-02, on request: "we
    need to add some level of configuration access to the alert dashboard... admins only have
    controlled access even over their own alert groups... when you... try to mute an alert
    this would have to filter through the permissions you have as per your designated alert
    group"). A full Administrator sees every candidate group, same as before. A Sub-Admin-
    shaped user (roles.can_edit_alert_group -- holds a role with can_edit_own_alert_groups=True
    AND is personally a stakeholder on that specific group) only ever sees the groups they
    personally hold edit rights on; `groups` comes back empty, and `can_mute` False, for a
    finding that belongs to a group they're not on -- the popup never shows a mute button that
    would just 403, rather than showing one and explaining the rejection after the fact."""
    if not can_view_alert_dashboard(request.user):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    from . import alert_catalog
    from .models import AlertGroup

    system = (request.GET.get("system") or "").strip()
    flag_key = (request.GET.get("flag_key") or "").strip()
    category = (request.GET.get("category") or "").strip()
    if not system or not flag_key:
        return JsonResponse({"ok": False, "error": "system and flag_key are required"}, status=400)

    comments = alert_catalog.comment_history(system, flag_key, category=category)
    all_candidates = alert_catalog.monitoring_groups_for(system, category) if category else []
    if is_role_admin(request.user):
        groups = all_candidates
    else:
        editable_ids = {g.pk for g in AlertGroup.objects.filter(pk__in=[c["id"] for c in all_candidates])
                        if can_edit_alert_group(request.user, g)}
        groups = [c for c in all_candidates if c["id"] in editable_ids]
    can_mute = bool(groups)
    # Explain, not just omit, when the mute button won't show (2026-10-02, reported twice:
    # "still no clealy labelled mute button"). A PAUSED group's own findings can't land here
    # any more (2026-10-02, "muted should mean the same thing" -- AlertGroup.save() now writes
    # a real whole-category silence the instant a group pauses, so those findings are already
    # muted, not firing-with-a-missing-button) -- the two real cases left are a genuine
    # coverage gap (no AlertGroup names this system/category at all, active or not -- found
    # live on "Voice Recorder") and a Sub-Admin viewing a group they don't personally hold
    # edit rights on.
    mute_unavailable_reason = None
    if not can_mute and comments and category:
        if all_candidates:
            mute_unavailable_reason = "Mute isn't available — you're not a stakeholder on the alert group that covers this."
        else:
            mute_unavailable_reason = (
                f"Mute isn't available — no Alert Group covers {system} for this category at "
                f"all, so there's nobody for a silence to roll into. This also means nobody is "
                f"notified for it today; add {system} to an Alert Group in Alert Groups config "
                f"first.")
    return JsonResponse({"ok": True, "comments": comments, "can_mute": can_mute, "groups": groups,
                        "mute_unavailable_reason": mute_unavailable_reason})


@never_cache
@login_required
@require_POST
def alert_mute_from_comment(request):
    """Create an AlertSilence straight from the comment drill-down popup, using one of the
    admin's own past comments as the mute reason verbatim (2026-10-01, on request: "for those
    issues where admins affirm normal behaviour mute alert and use one of their comments as
    mute reason"). Same validation and same AlertSilence.objects.create(...) shape as
    config_alerts' own "silence" section -- this is a second ENTRY POINT into identical
    behaviour, not a parallel implementation, so the two can never quietly diverge on what
    counts as a valid silence.

    Deliberately re-validates `group` against monitoring_groups_for(system, category) itself
    rather than trusting whatever group id the client posted back -- the client only ever saw
    that list to populate its own picker, but a request body is never trusted input.

    Permission-checked per GROUP, not just role (2026-10-02, on request: "when you open the
    dashboard and try to... mute an alert this would have to filter through the permissions
    you have as per your designated alert group, a cleanly designed error... should pop up
    when you try to mute an alert that does not belong to your group"). The comment popup's
    own group picker already only ever offers groups roles.can_edit_alert_group approves for
    this user (see alert_comment_history's own comment), so this re-check is a defence against
    a stale/tampered request, not the normal path -- but when it DOES trip, it returns the
    specific access_denied case the request asked for, distinct from "that group doesn't even
    cover this finding" (a genuinely different, plain-400 mistake)."""
    if not (is_role_admin(request.user) or can_reach_my_alert_groups(request.user)):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    from . import alert_catalog
    from .models import AlertGroup, AlertSilence

    system = (request.POST.get("system") or "").strip()
    category = (request.POST.get("category") or "").strip()
    flag_key = (request.POST.get("flag_key") or "").strip()
    reason = (request.POST.get("reason") or "").strip()
    try:
        group_id = int(request.POST.get("group") or "0")
    except ValueError:
        group_id = 0
    try:
        days = int(request.POST.get("expires_days") or "60")
    except ValueError:
        days = 60

    category_labels = dict(AlertGroup.CATEGORY_CHOICES)
    if not (system and category in category_labels and flag_key and reason):
        return JsonResponse({"ok": False, "error": "System, category, flag_key and a reason are all required."}, status=400)
    if days <= 0:
        return JsonResponse({"ok": False, "error": "Expires in: enter a whole number of days greater than zero."}, status=400)

    allowed_groups = {g["id"]: g["name"] for g in alert_catalog.monitoring_groups_for(system, category)}
    if group_id not in allowed_groups:
        return JsonResponse({"ok": False, "error": "Pick a monitoring alert group that actually covers this system/category."}, status=400)
    group = AlertGroup.objects.get(pk=group_id)
    if not can_edit_alert_group(request.user, group):
        return JsonResponse({
            "ok": False, "access_denied": True, "group_name": group.name,
            "error": f"You can mute alerts for your own Alert Group's systems — this one belongs to “{group.name}”, which you're not a stakeholder of.",
        }, status=403)

    if AlertSilence.objects.filter(system=system, category=category, flag_key=flag_key, active=True).exists():
        return JsonResponse({"ok": False, "error": f"{system} — {flag_key} is already silenced."}, status=400)

    AlertSilence.objects.create(
        system=system, category=category, flag_key=flag_key, group=group,
        reason=reason, created_by=request.user,
        expires_at=timezone.now() + datetime.timedelta(days=days))
    return JsonResponse({"ok": True, "message": f"Silenced {system} — {flag_key}. {group.name} will get a daily digest instead."})


@never_cache
@login_required
@require_POST
def alert_mute_bulk(request):
    """Bulk version of alert_mute_from_comment (2026-10-02, on request: "way too many to mute
    one by one allow a select then mute option" -- the comment-popup's own per-item flow asks
    for a reason/group/expiry on every single finding, workable for one or two, not the 10
    Degraded/Network findings that prompted this). ONE shared reason/expiry across every
    selected item -- the GROUP is still resolved per item (monitoring_groups_for), same auto-
    pick-the-one-candidate logic the single-item popup already uses, since items selected
    together can still belong to different Alert Groups; there's no single group field to ask
    for here the way the one-item form has one.

    Each item is independently validated and muted or skipped -- one item failing (ambiguous
    group, access denied, already muted, invalid) never blocks the rest, and the response
    names exactly which and why, same "never fail silently" standard as every other mute/
    unmute action on this page. `items` is a JSON array of {"system","category","flag_key",
    "label"} the client already has on hand from the SAME affected-items list the popup
    renders, not re-derived here."""
    if not (is_role_admin(request.user) or can_reach_my_alert_groups(request.user)):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    import json

    from . import alert_catalog
    from .models import AlertGroup, AlertSilence

    reason = (request.POST.get("reason") or "").strip()
    try:
        days = int(request.POST.get("expires_days") or "60")
    except ValueError:
        days = 60
    try:
        items = json.loads(request.POST.get("items") or "[]")
    except (ValueError, TypeError):
        items = []
    if not isinstance(items, list):
        items = []

    if not reason:
        return JsonResponse({"ok": False, "error": "A reason is required."}, status=400)
    if days <= 0:
        return JsonResponse({"ok": False, "error": "Expires in: enter a whole number of days greater than zero."}, status=400)
    if not items:
        return JsonResponse({"ok": False, "error": "Select at least one finding."}, status=400)

    category_labels = dict(AlertGroup.CATEGORY_CHOICES)
    expires_at = timezone.now() + datetime.timedelta(days=days)
    muted, skipped = [], []
    for item in items[:200]:   # a sane upper bound -- never trust a client-supplied list length
        if not isinstance(item, dict):
            continue
        system = (item.get("system") or "").strip()
        category = (item.get("category") or "").strip()
        flag_key = (item.get("flag_key") or "").strip()
        label = (item.get("label") or "").strip() or f"{system} — {flag_key or category}"
        if not (system and category in category_labels and flag_key):
            skipped.append({"label": label, "reason": "Invalid finding."})
            continue
        if AlertSilence.objects.filter(system=system, category=category, flag_key=flag_key, active=True).exists():
            skipped.append({"label": label, "reason": "Already silenced."})
            continue
        candidates = alert_catalog.monitoring_groups_for(system, category)
        if len(candidates) != 1:
            skipped.append({"label": label, "reason": "More than one Alert Group covers this — "
                                                       "mute it individually to pick one." if candidates
                                                       else "No Alert Group covers this."})
            continue
        group = AlertGroup.objects.get(pk=candidates[0]["id"])
        if not can_edit_alert_group(request.user, group):
            skipped.append({"label": label, "reason": f"Not your Alert Group ({group.name})."})
            continue
        AlertSilence.objects.create(
            system=system, category=category, flag_key=flag_key, group=group,
            reason=reason, created_by=request.user, expires_at=expires_at)
        muted.append(label)
    return JsonResponse({"ok": True, "muted": muted, "skipped": skipped})


@never_cache
@login_required
@require_POST
def alert_unmute(request):
    """Reverse of alert_mute_from_comment -- turn a real AlertSilence back off, straight from
    the Muted panel's own affected-items popup (2026-10-02, on request: "what about the
    ability to mute and unmute from alert dashboard we described" -- the dashboard could mute
    but never undo it). Same per-GROUP permission check as muting
    (roles.can_edit_alert_group), same access_denied shape when it fails -- an admin can only
    ever unmute what they could have muted themselves.

    Turns off a REAL AlertSilence row, full stop -- exact-flag_key match first, falling back
    to the whole-category silence that would also cover it (the same two shapes
    AlertSilence.is_category_wide already distinguishes). This used to branch into a whole
    second path for findings muted by a PAUSED AlertGroup, which had no AlertSilence row to
    toggle at all (2026-10-02, "muted should mean the same thing we cant have a muted unmuted
    transient state... when i tell you to pause a notification... this should translate to a
    mute") -- AlertGroup.save() now WRITES a real whole-category silence the moment a
    Monitoring group is paused (see that method's own docstring), so a pause-muted finding is
    just a silence like any other by the time this view runs. Unmuting one here only releases
    that ONE (system, category) -- it does not reactivate the group, and the group stays
    paused for everything else still covered by its own pause-silences, which is the more
    literal reading of "a mute is a mute": every mute, whatever created it, is the same single
    row, independently toggleable, nothing special about this one's origin."""
    if not (is_role_admin(request.user) or can_reach_my_alert_groups(request.user)):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    from .models import AlertSilence

    system = (request.POST.get("system") or "").strip()
    category = (request.POST.get("category") or "").strip()
    flag_key = (request.POST.get("flag_key") or "").strip()
    if not system or not category:
        return JsonResponse({"ok": False, "error": "System and category are required."}, status=400)

    silence = AlertSilence.objects.filter(
        system=system, category=category, flag_key=flag_key, active=True).first()
    if not silence and flag_key:
        silence = AlertSilence.objects.filter(
            system=system, category=category, flag_key="", active=True).first()
    if not silence:
        # This button only ever renders on an item the popup is already showing as muted, so
        # landing here means the real state moved since that popup loaded (the silence
        # expired, or someone else already unmuted it) -- never a dead end with no explanation
        # (2026-10-02, reported twice on the mute side before every case there got a reason).
        return JsonResponse({
            "ok": False,
            "error": "This isn't muted anymore — the silence may have expired, or someone "
                    "else already unmuted it. Refresh the dashboard to see the current state.",
        }, status=400)

    if not can_edit_alert_group(request.user, silence.group):
        return JsonResponse({
            "ok": False, "access_denied": True, "group_name": silence.group.name,
            "error": f"You can unmute alerts for your own Alert Group's systems — this one belongs to “{silence.group.name}”, which you're not a stakeholder of.",
        }, status=403)

    silence.active = False
    silence.save(update_fields=["active"])
    scope = flag_key or f"{category} (all)"
    return JsonResponse({"ok": True, "message": f"Unmuted {system} — {scope}."})


@never_cache
@login_required
@require_POST
def alert_mute_recurring(request):
    """"Mute recurring" dashboard button (2026-10-01, on request, right after the recurring-
    comment auto-mute mechanism itself was built: a button "that triggers the mechanism we
    just defined"). An on-demand sweep of every currently open finding via
    alert_catalog.run_recurring_auto_mute -- the normal path only checks whatever a just-
    submitted report touched, so this is how a finding that ALREADY qualifies right now (no
    new report needed) gets caught without waiting for one. Same is_role_admin gate as every
    other silence-creating surface on this page.

    Two-step confirm (2026-10-02, on request: "the mute recurring button should also open a
    confirmation dialog where it shows the results of its assessments... and a confirmation
    button") -- POST without `confirm` previews (dry_run=True, nothing written, returns
    `candidates`); POST with `confirm=1` applies the SAME evaluation for real (returns
    `muted`). Two separate requests rather than a single one returning both, so a slow click
    between preview and confirm can never apply a stale assessment silently -- the confirm
    request re-runs the real criteria at the moment it's clicked, not just replays a cached
    preview.

    Open to any Sub-Admin-shaped user now, not just a full Administrator (2026-10-02, on
    request: muting "would have to filter through the permissions you have as per your
    designated alert group") -- run_recurring_auto_mute's own `user` param scopes the sweep
    to findings whose covering group this specific user holds edit rights on; a full admin's
    own sweep is completely unchanged (every finding, as before)."""
    if not (is_role_admin(request.user) or can_reach_my_alert_groups(request.user)):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    from . import alert_catalog

    confirm = request.POST.get("confirm") == "1"
    result = alert_catalog.run_recurring_auto_mute(dry_run=not confirm, user=request.user)
    if confirm:
        return JsonResponse({"ok": True, "checked": result["checked"], "muted": result["muted"]})
    return JsonResponse({"ok": True, "checked": result["checked"], "candidates": result["candidates"]})


@never_cache
@login_required
def role_select(request):
    """The screen you land on after signing in: which role am I working as today?

    Only shown when there is a genuine choice. One role means there is nothing to pick, so
    it is selected silently and the user goes straight to work — a confirmation dialog with
    a single button is a speed bump, not a feature.

    Selecting a role SCOPES THE MENU. It does not grant anything: the per-view permission
    checks are untouched, so a role you do not hold stays shut whatever is chosen here.
    """
    held = held_roles(request.user)
    pending = set(request.user.role_requests.filter(status="pending").values_list("role", flat=True))

    if request.method == "POST":
        # Requesting a role you do not hold — the same action the first-login screen offers,
        # so the two screens differ in presentation and not in what they can do.
        wanted = [r for r in request.POST.getlist("request_role") if r in SELECTABLE_ROLE_NAMES]
        if wanted:
            created = 0
            for r in wanted:
                if r not in held and r not in pending:
                    RoleRequest.objects.create(user=request.user, role=r)
                    created += 1
            messages.success(request, f"Requested {created} role(s). An administrator will review it."
                             if created else "Those roles are already held or already requested.")
            return redirect("role_select")

        chosen = (request.POST.get("role") or "").strip()

        # "Load all my roles" — the UNSCOPED state, which the app has always had internally
        # for a session that never picked. It is offered again deliberately: someone who holds
        # several roles and is doing a round of everything should not have to walk back through
        # this screen between estates. Clearing the key rather than storing a sentinel keeps it
        # the same state a fresh session is already in, so nothing downstream needs to know
        # about a special value.
        if chosen == ALL_ROLES:
            request.session.pop(ROLE_SESSION_KEY, None)
            messages.success(request, "Working across all your roles.")
            return redirect("report_form")

        if chosen in held:
            request.session[ROLE_SESSION_KEY] = chosen
            messages.success(request, f"Working as {chosen}.")
            return redirect(ROLE_HOME.get(chosen, "report_form"))
        else:
            messages.error(request, "That is not a role you hold.")
        return redirect("role_select")

    # No auto-forward, for anyone. Signing in ALWAYS lands here.
    #
    # A single-role holder used to be skipped past this screen on the grounds that a question
    # with one answer is a speed bump. But the screen answers a second question as well —
    # what the other roles are, and how to ask for one — and skipping it meant the people who
    # most needed that answer were the only ones who never saw it. It is also the one moment
    # the app states plainly which hat you are wearing; arriving somewhere already scoped,
    # having chosen nothing, is how you end up unsure which estate you are looking at.
    #
    # It also means nobody is ever dropped into the UNSCOPED state by default. Landing without
    # a selection shows every screen from every role held at once, which is precisely what
    # picking a role exists to narrow.
    return render(request, "reports/role_select.html", {
        # Every SELECTABLE role in the catalogue (ROLE_NAMES minus Sub Admin -- see
        # SELECTABLE_ROLE_NAMES' own comment), each with its standing. The first-login screen
        # already lists them all; showing only what you hold here made the app look like it
        # had two different ideas of how many roles exist.
        "roles": [{"name": r,
                   "description": ROLE_DESCRIPTIONS.get(r, ""),
                   "icon": role_icon(r),
                   "pages": role_screens(r),
                   "held": r in held,
                   "pending": r in pending} for r in SELECTABLE_ROLE_NAMES],
        "held_count": len(held),
        "current": active_role(request),
        # offered only to someone with more than one role — for everyone else "all my roles"
        # and "my role" are the same thing, and a tile that changes nothing is noise
        "offer_all_roles": len(held) > 1,
        "all_roles_value": ALL_ROLES,
        "all_roles_label": ALL_ROLES_LABEL,
        "all_roles_icon": ALL_ROLES_ICON,
        "all_roles_description": ALL_ROLES_DESCRIPTION,
        "unscoped": not active_role(request),
    })


#: session keys holding when an open report lapses, per estate. An open report is a claim on
#: the admin's attention ("your answers are still there"), so it has to expire on its own —
#: otherwise the resume bar offers to continue a report whose numbers went stale hours ago.
_OPEN_UNTIL = {"systems": "report_expires_at",
              "infra": "infra_report_expires_at",
              "active_directory": "active_directory_report_expires_at",
              # Networks Report category (2026-09-22, split into four reports 2026-09-23 --
              # see roles.REPORTS' own comment) -- one estate entry per picker, same shape as
              # every other estate here, not a single "switches_routers" entry any more.
              "core_switches": "core_switches_report_expires_at",
              "routers": "routers_report_expires_at",
              "wireless_controller": "wireless_controller_report_expires_at",
              "access_switches": "access_switches_report_expires_at",
              "firewalls": "firewalls_report_expires_at"}

#: session keys an estate's open report claims, cleared together once it lapses or is closed.
_ESTATE_SESSION_KEYS = {
    "systems": {"report_systems", "snapshot_token", "report_expires_at"},
    "infra":   {"infra_report_systems", "infra_snapshot_token", "infra_report_expires_at"},
    "active_directory": {"active_directory_report_systems", "active_directory_snapshot_token",
                         "active_directory_report_expires_at"},
    "core_switches": {"core_switches_devices", "core_switches_token",
                      "core_switches_report_expires_at"},
    "routers": {"routers_devices", "routers_token", "routers_report_expires_at"},
    "wireless_controller": {"wireless_controller_devices", "wireless_controller_token",
                            "wireless_controller_report_expires_at"},
    "access_switches": {"access_switches_devices", "access_switches_token",
                        "access_switches_report_expires_at"},
    "firewalls": {"firewalls_devices", "firewalls_token", "firewalls_report_expires_at"},
}


def _open_report_seconds(request, estate: str) -> int:
    """Seconds left on the open report, 0 if none or lapsed. Clears the session when it has.

    Cleared HERE rather than by a background job: the picker is where the claim is displayed,
    so the moment it is looked at is exactly when it should be honest about being over.
    """
    until = request.session.get(_OPEN_UNTIL[estate]) or 0
    left = int(until - time.time())
    if left <= 0:
        if until:
            _close_open_report(request, estate)
        return 0
    return left


def _close_open_report(request, estate: str) -> None:
    for k in _ESTATE_SESSION_KEYS.get(estate, ()):
        request.session.pop(k, None)
# ---------------------------------------------------------------------------------------
#  Reports — the landing screen after Role Select
# ---------------------------------------------------------------------------------------
@never_cache
@login_required
def reports(request):
    """Which report am I running?

    The choice that comes BEFORE which systems it covers, so it sits in front of the pickers
    rather than beside them. Most roles have one and go straight through; Security Admin has
    two, which is what made a screen necessary rather than a menu entry per report.

    Tiles rather than a list, matching Role Select: the two screens ask the same shape of
    question one after the other, and answering them in two different visual languages makes
    the second look like a different kind of decision than it is.
    """
    available = reports_for(effective_roles(request))
    if not available:
        # Administrator configures the app rather than reporting on it; a role with no estate
        # yet has its own screen that says so. Neither should meet an empty grid.
        return redirect("configuration" if is_role_admin(request.user) else "role_empty")
    # `available` is built from effective_roles (the UNION of every role the user HOLDS, per
    # reports_for's own docstring), so a user holding both System Admin and Security Admin
    # still sees Automated Reports' tile exactly ONCE here regardless of role -- the label
    # override below therefore has to happen at RENDER time, keyed on active_role (the single
    # role currently SELECTED), not by adding a second roles.REPORTS entry for System Admin --
    # that would have shown two separate tiles to anyone holding both roles at once, pointing
    # at the identical page. 2026-09-10, on request ("its Automated Reports but only in the
    # System Admin Role") -- see _automated_reports_label's own docstring.
    options = []
    for r in available:
        label = _automated_reports_label(request) if r.key == "automated_reports" else r.label
        options.append({"key": r.key, "label": label, "blurb": r.blurb,
                        "url": reverse(r.url_name), "icon": r.icon, "initial": label[:1],
                        "category": r.category})
    # Grouped by category (2026-09-22, for the new "Networks Report" family) -- ungrouped
    # tiles (category == "") render first, in `available`'s own order, exactly as the screen
    # looked before this grouping existed; a truthy category gets its own heading afterwards.
    # Built here rather than via Django's {% regroup %} (which requires the list pre-sorted by
    # the group key, awkward when most items share the same "" category) -- a plain dict keeps
    # first-seen order for free and needs no sort.
    grouped: list = []
    by_category: dict = {}
    for o in options:
        cat = o["category"] or None
        if cat not in by_category:
            by_category[cat] = {"category": cat, "items": []}
            grouped.append(by_category[cat])
        by_category[cat]["items"].append(o)
    grouped.sort(key=lambda g: g["category"] is not None)
    # "options" kept alongside "groups" (2026-09-22) -- the flat list every existing test/
    # caller already reads (response.context["options"]) predates the grouping work; dropping
    # it in favour of "groups" alone broke every one of them. "groups" is what the template
    # actually renders from; "options" is the same tiles, ungrouped, for anything reading the
    # flat shape.
    return render(request, "reports/reports.html", {"groups": grouped, "options": options})


@never_cache
@login_required
def os_inventory(request):
    """OS Inventory — every host's operating system, patch level and support status.

    No system picker, unlike the other reports. An inventory that covered only the systems
    someone happened to tick would answer "what is the oldest OS we run" with a number that
    depends on the ticking; the question is only meaningful across the whole estate.

    Built on demand rather than from a cached snapshot: it reads two constant gauges rather
    than the wide metric sweep the health report needs, so there is nothing expensive to
    amortise and nothing to go stale between choosing and downloading.
    """
    if not (is_security_admin(request.user) or request.user.is_superuser):
        return redirect("reports")

    if request.method == "POST":
        theme = request.POST.get("theme")
        if theme not in ("dark", "light"):
            theme = getattr(getattr(request.user, "profile", None),
                            "default_report_theme", "dark")
        try:
            data, hosts, eol, extended = build_os_inventory(theme)
        except OsInventoryUnavailable as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
        filename = default_os_inventory_filename(timezone.localtime())
        ReportSubmission.objects.create(
            generated_by=request.user,
            author=_profile_author(request.user),
            theme=theme,
            delivery="download",
            prom_url=SystemConfig.get().prometheus_url or gr.load_config().prom,
            hosts_count=hosts,
            immediate_count=eol,          # end-of-life hosts are the report's red band
            watch_count=extended,         # extended-support-only are its amber
            filename=filename,
            report_content={"kind": "os_inventory", "hosts": hosts,
                            "end_of_life": eol, "extended_support": extended},
        )
        response = HttpResponse(
            data,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return mark_xlsx_download(response)

    return render(request, "reports/os_inventory.html", {
        "default_theme": getattr(getattr(request.user, "profile", None),
                                 "default_report_theme", "dark"),
    })


_BACKUP_HISTORY_MAX_DAYS = 92   # one quarter -- generous for the real use case (auditing a
                               # recent stretch), bounded so a typo'd decade-wide range can't
                               # trigger an unbounded sweep of per-day/per-instance queries.


def _backup_history_defaults(earliest):
    today = timezone.localtime().date()
    default_from = today - datetime.timedelta(days=7)
    if earliest and default_from < earliest:
        default_from = earliest
    return default_from, today


@never_cache
@login_required
def backup_history_report(request):
    """Backup History Report — a date range in, an estate-wide per-day/per-instance audit out
    (reachable / current-backup-available / real filename+timestamp when archived / which
    report that day traces back to). No system picker, same shape as os_inventory's own
    "GET shows the form, POST regenerates and downloads" flow — see build_backup_history_report
    in services.py for what the workbook actually contains and why.
    """
    if not (is_system_admin(request.user) or request.user.is_superuser):
        return redirect("reports")

    earliest = earliest_backup_history_date()
    default_from, default_to = _backup_history_defaults(earliest)

    if request.method == "POST":
        theme = request.POST.get("theme")
        if theme not in ("dark", "light"):
            theme = getattr(getattr(request.user, "profile", None),
                            "default_report_theme", "dark")
        raw_from, raw_to = request.POST.get("from", ""), request.POST.get("to", "")
        try:
            date_from = datetime.date.fromisoformat(raw_from)
            date_to = datetime.date.fromisoformat(raw_to)
        except ValueError:
            messages.error(request, "Enter two valid dates.")
            return redirect("backup_history_report")
        if date_from > date_to:
            messages.error(request, "The \"from\" date must be on or before the \"to\" date.")
            return redirect("backup_history_report")
        if date_to > timezone.localtime().date():
            messages.error(request, "The \"to\" date can't be in the future.")
            return redirect("backup_history_report")
        if (date_to - date_from).days + 1 > _BACKUP_HISTORY_MAX_DAYS:
            messages.error(request, f"Pick a range of {_BACKUP_HISTORY_MAX_DAYS} days or fewer.")
            return redirect("backup_history_report")
        if earliest is None:
            messages.error(request, "No backup data has been archived yet — nothing to report on.")
            return redirect("backup_history_report")
        if date_from < earliest:
            messages.error(request, f"No backup data is archived before {earliest:%d %b %Y}.")
            return redirect("backup_history_report")

        try:
            data, days, no_backup, no_report, rows = build_backup_history_report(
                date_from, date_to, theme)
        except BackupHistoryUnavailable as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=502)

        filename = default_backup_history_filename(timezone.localtime())
        ReportSubmission.objects.create(
            generated_by=request.user,
            author=_profile_author(request.user),
            theme=theme,
            delivery="download",
            prom_url=SystemConfig.get().prometheus_url or gr.load_config().prom,
            hosts_count=days,
            immediate_count=no_backup,    # days×systems with no current backup -- red band
            watch_count=no_report,        # days with no report at all that day -- amber band
            filename=filename,
            report_content={"kind": "backup_history", "date_from": str(date_from),
                            "date_to": str(date_to), "rows": rows},
        )
        response = HttpResponse(
            data,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return mark_xlsx_download(response)

    return render(request, "reports/backup_history.html", {
        "default_theme": getattr(getattr(request.user, "profile", None),
                                 "default_report_theme", "dark"),
        "default_from": default_from,
        "default_to": default_to,
        "min_date": earliest,              # None if the archive is completely empty -- the
                                            # template just skips the min= attribute then,
                                            # rather than rendering min="None".
        "max_date": default_to,            # "today" -- the date picker shouldn't offer the
                                            # future either, same rule the POST handler already
                                            # enforces server-side.
        "no_data_yet": earliest is None,
    })


def _automated_reports_gate(user) -> bool:
    return is_system_admin(user) or is_security_admin(user) or user.is_superuser


def _automated_reports_label(request) -> str:
    """"Analytical Reports" for a session CURRENTLY ACTING as System Admin, "Automated Reports"
    for everyone else who can reach this screen (Security Admin, or an unscoped/superuser
    session that hasn't picked a role) -- 2026-09-10, on request ("its Automated Reports but
    only in the System Admin Role"): a display-label rename scoped to how this ONE role sees
    the feature, not a rename of the feature itself -- reports.models.AutomatedReportGroup,
    reports.automated_reports's own module, the config_automated_reports screen, and every
    other role/internal name stay "Automated Report(s)" unchanged. Checked against
    active_role(request), not is_system_admin(user), since the same user can hold both System
    Admin and Security Admin and see either label depending which they've currently selected."""
    return "Analytical Reports" if active_role(request) == SYSTEM_ADMIN_ROLE else "Automated Reports"


@login_required
@never_cache
def automated_reports(request):
    """Automated Reports tile landing page (spec "New Promt.txt", section 17): the six
    scheduled report types, each with its most recent stored instance, so an admin can see
    at a glance whether anything new has landed since they last looked."""
    if not _automated_reports_gate(request.user):
        return redirect("reports")

    cards = []
    for key, spec in REPORT_TYPES.items():
        latest = (AutomatedReportInstance.objects.filter(report_type=key)
                 .order_by("-generated_at").first())
        cards.append({"key": key, **spec, "latest": latest})

    return render(request, "reports/automated_reports.html", {
        "cards": cards,
        "sc": SystemConfig.get(),
        "can_toggle_distribution": request.user.is_superuser,
        "page_label": _automated_reports_label(request),
    })


@login_required
@never_cache
def automated_report_type(request, report_type):
    """One report type's browsable history (Phase 5 item 13), plus a "Generate now" action
    an administrator uses to produce a fresh instance to review -- the same action the
    scheduled job runs unattended, and the only way System Attention Report ever gets a new
    instance at all, since that one type deliberately has no cron (section 17: "doesn't wait
    for a scheduled cycle")."""
    if not _automated_reports_gate(request.user):
        return redirect("reports")
    if report_type not in REPORT_TYPES:
        raise Http404("Unknown Automated Report type.")

    if request.method == "POST":
        report = generate_automated_report(report_type)
        instance = AutomatedReportInstance.objects.create(
            report_type=report_type, generated_at=report.generated_at,
            window_start=report.window_start, window_end=report.window_end,
            ai_provider=report.ai_provider, ai_requested_provider=report.ai_requested_provider,
            ai_error=report.ai_error, content=report_to_dict(report),
        )
        messages.success(request, f"Generated a fresh {report.label}.")
        return redirect("automated_report_detail", report_type=report_type, pk=instance.pk)

    instances = (AutomatedReportInstance.objects.filter(report_type=report_type)
                .order_by("-generated_at")[:60])
    return render(request, "reports/automated_report_history.html", {
        "spec": {"key": report_type, **REPORT_TYPES[report_type]},
        "instances": instances,
        "page_label": _automated_reports_label(request),
    })


@login_required
@require_POST
def automated_finding_action(request):
    """Saves one (system, flag_key) finding's Comment/Fix needed?/Resolved -- 2026-09-10, item
    10a. Updates the LIVE AutomatedFindingAction record (the value that carries forward into
    every FUTURE report run); the report instance the admin is currently looking at keeps
    showing whatever was already frozen into it at generation time until the NEXT run picks
    this edit up -- consistent with AutomatedReportInstance's own append-only/immutable
    design (see that model's own docstring), not a special case invented for this feature.

    Takes system/flag_key as POST fields, not URL path segments -- a flag_key routinely
    contains colons and slashes (e.g. "disk:DB:E:"), which would need per-character escaping
    to survive as a raw path component; a POST body has no such restriction."""
    from .models import AutomatedFindingAction

    if not _automated_reports_gate(request.user):
        return redirect("reports")

    system = (request.POST.get("system") or "").strip()
    flag_key = (request.POST.get("flag_key") or "").strip()
    next_url = request.POST.get("next") or reverse("reports")
    if not system or not flag_key:
        messages.error(request, "That finding could not be identified — nothing was saved.")
        return redirect(next_url)

    def _tristate(field):
        raw = request.POST.get(field, "")
        return raw if raw in (AutomatedFindingAction.YES, AutomatedFindingAction.NO) else AutomatedFindingAction.UNSET

    AutomatedFindingAction.objects.update_or_create(
        system=system, flag_key=flag_key,
        defaults={
            "comment": (request.POST.get("comment") or "").strip(),
            "fix_needed": _tristate("fix_needed"),
            "resolved": _tristate("resolved"),
            "updated_by": request.user,
        },
    )
    messages.success(request, f"Saved for {system} · {flag_key}. Takes effect on this "
                              f"finding's next report run.")
    return redirect(next_url)


def _extra_report_charts(content: dict, window_days: int, generated_at) -> dict:
    """The 4 new diagrams added 2026-09-10 (spec items 11-14): Pareto chart, category-
    breakdown donut, onset timeline, and aggregate-total sparklines -- SHARED between
    automated_report_detail (web) and build_automated_report_pdf (PDF/email), so all three
    surfaces render the identical image rather than three independent computations that could
    quietly drift. Rendered as static matplotlib PNGs everywhere, including the web view --
    unlike the donut/attention/themes charts (live Chart.js on web), these 4 don't currently
    have a web-interactive counterpart; adding one for each was out of scope for landing all
    four diagrams in one pass, and a static image is still a real chart, which is what items
    11-14 actually asked for. Returns {"pareto":, "category_breakdown":, "onset_timeline":,
    "totals_sparklines":} -- each a data URI or None if there was nothing to chart."""
    from . import report_charts
    from .totals_integrity import all_totals_series

    return {
        "pareto": report_charts.pareto_chart(content.get("system_attention", [])),
        "category_breakdown": report_charts.category_breakdown_chart(
            content.get("recurring_issues", [])),
        "onset_timeline": report_charts.onset_timeline_chart(
            content.get("recurring_issues", [])),
        "totals_sparklines": report_charts.totals_sparklines_chart(
            all_totals_series(window_days=window_days, now=generated_at)),
    }


def _persistent_recurring_counts(content: dict) -> tuple:
    recurring_issues = content.get("recurring_issues", [])
    persistent = sum(1 for i in recurring_issues if i.get("label") == "Persistent")
    return persistent, len(recurring_issues) - persistent


def _split_persistent_recurring(content: dict) -> tuple:
    """`report.recurring_issues` (the flat Persistent+Recurring pool) split into its own two
    lists -- Persistent and Recurring get separate report sections/tables now (2026-09-07, on
    request, after confirming a combined heatmap can't actually let a viewer tell them apart:
    a raw distinct-days count reads identically for 40/50 days, 80% coverage, Persistent, and
    40/200 days, 20% coverage, Recurring). Relative order is preserved from classify_all's own
    significance ranking -- filtering never reorders."""
    recurring_issues = content.get("recurring_issues", [])
    persistent = [i for i in recurring_issues if i.get("label") == "Persistent"]
    recurring = [i for i in recurring_issues if i.get("label") == "Recurring"]
    return persistent, recurring


#: Column-width legibility floor and the resulting portrait/landscape/collapse thresholds
#: (2026-09-10, item 23) -- confirmed against this report's own real print stylesheet: at the
#: portrait content width (~860px web / ~490pt PDF), a column narrower than ~200px is where
#: component labels ("DR Servers DB:/u01", "Backend:/perago") stop fitting on one line. 4
#: columns clears that floor in portrait; a 5th column needs landscape's wider content area to
#: clear it; 6+ drops below the floor even in landscape, so those get capped and folded behind
#: "+N more" rather than shrunk past legibility. A PER-REPORT switch (the whole PDF goes
#: landscape if ANY system needs a 5th simultaneous column), not per-page -- mixing orientations
#: within one PDF is real added production complexity item 23 explicitly said isn't worth
#: taking on here.
_SPIKE_COLS_PORTRAIT_MAX = 4
_SPIKE_COLS_LANDSCAPE_MAX = 5
_SPIKE_CHARTS_PER_COLUMN_MAX = 3   # "+N more" beyond this, per column, per item 23's own note


def _spike_chart_targets(recurring_issues: list) -> list:
    """Shared plumbing between automated_report_detail (Chart.js JSON), automated_report_
    download (web images), and build_automated_report_pdf: one SYSTEM subsection per affected
    system, each carrying every metric CATEGORY currently active for that system as its own
    column (2026-09-10, item 23, regrouping from an earlier category-first shape on request:
    "CRB's three active metrics... split across separate Disk/RAM sections, which buries the
    '3+ metrics simultaneously active' fan-in finding the report itself calls out in §02...
    grouping every flagged system's charts together makes that co-occurrence visible instead of
    requiring the reader to cross-reference sections").

    Columns, not a fixed disk/RAM pair (item 23's own instruction) -- ONE column per metric
    category currently active for THAT system, whatever categories those happen to be, not a
    hardcoded "disk left, RAM right" that only works for a two-category system.

    A percentage category (report_charts.PERCENT_CATEGORIES) can have more than one component
    per system (two hosts' readings can't share one line -- see spike_flag_keys_for_category),
    so `components` there is every flag_key actually affected, one chart each. A count-based
    category has exactly one whole-system chart (no further split -- see spike_systems_for_
    category), so `components` there is always the single-element `[None]`.

    Returns [{"system":, "categories": [
        {"category":, "category_label":, "is_percent":, "components": [flag_key, ...] or [None]}
    , ...]}] for every system with at least one active category, sorted by system name --
    `categories` sorted by category name too, for a stable, reproducible column order across
    renders of the same report."""
    from . import report_charts

    by_system: dict = {}
    for cat in report_charts.spike_categories(recurring_issues):
        cat_label = report_charts.resource_type_label(cat)
        is_percent = cat in report_charts.PERCENT_CATEGORIES
        per_system: dict = {}
        if is_percent:
            for sysname, flag_key in report_charts.spike_flag_keys_for_category(recurring_issues, cat):
                per_system.setdefault(sysname, []).append(flag_key)
        else:
            for sysname in report_charts.spike_systems_for_category(recurring_issues, cat):
                per_system.setdefault(sysname, []).append(None)
        for sysname, components in per_system.items():
            by_system.setdefault(sysname, []).append({
                "category": cat, "category_label": cat_label, "is_percent": is_percent,
                "components": components,
            })

    groups = []
    for sysname in sorted(by_system):
        categories = sorted(by_system[sysname], key=lambda c: c["category"])
        groups.append({"system": sysname, "categories": categories,
                       "needs_landscape": len(categories) >= _SPIKE_COLS_PORTRAIT_MAX + 1})
    return groups


def _spike_report_needs_landscape(spike_targets: list) -> bool:
    """Whether ANY system in this report needs a 5th simultaneous column -- a PER-REPORT switch
    (item 23's own instruction), computed once, not per-system, so the whole PDF's own page
    orientation is decided consistently rather than per-page."""
    return any(g["needs_landscape"] for g in spike_targets)


@login_required
@never_cache
def automated_report_detail(request, report_type, pk):
    """One stored instance, viewed in the browser -- renders automated_report_download.html
    (the browser-facing template; the actual downloadable FILE is a PDF from its own template,
    see automated_report_download below) with `inline=True`, which switches on the small
    in-app-only action bar (Back / Download / Send now) that has no place in a saved file, and
    lets Django's messages framework render here even though this template doesn't extend
    base.html (deliberately: the report keeps one consistent look, not the rest of the app's
    chrome). Also builds the Chart.js data this template's charts render live -- the browser-
    side counterpart to the static PNGs reports.report_charts pre-renders for the PDF."""
    if not _automated_reports_gate(request.user):
        return redirect("reports")
    instance = get_object_or_404(AutomatedReportInstance, pk=pk, report_type=report_type)

    if request.method == "POST" and request.POST.get("action") == "send_now":
        if not request.user.is_superuser:
            return redirect("automated_report_detail", report_type=report_type, pk=pk)
        try:
            subject = send_automated_report(instance)
        except Exception as exc:   # noqa: BLE001 -- surface any SMTP/config failure to the admin
            messages.error(request, f"Not sent: {exc}")
        else:
            instance.distributed = True
            instance.distributed_at = timezone.now()
            instance.save(update_fields=["distributed", "distributed_at"])
            messages.success(request, f"Sent: {subject}")
        return redirect("automated_report_detail", report_type=report_type, pk=pk)

    from . import report_charts
    from .ai_narrative import narrative_sections
    persistent_count, recurring_count = _persistent_recurring_counts(instance.content)
    persistent_issues, recurring_only_issues = _split_persistent_recurring(instance.content)
    extra_charts = _extra_report_charts(
        instance.content, instance.content.get("window_days", 7), instance.generated_at)
    # Live/interactive on the web (hover tooltips, load-in animation) -- unlike the PDF view,
    # which renders these same three as static matplotlib PNGs (xhtml2pdf can't run JS or a
    # <canvas>). 2026-09-07, on request: a static image on the WEB page lost the hover-
    # description/animation behaviour the console's other live charts already have, and there's
    # no PDF-side reason to hold the web page back to match it.
    chart_data = report_charts.chart_data_json(
        instance.content, persistent_count, recurring_count,
        total_systems=instance.content.get("total_systems", 0))
    # A plain table, not a chart -- see report_charts.finding_table's own docstring for why the
    # bar chart this replaced (2026-09-08) stopped earning its space once most of its rows tied
    # at the same coverage/days.
    persistent_table = report_charts.finding_table(persistent_issues)
    recurring_table = report_charts.finding_table(recurring_only_issues)
    # One Hourly Activity chart per COMPONENT AFFECTED, grouped under its issue type and then
    # under the system it belongs to -- a live percentage reading for cpu/ram/disk (2026-09-08,
    # on request: "shouldn't it be the percentage reading... wouldn't it be easier to read" than
    # a concurrent-incident count); the count-based chart for everything else (unreachable/
    # service/backup*, a binary state with no percentage to show). Systems get their own
    # subsection with their component charts nested under it (same day, on request: "CEPECS DB
    # and CEPECS APP... why not just have cepecs be a subsection and the servers be the indented
    # children") rather than every (system, component) pair reading as an unrelated grid cell.
    # See _spike_chart_targets for the shared category/system/component selection both this view
    # and automated_report_download build from.
    recurring_issues = instance.content.get("recurring_issues", [])
    spike_charts = []
    idx = 0
    for sysgrp in _spike_chart_targets(recurring_issues):
        sysname = sysgrp["system"]
        columns = []
        for catrow in sysgrp["categories"]:
            cat, cat_label = catrow["category"], catrow["category_label"]
            is_percent = catrow["is_percent"]
            charts = []
            for flag_key in catrow["components"]:
                if flag_key:
                    # days=30 (2026-09-18, on request: "store this data... so we can have a
                    # much longer retention window") -- reads MetricSample now, not live
                    # Prometheus, so this is no longer bounded by Prometheus's own ~15-day
                    # retention. The web chart's own default ZOOM still opens on the most
                    # recent 7 days (see the haveZoomPlugin block below) -- this just gives it
                    # real room to scroll/pan back further than that.
                    data = report_charts.resource_percent_line_data(sysname, flag_key, cat, days=30)
                    label = report_charts.flag_location(flag_key)
                else:
                    data = report_charts.spike_line_data_single(sysname, cat, days=30)
                    label = None
                if data:
                    charts.append({"canvas_id": f"spikeLines-{idx}", "label": label, "data": data})
                    idx += 1
            if charts:
                # Cap charts PER COLUMN (item 23: "cap charts per column... rather than
                # continuing to shrink" when one category has far more components than
                # another) -- the rest fold behind a "+N more" the template renders, not
                # dropped from the data entirely (still counted, just not all pre-rendered).
                columns.append({
                    "category_label": cat_label, "is_percent": is_percent,
                    "charts": charts[:_SPIKE_CHARTS_PER_COLUMN_MAX],
                    "more_count": max(0, len(charts) - _SPIKE_CHARTS_PER_COLUMN_MAX),
                })
        if columns:
            spike_charts.append({"system": sysname, "columns": columns})
    # "cluster" (items 33-37) -- every chart under the same system shares this key so the
    # web page's own zoom plugin can sync a drag/pinch/preset-range on ANY chart to every
    # other chart in the same system's cluster. Web-only: the PDF/email pipeline below never
    # reads this key, and the value carries no meaning outside this page's own in-memory
    # Chart.js instances (never persisted, never sent back to the server).
    chart_data["spikeCharts"] = [
        {"canvasId": c["canvas_id"], "data": c["data"], "isPercent": col["is_percent"],
         "cluster": sysgrp["system"]}
        for sysgrp in spike_charts for col in sysgrp["columns"] for c in col["charts"]
    ]
    # SWIFT transaction throughput -- its own Hourly Activity line, alongside the per-category
    # ones above (2026-09-08, on request: "add trend analyses for swift transactions as well...
    # very similar to existing line graphs"). Not tied to a system/category/recurring_issues at
    # all (see report_charts.swift_transaction_series), so it's built and gated independently
    # rather than folded into the _spike_chart_targets loop above.
    swift_data = report_charts.swift_transaction_line_data(days=30)
    if swift_data:
        # "cluster": "swift" -- gives swiftLine the same generic zoom+pan+Range-buttons+
        # scrollbar treatment every Hourly Activity chart's own cluster gets above. A SEPARATE
        # second chart (canvas "swiftCompareLine", template-only -- see automated_report_
        # download.html's own script block) reuses this identical data to draw the week-over-
        # week comparison (2026-09-18, on request: "make this a separate graph keep the
        # original as well") rather than this one switching shape under a Range button.
        chart_data["spikeCharts"].append(
            {"canvasId": "swiftLine", "data": swift_data, "isPercent": False, "cluster": "swift"})
    # COB duration -- both the original chart and a separate week-over-week comparison chart,
    # same as SWIFT (2026-09-18, on request: "add the superimposed one for cob time same
    # style... both everywhere else" -- this report counts as "everywhere else"). No "cluster"
    # key: COB's own data is now ONE POINT PER DAY (on request: "one solid bar per day" --
    # see report_charts.cob_time_line_data's own docstring), so it never joins the generic
    # hourly zoom+pan+Range-buttons+scrollbar mechanism above -- there's nothing to scroll
    # through at ~30 total points, and "24h"/"3d" would be meaningless button labels at daily
    # resolution. Built and rendered standalone -- see the template's own script block.
    cob_data = report_charts.cob_time_line_data(days=30)
    if cob_data:
        chart_data["spikeCharts"].append(
            {"canvasId": "cobLine", "data": cob_data, "isPercent": False})
    return render(request, "reports/automated_report_download.html", {
        "instance": instance, "report": instance.content,
        "sections": narrative_sections(instance.content.get("narrative", {})),
        "persistent_count": persistent_count, "recurring_count": recurring_count,
        "chart_data": chart_data,
        "extra_charts": extra_charts,
        "spike_charts": spike_charts,
        "swift_available": bool(swift_data),
        "cob_available": bool(cob_data),
        # Editable Action fields (item 10a) -- explicit context flag/URL rather than relying on
        # template auto-context for `request`. This template is ONLY ever rendered from here
        # (the downloaded PDF is a wholly separate template, automated_report_pdf.html, always
        # read-only), so editing is always allowed on this render path.
        "action_next_url": request.get_full_path(),
        "persistent_grid": report_charts.heatmap_grid(
            report_charts.persistent_issue_matrix(instance.content.get("recurring_issues", []))),
        "recurring_grid": report_charts.heatmap_grid(
            report_charts.recurring_issue_matrix(instance.content.get("recurring_issues", []))),
        "persistent_table": persistent_table, "recurring_table": recurring_table,
        "can_send": request.user.is_superuser, "inline": True,
    })


class PdfRenderError(RuntimeError):
    """Raised by build_automated_report_pdf when xhtml2pdf itself reports an error -- callers
    decide whether that's a 500 page (the download view) or a reason to abort/log a send (the
    mail sender), the same "raise, don't swallow" discipline EmailNotConfigured already uses."""


def build_automated_report_pdf(instance, *, zoom_persistent: float = 1.0,
                               zoom_recurring: float = 1.0) -> bytes:
    """The presentation-quality PDF for one stored AutomatedReportInstance -- shared by
    automated_report_download (the in-app "Download PDF" link) and automated_reports_mail.
    send_automated_report (2026-09-08, on request: the e-mailed report "had zero graphs... at
    least just send a pdf no need to use outlook html with its limitations" -- the Outlook-safe
    HTML body was deliberately chart-free from the start, since xhtml2pdf's renderer and an
    Outlook-safe inbox have almost nothing in common; attaching this actual PDF, which DOES
    carry every chart, is the fix, not trying to teach the HTML body to draw them).

    Rendered from automated_report_pdf.html, not automated_report_download.html: xhtml2pdf's
    renderer is reportlab-based, not a browser engine (no CSS variables, no grid/flexbox, no
    media queries) -- the same reason alert_email_templates.py renders a separate, plainer
    template for Outlook rather than reusing the browser-facing one.

    Raises PdfRenderError if xhtml2pdf itself reports a failure."""
    from xhtml2pdf import pisa

    from . import report_charts
    from .ai_narrative import narrative_sections

    content = dict(instance.content)
    persistent_count, recurring_count = _persistent_recurring_counts(content)
    extra_charts = _extra_report_charts(
        content, content.get("window_days", 7), instance.generated_at)
    attention_rows = content.get("system_attention", [])
    total_systems = content.get("total_systems", 0)
    red_systems = sum(1 for r in attention_rows if r["worst_band"] == "red")
    amber_systems = len(attention_rows) - red_systems
    healthy_systems = max(0, total_systems - len(attention_rows))
    persistent_issues, recurring_only_issues = _split_persistent_recurring(content)
    charts = {
        "donut": report_charts.issue_breakdown_donut(
            persistent_count, recurring_count,
            len(content.get("anomalies", [])), len(content.get("one_off_issues", []))),
        "estate_health": (report_charts.estate_health_donut(
            healthy_systems, amber_systems, red_systems) if total_systems else None),
        "attention_bar": report_charts.system_attention_bar(attention_rows),
        "persistent_heatmap": report_charts.issue_occurrence_heatmap(
            report_charts.persistent_issue_matrix(content.get("recurring_issues", [])),
            title="Persistent issue occurrence across all systems"),
        "recurring_heatmap": report_charts.issue_occurrence_heatmap(
            report_charts.recurring_issue_matrix(content.get("recurring_issues", [])),
            title="Recurring issue occurrence across all systems"),
        "theme_bar": report_charts.theme_bar_chart(content.get("themes", [])),
    }
    # A plain table, not a chart -- see report_charts.finding_table's own docstring for why the
    # bar chart this replaced (2026-09-08) stopped earning its space once most of its rows tied
    # at the same coverage/days.
    persistent_table = report_charts.finding_table(persistent_issues)
    recurring_table = report_charts.finding_table(recurring_only_issues)
    # One Hourly Activity chart per COMPONENT AFFECTED, grouped under its issue type and then
    # under the system it belongs to -- see automated_report_detail's own identical comment for
    # the full reasoning (2026-09-08).
    recurring_issues = content.get("recurring_issues", [])
    spike_targets = _spike_chart_targets(recurring_issues)
    needs_landscape = _spike_report_needs_landscape(spike_targets)
    spike_charts = []
    for sysgrp in spike_targets:
        sysname = sysgrp["system"]
        # NOT named `charts` -- 2026-09-08, on request, after confirming live: that name
        # collided with the OUTER `charts = {...}` dict (donut/heatmaps/attention_bar/
        # theme_bar) built above, silently overwriting it with this per-column list by the
        # time render_to_string ran. Django's template lookup on a list rather than a dict
        # just resolves every `charts.xxx` reference to nothing, which is why the heatmaps
        # (and donut/estate-health/attention-bar) were vanishing from the PDF specifically
        # -- the web view's own equivalent loop never had this bug, since its outer
        # variable is named `chart_data`, not `charts`.
        columns = []
        for catrow in sysgrp["categories"]:
            cat, cat_label = catrow["category"], catrow["category_label"]
            is_percent = catrow["is_percent"]
            sys_charts = []
            for flag_key in catrow["components"]:
                if flag_key:
                    label = report_charts.flag_location(flag_key)
                    chart = report_charts.resource_percent_chart_single(
                        sysname, flag_key, cat, title=f"{cat_label} — {sysname} · {label}")
                else:
                    label = None
                    chart = report_charts.issue_spike_line_single(
                        sysname, cat, title=f"{cat_label} — {sysname}")
                if chart:
                    sys_charts.append({"label": label, "chart": chart})
            if sys_charts:
                # Cap charts per column -- see automated_report_detail's own identical comment.
                columns.append({
                    "category_label": cat_label, "is_percent": is_percent,
                    "charts": sys_charts[:_SPIKE_CHARTS_PER_COLUMN_MAX],
                    "more_count": max(0, len(sys_charts) - _SPIKE_CHARTS_PER_COLUMN_MAX),
                })
        if columns:
            # Cap COLUMNS shown too (item 23: "cap visible columns (e.g. at 5) and fold any
            # remaining metric categories for that system behind a '+N more' expandable" for
            # the 6+ case) -- even in landscape, a 6th column drops below the 200px floor.
            col_cap = _SPIKE_COLS_LANDSCAPE_MAX if needs_landscape else _SPIKE_COLS_PORTRAIT_MAX
            spike_charts.append({
                "system": sysname, "columns": columns[:col_cap],
                "more_columns": max(0, len(columns) - col_cap),
            })
    # SWIFT transaction throughput -- see automated_report_detail's own identical comment
    # (2026-09-08); built independently of the _spike_chart_targets loop above since it has no
    # system/category of its own.
    swift_chart = report_charts.swift_transaction_chart(title="SWIFT Transactions")
    html = render_to_string("reports/automated_report_pdf.html", {
        "instance": instance, "report": content,
        "sections": narrative_sections(content.get("narrative", {})),
        "persistent_count": persistent_count, "recurring_count": recurring_count,
        "charts": charts, "spike_charts": spike_charts, "swift_chart": swift_chart,
        "extra_charts": extra_charts, "needs_landscape": needs_landscape,
        "zoom_persistent": zoom_persistent, "zoom_recurring": zoom_recurring,
        "persistent_table": persistent_table, "recurring_table": recurring_table,
        "logo_data_uri": report_charts.logo_data_uri(),
    })
    buffer = io.BytesIO()
    result = pisa.CreatePDF(io.StringIO(html), dest=buffer)
    if result.err:
        raise PdfRenderError(f"xhtml2pdf reported {result.err} error(s) rendering this report")
    return buffer.getvalue()


def automated_report_pdf_filename(instance) -> str:
    """Shared by automated_report_download and automated_reports_mail.send_automated_report so
    the downloaded file and the e-mailed attachment are never named differently."""
    return (f"{instance.content.get('label', 'Automated Report')} "
           f"{instance.generated_at:%Y-%m-%d %H%M}.pdf")


@login_required
def automated_report_download(request, report_type, pk):
    """A standalone, presentation-quality PDF of one stored instance -- the exact same data
    as the in-app view, formatted for saving/printing/forwarding outside the console
    (section 12: "Keep the visual design professional and suitable for presentation to
    management"). See build_automated_report_pdf for the actual rendering."""
    if not _automated_reports_gate(request.user):
        return redirect("reports")
    instance = get_object_or_404(AutomatedReportInstance, pk=pk, report_type=report_type)

    def _zoom(param):
        # "save this zoom config for when we download PDF" -- the web view's own heatmap zoom
        # (see automated_report_download.html's own script block) has no other way to reach
        # this separate, server-rendered request, so it rides along as a query param instead.
        # Clamped to the same [0.5, 2.0] range the web view's own zoom buttons enforce.
        try:
            return min(2.0, max(0.5, float(request.GET.get(param, 1.0))))
        except ValueError:
            return 1.0

    try:
        pdf_bytes = build_automated_report_pdf(
            instance, zoom_persistent=_zoom("zoom_persistent"),
            zoom_recurring=_zoom("zoom_recurring"))
    except PdfRenderError:
        return render(request, "reports/error.html",
                     {"detail": "Could not render this report as a PDF."}, status=500)

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{automated_report_pdf_filename(instance)}"'
    return response

@login_required
@require_POST
def automated_report_toggle_distribution(request):
    """Phase 7 rollout gate. Superuser-only: this decides whether every FUTURE scheduled
    Automated Report also gets e-mailed, not just this one instance (see automated_report_
    detail's "Send now" for a one-off send that bypasses the gate for the Phase 7 review
    itself)."""
    if not request.user.is_superuser:
        return redirect("automated_reports")
    sc = SystemConfig.get()
    sc.automated_reports_distribution_enabled = not sc.automated_reports_distribution_enabled
    sc.updated_by = request.user
    sc.save(update_fields=["automated_reports_distribution_enabled", "updated_at", "updated_by"])
    messages.success(
        request,
        "Automated Reports distribution ENABLED — future scheduled reports will be e-mailed."
        if sc.automated_reports_distribution_enabled else
        "Automated Reports distribution disabled — back to shadow mode (generate + store only).")
    return redirect("automated_reports")


@login_required
def report_form(request):
    """Landing page: the lightweight SYSTEM-SELECTION screen.

    Deliberately does NO Prometheus capture — it lists systems straight from the topology
    (a plain file read) so merely visiting, refreshing, or navigating back here is cheap.
    The heavy live capture is deferred to ``report`` (below), which only runs once the admin
    has picked systems and continued.
    """
    recent = _recently_reported()
    select_systems = [
        {"name": s["name"], "hosts": s["hosts"], "reported": recent.get(s["name"]),
         "mono_hue": _mono_hue(s["name"]),
         # The tile shows the platform glyph in place of the monogram; mono_hue stays because
         # a system whose scrape jobs don't identify an OS still falls back to its letter.
         "platform": s["platform"],
         "platform_label": PLATFORM_LABELS.get(s["platform"], PLATFORM_LABELS[""])}
        for s in list_systems()
    ]
    # This screen IS the picker, so arriving here mid-report used to leave only one way
    # forward: choose systems again — which pops the snapshot token and throws away answers
    # already typed. Surfacing the open report gives the admin the choice back. Nothing is
    # discarded by merely landing here; that only happens if they deliberately re-select.
    open_seconds = _open_report_seconds(request, "systems")
    open_systems = (request.session.get("report_systems") or []) if open_seconds else []
    return render(request, "reports/select.html", {
        "select_systems": select_systems,
        "recent_hours": _RECENT_REPORT_HOURS,
        "total_hosts": sum(s["hosts"] for s in select_systems),
        "recent_count": sum(1 for s in select_systems if s["reported"]),
        "open_report": list(open_systems),
        "open_seconds": open_seconds,
    })


@login_required
def report(request):
    """The report / annotation screen for the SELECTED systems.

    POST (from the selection screen): record the chosen systems and redirect to GET
    (Post/Redirect/Get, so a browser refresh never re-submits the selection).

    GET: ALWAYS captures a fresh live snapshot scoped to those systems — a plain browser
    refresh, clicking "Continue that report" from the picker, or any other way of landing
    back on this URL never serves numbers that quietly aged past the countdown without the
    admin knowing. Typed answers survive this because the page saves a draft to localStorage
    before it's ever navigated away from (see form.html) and restores it on load, so a fresh
    capture costs nothing the admin had already entered. The countdown is solely about how
    long THIS render's snapshot stays valid for Generate — refreshing always gets fresh data
    regardless of where the countdown is.
    """
    if request.method == "POST":
        names = [n for n in request.POST.getlist("include_system") if n]
        if not names:
            messages.error(request, "Select at least one system to include in the report.")
            return redirect("report_form")
        request.session["report_systems"] = names
        request.session.pop("snapshot_token", None)   # new selection -> fresh capture
        return redirect("report")

    names = request.session.get("report_systems")
    if not names:                                     # arrived without choosing -> pick first
        return redirect("report_form")

    token = uuid.uuid4().hex
    try:
        snapshot = capture_snapshot(token, only=set(names))
    except PrometheusUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:                      # selection no longer in the topology
        messages.error(request, "None of the selected systems were found. Please choose again.")
        request.session.pop("report_systems", None)
        return redirect("report_form")
    # Alphabetical, for the System Analyses Dashboard's A-Z letter key (see form.html) --
    # sorted once, HERE, before caching: generate()'s fix__<i>__<j> field names are built from
    # enumerate(snapshot.systems) against this SAME cached object, so the order fixed at
    # cache-write time is what both the page render and the answer-parsing on Generate agree
    # on. Sorting again later (or differently) would desync the two.
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, timeout=settings.SNAPSHOT_TTL)
    request.session["snapshot_token"] = token
    # The open report lapses on the same clock as its snapshot, so the picker's resume bar
    # counts down to the moment it stops being true.
    request.session["report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    # Anchor the countdown to the capture time so a refresh continues it (never restarts).
    # captured_at is a naive datetime.now(); compare against the same clock.
    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    # Per-system connect strip. Free: reuses the snapshot's own topology and `up` series, so
    # no extra Prometheus call and the status shown matches the numbers on the page. Attached
    # to each view model (the cache hands back a fresh unpickled copy per request, so this
    # mutation is request-local).
    hosts_by_system = connect.hosts_from_snapshot(snapshot._systems, snapshot._store)
    # colour each chip by the worst flag on that host, taken from the flags this page renders
    connect.attach_flag_severity(hosts_by_system, snapshot.systems)
    # Same platform the picker showed on the tile, carried onto the card the admin lands on,
    # so the glyph they chose by is still beside the system while they write about it.
    platforms = {s.name: gr.platform_of_system(s.components) for s in snapshot._systems}
    for svm in snapshot.systems:
        svm.connect_hosts = hosts_by_system.get(svm.name, [])
        svm.platform = platforms.get(svm.name, "")
        svm.platform_label = PLATFORM_LABELS.get(svm.platform, PLATFORM_LABELS[""])

    return render(request, "reports/form.html", {
        "generate_default": reverse("generate"),
        "dash_title": "System Analyses Dashboard",
        "subject": "system",
        # Only the systems flow's list is sorted (above) -- the network estate is 2 devices
        # today and its own list isn't alphabetised, so grouping it here would be undefined.
        "alpha_grouped": True,
        # Distinct first letters actually present, in order -- the LHS letter key only ever
        # lists a letter it can jump to (no dead "Q" that scrolls nowhere).
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        # Per-estate, per-selection draft key. One shared "reportDraft" meant a systems draft
        # was restored into a network report, where none of the card names match — so the
        # typed answers silently went nowhere and the page looked like it had forgotten them.
        "draft_key": "draft:systems:" + ",".join(sorted(names)),
        "picker_url": reverse("report_form"),
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,   # what the timer starts from on this render
    })


@login_required
@require_POST
def generate(request):
    """Rebuild the report from the cached snapshot + the submitted answers, then download it."""
    token = request.POST.get("token", "")
    snapshot = cache.get(_cache_key(token))
    if snapshot is None:
        # snapshot expired or the process restarted — send the admin back to a fresh capture
        return render(request, "reports/error.html", {
            "detail": "This snapshot expired. Please reload the form to capture fresh metrics.",
            "expired": True,
        }, status=410)

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    # report theme is a user setting (chosen in the Settings menu), not a per-report field
    theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in ("dark", "light"):
        theme = "dark"
    # Author (the report's master "By" line) self-populates from the profile; only an
    # explicit override in the form replaces it, so it is never blank.
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

    # For an e-mail we need somewhere to send it — validate before doing any work so the
    # snapshot stays intact and the admin can go back and add recipients.
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    # Rebuild annotations keyed by each flag's stable key. Fields are namespaced by the
    # system index and flag index in the snapshot, so we don't have to encode keys in HTML.
    # The snapshot is ALREADY scoped to the admin's selected systems (capture_snapshot), so
    # every system here belongs in the report.
    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        flags_ans = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                flags_ans[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if flags_ans or comment:
            annotations[sysvm.name] = {"flags": flags_ans, "comment": comment}

    data = build_report(
        snapshot, theme=theme, author=author,
        annotations=annotations, summary_comment=summary_comment,
    )
    filename = default_report_filename(theme, timezone.localtime())

    # Freeze exactly what the report presented (overview + per-system flagged items, each
    # married to the admin's answer) so History can replay it without touching Prometheus.
    # "kind" (2026-09-12) lets the Executive Dashboard find "the latest System Admin Report"
    # among ReportSubmission's shared table -- same ad-hoc tagging network_sod/os_inventory's
    # own report_content already used, just extended to the other xlsx-family reports too.
    report_content = {
        "kind": "system_admin",
        "overview": snapshot.overview,
        "systems": [
            {
                "name": sysvm.name,
                "hosts": sysvm.hosts,
                "flags": [
                    {
                        "key": flag.key, "text": flag.text,
                        "band": flag.band, "category": flag.category,
                        "answer": annotations.get(sysvm.name, {}).get("flags", {}).get(flag.key, ""),
                    }
                    for flag in sysvm.flags
                ],
                "comment": annotations.get(sysvm.name, {}).get("comment", ""),
            }
            for sysvm in snapshot.systems
        ],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # so a transient SMTP failure leaves the form retryable.
    subject = ""
    if action == "email":
        try:
            subject = email_report(snapshot, data, recipients=recipients,
                                   author=author, filename=filename)
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user,
        author=author,
        theme=theme,
        delivery=action,
        recipients=recipients_raw,
        prom_url=snapshot.prom_url,
        systems_count=len(snapshot.systems),
        hosts_count=snapshot.hosts_count,
        immediate_count=snapshot.immediate_count,
        watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
        annotations=annotations,
        report_content=report_content,
        filename=filename,
    )
    # The snapshot is NOT consumed here. It used to be — "one-shot: a fresh form gets a
    # fresh snapshot" — which made sense when a revisit reused the cache. Now that every GET
    # to the report re-captures, deleting it bought nothing and broke two things the admin
    # actually does: pressing Generate a second time (the page stays open after a download)
    # died with "this snapshot expired", and coming back after e-mailing hit the same wall,
    # which read as e-mailing having forced a refresh. It now simply lapses at its TTL.

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    response = HttpResponse(
        data,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(response)


@never_cache   # always reflect the newest submissions (no stale back/forward-cache copy)
@login_required
def history(request):
    """Recent report submissions (audit trail)."""
    submissions = ReportSubmission.objects.select_related("generated_by")[:100]
    return render(request, "reports/history.html", {"submissions": submissions})


@never_cache
@login_required
def submission_detail(request, pk):
    """Read-only replay of one past report (opened from a History row): the generated
    content + the admin's answers + audit-trail info, laid out as plain tables."""
    sub = get_object_or_404(ReportSubmission.objects.select_related("generated_by"), pk=pk)
    content = sub.report_content or {}
    overview = content.get("overview") or {}
    systems = content.get("systems")
    if not systems:
        # legacy rows saved before report_content existed — reconstruct from annotations
        systems = [
            {
                "name": name,
                "hosts": None,
                "flags": [{"key": k, "text": k, "band": "", "category": "", "answer": v}
                          for k, v in (data.get("flags") or {}).items()],
                "comment": (data.get("comment") or "").strip(),
            }
            for name, data in (sub.annotations or {}).items()
        ]
    systems = sorted(systems, key=lambda s: (s.get("name") or "").lower())
    recipients = [r.strip() for r in (sub.recipients or "").split(",") if r.strip()]
    comments = []
    if sub.summary_comment:
        comments.append({"label": "Overall", "text": sub.summary_comment})
    for s in systems:
        if s.get("comment"):
            comments.append({"label": s["name"], "text": s["comment"]})
    return render(request, "reports/submission_detail.html", {
        "sub": sub, "overview": overview, "systems": systems,
        "recipients": recipients, "comments": comments,
    })


@login_required
def recipient_search(request):
    """Type-ahead recipient lookup against AD/LDAP (empty list if LDAP isn't configured)."""
    return JsonResponse({"results": search_directory(request.GET.get("q", ""))})


@login_required
def connect_index(request):
    """The Connect inventory: every monitored host with a ready-to-use RDP / SSH launch.

    No Prometheus capture — the topology is a file read and reachability is ONE `up` query,
    so opening this page is cheap. Nothing here authenticates: see reports/connect.py for why
    the credential prompt deliberately stays in the admin's own client.
    """
    systems = connect.inventory()
    hosts = [h for s in systems for h in s["hosts"]]
    return render(request, "reports/connect.html", {
        "systems": systems,
        "total_hosts": len(hosts),
        "windows_hosts": sum(1 for h in hosts if h["os"] == "windows"),
        "linux_hosts": sum(1 for h in hosts if h["os"] == "linux"),
        # None anywhere means Prometheus itself was unreachable -> we say "unknown", not "down"
        "reachability_unknown": any(h["reachable"] is None for h in hosts),
        "unreachable": sum(1 for h in hosts if h["reachable"] is False),
    })


@login_required
def connect_rdp(request):
    """Serve a generated .rdp for one monitored host. Windows opens mstsc, and MSTSC prompts
       for the credential — this response contains no password field by design.

       The instance is validated against the topology (connect.find_host): a link that named
       an arbitrary address would let someone hand a colleague an attacker-controlled RDP
       target under this app's trusted URL."""
    host = connect.find_host(request.GET.get("host", "").strip())
    if not host or host["os"] != "windows":
        raise Http404("not a monitored Windows host")
    body = connect.rdp_file_text(host, username=request.GET.get("u", "").strip())
    resp = HttpResponse(body, content_type="application/x-rdp")
    resp["Content-Disposition"] = f'attachment; filename="{connect.rdp_filename(host)}"'
    return resp


@login_required
def folder_watch(request):
    """Folder Watch: the PARENT screen, listing the hosts that publish folder metrics.

    One child today (Temenos). It is its own page rather than a redirect so the next host to
    start publishing gets a tile here instead of a second top-level nav entry.
    """
    if not is_system_admin(request.user):
        return redirect("report_form")
    return render(request, "reports/folder_index.html", {})


@never_cache   # a cached copy of this page would show yesterday's folder ages
@login_required
def folder_watch_temenos(request):
    """Temenos: the T24 interface drop folders, each coloured by how long its oldest file has
    been waiting. One Prometheus query — no capture — so it is cheap to leave open.

    The page then keeps itself live on its own: the template hands the browser each folder's
    oldest-file TIMESTAMP (not its age), so the tiles re-age every second and a folder turns
    red the moment it crosses its limit, without waiting for the next poll.

    Reads folder_exporter on :9847, which replaced the Task Scheduler script and textfile
    collector this screen used to depend on.
    """
    if not is_system_admin(request.user):
        return redirect("report_form")
    try:
        data = folders.snapshot()
    except folders.FolderWatchUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    return render(request, "reports/folders.html", {"fw": data})


@never_cache
@login_required
def folder_watch_data(request):
    """The same snapshot as JSON — polled by the screen to pick up new scrapes.

    A Prometheus outage answers 502 with a reason rather than an empty folder list: the page
    keeps showing the last good grid, marked stale, instead of silently going all-clear.
    """
    if not is_system_admin(request.user):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)
    try:
        return JsonResponse(folders.snapshot())
    except folders.FolderWatchUnavailable as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)


@never_cache
@login_required
def core_switches_form(request):
    """The Core Switches Report's own landing page (2026-09-23, split out of the old
    combined Switches & Routers Report -- see network.core_switches_device_keys'
    own comment). Scoped to network.core_switches_device_keys() -- today three devices,
    HQ/DR/BYO (see DEVICES' own comment on them).

    Dual-role visibility, same idiom as active_directory_form: owned by Network Admin
    (this is squarely their estate), Infrastructure Admin has view access too (same
    precedent as the combined report this replaces).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")
    try:
        keys = network.core_switches_device_keys()
        devices = [d for d in network.device_inventory() if d["key"] in keys]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "core_switches")
    open_keys = (request.session.get("core_switches_devices") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/core_switches_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_interfaces": sum(d["iface_count"] for d in devices),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def core_switches_report(request):
    """The annotation screen for the SELECTED core switch -- network_report's own
    twin (same simple shape, no windows-exporter connect-strip machinery needed), scoped to
    network.core_switches_device_keys() and posting to its own core_switches_generate.

    GET: ALWAYS captures a fresh live snapshot -- same rule network_report's own docstring
    establishes and for the same reason (a Refresh click, or any other way of landing back on
    this URL, must never quietly serve numbers that aged past the countdown).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = network.core_switches_device_keys()
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("core_switches_form")
        request.session["core_switches_devices"] = keys
        request.session.pop("core_switches_token", None)   # new selection -> fresh capture
        return redirect("core_switches_report")

    keys = request.session.get("core_switches_devices")
    if not keys:
        return redirect("core_switches_form")

    token = uuid.uuid4().hex
    try:
        # report_kind="core_switches" (2026-09-24, on request: "for the core switch report
        # drop these metrics no need to check them") -- drops BGP/Active connections/
        # Connected devices from the catalogue this report's own "Metrics not collected"
        # tile and flag count against; see CATALOGUE's own skip_for comment.
        snapshot = network.capture_snapshot(token, only=set(keys), mode="switches_routers",
                                            report_kind="core_switches")
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("core_switches_devices", None)
        return redirect("core_switches_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["core_switches_token"] = token
    request.session["core_switches_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.core_switches_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "alpha_grouped": True,
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Core Switches Report",
        "subject": "device",
        "draft_key": "draft:core_switches:" + ",".join(sorted(keys)),
        "picker_url": reverse("core_switches_form"),
        "generate_url": reverse("core_switches_generate"),
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def core_switches_generate(request):
    """Build the Core Switches Report from the reviewed snapshot -- network_generate's own twin, calling network.build_report with title="Core Switches Report" (NOT the
    default "Infrastructure Report" -- see build_report's own docstring) so the downloaded
    xlsx never claims to be a report it isn't."""
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("core_switches_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("core_switches_report")

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_report(snapshot, theme=theme, author=author,
                                annotations=annotations, summary_comment=summary_comment,
                                title="Core Switches Report")
    filename = network.core_switches_report_filename(theme, timezone.localtime())

    # "kind" (2026-09-22): lets History/the Executive Dashboard find "the latest Switches &
    # Routers Report" the same way every other estate's own kind literal already does.
    report_content = {
        "kind": "core_switches",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract every other generate view here follows.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="CORE SWITCHES REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@never_cache
@login_required
def routers_form(request):
    """The Routers Report's own landing page (2026-09-23, split out of the old combined
    Switches & Routers Report -- see network.routers_device_keys' own comment).
    Scoped to network.routers_device_keys() -- today exactly one device,
    hre-dr-swift-router (the 2951 ISR).

    Dual-role visibility, same idiom as active_directory_form: owned by Network Admin
    (this is squarely their estate), Infrastructure Admin has view access too (same
    precedent as the combined report this replaces).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")
    try:
        keys = network.routers_device_keys()
        devices = [d for d in network.device_inventory() if d["key"] in keys]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "routers")
    open_keys = (request.session.get("routers_devices") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/routers_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_interfaces": sum(d["iface_count"] for d in devices),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def routers_report(request):
    """The annotation screen for the SELECTED router -- network_report's own
    twin (same simple shape, no windows-exporter connect-strip machinery needed), scoped to
    network.routers_device_keys() and posting to its own routers_generate.

    GET: ALWAYS captures a fresh live snapshot -- same rule network_report's own docstring
    establishes and for the same reason (a Refresh click, or any other way of landing back on
    this URL, must never quietly serve numbers that aged past the countdown).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = network.routers_device_keys()
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("routers_form")
        request.session["routers_devices"] = keys
        request.session.pop("routers_token", None)   # new selection -> fresh capture
        return redirect("routers_report")

    keys = request.session.get("routers_devices")
    if not keys:
        return redirect("routers_form")

    token = uuid.uuid4().hex
    try:
        snapshot = network.capture_snapshot(token, only=set(keys), mode="switches_routers")
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("routers_devices", None)
        return redirect("routers_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["routers_token"] = token
    request.session["routers_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.routers_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "alpha_grouped": True,
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Routers Report",
        "subject": "device",
        "draft_key": "draft:routers:" + ",".join(sorted(keys)),
        "picker_url": reverse("routers_form"),
        "generate_url": reverse("routers_generate"),
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def routers_generate(request):
    """Build the Routers Report from the reviewed snapshot -- network_generate's own twin, calling network.build_report with title="Routers Report" (NOT the
    default "Infrastructure Report" -- see build_report's own docstring) so the downloaded
    xlsx never claims to be a report it isn't."""
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("routers_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("routers_report")

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_report(snapshot, theme=theme, author=author,
                                annotations=annotations, summary_comment=summary_comment,
                                title="Routers Report")
    filename = network.routers_report_filename(theme, timezone.localtime())

    # "kind" (2026-09-22): lets History/the Executive Dashboard find "the latest Switches &
    # Routers Report" the same way every other estate's own kind literal already does.
    report_content = {
        "kind": "routers",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract every other generate view here follows.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="ROUTERS REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@never_cache
@login_required
def wireless_controller_form(request):
    """The Wireless Controller Report's own landing page (2026-09-23, split out of the
    old combined Switches & Routers Report on request: "the one without poe wireless
    controller... put it in its own report called wireless controller"). Scoped to
    network.wireless_controller_device_keys() -- today exactly one device, hre-wlc-02
    (a virtual C9800-CL with no PoE/PSU/fan of its own).

    Dual-role visibility, same idiom as active_directory_form: owned by Network Admin
    (this is squarely their estate), Infrastructure Admin has view access too (same
    precedent as the combined report this replaces).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")
    try:
        keys = network.wireless_controller_device_keys()
        devices = [d for d in network.device_inventory() if d["key"] in keys]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "wireless_controller")
    open_keys = (request.session.get("wireless_controller_devices") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/wireless_controller_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_interfaces": sum(d["iface_count"] for d in devices),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def wireless_controller_report(request):
    """The annotation screen for the SELECTED wireless controller -- network_report's own
    twin (same simple shape, no windows-exporter connect-strip machinery needed), scoped to
    network.wireless_controller_device_keys() and posting to its own wireless_controller_generate.

    GET: ALWAYS captures a fresh live snapshot -- same rule network_report's own docstring
    establishes and for the same reason (a Refresh click, or any other way of landing back on
    this URL, must never quietly serve numbers that aged past the countdown).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = network.wireless_controller_device_keys()
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("wireless_controller_form")
        request.session["wireless_controller_devices"] = keys
        request.session.pop("wireless_controller_token", None)   # new selection -> fresh capture
        return redirect("wireless_controller_report")

    keys = request.session.get("wireless_controller_devices")
    if not keys:
        return redirect("wireless_controller_form")

    token = uuid.uuid4().hex
    try:
        snapshot = network.capture_snapshot(token, only=set(keys), mode="switches_routers")
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("wireless_controller_devices", None)
        return redirect("wireless_controller_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["wireless_controller_token"] = token
    request.session["wireless_controller_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.wireless_controller_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "alpha_grouped": True,
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Wireless Controller Report",
        "subject": "device",
        "draft_key": "draft:wireless_controller:" + ",".join(sorted(keys)),
        "picker_url": reverse("wireless_controller_form"),
        "generate_url": reverse("wireless_controller_generate"),
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def wireless_controller_generate(request):
    """Build the Wireless Controller Report from the reviewed snapshot -- network_generate's own twin, calling network.build_report with title="Wireless Controller Report" (NOT the
    default "Infrastructure Report" -- see build_report's own docstring) so the downloaded
    xlsx never claims to be a report it isn't."""
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("wireless_controller_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("wireless_controller_report")

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_report(snapshot, theme=theme, author=author,
                                annotations=annotations, summary_comment=summary_comment,
                                title="Wireless Controller Report")
    filename = network.wireless_controller_report_filename(theme, timezone.localtime())

    # "kind" (2026-09-22): lets History/the Executive Dashboard find "the latest Switches &
    # Routers Report" the same way every other estate's own kind literal already does.
    report_content = {
        "kind": "wireless_controller",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract every other generate view here follows.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="WIRELESS CONTROLLER REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@never_cache
@login_required
def access_switches_form(request):
    """The Access Switches Report's own landing page -- the renamed, narrowed successor
    to the old combined Switches & Routers Report (2026-09-23, on request: "this
    current report rename it to Access switches"). Scoped to
    network.access_switches_device_keys() -- every switch except the one core switch
    (see is_access_switch's own comment), 36 devices today.

    Dual-role visibility, same idiom as active_directory_form: owned by Network Admin
    (this is squarely their estate), Infrastructure Admin has view access too (same
    precedent as the combined report this replaces).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")
    try:
        keys = network.access_switches_device_keys()
        devices = [d for d in network.device_inventory() if d["key"] in keys]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "access_switches")
    open_keys = (request.session.get("access_switches_devices") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/access_switches_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_interfaces": sum(d["iface_count"] for d in devices),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def access_switches_report(request):
    """The annotation screen for the SELECTED access switches -- network_report's own
    twin (same simple shape, no windows-exporter connect-strip machinery needed), scoped to
    network.access_switches_device_keys() and posting to its own access_switches_generate.

    GET: ALWAYS captures a fresh live snapshot -- same rule network_report's own docstring
    establishes and for the same reason (a Refresh click, or any other way of landing back on
    this URL, must never quietly serve numbers that aged past the countdown).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = network.access_switches_device_keys()
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("access_switches_form")
        request.session["access_switches_devices"] = keys
        request.session.pop("access_switches_token", None)   # new selection -> fresh capture
        return redirect("access_switches_report")

    keys = request.session.get("access_switches_devices")
    if not keys:
        return redirect("access_switches_form")

    token = uuid.uuid4().hex
    try:
        snapshot = network.capture_snapshot(token, only=set(keys), mode="switches_routers")
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("access_switches_devices", None)
        return redirect("access_switches_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["access_switches_token"] = token
    request.session["access_switches_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.access_switches_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "alpha_grouped": True,
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Access Switches Report",
        "subject": "device",
        "draft_key": "draft:access_switches:" + ",".join(sorted(keys)),
        "picker_url": reverse("access_switches_form"),
        "generate_url": reverse("access_switches_generate"),
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def access_switches_generate(request):
    """Build the Access Switches Report from the reviewed snapshot -- network_generate's own twin, calling network.build_report with title="Access Switches Report" (NOT the
    default "Infrastructure Report" -- see build_report's own docstring) so the downloaded
    xlsx never claims to be a report it isn't."""
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("access_switches_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("access_switches_report")

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_report(snapshot, theme=theme, author=author,
                                annotations=annotations, summary_comment=summary_comment,
                                title="Access Switches Report")
    filename = network.access_switches_report_filename(theme, timezone.localtime())

    # "kind" (2026-09-22): lets History/the Executive Dashboard find "the latest Switches &
    # Routers Report" the same way every other estate's own kind literal already does.
    report_content = {
        "kind": "access_switches",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract every other generate view here follows.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="ACCESS SWITCHES REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@never_cache
@login_required
def firewalls_form(request):
    """The Firewall Report's own landing page -- a fifth member of the Networks Report
    category (2026-09-29, on request: "add these firewalls to a new firewall report which is
    part of the network reports group"). Scoped to network.firewall_device_keys() -- today
    four devices, none of which answer SNMP yet (see their own DEVICES comment): they were
    added anyway, on request ("firewalls not yet on snmp but just add them for now"), and
    will show here, honestly, as unreachable -- but `kind: "Firewall"` keeps them out of
    switches_routers_device_keys() entirely, so this gap never reaches the alert poller or
    the Executive Dashboard's Network tile (see firewall_device_keys' own comment).

    Dual-role visibility, same idiom as the other three narrow pickers: owned by Network
    Admin (this is squarely their estate), Infrastructure Admin has view access too.
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")
    try:
        keys = network.firewall_device_keys()
        devices = [d for d in network.device_inventory() if d["key"] in keys]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "firewalls")
    open_keys = (request.session.get("firewalls_devices") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/firewalls_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_interfaces": sum(d["iface_count"] for d in devices),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def firewalls_report(request):
    """The annotation screen for the SELECTED firewall(s) -- network_report's own twin (same
    simple shape, no windows-exporter connect-strip machinery needed), scoped to
    network.firewall_device_keys() and posting to its own firewalls_generate.

    GET: ALWAYS captures a fresh live snapshot -- same rule network_report's own docstring
    establishes and for the same reason (a Refresh click, or any other way of landing back on
    this URL, must never quietly serve numbers that aged past the countdown).
    """
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = network.firewall_device_keys()
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("firewalls_form")
        request.session["firewalls_devices"] = keys
        request.session.pop("firewalls_token", None)   # new selection -> fresh capture
        return redirect("firewalls_report")

    keys = request.session.get("firewalls_devices")
    if not keys:
        return redirect("firewalls_form")

    token = uuid.uuid4().hex
    try:
        snapshot = network.capture_snapshot(token, only=set(keys), mode="switches_routers")
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("firewalls_devices", None)
        return redirect("firewalls_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["firewalls_token"] = token
    request.session["firewalls_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.firewalls_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "alpha_grouped": True,
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Firewall Report",
        "subject": "device",
        "draft_key": "draft:firewalls:" + ",".join(sorted(keys)),
        "picker_url": reverse("firewalls_form"),
        "generate_url": reverse("firewalls_generate"),
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def firewalls_generate(request):
    """Build the Firewall Report from the reviewed snapshot -- network_generate's own twin,
    calling network.build_report with title="Firewall Report" (NOT the default
    "Infrastructure Report" -- see build_report's own docstring) so the downloaded xlsx never
    claims to be a report it isn't."""
    if not (is_network_admin(request.user) or is_infra_admin(request.user)):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("firewalls_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("firewalls_report")

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_report(snapshot, theme=theme, author=author,
                                annotations=annotations, summary_comment=summary_comment,
                                title="Firewall Report")
    filename = network.firewalls_report_filename(theme, timezone.localtime())

    report_content = {
        "kind": "firewalls",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract every other generate view here follows.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="FIREWALL REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@never_cache
@login_required
def network_sod_select(request):
    """The device picker in front of the SOD checklist — the same convention as the Network
    Report's picker and the systems picker next door: choose what this run covers before
    answering for it.

    The estate is fixed morning to morning, unlike a systems report's, so this defaults to
    everything ticked rather than nothing: unticking is for the exception (a device under
    maintenance, a decommissioned circuit), not the daily starting point.
    """
    if not is_network_admin(request.user):
        return redirect("report_form")

    data = network_sod.blank_checklist()
    live = set(k for k, v in network_sod.collect().items() if v)
    prior = request.session.get("network_sod_devices")
    prior = set(prior) if prior else None

    def tile(key, label):
        return {"key": key, "label": label, "mono_hue": _mono_hue(label),
                "live": key in live, "checked": prior is None or key in prior}

    sections = [
        ("Core switches & WAN links", [tile(c.key, c.label) for c in data["core_wan"]]),
        ("Firewalls", [tile(c.key, c.label)
                       for g in data["firewalls"] for c in g.checks]),
        ("Floor switches", [tile(c.key, c.label) for c in data["floor"]]),
        ("Internet circuits", [tile(c.key, c.provider) for c in data["circuits"]]),
        ("Wireless LAN controllers", [tile(c.key, c.site) for c in data["controllers"]]),
        ("DR Mazowe WAN links", [tile(d.key, d.label) for d in data["dr_links"]]),
        ("Radware WAF", [tile("waf", "All {} protected applications".format(
            network_sod.WAF_PROTECTED_TOTAL))]),
    ]
    total = sum(len(items) for _label, items in sections)
    known = {t["key"] for _label, items in sections for t in items}

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k in known]
        if not keys:
            messages.error(request, "Select at least one item to include in the checklist.")
            return redirect("network_sod_select")
        request.session["network_sod_devices"] = keys
        return redirect("network_sod")

    return render(request, "reports/network_sod_select.html", {
        "sections": sections,
        "total": total,
    })


@never_cache
@login_required
def network_sod_form(request):
    """The Start-of-Day checklist screen, scoped to what the picker chose.

    Every field arrives blank except the handful network_sod.collect() can answer from
    Prometheus. That is deliberate and is the point of the sheet — see the module docstring.
    """
    if not is_network_admin(request.user):
        return redirect("report_form")

    selected = request.session.get("network_sod_devices")
    if not selected:
        return redirect("network_sod_select")
    selected = set(selected)

    data = network_sod.prefilled_checklist()
    scoped = network_sod.scoped_for_display(data, selected)
    live_keys = sorted(k for k, v in network_sod.collect().items() if v)
    return render(request, "reports/network_sod.html", {
        "data": scoped,
        "summary": network_sod.summarise(scoped),
        "status_choices": network_sod.STATUS_CHOICES,
        "live_count": len(live_keys),
        "suggested_author": _profile_author(request.user),
        "today": timezone.localdate(),
        "report_theme": getattr(getattr(request.user, "profile", None),
                                "default_report_theme", "dark"),
        "generate_url": reverse("network_sod_generate"),
        "waf_total": network_sod.WAF_PROTECTED_TOTAL,
        "picker_url": reverse("network_sod_select"),
    })


@login_required
@require_POST
def network_sod_generate(request):
    """Build the SOD workbook from what the engineer keyed in.

    Nothing is cached between the screen and here — there is no snapshot to expire, because
    the readings came off vendor consoles by hand rather than out of Prometheus. The POST
    itself IS the capture, which is why this view has no token and no "that snapshot has
    expired" path.
    """
    if not is_network_admin(request.user):
        return redirect("report_form")

    data = network_sod.from_post(request.POST)
    summary = network_sod.summarise(data)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    when = timezone.localtime()
    payload = network_sod.build_report(data, theme=theme, author=author, when=when,
                                       summary_comment=summary_comment)

    # Frozen exactly as presented, so History replays the morning without re-keying it.
    report_content = {
        "kind": "network_sod",
        "summary": {k: v for k, v in summary.items() if k != "banners"},
        "banners": summary["banners"],
        "core_wan": [{"label": c.label, "result": c.result, "status": c.status}
                     for c in data["core_wan"]],
        "firewalls": [{"group": g.label,
                       "checks": [{"label": c.label, "result": c.result, "status": c.status}
                                  for c in g.checks]}
                      for g in data["firewalls"]],
        "floor": [{"label": c.label, "result": c.result, "status": c.status}
                  for c in data["floor"]],
        "circuits": [vars(c) for c in data["circuits"]],
        "controllers": [vars(c) for c in data["controllers"]],
        "dr_links": [vars(d) for d in data["dr_links"]],
        "waf": data["waf"],
    }

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        annotations={}, report_content=report_content,
        # A SOD row that is DOWN is the immediate finding; a degraded circuit or a controller
        # with rogue APs is a watch item. Mapping them onto the shared counters keeps this
        # report legible in the same History list as the other two rather than showing 0/0.
        immediate_count=summary["links_down"],
        watch_count=summary["degraded_circuits"] + summary["rogue_controllers"],
        summary_comment=summary_comment,
    )

    resp = HttpResponse(
        payload,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = (
        'attachment; filename="{}"'.format(network_sod.sod_report_filename(theme, when)))
    return mark_xlsx_download(resp)


@never_cache
@login_required
def infra_form(request):
    """Infrastructure Admin's landing page — the SAME device-picker shape network_dashboard
    uses (see its docstring), scoped to the windows-kind devices in network.DEVICES (HCI
    Cluster, Root Domain Controllers) rather than the switch.

    Reads network.device_inventory() directly, NOT gr.load_topology(scope="infra"): the real
    data for this estate has always lived in network.DEVICES (see its own comments on
    hci-cluster/root-dc-1/root-dc-2), and no scrape config actually assigns INFRA_SYSTEMS'
    "hci cluster"/"oracle hosts" system labels to a real target, so that topology path was
    dead — this screen would show devices with zero real data behind them. Infrastructure
    Admin reads the SAME live Prometheus data Network Admin's own report reads; ownership of
    these devices stays with Network Admin (display-only, per network.DEVICES' own comments).

    Active Directory devices (Root/Child Domain Controllers, AD Sync & Authentication) are
    EXCLUDED here (2026-09-11: split into their own Active Directory Report, reachable from
    both this role and Network Admin -- see active_directory_form/_report/_generate below) --
    they no longer belong in the general hardware picker now that they have a home of their
    own; HCI Cluster and Oracle Hosts still do.
    """
    if not is_infra_admin(request.user):
        return redirect("report_form")
    try:
        devices = [d for d in network.device_inventory()
                  if d.get("kind") == "windows" and d.get("system") not in network.AD_SYSTEMS]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "infra")
    open_keys = (request.session.get("infra_report_systems") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/infra_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_hosts": len(devices),
        # A relay device confirmed alive via ping (host_reachable) despite stale metrics is NOT
        # counted here as "not responding" -- 2026-09-09, on request: "the whole chain of
        # screens... still reflecting that one server is down" -- matches network._windows_
        # reading_trusted's own definition, so this summary stat and the per-row badge below
        # never disagree.
        "unreachable_count": sum(1 for d in devices
                                 if d["known"] and not d["reachable"] and not d.get("host_reachable")),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def infra_report(request):
    """The annotation screen for the SELECTED infrastructure devices — device picker -> capture
    -> the shared form.html annotation screen, same as network_report, but posting to its own
    infra_generate rather than the shared `generate`: the data here is network.py's Snapshot/
    SystemVM shape (windows-kind devices), not generate_report.py's business-system Store/
    System shape the plain systems flow expects.

    GET: ALWAYS captures a fresh live snapshot, the same rule `report()`'s own docstring uses
    and for the same reason -- a plain browser refresh, or any other way of landing back on
    this URL, must never quietly serve numbers that aged past the countdown without the admin
    knowing. This used to reuse whatever snapshot was still sitting in the cache under the
    session's token (added on the `fresh=1` query param, easy to land on this page without),
    which is exactly what made a bare refresh here feel glitchy compared to the plain systems
    report -- fixed 2026-09-17 by dropping the cache-reuse branch and matching `report()`
    exactly: every GET is its own capture, cached under a brand-new token purely so
    infra_generate can read it back moments later.

    Session key kept as "infra_report_systems" (now holding device KEYS rather than system
    names) — context.py's back-button override only checks it for truthiness, so renaming it
    would have touched a second file for no behavioural gain.

    Active Directory device keys are rejected here (2026-09-11, same split as infra_form's
    own docstring) -- they post to active_directory_report instead.
    """
    if not is_infra_admin(request.user):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = {d["key"] for d in network.DEVICES
                if d.get("kind") == "windows" and d.get("system") not in network.AD_SYSTEMS}
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("infra_form")
        request.session["infra_report_systems"] = keys
        request.session.pop("infra_snapshot_token", None)   # new selection -> fresh capture
        return redirect("infra_report")

    keys = request.session.get("infra_report_systems")
    if not keys:
        return redirect("infra_form")

    token = uuid.uuid4().hex
    try:
        snapshot = network.capture_snapshot(token, only=set(keys), infra=True)
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("infra_report_systems", None)
        return redirect("infra_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["infra_snapshot_token"] = token
    request.session["infra_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    # Per-device connect strip -- same as active_directory_report's own (see its comment).
    # HCI Cluster is one SystemVM covering several nodes; hosts_from_ad_snapshot's own
    # one-host-per-system shape only reaches its primary target (node 1) here, a real but
    # non-regressive limitation -- this screen had no connect chip at all before.
    hosts_by_system = network.hosts_from_ad_snapshot(snapshot.systems, getattr(snapshot, "_wm", None))
    network.attach_ad_severity(hosts_by_system, snapshot.systems)
    for svm in snapshot.systems:
        svm.connect_hosts = hosts_by_system.get(svm.name, [])

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.infrastructure_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Infrastructure Analyses Dashboard",
        "subject": "device",
        "draft_key": "draft:infra:" + ",".join(sorted(keys)),
        "picker_url": reverse("infra_form"),
        "generate_url": reverse("infra_generate"),
        # form.html's <form action> is `{{ generate_url|default:generate_default }}` -- the
        # `default` filter still RESOLVES its argument even when generate_url is truthy (as it
        # always is here), and a missing filter ARGUMENT (unlike a missing top-level {{ var }})
        # is not silently swallowed -- it raises VariableDoesNotExist and 500s the whole page.
        # report()/network_report() both already set this; this view just needed the same line.
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def infra_generate(request):
    """Build the Infrastructure Report from the reviewed snapshot — network_generate's twin,
    but rendering through the new tree-nested template (network.build_infrastructure_report)
    instead of the flat band/table layout network.build_report still uses for the switch."""
    if not is_infra_admin(request.user):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("infra_snapshot_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("infra_report")

    # 2026-09-17: this view never read `action` -- see network_generate's own comment on this
    # exact fix, the same bug, same shared "Generate & email" button.
    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_infrastructure_report(
        snapshot, theme=theme, author=author,
        annotations=annotations, summary_comment=summary_comment)
    filename = network.infrastructure_report_filename(theme, timezone.localtime())

    # "kind" (2026-09-12): lets the Executive Dashboard find "the latest Infrastructure Admin Report".
    report_content = {
        "kind": "infrastructure",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract generate()'s own docstring establishes for the System Admin report.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="CLUSTER HEALTH REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@never_cache
@login_required
def active_directory_form(request):
    """Active Directory's own landing page (2026-09-11, split out of the combined
    Infrastructure Admin Report into its own report, on request: "separate the Active
    Directory section to be its own report under the infrastructure role... the networks
    role can also have this"). Same device-picker shape as infra_form -- literally the same
    network.device_inventory() call -- just scoped to network.AD_SYSTEMS (Root/Child Domain
    Controllers, AD Sync & Authentication) instead of every windows-kind device.

    Reachable from EITHER Infrastructure Admin (the real owner -- these are physical/virtual
    hosts, infra's own estate) or Network Admin (view access -- AD is core network-adjacent
    infrastructure their team also cares about). See roles.py's own REPORTS entry for the
    "owned by Infrastructure Admin" hint shown on the Reports tile.
    """
    if not (is_infra_admin(request.user) or is_network_admin(request.user)):
        return redirect("report_form")
    try:
        devices = [d for d in network.device_inventory() if d.get("system") in network.AD_SYSTEMS]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "active_directory")
    open_keys = (request.session.get("active_directory_report_systems") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/active_directory_select.html", {
        # `label` (2026-09-11, on request: "hide hostnames from the picker... a neutral way
        # of referencing this devices") is what the tile shows by default; `name`/`target`
        # (the real hostname/IP) stay in the payload for the per-tile reveal button, never
        # removed -- an admin who needs to actually connect to one still can, just not by
        # default and not for every device at a glance.
        "devices": [dict(d, mono_hue=_mono_hue(d["name"]), label=network.ad_device_label(d))
                   for d in devices],
        "total_hosts": len(devices),
        # Same "confirmed alive despite stale metrics" carve-out as infra_form's own summary
        # stat -- see its docstring for why host_reachable is excluded here.
        "unreachable_count": sum(1 for d in devices
                                 if d["known"] and not d["reachable"] and not d.get("host_reachable")),
        "open_report": [network.ad_device_label(by_key[k]) for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def active_directory_report(request):
    """The annotation screen for the SELECTED Active Directory devices -- infra_report's own
    twin, same network.py Snapshot/SystemVM capture and the same shared form.html annotation
    screen, just its own session keys/picker/generate endpoint so the two estates' open
    reports never collide.

    GET: ALWAYS captures a fresh live snapshot -- see infra_report's own docstring (2026-09-17)
    for why: this view had the identical cache-reuse-unless-`fresh=1` branch, so form.html's
    shared "Refresh" button (a plain reload, no query param) silently kept serving whatever
    snapshot was cached under the session's token. Fixed the same way, for the same reason.
    """
    if not (is_infra_admin(request.user) or is_network_admin(request.user)):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = {d["key"] for d in network.DEVICES if d.get("system") in network.AD_SYSTEMS}
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("active_directory_form")
        request.session["active_directory_report_systems"] = keys
        request.session.pop("active_directory_snapshot_token", None)   # new selection -> fresh capture
        return redirect("active_directory_report")

    keys = request.session.get("active_directory_report_systems")
    if not keys:
        return redirect("active_directory_form")

    token = uuid.uuid4().hex
    try:
        snapshot = network.capture_snapshot(token, only=set(keys), infra=True)
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    if not snapshot.systems:
        messages.error(request, "Those devices are no longer being monitored. Please choose again.")
        request.session.pop("active_directory_report_systems", None)
        return redirect("active_directory_form")
    snapshot.systems.sort(key=lambda s: s.name.lower())
    cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
    request.session["active_directory_snapshot_token"] = token
    request.session["active_directory_report_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    # Per-device connect strip -- report()'s own pattern (2026-09-11, on request: "a button
    # that shows both ip and hostname for whichever device has issues, this is the exact same
    # pattern we have for systems"), adapted for this module's Snapshot shape (one host per
    # SystemVM) via hosts_from_ad_snapshot/attach_ad_severity -- see their own docstrings for
    # why connect.hosts_from_snapshot/attach_flag_severity themselves don't fit unchanged.
    hosts_by_system = network.hosts_from_ad_snapshot(snapshot.systems, getattr(snapshot, "_wm", None))
    network.attach_ad_severity(hosts_by_system, snapshot.systems)
    for svm in snapshot.systems:
        svm.connect_hosts = hosts_by_system.get(svm.name, [])

    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.active_directory_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "dash_title": "Active Directory Analyses Dashboard",
        "subject": "device",
        "draft_key": "draft:ad:" + ",".join(sorted(keys)),
        "picker_url": reverse("active_directory_form"),
        "generate_url": reverse("active_directory_generate"),
        # See infra_report's own comment: form.html's <form action> always RESOLVES the
        # `default` filter's argument even when generate_url is truthy, so this must still
        # be a real, reversible url name or the page 500s.
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def active_directory_generate(request):
    """Build the Active Directory Report from the reviewed snapshot -- infra_generate's own
    twin, rendering through the same network.build_infrastructure_report tree-nested template
    (already correctly scoped to whatever `only=` subset of devices the snapshot carries,
    proven throughout this session's own AD-specific testing), just its own filename/session
    keys."""
    if not (is_infra_admin(request.user) or is_network_admin(request.user)):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("active_directory_snapshot_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("active_directory_report")

    # 2026-09-17: this view never read `action` -- see network_generate's own comment on this
    # exact fix, the same bug, same shared "Generate & email" button.
    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in gr.PALETTES:
        theme = "dark"
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()

    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        answers = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                answers[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if answers or comment:
            annotations[sysvm.name] = {"flags": answers, "comment": comment}

    data = network.build_infrastructure_report(
        snapshot, theme=theme, author=author,
        annotations=annotations, summary_comment=summary_comment,
        report_title="ACTIVE DIRECTORY REPORT")
    filename = network.active_directory_report_filename(theme, timezone.localtime())

    # "kind" (2026-09-12): lets the Executive Dashboard find "the latest Active Directory Report".
    report_content = {
        "kind": "active_directory",
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # same contract generate()'s own docstring establishes for the System Admin report.
    subject = ""
    if action == "email":
        try:
            subject = network.email_windows_report(
                snapshot, data, recipients=recipients, author=author,
                filename=filename, title="ACTIVE DIRECTORY REPORT")
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        delivery=action, recipients=recipients_raw,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return mark_xlsx_download(resp)


@login_required
@require_POST
def mark_notifications_seen(request):
    """Called when the user opens the notifications (in the hamburger) — clears the red dot."""
    prof = getattr(request.user, "profile", None) or UserProfile.objects.create(user=request.user)
    prof.notifications_seen_at = timezone.now()
    prof.save(update_fields=["notifications_seen_at", "updated_at"])
    return JsonResponse({"ok": True})


@login_required
@require_POST
def set_report_theme(request):
    """Report theme is a user setting (lives in the Settings menu) — persist it on the profile."""
    theme = request.POST.get("theme")
    if theme in ("dark", "light"):
        prof = getattr(request.user, "profile", None) or UserProfile.objects.create(user=request.user)
        prof.default_report_theme = theme
        prof.save(update_fields=["default_report_theme", "updated_at"])
    # AJAX (from the Settings menu) -> no page reload, so the admin's form entries survive.
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"ok": True, "theme": theme})
    return redirect(request.META.get("HTTP_REFERER") or "report_form")


# ---------------------------------------------------------------------------------------
#  Configuration — every configuration screen lives under here (drawer › Configuration)
# ---------------------------------------------------------------------------------------
#  Configuration is a HUB with one child per thing being configured, nested in the drawer the
#  way Temenos nests under Folder Watch. Each child owns its own screen; the raw-text editors
#  hang off the child whose settings they hold, not off the hub, so "edit the raw YAML" is an
#  option ON the Prometheus screen rather than a sibling of it.
#
#      Configuration                                 (Administrator's landing page)
#        ├─ Roles          ONE PAGE, collapsible sections (2026-09-04) -- Role assignments +
#        │                 Role scopes, reachable via config_roles/roles_console/
#        │                 config_role_scopes (all three render the same page; see
#        │                 config_roles' own docstring for why there are still three URLs).
#        │                 Who holds which role -- an Administrator's own job, not an
#        │                 account-level one, so it stays here even though Users (below) now
#        │                 owns everything else about an account.
#        ├─ Users          Superuser-only (2026-09-04: "make user management a screen on its
#        │                 own, separate it from roles... gray it out unless the user is a
#        │                 super user") -- profile edits, password resets, deletion. Grayed
#        │                 out on this very hub for anyone else, not merely hidden -- see
#        │                 _SUPERUSER_ONLY_CHILDREN and configuration.html's own template
#        │                 logic; the actual URL is ALSO blocked server-side (config_users'
#        │                 own is_superuser check), since a disabled tile is presentation,
#        │                 not access control.
#        ├─ Prometheus     global/storage/rules   → Edit raw YAML → rule files
#        ├─ Grafana        custom.ini
#        ├─ SNMP           (awaiting the server-side update)
#        ├─ Topology       systems → hosts, pivoted out of the same prometheus.yml
#        ├─ Backup policy  per-host backup-frequency overrides
#        ├─ Data sources   which Prometheus/Grafana to read
#        └─ Alerts         ONE PAGE, collapsible sections (2026-09-04) -- Alert groups,
#                          Notification reminder schedule, Alert templates, Drainage,
#                          Disk/RAM/CPU usage, Size monitoring -- see config_alerts' own
#                          docstring
_CONFIG_CHILDREN = [
    ("config_roles", "Roles", "Who holds which role, pending requests, and which systems each role sees"),
    ("config_users", "Users", "Accounts: profile, password reset, deletion — superuser only"),
    ("config_prometheus", "Prometheus", "Scrape intervals, storage and rule files"),
    ("grafana_config", "Grafana", "custom.ini, versioned and applied"),
    ("config_snmp", "SNMP", "Network device polling"),
    ("config_topology", "Topology", "Which hosts belong to which system"),
    ("config_backup_policy", "Backup policy", "Per-host backup-frequency overrides"),
    ("config_scripts", "Scripts", "Generate the checker scripts hosts run"),
    ("system_settings", "Data sources", "Which Prometheus / Grafana to read"),
    # Renamed from "Alerts" to "Alerting" (2026-09-05, on request) -- now also the home for
    # System Alerting (see config_alerts' own docstring), which used to be a separate sibling
    # tile here until the same request folded it in as one more section of this same page.
    ("config_alerts", "Alerting", "Notification groups, reminder timing, System Alerting, and the e-mail design"),
    # Deliberately a SIBLING of Alerting, not a child of it (2026-09-04: "decouple notifications
    # from alerts") -- an event group has no severity/reminders at all, see reports.models.
    # EventGroup's own docstring on why it's a different notification TYPE, not a variant of
    # an alert.
    ("config_events", "Events", "Who hears about a system event (e.g. a backup file dropping)"),
    # Third sibling notification family alongside Alerting and Events (2026-09-08, on request:
    # "we also need Automated report Groups and event groups in much the same way we have
    # alert groups") -- who receives which of the six scheduled Automated Reports. Relabelled
    # "Reporting" (2026-09-12, on request) once it stopped being narrative-only: the same
    # group mechanism now also covers the unattended xlsx Active Directory Report (see
    # reports.scheduled_xlsx_reports.XLSX_REPORT_TYPES) -- url_name kept as-is, label-only.
    ("config_automated_reports", "Reporting", "Who receives which scheduled report"),
    # 2026-09-12, on request: "I also dont see the folder exporter config in administrator
    # role" -- unlike Prometheus/SNMP/Grafana, this is not a DB-versioned editor (this screen
    # never writes folder_exporter.yml, it only reflects what's already on disk/running) and
    # it's superuser-only (see _SUPERUSER_ONLY_CHILDREN below): the service it reports on is
    # what every one of this app's OWN scheduled jobs (alert/event pollers, automated reports)
    # runs through, so the blast radius of getting this wrong matches config_users' own.
    ("config_folder_exporter", "Folder Exporter", "Job scheduler and monitored folders — status and install guidance"),
]
#: hub cards that render grayed-out/unclickable for anyone who isn't a superuser -- the
#: server-side gate lives on each such view itself (is_superuser check, redirect otherwise);
#: this set only controls the HUB TILE's own presentation.
_SUPERUSER_ONLY_CHILDREN = {"config_users", "config_folder_exporter"}


def _hub_cards(children: list, active: str | None, *, viewer_is_superuser: bool = True) -> list:
    return [{"url_name": n, "label": lbl, "hint": hint, "active": n == active,
             "disabled": n in _SUPERUSER_ONLY_CHILDREN and not viewer_is_superuser}
           for n, lbl, hint in children]


def _config_context(active: str, *, viewer_is_superuser: bool = True) -> dict:
    return {
        "config_children": _hub_cards(_CONFIG_CHILDREN, active, viewer_is_superuser=viewer_is_superuser),
        "yaml_source": promconfig.source_info(),
        "service_status": prometheus_admin.service_status(),
    }


@never_cache
@login_required
def config_roles(request):
    """Everything to do with roles, ONE PAGE with a properly labelled, collapsible SECTION
    per concern -- Role assignments (who holds which role, and pending requests) and Role
    scopes (which systems each role sees) -- the same "one screen, not several" treatment
    Alerts gets (config_alerts' own docstring), on request (2026-09-04: "do the same for
    roles as well").

    THREE URLs still render this identical page -- this one (the canonical entry point),
    roles_console (`/roles/`, this app's own former landing page, still linked from the
    notifications bell and several defaults -- see _safe_next/context._NAV_PARENT) and
    config_role_scopes (kept for its own pre-existing tests that assert on
    resp.context["systems"] after a GET). All three share _role_assignments_context/
    _role_scopes_context for their read-side data and differ only in which section opens by
    default and which URL actually processes their own POST -- so wherever a request lands,
    the SAME combined page renders, and nothing that already links to/tests the older URLs
    needed to change."""
    denied = _require_admin(request)
    if denied:
        return denied
    return render(request, "reports/config_roles.html", {
        **_config_context("config_roles"),
        **_role_assignments_context(request),
        **_role_scopes_context(),
        "default_open": "assignments",
    })


_DURATION_UNITS = {
    "": 60,       # a bare number means MINUTES -- every value this app ever stored before
                  # units existed was already in minutes; a plain "10" must keep meaning that.
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
}
_DURATION_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([a-zA-Z]*)\s*$")


def _parse_duration_seconds(raw: str):
    """"10" (bare number = minutes), "45s", "2h", "1.5m" -> seconds (a float, so "30s" is
    exact rather than rounding through minutes first), or None if it doesn't parse / the unit
    isn't recognised (2026-09-04: "in alerts allow users to specify the time value units eg
    15s is 15 seconds h is hours"). One parser for every time-value field in Alerts (Drainage
    Critical/Warning, the Backup drainage override, and each entry in a group's own Reminders
    list) rather than each field inventing its own bare-number-means-minutes convention."""
    m = _DURATION_RE.match(raw or "")
    if not m:
        return None
    amount, unit = m.groups()
    factor = _DURATION_UNITS.get(unit.lower())
    if factor is None:
        return None
    return float(amount) * factor


def _seconds_to_duration_str(seconds) -> str:
    """Seconds -> the cleanest unit it divides evenly into -- whole hours as "2h", whole
    minutes as "10m", anything else (including a sub-minute value only a unit suffix could
    have produced, e.g. 15s) as a plain seconds count "15s" -- so a saved value redisplays
    recognisably instead of always being forced back through decimal minutes."""
    seconds = float(seconds)
    if seconds == int(seconds):
        seconds = int(seconds)
        if seconds % 3600 == 0:
            return f"{seconds // 3600}h"
        if seconds % 60 == 0:
            return f"{seconds // 60}m"
        return f"{seconds}s"
    return f"{seconds:g}s"


def _backup_drainage_rows(request, section: str) -> list:
    """One row per system in the FULL topology, not just ones with currently-live backup
    folder data (2026-09-04: "show all systems and their current values as intuited from
    backup policy here... even though the live data not there you may gray out these systems
    but add them") -- 'auto' is what folders.backup_drain_limits computes for that system
    RIGHT NOW (its own backup cadence, or the documented 24h fallback); 'override_value' is
    this admin's own saved override for it, or -- if THIS section's own save was just rejected
    -- exactly what was typed, so a rejected save re-shows what you typed rather than what's
    still saved (the same pattern every other Alerts field in this view uses); 'live'
    distinguishes a system reports.folders.backup_drainage_systems() currently sees real
    folder data for from one that's topology-only so far (rendered greyed out, not omitted --
    the override still applies the moment a folder does show up)."""
    cfg = gr.load_config()
    topo_systems = gr.load_topology(cfg.prometheus_yml, scope="all")
    live = folders.backup_drainage_systems()
    overrides = DrainageThresholdConfig.get().backup_red_seconds_overrides or {}
    rejected = section == "backup_drainage"
    rows = []
    for s in sorted(topo_systems, key=lambda x: x.name):
        _, auto_red = folders.backup_drain_limits(s.name)
        if rejected:
            override_value = request.POST.get(f"backup_override__{s.name}", "")
        else:
            override_value = _seconds_to_duration_str(overrides[s.name]) if s.name in overrides else ""
        rows.append({
            "system": s.name,
            "auto": _seconds_to_duration_str(auto_red),
            "override_value": override_value,
            "live": s.name in live,
        })
    return rows


def _alert_group_health(group) -> dict:
    """Whether one AlertGroup is genuinely wired to fire, and exactly why not if it isn't --
    on request (2026-09-04): "have a small section where we show all successfully configured
    alerts that are set to fire... a glowing green halo... If an alert was configured, for
    example but has no recipients or has not proper notification config it must have a red
    halo... tell you exactly whats wrong." Pure config inspection (no live Prometheus call) --
    "live" here means "correctly configured to fire", not "currently firing".

    THREE states, not two (2026-10-01, on request: "how come the alert groups we added for
    networks and infrastructure teams show green but they are not yet sending to these
    teams... they should not be green unless already sending") -- found that Network Team/
    Infrastructure Team were perfectly configured (active, systems, real recipients) yet had
    sent exactly zero notifications ever, because the alert-poller's "kind" loop (Infrastructure/
    AD/Switches & Routers) never actually evaluated AlertGroup matching until that same date's
    pipeline fix (see alerting._evaluate_for_groups' own docstring). "Correctly configured" and
    "confirmed to have actually notified someone" are different claims; green must mean the
    second one, not just the first. `AlertFinding.last_notified_at` is the one real signal of
    confirmed delivery (set only once send_email has actually succeeded, see
    alerting.run_alert_cycle's own comment) -- NOT the presence of matching IssueOccurrence
    rows, which get written unconditionally for every system regardless of any AlertGroup."""
    from .models import AlertFinding

    problems = []
    if not group.active:
        problems.append("Paused — nothing will fire until it's reactivated.")
    if not group.systems:
        problems.append("No systems selected — it has nothing to watch.")
    if not group.recipient_emails():
        problems.append("No stakeholders with a valid e-mail address.")
    if problems:
        return {"group": group, "is_live": False, "is_unconfirmed": False, "problems": problems}

    if not AlertFinding.objects.filter(group=group, last_notified_at__isnull=False).exists():
        return {"group": group, "is_live": False, "is_unconfirmed": True, "problems": [
            "Configured correctly, but has never actually sent a notification yet — "
            "waiting for a qualifying finding and its next poll cycle."]}
    return {"group": group, "is_live": True, "is_unconfirmed": False, "problems": []}


def _grouped_alert_groups(groups) -> list:
    """[{"label": "Monitoring Alert"/"System Alert", "key": "monitoring"/"system",
    "subtypes": [{"label": "" or "Staleness Alert", "key": "monitoring:"/"system:staleness",
    "groups": [AlertGroup, ...]}]}] -- the Alert groups list's own two-level hierarchy
    (2026-09-05, on request: "make the system hierarchy more readable, different font sizes
    and opacity for children... following the already established structure" -- the
    established structure being the Freshness checks list's own grouped-table-with-
    sub-header-rows treatment, extended one level deeper here since Type has its own nested
    Sub type). Monitoring Alert has no real subtype tier today (one implicit blank-label
    bucket, rendered as data rows straight under the Type header, no Sub type row); System
    Alert nests by alert_subtype (currently just "staleness"/Staleness Alert)."""
    type_order = [AlertGroup.ALERT_TYPE_MONITORING, AlertGroup.ALERT_TYPE_SYSTEM]
    type_labels = dict(AlertGroup.ALERT_TYPE_CHOICES)
    subtype_labels = dict(AlertGroup.ALERT_SUBTYPE_CHOICES)
    by_type: dict = {}
    for g in groups:
        by_type.setdefault(g.alert_type, {}).setdefault(g.alert_subtype, []).append(g)

    result = []
    for t in type_order:
        if t not in by_type:
            continue
        subtypes = []
        for subtype_key in sorted(by_type[t], key=lambda k: subtype_labels.get(k, "")):
            subtypes.append({
                "label": subtype_labels.get(subtype_key, ""),
                "key": f"{t}:{subtype_key}",
                "groups": sorted(by_type[t][subtype_key], key=lambda g: g.name),
            })
        result.append({"label": type_labels[t], "key": t, "subtypes": subtypes})
    return result


_SIZE_MONITORING_FOLDER = "T24 Log File"   # the only entry FOLDER_EXPECTED_PCT has today

#: 0=Monday .. 6=Sunday, matching AlertGroup.schedule_days/in_schedule's own numbering
#: (Python's own date.weekday()) -- used by config_alert_group_edit's Schedule section.
_WEEKDAY_CHOICES = [(0, "Mon"), (1, "Tue"), (2, "Wed"), (3, "Thu"), (4, "Fri"), (5, "Sat"), (6, "Sun")]


def _category_headers() -> list:
    """[{"value":, "label":, "group_label":}, ...] in AlertGroup.CATEGORY_CHOICES' own order
    -- one list the template iterates for BOTH header rows of the categories grid (the plain
    labels and the folder-group super-labels above them), rather than two separate lists a
    Django template would have no clean way to zip together by position."""
    return [{"value": v, "label": l, "group_label": AlertGroup.CATEGORY_GROUP_LABELS.get(v, "")}
           for v, l in AlertGroup.CATEGORY_CHOICES]


@never_cache
@login_required
def config_alerts(request):
    """Everything to do with alerts, ONE PAGE with a properly labelled, collapsible SECTION
    per concern (on request, 2026-09-04: "consolidate everything to do with alerts on one
    screen have properly labelled and collapsible sections with clear and clean separation of
    concerns this is better than multiple screens" -- replaces the earlier hub-of-cards
    version of this same page, which itself replaced four separate screens before that). Each
    section is independently submitted (own <form>, own `section` hidden field, own Save
    button) so saving one never touches another's unsaved edits; which section reopens after
    a save is left to the page's own client-side memory (see the template's own script), not
    tracked here.

      - Alert groups -- who gets notified, and when, per system group (AlertGroup). Creating
        one still opens its own full edit screen next (config_alert_group_edit) -- one
        record's full form (systems, categories, stakeholders, test tools, its OWN reminder
        schedule -- group-specific, 2026-09-04, not app-wide any more) is a drill-down, not
        something that folds into an accordion row.
      - Alert templates -- the designed sample e-mail gallery, read-only (opens
        config_alert_template_preview in a new tab).
      - Per Alert Config -- the thresholds that actually alert (Critical only, 2026-09-04:
        "there are no expected alerts for warning severity"): payment & interface queue
        drainage, an admin override onto backup drainage's own automatic per-system cadence
        ("backup drainage monitoring and payment and interface queues... have a different
        cadence"), Disk/RAM/CPU usage, and Size monitoring.
      - Display thresholds -- the Warning/amber values Per Alert Config used to also carry,
        moved out (2026-09-04) since they no longer alert anyone; kept editable here because
        they still drive Folder Watch's amber tile colour and the daily report's amber chip.
      - System Alerting -- a SECTION of this page, not its own Configuration hub tile any
        more (2026-09-05, on request: "rename the main alerts screen to alerting and add
        system alerting as a section of alerting"). Still a genuinely separate notification
        type underneath (SystemAlertGroup/FreshnessCheck, reports.system_alerts -- a checker
        going silently stale is a structurally different thing from a monitored value
        crossing a threshold, see FreshnessCheck's own docstring) -- only the PAGE moved, not
        the model or its detection logic. "Staleness Alert" (the checker/exporter-freshness
        check type) is this section's own first, so-far-only check type.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    section = request.POST.get("section") if request.method == "POST" else None

    # ---- Alert groups: create-new only; editing/deleting one lives on its own screen -------
    # Covers EVERY alert group regardless of classification (2026-09-05, on request: "alert
    # groups must be for all alerts even if there are system alerts, let user specify this in
    # the alert type and sub type in alert groups") -- alert_type/alert_subtype are picked
    # HERE, at creation, and are immutable afterward (see AlertGroup's own docstring on why).
    if section == "groups":
        name = (request.POST.get("name") or "").strip()
        alert_type = request.POST.get("alert_type") or AlertGroup.ALERT_TYPE_MONITORING
        if alert_type not in dict(AlertGroup.ALERT_TYPE_CHOICES):
            alert_type = AlertGroup.ALERT_TYPE_MONITORING
        if alert_type == AlertGroup.ALERT_TYPE_SYSTEM:
            # Only one subtype exists today -- picked automatically rather than shown as a
            # single-option dropdown with nothing else to choose (a future second System
            # Alert subtype would need this to actually read the posted value).
            alert_subtype = AlertGroup.ALERT_SUBTYPE_STALENESS
        else:
            alert_subtype = ""
        if not name:
            messages.error(request, "Give the group a name.")
        elif AlertGroup.objects.filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
        else:
            create_kwargs = {"name": name, "updated_by": request.user,
                             "alert_type": alert_type, "alert_subtype": alert_subtype}
            if alert_type == AlertGroup.ALERT_TYPE_SYSTEM:
                create_kwargs["reminder_minutes"] = [AlertGroup.DEFAULT_SYSTEM_ALERT_REMINDER_MINUTES]
            group = AlertGroup.objects.create(**create_kwargs)
            messages.success(request, f"Created “{name}”. Add its systems and stakeholders below.")
            return redirect("config_alert_group_edit", pk=group.pk)
        return redirect("config_alerts")

    # ---- Drainage: Critical (payment & interface queues) -- the one value that actually
    # alerts; Warning lives in the "display" section below since it no longer does ------------
    elif section == "drainage_critical":
        drainage_cfg = DrainageThresholdConfig.get()
        if request.POST.get("action") == "reset":
            drainage_cfg.red_seconds = None
            drainage_cfg.updated_by = request.user
            drainage_cfg.save(update_fields=["red_seconds", "updated_by", "updated_at"])
            messages.success(request, "Drainage Critical reset to the shipped default (10 minutes).")
            return redirect("config_alerts")
        errors = []
        red_s = _parse_duration_seconds(request.POST.get("red_minutes", "").strip())
        if red_s is None:
            errors.append("Drainage: enter a duration like 10, 10m, 30s, or 2h.")
        current_amber_s, _ = drainage_cfg.effective_seconds
        if red_s is not None:
            if red_s <= 0:
                errors.append("Drainage: must be greater than zero.")
            elif red_s <= current_amber_s:
                errors.append("Drainage: Critical must be greater than the current Warning "
                              "display threshold (see Display thresholds).")
        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            drainage_cfg.red_seconds = round(red_s)
            drainage_cfg.updated_by = request.user
            drainage_cfg.save(update_fields=["red_seconds", "updated_by", "updated_at"])
            messages.success(request, "Drainage Critical saved — the next page load / poll uses it.")
            return redirect("config_alerts")

    # ---- Drainage: backup folders -- an explicit override onto the otherwise-automatic
    # per-system backup-cadence calculation (2026-09-04: "backup drainage monitoring and
    # payment and interface queues... have a different cadence to be set") ------------------
    elif section == "backup_drainage":
        drainage_cfg = DrainageThresholdConfig.get()
        if request.POST.get("action") == "reset":
            drainage_cfg.backup_red_seconds_overrides = {}
            drainage_cfg.updated_by = request.user
            drainage_cfg.save(update_fields=["backup_red_seconds_overrides", "updated_by", "updated_at"])
            messages.success(request, "Every system back to its own automatic backup-cadence calculation.")
            return redirect("config_alerts")
        # One row per system, one Save for the whole table -- a blank field means "no override
        # for this system", so a save always fully replaces the dict rather than merging, the
        # same "Metrics to alert on, per system" pattern config_alert_group_edit.html uses.
        cfg_ini = gr.load_config()
        topo_systems = gr.load_topology(cfg_ini.prometheus_yml, scope="all")
        errors = []
        new_overrides = {}
        for s in topo_systems:
            raw = (request.POST.get(f"backup_override__{s.name}") or "").strip()
            if not raw:
                continue
            seconds = _parse_duration_seconds(raw)
            if seconds is None or seconds <= 0:
                errors.append(f"{s.name}: enter a duration like 10, 10m, 30s, or 2h, or leave blank for automatic.")
                continue
            new_overrides[s.name] = round(seconds)
        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            drainage_cfg.backup_red_seconds_overrides = new_overrides
            drainage_cfg.updated_by = request.user
            drainage_cfg.save(update_fields=["backup_red_seconds_overrides", "updated_by", "updated_at"])
            messages.success(request, "Backup drainage overrides saved.")
            return redirect("config_alerts")

    # ---- Disk, RAM & CPU usage: Critical -- the one value that actually alerts; Warning
    # lives in the "display" section below since it no longer does -----------------------------
    elif section == "usage_critical":
        if request.POST.get("action") == "reset":
            current_amber, _ = usage_threshold_admin.read_live()
            ok, msg = usage_threshold_admin.write_live(current_amber, usage_threshold_admin.DEFAULT_RED_PCT)
            (messages.success if ok else messages.error)(request, msg)
            return redirect("config_alerts")
        errors = []
        try:
            red_pct = int(request.POST.get("red_pct", "").strip())
        except ValueError:
            errors.append("Disk/RAM/CPU: enter a whole-number percentage.")
            red_pct = None
        current_amber, _ = usage_threshold_admin.read_live()
        if red_pct is not None:
            if not (0 < red_pct < 100):
                errors.append("Disk/RAM/CPU: must be between 1 and 99.")
            elif red_pct <= current_amber:
                errors.append("Disk/RAM/CPU: Critical must be greater than the current Warning "
                              "display threshold (see Display thresholds).")
        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            ok, msg = usage_threshold_admin.write_live(current_amber, red_pct)
            (messages.success if ok else messages.error)(request, msg)
            return redirect("config_alerts")

    # ---- Display thresholds: the amber/Warning values, kept editable here since they still
    # drive Folder Watch's tile colour and the daily report's chip colour even though neither
    # any longer triggers an alert (only "red" does, 2026-09-04) --------------------------------
    elif section == "drainage_warning":
        drainage_cfg = DrainageThresholdConfig.get()
        if request.POST.get("action") == "reset":
            drainage_cfg.amber_seconds = None
            drainage_cfg.updated_by = request.user
            drainage_cfg.save(update_fields=["amber_seconds", "updated_by", "updated_at"])
            messages.success(request, "Drainage Warning reset to the shipped default (5 minutes).")
            return redirect("config_alerts")
        errors = []
        amber_s = _parse_duration_seconds(request.POST.get("amber_minutes", "").strip())
        if amber_s is None:
            errors.append("Drainage: enter a duration like 5, 5m, 30s, or 1h.")
        _, current_red_s = drainage_cfg.effective_seconds
        if amber_s is not None:
            if amber_s <= 0:
                errors.append("Drainage: must be greater than zero.")
            elif amber_s >= current_red_s:
                errors.append("Drainage: Warning must be less than the current Critical threshold.")
        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            drainage_cfg.amber_seconds = round(amber_s)
            drainage_cfg.updated_by = request.user
            drainage_cfg.save(update_fields=["amber_seconds", "updated_by", "updated_at"])
            messages.success(request, "Drainage Warning saved.")
            return redirect("config_alerts")

    elif section == "usage_warning":
        if request.POST.get("action") == "reset":
            _, current_red = usage_threshold_admin.read_live()
            ok, msg = usage_threshold_admin.write_live(usage_threshold_admin.DEFAULT_AMBER_PCT, current_red)
            (messages.success if ok else messages.error)(request, msg)
            return redirect("config_alerts")
        errors = []
        try:
            amber_pct = int(request.POST.get("amber_pct", "").strip())
        except ValueError:
            errors.append("Disk/RAM/CPU: enter a whole-number percentage.")
            amber_pct = None
        _, current_red = usage_threshold_admin.read_live()
        if amber_pct is not None:
            if not (0 < amber_pct < 100):
                errors.append("Disk/RAM/CPU: must be between 1 and 99.")
            elif amber_pct >= current_red:
                errors.append("Disk/RAM/CPU: Warning must be less than the current Critical threshold.")
        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            ok, msg = usage_threshold_admin.write_live(amber_pct, current_red)
            (messages.success if ok else messages.error)(request, msg)
            return redirect("config_alerts")

    # ---- Size monitoring ----------------------------------------------------------------------
    elif section == "size":
        policy = folder_size_admin.parse_live_policy()
        entry = policy.get(_SIZE_MONITORING_FOLDER, {"mount": "F:", "pct": 80})
        if request.POST.get("action") == "reset":
            entry["pct"] = round(0.80 * 100, 2)
            policy[_SIZE_MONITORING_FOLDER] = entry
            ok, msg = folder_size_admin.write_policy(policy)
            (messages.success if ok else messages.error)(request, "Size monitoring reset to the shipped default (80%).")
            return redirect("config_alerts")
        errors = []
        try:
            size_pct = float(request.POST.get("size_pct", "").strip())
        except ValueError:
            errors.append("Size monitoring: enter a percentage.")
            size_pct = None
        if size_pct is not None and not (0 < size_pct < 100):
            errors.append("Size monitoring: must be between 1 and 99.")
        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            entry["pct"] = size_pct
            policy[_SIZE_MONITORING_FOLDER] = entry
            ok, msg = folder_size_admin.write_policy(policy)
            (messages.success if ok else messages.error)(request, msg)
            return redirect("config_alerts")

    # ---- System Alerting: Freshness checks -- what's WATCHED for staleness, a SECTION of
    # this same page (2026-09-05, on request: "add system alerting as a section of alerting").
    # Groups that HEAR about staleness are just AlertGroup rows now (alert_type=System Alert,
    # created via the "groups" section above) -- FreshnessCheck stays its own model, since a
    # staleness finding is structurally different from a threshold finding (see that model's
    # own docstring). ---------------------------------------------------------------------------
    elif section == "freshness_check":
        name = (request.POST.get("name") or "").strip()
        system_name = (request.POST.get("system") or "").strip()
        kind = request.POST.get("kind") or FreshnessCheck.KIND_TEXTFILE_MTIME
        instance = (request.POST.get("instance") or "").strip()
        file = (request.POST.get("file") or "").strip()
        needs_file = kind == FreshnessCheck.KIND_TEXTFILE_MTIME
        max_age_s = _parse_duration_seconds((request.POST.get("max_age") or "").strip())
        if not (name and system_name and instance) or (needs_file and not file):
            messages.error(request, "Name, system, instance"
                                    + (" and file" if needs_file else "") + " are all required.")
        elif max_age_s is None:
            messages.error(request, "Max age must be a number, optionally suffixed s/m/h "
                                    "(e.g. \"2h\").")
        elif FreshnessCheck.objects.filter(instance=instance, file=file if needs_file else "").exists():
            messages.error(request, f"A check for {instance} / {file or '(backup checker)'} already exists.")
        else:
            FreshnessCheck.objects.create(
                name=name, system=system_name, kind=kind, instance=instance,
                file=file if needs_file else "",
                max_age_seconds=int(max_age_s),
                scheduler_instance=(request.POST.get("scheduler_instance") or "").strip(),
                scheduler_job=(request.POST.get("scheduler_job") or "").strip())
            messages.success(request, f"Added “{name}”.")
        return redirect("config_alerts")

    # ---- Alert Silencing: known, self-resolving findings rolled into ONE daily digest
    # instead of individual new/reminder e-mails (2026-09-19, on request: "reduce the
    # intrusiveness of alerts" for alerts "not being actioned at all by admins... that self
    # resolve and then start again"). See AlertSilence's own docstring for the full design.
    # Component picker (2026-09-30, on request: "in config allow to select which mount or
    # component before muting") -- `flag_key` is now chosen from a real, live-derived list
    # (see silence_component_map below), not typed free text. Leaving it blank silences the
    # WHOLE `category` for this system instead of one component -- current AND future ones
    # (2026-09-30, on request: "mute crb disk usage rtgs disk usage, ebis disk usage", "add a
    # new config in alerting to mute specific alert"). Monitoring groups only: System Alert
    # (staleness) findings go through a completely separate pipeline (reports.system_alerts)
    # this feature does not touch yet. -----------------------------------------------------
    elif section == "silence":
        system_name = (request.POST.get("system") or "").strip()
        category_name = (request.POST.get("category") or "").strip()
        flag_key = (request.POST.get("flag_key") or "").strip()
        group_id = request.POST.get("group")
        reason = (request.POST.get("reason") or "").strip()
        try:
            days = int(request.POST.get("expires_days") or "60")
        except ValueError:
            days = 60
        group = AlertGroup.objects.filter(
            pk=group_id, alert_type=AlertGroup.ALERT_TYPE_MONITORING).first()
        category_labels = dict(AlertGroup.CATEGORY_CHOICES)
        if not (system_name and category_name in category_labels and group):
            messages.error(request, "System, category and a Monitoring alert group are all required.")
        elif days <= 0:
            messages.error(request, "Expires in: enter a whole number of days greater than zero.")
        elif AlertSilence.objects.filter(system=system_name, category=category_name,
                                         flag_key=flag_key, active=True).exists():
            scope = flag_key or f"ALL {category_labels[category_name]}"
            messages.error(request, f"{system_name} — {scope} is already silenced.")
        else:
            AlertSilence.objects.create(
                system=system_name, category=category_name, flag_key=flag_key, group=group,
                reason=reason, created_by=request.user,
                expires_at=timezone.now() + datetime.timedelta(days=days))
            scope = flag_key or f"ALL {category_labels[category_name]} components (current + future)"
            messages.success(request, f"Silenced {system_name} — {scope}. "
                                      f"{group.name} will get a daily digest instead.")
        return redirect("config_alerts")

    elif section == "silence_toggle":
        silence = AlertSilence.objects.filter(pk=request.POST.get("id")).first()
        if silence:
            silence.active = not silence.active
            silence.save(update_fields=["active"])
            messages.success(request, ("Re-activated " if silence.active else "Deactivated ")
                             + f"{silence.system} — {silence.flag_key}.")
        return redirect("config_alerts")

    # ---- Read-side context for every section, regardless of which one (if any) was posted ----
    # `groups` deliberately includes EVERY alert_type/alert_subtype (2026-09-05) -- ONE list
    # for the whole "Alert groups" section, with a Type column distinguishing them, rather
    # than a second parallel list for System Alert groups.
    groups = AlertGroup.objects.all()
    health_rows = [_alert_group_health(g) for g in groups]
    grouped_alert_groups = _grouped_alert_groups(groups)
    freshness_checks = FreshnessCheck.objects.all()
    topology_systems = _topology_systems()
    alert_silences = AlertSilence.objects.select_related("group").all()
    monitoring_groups = groups.filter(alert_type=AlertGroup.ALERT_TYPE_MONITORING)

    template_rows = [{"category": cat, "label": lbl, "available": cat in alert_email_templates.FILE_BY_CATEGORY}
                     for cat, lbl in AlertGroup.CATEGORY_CHOICES]

    # {system: {category: [flag_key, ...]}} -- powers the Component picker's cascading select
    # (2026-09-30, on request: "in config allow to select which mount or component before
    # muting"). Sourced from real IssueOccurrence history, not hand-maintained, same "never a
    # catalog that can drift" discipline as metric_registry.py/IssueOccurrence.domain -- a
    # mount that has never actually fired simply never appears as a choice, and one added next
    # month appears here the first time it does. 90 days is generous for a "has this ever
    # happened recently" picker without scanning the table's full history every page load.
    from .models import IssueOccurrence
    silence_component_map = {}
    since_90d = timezone.now() - datetime.timedelta(days=90)
    for row in (IssueOccurrence.objects.filter(started_at__gte=since_90d)
               .values("system", "category", "flag_key").distinct()):
        by_cat = silence_component_map.setdefault(row["system"], {})
        keys = by_cat.setdefault(row["category"], [])
        if row["flag_key"] not in keys:
            keys.append(row["flag_key"])
    for by_cat in silence_component_map.values():
        for keys in by_cat.values():
            keys.sort()

    drainage_cfg = DrainageThresholdConfig.get()
    drainage_amber_s, drainage_red_s = drainage_cfg.effective_seconds
    if section == "drainage_critical":
        # A rejected save re-shows exactly what was typed, not what's still saved.
        drainage_red_min = request.POST.get("red_minutes", "")
    else:
        drainage_red_min = _seconds_to_duration_str(drainage_red_s)
    if section == "drainage_warning":
        drainage_amber_min = request.POST.get("amber_minutes", "")
    else:
        drainage_amber_min = _seconds_to_duration_str(drainage_amber_s)
    backup_drainage_rows = _backup_drainage_rows(request, section)

    usage_amber_pct, usage_red_pct = usage_threshold_admin.read_live()
    usage_red_val = request.POST.get("red_pct", "") if section == "usage_critical" else str(usage_red_pct)
    usage_amber_val = request.POST.get("amber_pct", "") if section == "usage_warning" else str(usage_amber_pct)

    size_policy = folder_size_admin.parse_live_policy()
    size_entry = size_policy.get(_SIZE_MONITORING_FOLDER, {"mount": "F:", "pct": 80})
    if section == "size":
        size_pct_val = request.POST.get("size_pct", "")
    else:
        size_pct_val = str(size_entry.get("pct", 80))

    return render(request, "reports/config_alerts.html", {
        **_config_context("config_alerts"),
        "groups": groups,
        "grouped_alert_groups": grouped_alert_groups,
        "health_rows": health_rows,
        "template_rows": template_rows,
        "drainage_amber_minutes": drainage_amber_min,
        "drainage_red_minutes": drainage_red_min,
        "backup_drainage_rows": backup_drainage_rows,
        "usage_amber_pct": usage_amber_val,
        "usage_red_pct": usage_red_val,
        "size_folder_name": _SIZE_MONITORING_FOLDER,
        "size_mount": size_entry.get("mount", "F:"),
        "size_pct": size_pct_val,
        "freshness_checks": freshness_checks,
        "topology_systems": topology_systems,
        "alert_silences": alert_silences,
        "monitoring_groups": monitoring_groups,
        "category_choices": AlertGroup.CATEGORY_CHOICES,
        "silence_component_map": silence_component_map,
    })


@never_cache
@login_required
def config_events(request):
    """Everything to do with EVENT notifications -- a screen deliberately SEPARATE from
    Alerts (2026-09-04: "decouple notifications from alerts... I want to have notification
    types, alert notification and event notification"). Mirrors config_alerts' own "one
    screen, collapsible sections" shape but for a genuinely different, simpler concept: an
    EventGroup has no severity, no per-category filter and no reminder schedule, because an
    event has none of those either -- see reports.events' own module docstring. Today's only
    event type is "backup file dropped" (reports.events.run_event_cycle); this page just
    manages who hears about it, per system, the same stakeholder-management shape
    config_alerts uses for Alert groups."""
    denied = _require_admin(request)
    if denied:
        return denied

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        if not name:
            messages.error(request, "Give the group a name.")
        elif EventGroup.objects.filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
        else:
            group = EventGroup.objects.create(name=name, updated_by=request.user)
            messages.success(request, f"Created “{name}”. Add its systems and stakeholders below.")
            return redirect("config_event_group_edit", pk=group.pk)
        return redirect("config_events")

    groups = EventGroup.objects.all()
    return render(request, "reports/config_events.html", {
        **_config_context("config_events"),
        "groups": groups,
    })


@login_required
def config_event_group_edit(request, pk):
    """One event group's own screen: which systems it covers and who its stakeholders are --
    the stakeholder half of AlertGroup's own edit screen, none of the alert-specific half
    (severity, per-category metrics, reminder schedule), since an EventGroup has none of
    those (see reports.models.EventGroup's own docstring)."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(EventGroup, pk=pk)
    systems = _topology_systems()
    users = get_user_model().objects.filter(is_active=True).order_by("username")

    if request.method == "POST":
        if request.POST.get("action") == "delete":
            name = group.name
            group.delete()
            messages.success(request, f"Removed “{name}”.")
            return redirect("config_events")

        name = (request.POST.get("name") or group.name).strip()
        if EventGroup.objects.exclude(pk=group.pk).filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
            return redirect("config_event_group_edit", pk=group.pk)

        chosen_systems = [s for s in request.POST.getlist("systems") if s in systems]
        chosen_user_ids = [int(i) for i in request.POST.getlist("users") if i.isdigit()]
        raw = request.POST.get("emails", "")
        # ";" too, not just "," / newline -- see config_alert_group_edit's identical fix
        # (2026-09-08) for why an Outlook "To:" field pasted verbatim used to wipe this field.
        candidates = [e.strip() for e in re.split(r"[,;\n]", raw) if e.strip()]
        valid, bad = [], []
        for e in candidates:
            try:
                validate_email(e)
                valid.append(e)
            except ValidationError:
                bad.append(e)
        if bad:
            messages.error(request, "Dropped invalid address(es): " + ", ".join(bad))

        group.name = name
        group.systems = chosen_systems
        group.emails = sorted(set(valid))
        group.active = request.POST.get("active") == "on"
        group.updated_by = request.user
        group.save()
        group.users.set(get_user_model().objects.filter(pk__in=chosen_user_ids))
        messages.success(request, f"Saved — {len(group.emails)} plain e-mail address(es), "
                                  f"{group.users.count()} app-user stakeholder(s) on file.")
        return redirect("config_event_group_edit", pk=group.pk)

    return render(request, "reports/config_event_group_edit.html", {
        "group": group, "systems": systems, "users": users,
        "chosen_users": set(group.users.values_list("pk", flat=True)),
        "email_list": "\n".join(group.emails or []),
    })


def _automated_report_group_health(group) -> dict:
    """Reporting's own twin of _alert_group_health -- same "glowing green halo / red halo,
    click to see exactly what's wrong" treatment (2026-09-22, on request: "add the glowing
    report group names so we see if there[']s reports that are configured properly....as is
    done for alert groups"). `report_types` standing in for AlertGroup.systems as the "has
    nothing to watch" check, matching AutomatedReportGroup's own docstring ("Empty means
    covers nothing yet")."""
    problems = []
    if not group.active:
        problems.append("Paused — nothing will fire until it's reactivated.")
    if not group.report_types:
        problems.append("No report types selected — it covers nothing yet.")
    if not group.recipient_emails():
        problems.append("No stakeholders with a valid e-mail address.")
    return {"group": group, "is_live": not problems, "problems": problems}


@never_cache
@login_required
def config_automated_reports(request):
    """Everything to do with AUTOMATED REPORT notifications -- the third notification family
    alongside AlertGroup and EventGroup (2026-09-08, on request: "we also need Automated report
    Groups and event groups in much the same way we have alert groups to maintain a consistant
    design"). Mirrors config_events' own "one screen, groups list + create form" shape exactly:
    an AutomatedReportGroup is thin like an EventGroup (no severity, no reminder schedule), just
    with `report_types` (which of the six scheduled report kinds it receives) standing in for
    EventGroup's `systems` -- see AutomatedReportGroup's own docstring on why it has no systems
    field at all (reports are estate-wide)."""
    denied = _require_admin(request)
    if denied:
        return denied

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        if not name:
            messages.error(request, "Give the group a name.")
        elif AutomatedReportGroup.objects.filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
        else:
            group = AutomatedReportGroup.objects.create(name=name, updated_by=request.user)
            messages.success(request, f"Created “{name}”. Choose its report types and stakeholders below.")
            return redirect("config_automated_report_group_edit", pk=group.pk)
        return redirect("config_automated_reports")

    groups = AutomatedReportGroup.objects.all()
    health_rows = [_automated_report_group_health(g) for g in groups]
    return render(request, "reports/config_automated_reports.html", {
        **_config_context("config_automated_reports"),
        "groups": groups,
        "health_rows": health_rows,
        # Narrative REPORT_TYPES + the xlsx family (reports.scheduled_xlsx_reports) --
        # widened here only, not in REPORT_TYPES itself: generate_automated_report.py's own
        # CLI choices must stay narrative-only (see that module's own docstring).
        "report_type_choices": [(k, v["label"])
                                for k, v in {**REPORT_TYPES, **XLSX_REPORT_TYPES}.items()],
    })


@login_required
def config_automated_report_group_edit(request, pk):
    """One automated-report group's own screen: which report types it receives and who its
    stakeholders are -- the stakeholder half of AlertGroup's own edit screen, with
    `report_types` (checkboxes against the six REPORT_TYPES keys) standing in for the
    system/category pickers, since a report type isn't scoped to a system the way an alert
    category is (see AutomatedReportGroup.covers_report_type)."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(AutomatedReportGroup, pk=pk)
    combined_report_types = {**REPORT_TYPES, **XLSX_REPORT_TYPES}
    report_type_choices = [(k, v["label"]) for k, v in combined_report_types.items()]
    valid_types = set(combined_report_types.keys())
    users = get_user_model().objects.filter(is_active=True).order_by("username")

    if request.method == "POST":
        if request.POST.get("action") == "delete":
            name = group.name
            group.delete()
            messages.success(request, f"Removed “{name}”.")
            return redirect("config_automated_reports")

        name = (request.POST.get("name") or group.name).strip()
        if AutomatedReportGroup.objects.exclude(pk=group.pk).filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
            return redirect("config_automated_report_group_edit", pk=group.pk)

        chosen_types = [t for t in request.POST.getlist("report_types") if t in valid_types]
        chosen_user_ids = [int(i) for i in request.POST.getlist("users") if i.isdigit()]
        raw = request.POST.get("emails", "")
        candidates = [e.strip() for e in re.split(r"[,;\n]", raw) if e.strip()]
        valid, bad = [], []
        for e in candidates:
            try:
                validate_email(e)
                valid.append(e)
            except ValidationError:
                bad.append(e)
        if bad:
            messages.error(request, "Dropped invalid address(es): " + ", ".join(bad))

        group.name = name
        group.report_types = chosen_types
        group.emails = sorted(set(valid))
        group.active = request.POST.get("active") == "on"
        group.updated_by = request.user
        group.save()
        group.users.set(get_user_model().objects.filter(pk__in=chosen_user_ids))
        messages.success(request, f"Saved — {len(group.emails)} plain e-mail address(es), "
                                  f"{group.users.count()} app-user stakeholder(s) on file.")
        return redirect("config_automated_report_group_edit", pk=group.pk)

    return render(request, "reports/config_automated_report_group_edit.html", {
        "group": group, "report_type_choices": report_type_choices, "users": users,
        "chosen_users": set(group.users.values_list("pk", flat=True)),
        "email_list": "\n".join(group.emails or []),
        "test_recipients": group.recipient_emails(),
    })


def _send_narrative_report_test(report_type: str, recipients: list) -> None:
    """Reporting's own fire_live equivalent for a narrative report type: generates the SAME
    real content generate_active_directory_report/generate_automated_report would (no
    fabricated finding -- unlike a Monitoring Alert's single flag, there is no cheap fake
    stand-in for a whole trend report), wraps it in a throwaway (never persisted) stand-in
    object so render_report_html/build_automated_report_pdf can be reused unmodified, and
    sends it with the subject clearly marked [SYNTHETIC TEST]. No AutomatedReportInstance row
    is ever created -- same "never touch real history" principle config_alert_group_test's
    own fire_live already established."""
    import os
    import pathlib
    import tempfile
    from types import SimpleNamespace

    import generate_report as gr
    import mail_report as mr

    from . import automated_reports_mail as arm

    report = generate_automated_report(report_type)
    content = report_to_dict(report)
    # pk=0 -- never a real AutomatedReportInstance row, so the e-mail's own "View full report"
    # link will 404 if clicked; acceptable for a synthetic test (clearly marked as one) and
    # far simpler than teaching render_report_html to omit that link for a fake instance.
    fake = SimpleNamespace(content=content, report_type=report_type,
                           generated_at=report.generated_at, pk=0)
    chart_images = arm._summary_chart_images(content)
    chart_cids = {key: key for key in chart_images}
    html_body = arm.render_report_html(fake, chart_cids)
    subject = f"[SYNTHETIC TEST] {content.get('label', 'Automated Report')} — {report.generated_at:%d %b %Y}"
    text_body = (f"[SYNTHETIC TEST]\n\n{content.get('label', 'Automated Report')}\n\n"
                "This is a test send, not saved to report history.")
    pdf_bytes = build_automated_report_pdf(fake)
    filename = automated_report_pdf_filename(fake)

    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        raise RuntimeError("No SMTP host configured in send_report/config.ini ([smtp]).")
    mailcfg["from_name"] = "RBZ Monitoring Console · Reporting"
    tmpdir = tempfile.mkdtemp(prefix="reporting_test_")
    path = pathlib.Path(tmpdir) / filename
    try:
        path.write_bytes(pdf_bytes)
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, path,
                      inline_images=chart_images)
    finally:
        try:
            path.unlink()
            os.rmdir(tmpdir)
        except OSError:
            pass


def _send_system_admin_report_test(recipients: list) -> None:
    """Reporting's own fire_live equivalent for the System Admin Report xlsx type -- generates
    the real, current estate-wide snapshot and e-mails it through the EXACT same
    services.capture_snapshot/build_report/email_report pipeline generate_system_admin_report's
    own scheduled run uses (2026-09-22 migration off the old standalone/ fork -- see that
    command's own module docstring), not a second implementation. Never creates a
    ReportSubmission row, same "never touch real history" principle _send_xlsx_report_test's
    own docstring already established for the Active Directory twin below. `author` stays
    "Automated" (real production value, same as generate_system_admin_report's own scheduled
    run) -- the test marker goes in the SUBJECT only, via subject_prefix (2026-09-22, fixed
    after a real test send arrived showing sender "Unknown": stuffing "[SYNTHETIC TEST]" into
    `author` instead put it in the From display name, and mail_report.send_email's old raw
    f-string From header couldn't parse the brackets, swallowing the address entirely -- see
    mail_report.send_email's own formataddr fix. This is also just more correct on its own
    terms: `author` becomes the xlsx's own "By" field too, and a test send's report content
    should look identical to a real one)."""
    token = uuid.uuid4().hex
    snapshot = capture_snapshot(token)
    data = build_report(snapshot, theme="dark", author="Automated",
                        annotations={}, summary_comment="")
    filename = default_report_filename("dark", timezone.localtime())
    email_report(snapshot, data, recipients=recipients, author="Automated", filename=filename,
                subject_prefix="[SYNTHETIC TEST]")


def _send_network_reports_test(recipients: list) -> None:
    """Reporting's own fire_live equivalent for the "network_reports" bundle -- generates all
    four Networks Report pickers CONCURRENTLY through the EXACT same
    generate_network_reports.JOBS/_build_one pipeline the real 07:30 scheduled run uses (not
    a second implementation -- imported directly, same "kept in step with production" rule
    every other test-fire function on this screen already follows), and e-mails whichever of
    the four succeeded as one bundle via network.email_network_reports_bundle, subject marked
    [SYNTHETIC TEST]. Never creates a ReportSubmission row for any of the four, same "never
    touch real history" principle _send_xlsx_report_test's own docstring already established.

    This is also the app's own safe way to exercise the ThreadPoolExecutor path against real
    Prometheus without touching the real "Infrastructure reports" recipients -- clicking this
    button IS a live concurrency test, not just a content preview.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from reports.management.commands.generate_network_reports import JOBS, _build_one

    results = []
    with ThreadPoolExecutor(max_workers=len(JOBS), thread_name_prefix="network_report_test") as pool:
        futures = {pool.submit(_build_one, job): job for job in JOBS}
        for future in as_completed(futures):
            results.append(future.result())

    succeeded = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    if not succeeded:
        raise RuntimeError(
            "All four network reports failed: "
            + "; ".join(f"{r['title']} ({r['error']})" for r in failed))

    network.email_network_reports_bundle(succeeded, recipients=recipients, author="Automated",
                                         subject_prefix="[SYNTHETIC TEST]")
    if failed:
        # The send above still went out with whatever succeeded -- surface the partial
        # failure to the admin clicking "test" rather than reporting a clean success, same
        # honesty the real scheduled command's own CommandError gives folder_exporter's log.
        raise RuntimeError(
            "Sent, but " + "; ".join(f"{r['title']} failed ({r['error']})" for r in failed))


def _send_xlsx_report_test(report_type: str, recipients: list) -> None:
    """Reporting's own fire_live equivalent for an xlsx report type -- generates the real,
    current Active Directory Report and e-mails it through the EXACT same pipeline
    generate_active_directory_report's own scheduled run uses (send_report/mail_report.py's
    render_html()/analyse(), not a second implementation -- see that command's own module
    docstring for why, 2026-09-14), subject clearly marked [SYNTHETIC TEST], and never
    creates a ReportSubmission row (there is no `kind` field on that model to tag a test row
    as such anyway, so simply not persisting one is the only clean option -- same "never
    touch real history" principle as the narrative twin above). Kept in step with that
    command deliberately: a test-fire tool that exercises a DIFFERENT code path than
    production would be testing the wrong thing.

    2026-09-17: this had fallen OUT of step with that command -- the dual Cluster Health
    Report attachment, the extra_estate tile consolidation, and the "Infrastructure Reports"
    title/subject rename all landed in generate_active_directory_report.py alone, so clicking
    this group's own "test" button in the admin kept showing the OLD single-attachment,
    AD-only output while the real 07:30 run already had every fix (on request: "I remember
    asking you to combine the [scheduled] report... apparently none of those changes where
    actually added to the scheduled report Active Directory report group" -- the code was
    never lost, this specific test path just never got it in the first place). Brought back
    in step by hand, same as before -- see that command's own comments for the full reasoning
    behind each piece; only reproduced here, not re-derived."""
    import dataclasses
    import tempfile
    import uuid
    from pathlib import Path

    import mail_report as mr

    if report_type == "system_admin":
        # Simple, single-report twin -- see _send_system_admin_report_test's own docstring.
        _send_system_admin_report_test(recipients)
        return

    if report_type == "network_reports":
        # Simple, single-report... well, single-CALL twin -- see
        # _send_network_reports_test's own docstring.
        _send_network_reports_test(recipients)
        return

    if report_type != "active_directory":
        # Every OTHER xlsx type registered (reports.scheduled_xlsx_reports.XLSX_REPORT_TYPES)
        # needs its own branch here, same as generate_active_directory_report needed its own
        # management command rather than a generic "generate any xlsx type" dispatcher.
        raise ValueError(f"No test generator wired up for xlsx report type {report_type!r}.")

    theme, author = "dark", "Automated"
    only = {d["key"] for d in network.DEVICES if d.get("system") in network.AD_SYSTEMS}
    snapshot = network.capture_snapshot(uuid.uuid4().hex, only=only, infra=True)
    data = network.build_infrastructure_report(
        snapshot, theme=theme, author=author, annotations={}, summary_comment="",
        report_title="ACTIVE DIRECTORY REPORT")
    filename = network.active_directory_report_filename(theme, timezone.localtime())

    # Second, best-effort attachment -- same as generate_active_directory_report's own (see
    # that command's module docstring): a failure here must not break the AD-alone send.
    infra_data = infra_filename = infra_snapshot = None
    infra_only = {d["key"] for d in network.DEVICES
                 if d.get("kind") == "windows" and d.get("system") not in network.AD_SYSTEMS}
    try:
        infra_snapshot = network.capture_snapshot(uuid.uuid4().hex, only=infra_only, infra=True)
        infra_data = network.build_infrastructure_report(
            infra_snapshot, theme=theme, author=author, annotations={}, summary_comment="")
        infra_filename = network.infrastructure_report_filename(theme, timezone.localtime())
    except Exception:   # noqa: BLE001 -- best-effort, see generate_active_directory_report's own
        infra_data = infra_filename = infra_snapshot = None

    cfg = gr.load_config()
    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, getattr(cfg, "verify_tls", True))
    ad_systems = gr.load_topology(cfg.prometheus_yml, scope="ad")
    ad_store = gr.capture(prom, ad_systems, cfg)
    # Same fixes as generate_active_directory_report's own real scheduled run (2026-09-21, see
    # that command's own comments) -- kept in step deliberately, same as this whole function's
    # own docstring already explains for every other piece: web links scoped down to AD's own
    # (none), and WARN raised to 80 to match network.py's own CPU/RAM/disk amber threshold
    # used everywhere else in the Infrastructure/AD realm, not mail_report.py's business-
    # estate-oriented 75.
    gr.scope_links_to_systems(ad_store, ad_systems)
    ad_cfg = dataclasses.replace(cfg, chip_amber=80)
    unreach, crit, warn, nodata = mr.analyse(ad_store, ad_systems, cfg=ad_cfg)

    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    mailcfg["from_name"] = "RBZ Monitoring Console · Reporting"
    mailcfg["author"] = author
    mailcfg["grafana"] = cfg.grafana
    mailcfg["prom"] = cfg.prom
    mailcfg["elevated"] = cfg.overview_threshold
    mailcfg["report_url"] = "https://monitoring.rbz.co.zw"
    mailcfg["attachments"] = [{
        "name": filename, "theme": theme,
        "label": "the complete Active Directory Report",
        "detail": "(Services / Memory / Disk / Replication / NTP per domain controller)",
    }]
    attachment_names = [filename]
    if infra_data is not None:
        mailcfg["attachments"].append({
            "name": infra_filename, "theme": theme,
            "label": "the complete Cluster Health Report",
            "detail": "(Services / Memory / Disk / Storage volumes per cluster node)",
        })
        attachment_names.append(infra_filename)

    infra_immediate = infra_snapshot.overview.get("immediate", []) if infra_snapshot else []
    # "Unreachable components" (2026-10-03: network._infra_overview's own tile was renamed
    # from "Components down" -- see that function's own comment -- "just to standardise
    # things" against the identically-renamed Systems/Network tiles; this extraction updated
    # in the same pass so it keeps finding the tile under its new name).
    components_down = next(
        (int(str(t["value"]).split(" | ")[0]) for t in infra_immediate
        if t["label"] == "Unreachable components"), 0)
    # extra_disk/extra_disk_total now read "Storage critical" (immediate tier), not "Storage
    # at capacity" -- that watch-tier tile is GONE (2026-09-18, on request: "storage capacity
    # and storage critical are the same metric... combine every occurrence", confirmed after a
    # first pass: "infrastructure still views these as separate" -- see network._infra_
    # overview's own comment on the removal). "Storage critical" is excluded from
    # immediate_tiles' own generic "others" loop below for the same reason "Unreachable
    # components"/"Nodes down" already are: it's merged into the AD report's own "High disk
    # usage" tile via extra_disk AND still gets its own dedicated red banner
    # (storage_critical_items / mail_report._cluster_storage_critical_block) -- rendering it a
    # THIRD time as a plain generic tile here would be exactly the redundancy this whole change
    # is about removing.
    extra_disk = next((int(str(t["value"]).split(" | ")[0]) for t in infra_immediate
                       if t["label"] == "Storage critical"), 0)
    extra_disk_total = next((int(str(t["value"]).split(" | ")[1]) for t in infra_immediate
                             if t["label"] == "Storage critical"), 0)
    immediate_tiles = [t for t in infra_immediate
                      if t["label"] not in ("Unreachable components", "Nodes down", "Storage critical")]
    infra_watch = infra_snapshot.overview.get("watch", []) if infra_snapshot else []
    def _tile_num(label: str) -> int:
        return next((int(str(t["value"]).split(" | ")[0]) for t in infra_watch
                    if t["label"] == label), 0)
    extra_cpu = _tile_num("High CPU")
    extra_ram = _tile_num("High memory")
    watch_tiles = [t for t in infra_watch if t["label"] not in ("High CPU", "High memory")]
    # storage_critical_items (2026-09-17) -- see network.critical_disk_items' own docstring;
    # kept in step with generate_active_directory_report's own identical addition.
    storage_critical_items = network.critical_disk_items(infra_snapshot) if infra_snapshot else []
    # cluster_count/cluster_nodes/total_devices -- see generate_active_directory_report's own
    # identical fix and render_html's own docstring on extra_estate for why these three are
    # separate keys now (Standalone Servers had been inflating cluster_count/cluster_nodes).
    by_name = {d["name"]: d for d in network.DEVICES}
    cluster_count = (sum(1 for s in infra_snapshot.systems if by_name.get(s.name, {}).get("cluster"))
                     if infra_snapshot else 0)
    cluster_nodes = len(infra_snapshot._hci_nodes) if infra_snapshot else 0
    total_devices = infra_snapshot.hosts_count if infra_snapshot else 0
    extra_estate = ({"cluster_count": cluster_count,
                    "cluster_nodes": cluster_nodes,
                    "total_devices": total_devices,
                    "extra_down": components_down,
                    "extra_cpu": extra_cpu, "extra_ram": extra_ram,
                    "extra_disk": extra_disk, "extra_disk_total": extra_disk_total,
                    "storage_critical_items": storage_critical_items,
                    "immediate_tiles": immediate_tiles, "watch_tiles": watch_tiles}
                   if infra_snapshot is not None else None)

    infra_red = infra_snapshot.immediate_count if infra_snapshot else 0
    infra_amber = infra_snapshot.watch_count if infra_snapshot else 0
    if unreach:
        sev = f"{len(unreach)} unreachable"
    elif crit or infra_red:
        parts = ([f"{len(crit)} AD critical"] if crit else []) + \
               ([f"{infra_red} cluster critical"] if infra_red else [])
        sev = " · ".join(parts)
    elif warn or infra_amber:
        parts = ([f"{len(warn)} AD warning"] if warn else []) + \
               ([f"{infra_amber} cluster warning"] if infra_amber else [])
        sev = " · ".join(parts)
    else:
        sev = "all healthy"
    report_names = "Infrastructure Reports" if infra_data is not None else "Active Directory Report"
    subject = f"[SYNTHETIC TEST] {report_names} — {timezone.localdate():%d %b %Y} — {sev}"
    # Same fixes as generate_active_directory_report's own real scheduled run (2026-09-21, see
    # that command's own comments) -- kept in step deliberately.
    from .models import SystemAlertFinding

    def _age_str(seconds: float) -> str:
        days, rem = divmod(max(0, int(seconds)), 86400)
        hours, rem = divmod(rem, 3600)
        return f"{days}d {hours}h" if days else f"{hours}h {rem // 60}m"

    stale_systems = {s.name for s in ad_systems}
    if infra_snapshot is not None:
        stale_systems |= {s.name for s in infra_snapshot.systems}
    _now = timezone.now()
    stale_metrics = [
        (f"{f.freshness_check.system} · {f.freshness_check.name}",
         f"not updated in {_age_str((_now - f.first_seen_at).total_seconds())}")
        for f in SystemAlertFinding.objects.filter(
            freshness_check__system__in=stale_systems, resolved_at__isnull=True)
            .select_related("freshness_check")
    ]
    stale_metrics += [
        (sysvm.name, f.text) for sysvm in snapshot.systems for f in sysvm.flags
        if f.key == "win_stale_but_pinging"
    ]
    html_body = mr.render_html(ad_store, ad_systems, unreach, crit, warn, nodata, mailcfg,
                               title=report_names.upper(), system_label="Devices",
                               show_backups=False, show_web_links=False, show_swift=False,
                               show_cob=False, show_certs=False, show_queues=False,
                               extra_estate=extra_estate, stale_metrics=stale_metrics)
    text_body = mr.plain_summary(unreach, crit, warn, nodata, mailcfg["report_url"], attachment_names)

    tmpdir = tempfile.mkdtemp(prefix="ad_report_test_")
    attachments = [Path(tmpdir) / filename]
    if infra_data is not None:
        attachments.append(Path(tmpdir) / infra_filename)
    try:
        attachments[0].write_bytes(data)
        if infra_data is not None:
            attachments[1].write_bytes(infra_data)
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, attachments)
    finally:
        for a in attachments:
            try:
                a.unlink()
            except OSError:
                pass
        try:
            Path(tmpdir).rmdir()
        except OSError:
            pass


@login_required
def config_automated_report_group_test(request, pk):
    """Reporting's own test-fire screen -- config_alert_group_test's blueprint (2026-09-12,
    on request: "how come reporting doesnt have a test fire screen" / "yes same blueprint"),
    adapted: a Reporting group can cover several report types (narrative + xlsx) at once, so
    this picks ONE (scoped to the group's own report_types, matching how config_alert_group_
    test scopes its own pickers to the group's own systems/categories) and sends REAL,
    freshly-generated content for it right now -- clearly marked [SYNTHETIC TEST] -- to one or
    all of the group's own current recipients, without persisting any history row.

    Only ONE action, not three: every report type here is an aggregate over real data with no
    cheap fabricated-single-finding equivalent the way a Monitoring Alert has one flag to fake
    -- this is fire_live's own "real data, sent for real" mode, generalised, with no
    fire_positive/fire_resolved equivalent to offer."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(AutomatedReportGroup, pk=pk)
    if request.method != "POST":
        return redirect("config_automated_report_group_edit", pk=group.pk)

    combined_report_types = {**REPORT_TYPES, **XLSX_REPORT_TYPES}
    ttype = request.POST.get("ttype", "")
    if ttype not in (group.report_types or []):
        messages.error(request, "Pick one of this group's own report types to test.")
        return redirect("config_automated_report_group_edit", pk=group.pk)

    tto = request.POST.get("tto", "").strip()
    all_recipients = group.recipient_emails()
    if tto and tto not in all_recipients:
        messages.error(request, "That address isn't one of this group's current stakeholders.")
        return redirect("config_automated_report_group_edit", pk=group.pk)
    recipients = [tto] if tto else all_recipients
    if not recipients:
        messages.error(request, "This group has no stakeholders to send a test to yet.")
        return redirect("config_automated_report_group_edit", pk=group.pk)

    label = combined_report_types.get(ttype, {}).get("label", ttype)
    try:
        if ttype in XLSX_REPORT_TYPES:
            _send_xlsx_report_test(ttype, recipients)
        else:
            _send_narrative_report_test(ttype, recipients)
    except Exception as exc:   # noqa: BLE001 -- surfaced to the admin, not swallowed silently
        messages.error(request, f"Test send failed: {exc}")
        return redirect("config_automated_report_group_edit", pk=group.pk)

    messages.success(request, f"Sent a synthetic test of “{label}” to {len(recipients)} address(es).")
    return redirect("config_automated_report_group_edit", pk=group.pk)


@login_required
def config_freshness_check_edit(request, pk):
    """One watched checker source's own screen -- name/system/instance/file plus how stale
    its own last write may get before AlertGroups covering its system (alert_type=System
    Alert) are notified (see FreshnessCheck's own docstring for the mechanism and the T24 incident that motivated
    it)."""
    denied = _require_admin(request)
    if denied:
        return denied
    check = get_object_or_404(FreshnessCheck, pk=pk)
    systems = _topology_systems()

    if request.method == "POST":
        if request.POST.get("action") == "delete":
            name = check.name
            check.delete()
            messages.success(request, f"Removed “{name}”.")
            return redirect("config_alerts")

        name = (request.POST.get("name") or check.name).strip()
        system = (request.POST.get("system") or check.system).strip()
        kind = request.POST.get("kind") or check.kind
        instance = (request.POST.get("instance") or check.instance).strip()
        file = (request.POST.get("file") or "").strip()
        needs_file = kind == FreshnessCheck.KIND_TEXTFILE_MTIME
        max_age_s = _parse_duration_seconds((request.POST.get("max_age") or "").strip())
        if not (name and system and instance) or (needs_file and not file):
            messages.error(request, "Name, system, instance"
                                    + (" and file" if needs_file else "") + " are all required.")
            return redirect("config_freshness_check_edit", pk=check.pk)
        if max_age_s is None:
            messages.error(request, "Max age must be a number, optionally suffixed s/m/h "
                                    "(e.g. \"2h\").")
            return redirect("config_freshness_check_edit", pk=check.pk)
        if FreshnessCheck.objects.exclude(pk=check.pk).filter(
                instance=instance, file=file if needs_file else "").exists():
            messages.error(request, f"A check for {instance} / {file or '(backup checker)'} already exists.")
            return redirect("config_freshness_check_edit", pk=check.pk)

        check.name, check.system, check.kind, check.instance = name, system, kind, instance
        check.file = file if needs_file else ""
        check.max_age_seconds = int(max_age_s)
        check.scheduler_instance = (request.POST.get("scheduler_instance") or "").strip()
        check.scheduler_job = (request.POST.get("scheduler_job") or "").strip()
        check.active = request.POST.get("active") == "on"
        check.save()
        messages.success(request, "Saved.")
        return redirect("config_freshness_check_edit", pk=check.pk)

    return render(request, "reports/config_freshness_check_edit.html", {
        "check": check, "systems": systems,
        "max_age_str": _seconds_to_duration_str(check.max_age_seconds),
    })


def _save_prometheus(request, doc):
    """Shared save for the two screens that edit prometheus.yml as fields.

    Both post the WHOLE document — each screen renders the half it doesn't show as hidden
    fields — so either can save without needing to know what the other was displaying. The
    write path is promconfig.save_revision, the same one the raw editor uses.
    """
    new_doc, errors = promconfig.parse_post(request.POST, doc)
    if errors:
        return errors, None
    _, ok, message = promconfig.save_revision(
        new_doc,
        header=promconfig.header_comment(promconfig.current_text()),
        user=request.user,
        note=(request.POST.get("note") or "").strip(),
        apply=request.POST.get("action") == "apply",
    )
    return [], (ok, message)


def _require_admin(request):
    """Configuration is Administrator-only; everyone else goes back to the dashboard."""
    return None if is_role_admin(request.user) else redirect("report_form")


def _topology_systems() -> list:
    """Every system name a role scope / alert group / event group / freshness check can be
    pointed at -- every picker in Configuration that lists "systems" calls this one function,
    so they all agree on what exists.

    UNION of two real catalogues, not just prometheus.yml (2026-10-01 fix, found while trying
    to put the 49 SNMP-monitored switches/routers/WLCs into a new AlertGroup: every one of
    them was silently dropped on save, with no error, because this function only ever read
    promconfig's own topology -- confirmed live, zero overlap between the two lists. The
    Networks Report estate (network.DEVICES) has always been a SEPARATE catalogue from
    prometheus.yml's business/infra topology (see network.DEVICES' own comment on why), so a
    function named "every system" that only read one of them was quietly impossible to use
    for the other -- not a one-off gap, every picker above shared the identical bug. Returns
    empty on a promconfig read failure same as before -- never raises -- so a broken YAML
    degrades this screen instead of taking it down; network.DEVICES is a plain Python list, so
    it can't fail the same way.
    """
    try:
        topo = promconfig.system_names(promconfig.load())
    except Exception:      # noqa: BLE001 — surfaced properly on the configuration form
        topo = []
    return sorted(set(topo) | {d["name"] for d in network.DEVICES})


@never_cache
@login_required
def configuration(request):
    """The Configuration hub: one card per thing that can be configured.

    A landing page rather than a screen that configures something itself. Its children are
    real screens with their own URLs, nested under this one in the drawer and in the Back
    hierarchy, so "where do I configure X" has one answer and one route to it.
    """
    denied = _require_admin(request)
    if denied:
        return denied
    return render(request, "reports/configuration.html",
                 _config_context("configuration", viewer_is_superuser=is_superuser(request.user)))


def _prometheus_screen(request, *, active: str, template: str, extra=None):
    """Shared body for the two screens that edit prometheus.yml as labelled fields.

    Prometheus and Topology are two windows onto ONE document: each shows its own half and
    carries the other half as hidden fields, so a save from either preserves the whole file.
    They therefore need identical load/save/error handling, which lives here rather than
    being written twice and drifting.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    try:
        doc = promconfig.load()
    except promconfig.ConfigError as exc:
        return render(request, template,
                      {**_config_context(active), "load_error": str(exc)}, status=200)

    errors: list = []
    if request.method == "POST":
        try:
            errors, outcome = _save_prometheus(request, doc)
        except promconfig.ConfigError as exc:
            messages.error(request, str(exc))
            return redirect(active)
        if outcome is not None:
            ok, message = outcome
            # A rejected apply still recorded the revision — say so rather than implying the
            # edit was lost, and keep the promtool output visible so it can be acted on.
            (messages.success if ok or request.POST.get("action") != "apply"
             else messages.error)(request, message)
            return redirect(active)
        view = promconfig.view_from_post(request.POST, doc)
    else:
        view = promconfig.to_view(doc)

    ctx = {
        **_config_context(active),
        "view": view, "errors": errors,
        "history": PrometheusConfigRevision.objects.all()[:10],
    }
    if extra:
        ctx.update(extra(view))
    return render(request, template, ctx)


@never_cache
@login_required
def config_prometheus(request):
    """Prometheus settings as labelled fields: global intervals, storage, rule files.

    The scrape jobs live here as hidden fields — they are edited on the Topology screen,
    which presents them by system rather than by exporter. Same document, same revision
    history, same promtool gate on apply.
    """
    return _prometheus_screen(request, active="config_prometheus",
                              template="reports/config_prometheus.html")


@never_cache
@login_required
def config_topology(request):
    """Which hosts belong to which system — the estate, not the exporter layout.

    prometheus.yml is organised by exporter; the report is organised by system. This screen
    does that translation so nobody has to do it in their head: it lists every system with
    its hosts, and writes edits back into whichever scrape job each host actually lives in.
    """
    return _prometheus_screen(request, active="config_topology",
                              template="reports/config_topology.html",
                              extra=lambda view: {"topo": promconfig.to_topology(view)})


def _parse_snmp_post(post) -> dict:
    """{profile_name: {field: submitted_value, ...}, ...} from `profile__<name>__<field>`
    POST keys, in submission order (the order the template renders each profile's fields
    in). `version` is coerced back to int — the only numeric field a profile carries — so
    Save & Apply writes `version: 3`, not the quoted string `version: '3'`."""
    profiles: dict = {}
    for key in post.keys():
        if not key.startswith("profile__"):
            continue
        _, name, field = key.split("__", 2)
        value = post.get(key, "").strip()
        if field == "version" and value:
            try:
                value = int(value)
            except ValueError:
                pass
        profiles.setdefault(name, {})[field] = value
    return profiles


@never_cache
@login_required
def config_snmp(request):
    """SNMP credential profiles — the `auths:` section of the snmp_exporter's snmp.yml that
    prometheus.yml's snmp/snmp_hardware/snmp_system jobs reference by name (`auth: [RBZ_v2]`).

    Same DB-versioned, mask-before-display shape as grafana_config — but per labelled field
    (profile -> field -> value) rather than one raw-text blob, and scoped to just that ~20-line
    section: snmp.yml's other ~2MB (`modules:`) is generator output nothing here ever parses
    or rewrites. See reports/snmp_admin.py.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    current = SnmpConfigRevision.current()

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "restore":
            rev_id = request.POST.get("rev_id")
            restore_rev = get_object_or_404(SnmpConfigRevision, pk=rev_id)
            view_profiles = restore_rev.profiles
            messages.info(request, f"Loaded the {restore_rev.created_at:%d %b %Y %H:%M} "
                                   "revision — review below, then Save or Save & Apply to "
                                   "make it current.")
        else:
            submitted = _parse_snmp_post(request.POST)
            baseline_secrets = current.secrets_encrypted if current is not None else {}
            live_profiles = None   # loaded lazily — only the very first-ever save needs it
            masked_profiles: dict = {}
            secrets_encrypted: dict = {}
            for name, fields in submitted.items():
                masked_fields, enc_fields = {}, {}
                prev_enc = baseline_secrets.get(name, {})
                for field, value in fields.items():
                    if field not in snmp_admin.SECRET_FIELDS:
                        masked_fields[field] = value
                        continue
                    if value and value != snmp_admin.PASSWORD_PLACEHOLDER:
                        enc = crypto.encrypt(value)
                    elif name in prev_enc:
                        enc = prev_enc[field]              # unchanged — carry forward
                    else:
                        # very first-ever save: no revision to carry a secret forward from —
                        # fall back to what's actually in the live file right now.
                        if live_profiles is None:
                            try:
                                live_profiles = snmp_admin.parse_live_auths()
                            except (OSError, ValueError):
                                live_profiles = {}
                        enc = crypto.encrypt(str(live_profiles.get(name, {}).get(field, "")))
                    enc_fields[field] = enc
                    masked_fields[field] = snmp_admin.PASSWORD_PLACEHOLDER if enc else ""
                masked_profiles[name] = masked_fields
                secrets_encrypted[name] = enc_fields

            rev = SnmpConfigRevision(created_by=request.user,
                                     note=(request.POST.get("note") or "").strip(),
                                     profiles=masked_profiles, secrets_encrypted=secrets_encrypted)
            rev.save()
            if action == "apply":
                real_profiles = {
                    name: {field: (crypto.decrypt(secrets_encrypted[name].get(field, ""))
                                   if field in snmp_admin.SECRET_FIELDS else value)
                          for field, value in fields.items()}
                    for name, fields in masked_profiles.items()
                }
                ok, message = snmp_admin.write_auths_and_restart(real_profiles)
                (messages.success if ok else messages.error)(request, message)
            else:
                messages.success(request, "Revision saved (not applied — snmp.yml is unchanged).")
            return redirect("config_snmp")
    else:
        if current is not None:
            view_profiles = current.profiles
        else:
            try:
                view_profiles = snmp_admin.mask_profiles(snmp_admin.parse_live_auths())
            except (OSError, ValueError) as exc:
                view_profiles = {}
                messages.error(request, f"Could not read the live snmp.yml: {exc}")

    return render(request, "reports/config_snmp.html", {
        **_config_context("config_snmp"),
        "view_profiles": view_profiles,
        "secret_fields": sorted(snmp_admin.SECRET_FIELDS),
        "placeholder": snmp_admin.PASSWORD_PLACEHOLDER,
        "current": current,
        "history": SnmpConfigRevision.objects.all()[:20],
        "bootstrapped_from_file": current is None,
        "service_status": snmp_admin.service_status(),
    })


def _parse_backup_policy_post(post, all_instances) -> dict:
    """{instance: {"frequency_days": N, "off_weekdays": [...], "folder_drain_hours": N}, ...}
    — sparse: an instance is only kept if it has a non-default frequency, at least one
    off-weekday checked, AND/OR an explicit drain-hours override, matching the engine's own
    sparse-override design (a host absent from the dict just gets DEFAULT_BACKUP_MAX_AGE_DAYS,
    no off-days, and its drain window intuited fresh from whatever frequency applies).

    Drain hours is compared against intuited_drain_hours(days) using THIS SAME submission's
    frequency (not the previously-stored one), so changing a host's frequency and leaving
    drain untouched keeps drain un-overridden even though the intuited number just moved —
    the field the admin didn't touch should keep following the frequency, not freeze at
    whatever it happened to compute to before this save."""
    policy: dict = {}
    for inst in all_instances:
        entry: dict = {}
        raw = (post.get(f"freq__{inst}") or "").strip()
        days = backup_policy_admin.DEFAULT_FREQUENCY_DAYS
        if raw:
            try:
                parsed_days = int(raw)
            except ValueError:
                parsed_days = None
            if parsed_days is not None and parsed_days > 0:
                days = parsed_days
                if days != backup_policy_admin.DEFAULT_FREQUENCY_DAYS:
                    entry[backup_policy_admin.FREQUENCY_FIELD] = days
        off_days = sorted({int(d) for d in post.getlist(f"off__{inst}") if d.isdigit() and 0 <= int(d) <= 6})
        if off_days:
            entry[backup_policy_admin.OFF_WEEKDAYS_FIELD] = off_days
        drain_raw = (post.get(f"drain__{inst}") or "").strip()
        if drain_raw:
            try:
                drain_hours = int(drain_raw)
            except ValueError:
                drain_hours = None
            if (drain_hours is not None and drain_hours > 0
                    and drain_hours != backup_policy_admin.intuited_drain_hours(days)):
                entry[backup_policy_admin.FOLDER_DRAIN_HOURS_FIELD] = drain_hours
        if entry:
            policy[inst] = entry
    return policy


@never_cache
@login_required
def config_backup_policy(request):
    """Per-host backup-frequency overrides — how many days old a host's newest backup may be
    and still count as current (see reports/backup_policy_admin.py). "Frequency" is the only
    component this models today.

    Same DB-versioned, append-only shape as the other config screens — but there is no live
    service to restart here: Save & Apply just rewrites backup_policy.json, which
    generate_report.capture() re-reads fresh on the very next report (webapp, mail_report.py,
    or the scheduled CLI run all pick it up the same way).
    """
    denied = _require_admin(request)
    if denied:
        return denied

    cfg = gr.load_config()
    # scope="all": a host's backup cadence isn't a System-Admin-only concern — Infrastructure
    # Admin's hosts belong on this screen too, the same reasoning Connect's inventory uses.
    systems = gr.load_topology(cfg.prometheus_yml, scope="all")
    all_instances = [c.instance for s in systems for c in s.components]
    current = BackupPolicyRevision.current()

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "restore":
            rev_id = request.POST.get("rev_id")
            restore_rev = get_object_or_404(BackupPolicyRevision, pk=rev_id)
            view_policy = restore_rev.policy
            messages.info(request, f"Loaded the {restore_rev.created_at:%d %b %Y %H:%M} "
                                   "revision — review below, then Save or Save & Apply to "
                                   "make it current.")
        else:
            view_policy = _parse_backup_policy_post(request.POST, all_instances)
            rev = BackupPolicyRevision(created_by=request.user,
                                       note=(request.POST.get("note") or "").strip(),
                                       policy=view_policy)
            rev.save()
            if action == "apply":
                ok, message = backup_policy_admin.write_policy(view_policy)
                (messages.success if ok else messages.error)(request, message)
            else:
                messages.success(request, "Revision saved (not applied — backup_policy.json "
                                          "is unchanged).")
            return redirect("config_backup_policy")
    else:
        view_policy = (current.policy if current is not None
                       else backup_policy_admin.parse_live_policy())

    default_days = backup_policy_admin.DEFAULT_FREQUENCY_DAYS
    groups = []
    for s in systems:
        hosts = []
        for c in s.components:
            entry = view_policy.get(c.instance, {})
            off_days = set(entry.get(backup_policy_admin.OFF_WEEKDAYS_FIELD, []))
            days = entry.get(backup_policy_admin.FREQUENCY_FIELD, default_days)
            intuited_drain = backup_policy_admin.intuited_drain_hours(days)
            hosts.append({
                "label": c.label, "instance": c.instance,
                "days": days,
                "off_weekdays": [{"value": i, "label": lbl, "checked": i in off_days}
                                 for i, lbl in enumerate(backup_policy_admin.WEEKDAY_LABELS)],
                "drain_hours": entry.get(backup_policy_admin.FOLDER_DRAIN_HOURS_FIELD, intuited_drain),
                "drain_intuited": intuited_drain,
                "drain_overridden": backup_policy_admin.FOLDER_DRAIN_HOURS_FIELD in entry,
            })
        groups.append({"name": s.name, "hosts": hosts,
                       "overridden": any(h["days"] != default_days or h["drain_overridden"] or
                                        any(d["checked"] for d in h["off_weekdays"])
                                        for h in hosts)})

    return render(request, "reports/config_backup_policy.html", {
        **_config_context("config_backup_policy"),
        "groups": groups,
        "default_days": default_days,
        "current": current,
        "history": BackupPolicyRevision.objects.all()[:20],
        "bootstrapped_from_file": current is None,
    })


@never_cache
@login_required
def config_yaml(request):
    """The current prometheus.yml as text — what the labelled form would save right now.

    Read-only on purpose: this is the same content the raw editor holds, so editing belongs
    there (one editable text box for one file, not two).
    """
    denied = _require_admin(request)
    if denied:
        return denied
    try:
        raw, error = promconfig.current_text(), ""
    except promconfig.ConfigError as exc:
        raw, error = "", str(exc)
    if request.GET.get("download") == "1" and raw:
        resp = HttpResponse(raw, content_type="text/yaml; charset=utf-8")
        resp["Content-Disposition"] = 'attachment; filename="prometheus.yml"'
        return resp
    return render(request, "reports/config_yaml.html", {
        **_config_context("config_yaml"),
        "raw": raw, "error": error,
        "line_count": len(raw.splitlines()),
        "history": PrometheusConfigRevision.objects.all()[:10],
    })
# ---------------------------------------------------------------------------------------
#  Scripts — generate the checker scripts the monitored hosts run
# ---------------------------------------------------------------------------------------
@never_cache
@login_required
def config_scripts(request):
    """The catalogue of script definitions, and the form that adds one.

    Lists every TYPE, not only the generatable ones: a type that is registered but waiting on
    its source (COB, SWIFT) should be visible as a known gap rather than absent, which reads
    as "not supported" to whoever comes looking for it.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    if request.method == "POST":
        stype = (request.POST.get("script_type") or "").strip()
        name = (request.POST.get("name") or "").strip()
        try:
            spec = scripts.get_type(stype)
        except scripts.ScriptError as exc:
            messages.error(request, str(exc))
            return redirect("config_scripts")
        if not spec.available:
            messages.error(request, f"{spec.label} cannot be generated yet.")
            return redirect("config_scripts")
        if not name:
            messages.error(request, "Give the script a name — it becomes the filename.")
            return redirect("config_scripts")
        if GeneratedScript.objects.filter(script_type=stype, name=name).exists():
            messages.error(request, f"A {spec.label} called \u201c{name}\u201d already exists.")
            return redirect("config_scripts")
        definition = GeneratedScript.objects.create(
            name=name, script_type=stype,
            system=(request.POST.get("system") or "").strip(),
            host=(request.POST.get("host") or "").strip(),
            parameters={f.name: f.default for f in spec.fields},
            updated_by=request.user,
        )
        messages.success(request, f"Created \u201c{name}\u201d. Set its parameters, then generate.")
        return redirect("config_script_edit", pk=definition.pk)

    by_type = {}
    for d in GeneratedScript.objects.all():
        by_type.setdefault(d.script_type, []).append(d)
    catalogue = [{"spec": spec, "definitions": by_type.get(key, [])}
                 for key, spec in scripts.SCRIPT_TYPES.items()]
    return render(request, "reports/config_scripts.html", {
        **_config_context("config_scripts"),
        "catalogue": catalogue,
        "creatable": scripts.available_types(),
        "output_dir": scripts.configuration_dir(),
        "systems": _topology_systems(),
    })


@never_cache
@login_required
def config_script_edit(request, pk):
    """One definition: its parameters, and the two things you can do with them.

    Save records the parameters; Generate writes the files. Separate, because writing to disk
    is the side effect — correcting a typo in a note should not overwrite a live script on
    the way past.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    definition = get_object_or_404(GeneratedScript, pk=pk)
    try:
        spec = scripts.get_type(definition.script_type)
    except scripts.ScriptError as exc:
        messages.error(request, str(exc))
        return redirect("config_scripts")

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "delete":
            name = definition.name
            definition.delete()
            # Deliberately does NOT delete the generated files. They are on a monitored host by
            # now; removing a definition is how you stop managing a script, not how you stop a
            # host running one — that needs the scheduled task removing too.
            messages.success(request, f"Removed the definition for \u201c{name}\u201d. Files "
                                      "already written are left in place.")
            return redirect("config_scripts")

        definition.name = (request.POST.get("name") or definition.name).strip()
        definition.system = (request.POST.get("system") or "").strip()
        definition.host = (request.POST.get("host") or "").strip()
        definition.notes = (request.POST.get("notes") or "").strip()
        definition.parameters = {
            f.name: (request.POST.get("p_" + f.name) or "").strip()
            for f in spec.fields if not f.secret
        }
        posted_secrets = {
            f.name: (request.POST.get("p_" + f.name) or "")
            for f in spec.fields if f.secret
        }
        definition.secrets_encrypted = scripts.merge_secrets(
            definition.secrets_encrypted, posted_secrets)
        definition.updated_by = request.user

        if action == "generate":
            try:
                written = scripts.write(definition)
            except scripts.ScriptError as exc:
                # Save the edit anyway: the parameters are the admin's work, and losing them
                # because a folder was read-only would be its own bug.
                definition.save()
                messages.error(request, str(exc))
                return redirect("config_script_edit", pk=definition.pk)
            definition.last_generated_at = timezone.now()
            definition.last_generated_files = written
            definition.save()
            messages.success(request, "Generated: " + ", ".join(Path(p).name for p in written))
        else:
            definition.save()
            messages.success(request, "Saved. Nothing written yet — use Generate for that.")
        return redirect("config_script_edit", pk=definition.pk)

    secrets_set = set(definition.secret_names)
    fields = [{
        "spec": f,
        # A secret shows the placeholder, never the value. Posting it back means "keep what is
        # stored", so editing never requires re-typing it and the value never reaches the browser.
        "value": (scripts.SECRET_PLACEHOLDER if f.secret and f.name in secrets_set
                  else (definition.parameters or {}).get(f.name, f.default)),
    } for f in spec.fields]
    return render(request, "reports/config_script_edit.html", {
        **_config_context("config_scripts"),
        "definition": definition, "spec": spec, "fields": fields,
        "output_dir": scripts.configuration_dir() / definition.script_type,
        "systems": _topology_systems(),
    })


@never_cache
@login_required
def config_script_preview(request, pk):
    """The exact bytes Generate would write, without writing them.

    Worth its own screen: these files run unattended on production hosts, and reading one
    before it lands is the only review step between a mistyped path and a check that silently
    monitors nothing.
    """
    denied = _require_admin(request)
    if denied:
        return denied
    definition = get_object_or_404(GeneratedScript, pk=pk)
    try:
        files = scripts.render(definition.script_type, definition.name, definition.system,
                               definition.parameters or {}, definition.secret_values())
        error = ""
    except scripts.ScriptError as exc:
        files, error = {}, str(exc)

    wanted = request.GET.get("file")
    if wanted and wanted in files:
        resp = HttpResponse(files[wanted], content_type="text/plain; charset=utf-8")
        resp["Content-Disposition"] = 'attachment; filename="%s"' % wanted
        return resp
    return render(request, "reports/config_script_preview.html", {
        **_config_context("config_scripts"),
        "definition": definition,
        "files": sorted(files.items()),
        "error": error,
    })


def _role_scopes_context() -> dict:
    """Which systems each role's workspace covers -- read-side only, reused by every entry
    point onto the combined Roles page (config_roles / roles_console / config_role_scopes,
    see config_roles' own docstring for why all three still exist) so whichever URL a request
    lands on, the Role scopes section shows the same real data."""
    systems = _topology_systems()
    mapped = {s.role: s for s in RoleScope.objects.all()}
    rows = [{
        "role": role,
        "icon": role_icon(role),
        "description": ROLE_DESCRIPTIONS.get(role, ""),
        "chosen": set(mapped[role].systems or []) if role in mapped else set(),
        "unscoped": not (mapped.get(role) and mapped[role].systems),
        "can_edit_own_alert_groups": bool(mapped.get(role) and mapped[role].can_edit_own_alert_groups),
    } for role in ROLE_NAMES]
    return {"rows": rows, "systems": systems}


@never_cache
@login_required
def config_role_scopes(request):
    """Which systems each role's workspace covers — what the role tiles at sign-in select.

    A role with nothing ticked is UNRESTRICTED (it sees the whole estate), so the mapping can
    be filled in one role at a time without hiding systems from anyone in the meantime.

    Renders the same combined Roles page as roles_console/config_roles (see config_roles'
    own docstring) -- this URL's own POST handling (saving scopes) is unchanged, only what it
    renders afterward changed, so the Role scopes section stays open when it lands you back
    here.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    systems = _topology_systems()
    if request.method == "POST":
        for role in ROLE_NAMES:
            chosen = [s for s in request.POST.getlist(f"systems__{role}") if s in systems]
            scope, _ = RoleScope.objects.get_or_create(role=role)
            scope.systems = chosen
            scope.can_edit_own_alert_groups = bool(request.POST.get(f"can_edit_own_alert_groups__{role}"))
            scope.updated_by = request.user
            scope.save()
        messages.success(request, "Role scopes saved — they apply the next time a role is selected.")
        return redirect("config_role_scopes")

    return render(request, "reports/config_roles.html", {
        **_config_context("config_roles"),
        **_role_assignments_context(request),
        **_role_scopes_context(),
        "default_open": "scopes",
    })


@never_cache
@login_required
def config_alert_group_edit(request, pk):
    """One group: which systems it covers, who its stakeholders are, and its own alerting
    policy (minimum severity, re-notify behaviour, which metric categories) — all
    admin-configurable, on purpose, so the organization's own idea of "who owns what" and
    "what to page them for" is never hardcoded here."""
    group = get_object_or_404(AlertGroup, pk=pk)
    if not can_edit_alert_group(request.user, group):
        return redirect("report_form")
    is_full_admin = is_role_admin(request.user)
    can_delete = can_delete_alert_group(request.user)
    systems = _topology_systems()
    users = get_user_model().objects.filter(is_active=True).order_by("username")
    valid_categories = {k for k, _ in AlertGroup.CATEGORY_CHOICES}

    if request.method == "POST":
        if request.POST.get("action") == "delete":
            if not can_delete:
                return redirect("config_alert_group_edit", pk=group.pk)
            name = group.name
            group.delete()
            messages.success(request, f"Removed “{name}” and its notification history.")
            return redirect("config_alerts")

        # ---- Schedule: own <form>, own submit -- applies identically to Monitoring and
        # System Alert groups alike (2026-09-07, on request: "people are asking for these
        # alerts to be schedulable... enable them at a certain time and disable them at a
        # certain time, even in terms of days"). Reads exactly like the Active toggle but on
        # a recurring day/time window instead of a manual switch -- see AlertGroup.
        # in_schedule's own docstring for the exact semantics.
        if request.POST.get("form") == "schedule":
            schedule_enabled = request.POST.get("schedule_enabled") == "on"
            days = sorted({int(d) for d in request.POST.getlist("schedule_days")
                          if d.isdigit() and 0 <= int(d) <= 6})
            start_raw = (request.POST.get("schedule_start") or "").strip()
            end_raw = (request.POST.get("schedule_end") or "").strip()
            start_time = end_time = None
            errors = []
            try:
                start_time = datetime.time.fromisoformat(start_raw) if start_raw else None
            except ValueError:
                errors.append("Start time is not valid.")
            try:
                end_time = datetime.time.fromisoformat(end_raw) if end_raw else None
            except ValueError:
                errors.append("End time is not valid.")
            if not errors and (start_time is None) != (end_time is None):
                errors.append("Set both a start and an end time, or leave both blank to "
                             "restrict by day only.")
            if errors:
                for e in errors:
                    messages.error(request, e)
                return redirect("config_alert_group_edit", pk=group.pk)
            group.schedule_enabled = schedule_enabled
            group.schedule_days = days
            group.schedule_start = start_time
            group.schedule_end = end_time
            group.updated_by = request.user
            group.save(update_fields=["schedule_enabled", "schedule_days", "schedule_start",
                                      "schedule_end", "updated_by", "updated_at"])
            messages.success(request, "Schedule saved.")
            return redirect("config_alert_group_edit", pk=group.pk)

        # ---- Reminders: own <form>, own submit -- saving the main fields below never touches
        # this group's reminder schedule, and vice versa (2026-09-04: "notification reminder
        # schedule should be group specific").
        if request.POST.get("form") == "reminders" and group.alert_type == AlertGroup.ALERT_TYPE_SYSTEM:
            # A System Alert group has ONE persistent interval, not a capped schedule -- see
            # AlertGroup.effective_system_reminder_minutes' own docstring on why one field
            # serves both shapes (2026-09-05, merged from the since-retired SystemAlertGroup).
            if request.POST.get("action") == "reset":
                group.reminder_minutes = [AlertGroup.DEFAULT_SYSTEM_ALERT_REMINDER_MINUTES]
                group.updated_by = request.user
                group.save(update_fields=["reminder_minutes", "updated_by", "updated_at"])
                messages.success(request, f"Reminder interval reset to the shipped default "
                                          f"({AlertGroup.DEFAULT_SYSTEM_ALERT_REMINDER_MINUTES} minutes).")
                return redirect("config_alert_group_edit", pk=group.pk)
            seconds = _parse_duration_seconds((request.POST.get("system_reminder_minutes") or "").strip())
            if seconds is None or seconds <= 0:
                messages.error(request, "Reminder interval must be a number, optionally "
                                        "suffixed s/m/h (e.g. \"60m\").")
                return redirect("config_alert_group_edit", pk=group.pk)
            group.reminder_minutes = [max(1, round(seconds / 60))]
            group.updated_by = request.user
            group.save(update_fields=["reminder_minutes", "updated_by", "updated_at"])
            messages.success(request, "Reminder interval saved.")
            return redirect("config_alert_group_edit", pk=group.pk)

        if request.POST.get("form") == "reminders":
            if request.POST.get("action") == "reset":
                group.reminder_minutes = []
                group.imminent_reminder_minutes = None
                group.updated_by = request.user
                group.save(update_fields=["reminder_minutes", "imminent_reminder_minutes",
                                          "updated_by", "updated_at"])
                messages.success(request, "Reminder schedule reset to the shipped default (10, 40, 60 minutes; imminent every 10 minutes).")
                return redirect("config_alert_group_edit", pk=group.pk)
            minutes, errors = _parse_reminder_minutes(request.POST.get("reminder_minutes", ""))
            # Imminent (component unreachable) persistence interval -- its OWN field, on
            # request (2026-09-04: "value must be editable in our already established
            # reminder section"), sharing the same unit-aware parser every other Alerts
            # time-value field uses. Blank = keep the shipped default (10 minutes).
            imminent_raw = (request.POST.get("imminent_reminder_minutes") or "").strip()
            imminent_minutes = None
            if imminent_raw:
                imminent_seconds = _parse_duration_seconds(imminent_raw)
                if imminent_seconds is None or imminent_seconds <= 0:
                    errors.append("Imminent persistence: enter a duration like 10, 10m, 30s, or 1h.")
                else:
                    imminent_minutes = round(imminent_seconds / 60)
                    if imminent_minutes <= 0:
                        imminent_minutes = 1
            if errors:
                for e in errors:
                    messages.error(request, e)
                # Re-render (not redirect) so the rejected input re-shows exactly what was
                # typed, same pattern config_alerts' own per-section forms use.
                return render(request, "reports/config_alert_group_edit.html", {
                    **_config_context("config_alert_groups"),
                    "group": group, "systems": systems, "users": users,
                    "chosen_users": set(group.users.values_list("pk", flat=True)),
                    "category_grid": _category_grid_rows(group),
                    "email_list": "\n".join(group.emails or []),
                    "test_recipients": group.recipient_emails(),
                    "schedule_raw_value": request.POST.get("reminder_minutes", ""),
                    "schedule_preview_rows": _reminder_preview_rows(minutes),
                    "imminent_reminder_value": imminent_raw,
                    "weekday_choices": _WEEKDAY_CHOICES,
                    "category_headers": _category_headers(),
                    "health": _alert_group_health(group),
                    "can_delete": can_delete, "can_remove_stakeholders": is_full_admin,
                })
            group.reminder_minutes = minutes
            group.imminent_reminder_minutes = imminent_minutes
            group.updated_by = request.user
            group.save(update_fields=["reminder_minutes", "imminent_reminder_minutes",
                                      "updated_by", "updated_at"])
            messages.success(request, "Reminder schedule saved — the alert poller's next run uses it.")
            return redirect("config_alert_group_edit", pk=group.pk)

        name = (request.POST.get("name") or group.name).strip()
        if AlertGroup.objects.exclude(pk=group.pk).filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
            return redirect("config_alert_group_edit", pk=group.pk)

        chosen_systems = [s for s in request.POST.getlist("systems") if s in systems]
        # Per-system, not global (see AlertGroup.categories' own help_text): a system left
        # absent from the saved dict -- whether nothing was ticked for it, or everything was
        # ticked -- means ALL categories for it, so both those cases collapse to simply not
        # writing a key, keeping the stored shape as small as what it actually restricts.
        chosen_categories = {}
        for sys_name in chosen_systems:
            picked = {c for c in request.POST.getlist(f"categories__{sys_name}") if c in valid_categories}
            if picked and picked != valid_categories:
                chosen_categories[sys_name] = sorted(picked)
        chosen_user_ids = [int(i) for i in request.POST.getlist("users") if i.isdigit()]
        raw = request.POST.get("emails", "")
        # Split on ";" too, not just "," / newline (2026-09-08: reported as "save clears the
        # email" -- an Outlook "To:" field pasted verbatim is semicolon-separated, which used
        # to survive as one long unsplit string, fail validate_email, land wholly in `bad`, and
        # silently zero out group.emails since none of it ever reached `valid`).
        candidates = [e.strip() for e in re.split(r"[,;\n]", raw) if e.strip()]
        valid, bad = [], []
        for e in candidates:
            try:
                validate_email(e)
                valid.append(e)
            except ValidationError:
                bad.append(e)
        if bad:
            messages.error(request, "Dropped invalid address(es): " + ", ".join(bad))

        # Sub Admin (or any role opted into can_edit_own_alert_groups): add-only stakeholders
        # -- an unchecked EXISTING user or a dropped existing e-mail never actually leaves the
        # group, it's just a union with whatever's already there (2026-09-18, on request: "he
        # can add but not remove"). A full Administrator's save is a real replacement, same as
        # always.
        new_user_ids = set(chosen_user_ids)
        new_emails = set(valid)
        if not is_full_admin:
            new_user_ids |= set(group.users.values_list("pk", flat=True))
            new_emails |= set(group.emails or [])

        group.name = name
        group.systems = chosen_systems
        group.categories = chosen_categories
        group.emails = sorted(new_emails)
        group.active = request.POST.get("active") == "on"
        group.updated_by = request.user
        group.save()
        group.users.set(get_user_model().objects.filter(pk__in=new_user_ids))
        # State what actually landed, not just "Saved." -- the reported confusion was not
        # knowing whether an e-mail was really kept after a save. An unchecked "Stakeholders"
        # box submits nothing at all (plain HTML checkbox behaviour), so a save that touches
        # only Name/Systems/When-to-fire silently zeroes .users right along with them if it
        # was ever non-empty -- traced 2026-09-14 as exactly how "Innocent Nyama" lost its one
        # stakeholder (re-saved from a browser tab that had loaded the page before the
        # stakeholder was added, so its form still showed the checkbox unticked). A plain
        # green "Saved" here is how that went unnoticed both times -- this is now a warning
        # instead whenever the save leaves an ACTIVE group with nobody to actually notify.
        recipients_now = group.recipient_emails()
        summary = (f"{len(group.emails)} plain e-mail address(es), "
                  f"{group.users.count()} app-user stakeholder(s) on file.")
        if group.active and not recipients_now:
            messages.warning(request, f"Saved — but {summary} This group will not notify "
                                      f"anyone until it has at least one valid stakeholder.")
        else:
            messages.success(request, f"Saved — {summary}")
        return redirect("config_alert_group_edit", pk=group.pk)

    schedule_minutes = group.effective_reminder_minutes
    return render(request, "reports/config_alert_group_edit.html", {
        **_config_context("config_alert_groups"),
        "group": group, "systems": systems, "users": users,
        "chosen_users": set(group.users.values_list("pk", flat=True)),
        "category_grid": _category_grid_rows(group),
        "email_list": "\n".join(group.emails or []),
        "test_recipients": group.recipient_emails(),
        "schedule_raw_value": ", ".join(str(m) for m in schedule_minutes),
        "schedule_preview_rows": _reminder_preview_rows(schedule_minutes),
        "imminent_reminder_value": _seconds_to_duration_str(group.effective_imminent_reminder_minutes * 60),
        "system_reminder_value": _seconds_to_duration_str(group.effective_system_reminder_minutes * 60),
        "weekday_choices": _WEEKDAY_CHOICES,
        "category_headers": _category_headers(),
        "health": _alert_group_health(group),
        "can_delete": can_delete, "can_remove_stakeholders": is_full_admin,
    })


@never_cache
@login_required
def my_alert_groups(request):
    """A narrow, Sub-Admin-shaped alternative to the full Alerting hub (config_alerts) --
    just the groups screen's own list, filtered to the groups the signed-in user actually
    belongs to (a full Administrator sees every group, same as the hub's own list, since
    nothing here is a restriction for them). Deliberately not a section of config_alerts
    itself: that hub also holds per-alert thresholds, templates and System Alerting config
    that a Sub Admin -- who can edit at most a couple of groups they're a stakeholder on --
    should never see (2026-09-18, on request: "create a weaker admin role... access their
    own alert group any alert group they are a part off and modify it")."""
    if not can_reach_my_alert_groups(request.user):
        return redirect("report_form")
    is_full_admin = is_role_admin(request.user)
    groups = AlertGroup.objects.all() if is_full_admin else request.user.alert_groups.all()
    return render(request, "reports/my_alert_groups.html", {
        "grouped_alert_groups": _grouped_alert_groups(groups),
        "is_full_admin": is_full_admin,
    })


@require_POST
def config_alert_group_test(request, pk):
    """Three ways to exercise a group without waiting for a real incident, all tested against
    the group AS CURRENTLY SAVED (not unsaved form edits — save first to test your changes):

    fire_positive / fire_resolved — a FABRICATED, clearly [SYNTHETIC TEST]-marked finding for
    an admin-picked system/metric/severity, sent for real to the group's own stakeholders, so
    "what would recipients actually see" never depends on there being a live incident right now.

    fire_live — actually checks Prometheus for this group's real systems and sends only if
    something genuinely qualifies right now (reuses alerting.send_test_alert, unchanged).

    All three also take an optional `tto` -- one address, which MUST already be one of this
    group's own current recipient_emails() -- narrowing delivery to just that one stakeholder
    instead of the whole group, so iterating on a test doesn't re-notify everyone every time.
    Blank means "all current stakeholders", same as before this existed.

    None of the three ever touch AlertFinding — see send_test_alert's own docstring for why."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(AlertGroup, pk=pk)
    if group.alert_type != AlertGroup.ALERT_TYPE_MONITORING:
        # Flag-based test tools only make sense for a Monitoring Alert group -- a System
        # Alert group has no category/severity concept for these to fabricate against
        # (2026-09-05, after alert_type became a real classification on this same model).
        messages.error(request, "Test tools are only available for Monitoring Alert groups.")
        return redirect("config_alert_group_edit", pk=group.pk)
    taction = request.POST.get("taction")

    tto = request.POST.get("tto", "").strip()
    if tto and tto not in group.recipient_emails():
        messages.error(request, "Pick one of this group's own current stakeholders to narrow to.")
        return redirect("config_alert_group_edit", pk=group.pk)
    to = tto or None

    if taction == "fire_live":
        ok, msg = alerting.send_test_alert(group, to=to)
        (messages.success if ok else messages.error)(request, msg)
        return redirect("config_alert_group_edit", pk=group.pk)

    if taction in ("fire_positive", "fire_resolved"):
        tsys = request.POST.get("tsys", "")
        tcat = request.POST.get("tcat", "")
        tband = request.POST.get("tband", "red")
        valid_categories = {k for k, _ in AlertGroup.CATEGORY_CHOICES}
        if tsys not in (group.systems or []):
            messages.error(request, "Pick one of this group's own systems to test with.")
        elif tcat not in valid_categories:
            messages.error(request, "Pick a metric to test with.")
        elif tband not in ("red", "amber"):
            messages.error(request, "Pick a severity to test with.")
        else:
            kind = "positive" if taction == "fire_positive" else "resolved"
            ok, msg = alerting.send_test_email(group, kind=kind, system=tsys, category=tcat,
                                               band=tband, to=to)
            (messages.success if ok else messages.error)(request, msg)
        return redirect("config_alert_group_edit", pk=group.pk)

    raise Http404


def config_alert_group_preview(request, pk):
    """Renders the actual HTML e-mail body in-browser (no send, no AlertFinding) for the
    admin-picked system/metric/severity/kind — opened in a new tab from the Test tools
    section, so the SAME render_test_email() a real synthetic test would send can be eyeballed
    first without generating any e-mail traffic at all."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(AlertGroup, pk=pk)
    if group.alert_type != AlertGroup.ALERT_TYPE_MONITORING:
        return HttpResponse("Preview is only available for Monitoring Alert groups.", content_type="text/plain")
    valid_categories = {k for k, _ in AlertGroup.CATEGORY_CHOICES}
    kind = request.GET.get("kind") if request.GET.get("kind") in ("positive", "resolved") else "positive"
    tsys = request.GET.get("tsys") or (group.systems or [""])[0]
    tcat = request.GET.get("tcat") if request.GET.get("tcat") in valid_categories else next(iter(valid_categories), "")
    tband = request.GET.get("tband") if request.GET.get("tband") in ("red", "amber") else "red"
    if not tsys or not tcat:
        return HttpResponse("Add at least one system before previewing.", content_type="text/plain")
    _subject, _text, html_body, _images = alerting.render_test_email(
        group, kind=kind, system=tsys, category=tcat, band=tband, for_browser=True)
    return HttpResponse(html_body)


def _parse_reminder_minutes(raw: str) -> tuple:
    """"10, 40, 60" or "30s, 10m, 2h" -> ([10, 40, 60], []) or (parsed-so-far, [error, ...]) --
    one text field rather than N number inputs with add/remove buttons, on request ("keep UI
    clean", 2026-09-04): admins type the schedule the same way they'd say it out loud. Each
    entry goes through the SAME unit-aware parser every other Alerts time-value field uses
    (2026-09-04: "in alerts allow users to specify the time value units eg 15s is 15 seconds h
    is hours") -- still stored/returned as MINUTES (AlertGroup.reminder_minutes' own field, and
    reports.alerting._decide's timedelta(minutes=...) comparison), just no longer restricted to
    whole ones: "30s" is exactly 0.5, not rounded away. Strictly ascending (a reminder schedule
    that doesn't move forward in time isn't a schedule) and capped at
    AlertGroup.MAX_REMINDER_COUNT so neither this form nor a fired-digest e-mail can grow
    unreadably long."""
    errors = []
    minutes = []
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        return [], ["Enter at least one reminder time."]
    if len(parts) > AlertGroup.MAX_REMINDER_COUNT:
        errors.append(f"At most {AlertGroup.MAX_REMINDER_COUNT} reminders are supported.")
        parts = parts[:AlertGroup.MAX_REMINDER_COUNT]
    for p in parts:
        seconds = _parse_duration_seconds(p)
        if seconds is None:
            errors.append(f"“{p}” isn't a duration — try 10, 10m, 30s, or 2h.")
            continue
        n = seconds / 60
        n = int(n) if n == int(n) else round(n, 4)
        if n <= 0:
            errors.append(f"“{p}” isn't positive — every reminder must be after the last.")
            continue
        minutes.append(n)
    if not errors and minutes != sorted(set(minutes)):
        errors.append("Reminder times must be strictly ascending — each one after the last, "
                      "with no repeats.")
    return minutes, errors


def _reminder_preview_rows(minutes: list) -> list:
    total = len(minutes)
    return [{"n": i + 1, "minutes": _seconds_to_duration_str(m * 60),
             "label": alert_email_templates.reminder_label(i + 1, total)}
           for i, m in enumerate(minutes)]


def config_alert_template_preview(request, category):
    """Serves one sample e-mail's raw, UNsubstituted HTML for in-browser viewing (opened in a
    new tab from the gallery) — a direct file read, not run through Django's template engine.
    A group's own Test tools page previews the SUBSTITUTED version instead (system/severity/
    group filled in — see alert_email_templates.render), which this gallery deliberately
    doesn't do: it has no group or system in scope, only a category."""
    denied = _require_admin(request)
    if denied:
        return denied
    filename = alert_email_templates.FILE_BY_CATEGORY.get(category)
    if not filename:
        raise Http404
    return HttpResponse((alert_email_templates.SAMPLES_DIR / filename).read_text(encoding="utf-8"))


def _category_grid_rows(group) -> list:
    """[{"system":, "cells": [{"category":, "label":, "checked":, "applicable":}, ...]}, ...]
    for the per-system, per-category "Metrics to alert on" table -- one row per system the
    group covers, one column per AlertGroup.CATEGORY_CHOICES entry.

    `applicable` gates whether the template renders a real checkbox at all for that cell (an
    inapplicable one shows a muted em-dash instead, see config_alert_group_edit.html) --
    still just a topology-derived HINT, not a stored restriction: a system added to this group
    later, or a metric that starts reporting later, can make a cell applicable on a future
    visit with no data lost, since `applicable` is recomputed fresh every render rather than
    saved. Categories carrying a genuine static/live signal: `service` from generate_report's
    own SERVICE_CHECKS (surfaced on the System.services topology object); `folder`/
    `undrained_folders` from folders.folder_watch_systems (same folder_exporter job, same
    T24-only applicability, two different live verdicts); `backup_uncleared` (2026-09-07,
    real detection since alerting._backup_uncleared_flags_by_system) from
    folders.backup_drainage_systems() -- live backup/log folder data, currently Temenos only,
    same source `backup_drainage_systems()` already used for Per Alert Config's own backup
    drainage override table. Every other category (disk/ram/cpu/unreachable, always
    structurally available; backup/untracked, which have no config-side declaration at all --
    entirely metric-driven, only ever visible from a live capture) is always applicable.
    """
    cfg = gr.load_config()
    try:
        all_systems = {s.name: s for s in gr.load_topology(cfg.prometheus_yml, scope="business")}
    except Exception:      # noqa: BLE001 -- topology load errors already surface properly on
        all_systems = {}   # the Topology config screen itself; this grid degrades to
                            # "everything applicable" rather than failing to render at all.
    folder_systems = folders.folder_watch_systems(cfg.prometheus_yml)
    # backup_uncleared (2026-09-07): real detection now exists (alerting.
    # _backup_uncleared_flags_by_system) for the Temenos Backup & Log Folders specifically --
    # applicable exactly where folders.backup_drainage_systems() has live backup/log folder
    # data, the same "only offer it where there's real data" gating folder_systems above uses.
    backup_drainage_systems = folders.backup_drainage_systems()

    chosen_by_system = group.categories or {}
    rows = []
    for sys_name in sorted(group.systems or []):
        sysm = all_systems.get(sys_name)
        allowed = set(chosen_by_system.get(sys_name) or []) or {k for k, _ in AlertGroup.CATEGORY_CHOICES}

        def _applicable(value):
            if value == "service":
                return bool(sysm.services) if sysm else True
            if value in ("folder", "undrained_folders"):
                return sys_name in folder_systems
            if value == "backup_uncleared":
                return sys_name in backup_drainage_systems
            return True

        cells = [{"category": value, "label": label, "checked": value in allowed,
                 "applicable": _applicable(value)} for value, label in AlertGroup.CATEGORY_CHOICES]
        rows.append({"system": sys_name, "cells": cells})
    return rows


def _safe_next(request, default="roles_console"):
    """A redirect target from a `next` GET/POST param, validated against open-redirect abuse
    (the param is attacker-controllable input, never trusted as-is)."""
    next_url = request.POST.get("next") or request.GET.get("next") or ""
    if next_url and url_has_allowed_host_and_scheme(
            next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return next_url
    return default


@login_required
def config_create_user(request):
    """Create a bare local account for a stakeholder who has none yet (reached from Alert
    groups' "Add stakeholder" button, or anywhere else that needs one) — then returns to
    wherever the caller came from via `next`.

    Superuser-gated, same as reset_password/delete_user on the Roles console: creating an
    account is an ACCOUNT-level action, not a role-level one, so it follows that existing
    precedent rather than the plain Administrator gate every Configuration screen otherwise
    uses. Real staff logins are normally provisioned by the org auth endpoint on first sign-in
    (see deployment.txt) — this is for the other case, someone who needs to be addressable as
    a stakeholder but may never sign in at all.
    """
    next_url = _safe_next(request)
    if not is_superuser(request.user):
        messages.error(request, "Only a superuser may create accounts.")
        return redirect(next_url)

    if request.method == "POST":
        next_url = _safe_next(request)
        username = (request.POST.get("username") or "").strip()
        email = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name = (request.POST.get("last_name") or "").strip()
        password1 = request.POST.get("password1") or ""
        password2 = request.POST.get("password2") or ""

        errors = []
        if not username:
            errors.append("Username is required.")
        elif get_user_model().objects.filter(username=username).exists():
            errors.append(f"“{username}” is already taken.")
        if password1 != password2:
            errors.append("Passwords do not match.")
        else:
            try:
                validate_password(password1)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if errors:
            for e in errors:
                messages.error(request, e)
            return render(request, "reports/config_create_user.html", {
                "next": next_url, "username": username, "email": email,
                "first_name": first_name, "last_name": last_name,
            })

        get_user_model().objects.create_user(
            username=username, email=email, password=password1,
            first_name=first_name, last_name=last_name)
        messages.success(request, f"Created “{username}”.")
        return redirect(next_url)

    return render(request, "reports/config_create_user.html", {"next": next_url})


@login_required
def config_users(request):
    """The account-management screen -- deliberately SEPARATE from Roles (on request,
    2026-09-04: "make user management a screen on its own, separate it from roles") and
    superuser-only, grayed out (not merely hidden) on the Configuration hub itself for anyone
    else (see _SUPERUSER_ONLY_CHILDREN). Roles still lets an Administrator manage who holds
    which role -- that stays a role-level job, tested by
    RoleWorkflow.test_administrator_sets_roles_directly, untouched by this screen's own gate --
    but editing the ACCOUNT itself (profile, password, deletion, all on config_edit_user) is a
    different kind of power, same reasoning AccountManagementAccess's own docstring already
    gives for why that boundary sits on is_superuser, not is_role_admin.

    A plain list + "Edit" per row; the actual editing (and its own superuser check, enforced
    again there since a crafted URL must never rely on this list simply not linking to it) lives
    on config_edit_user."""
    if not is_superuser(request.user):
        messages.error(request, "Only a superuser may manage user accounts.")
        return redirect("configuration")

    users = get_user_model().objects.all().prefetch_related("groups").order_by("username")
    me = request.user
    user_rows = [{
        "u": u,
        "roles": sorted(u.groups.values_list("name", flat=True)),
        "is_me": u.pk == me.pk,
    } for u in users]
    return render(request, "reports/config_users.html", {
        **_config_context("config_users", viewer_is_superuser=True),
        "user_rows": user_rows,
    })


@login_required
def config_folder_exporter(request):
    """folder_exporter's own status/mapping screen (2026-09-12, on request: "I also dont see
    the folder exporter config in administrator role"). Superuser-only, same reasoning as
    config_users -- the service this reports on is what every one of this app's OWN scheduled
    jobs (alert/event pollers, automated reports) runs through.

    Deliberately READ-ONLY and non-executing (on request, after the risk was laid out: the
    project has no releases/tags/signing, so "install the latest version" would mean running
    unverified code from a public GitHub repo as a privileged Windows service): this screen
    only ever detects and shows the exact commands to run by hand, never clones/builds/
    installs anything itself. See folder_exporter_admin's own module docstring."""
    if not is_superuser(request.user):
        messages.error(request, "Only a superuser may view Folder Exporter status.")
        return redirect("configuration")

    installed = folder_exporter_admin.is_installed()
    jobs, folders = folder_exporter_admin.read_jobs_and_folders() if installed else ([], [])
    return render(request, "reports/config_folder_exporter.html", {
        **_config_context("config_folder_exporter", viewer_is_superuser=True),
        "installed": installed,
        "version": folder_exporter_admin.installed_version(),
        "mtime": folder_exporter_admin.installed_mtime(),
        "service_status": folder_exporter_admin.service_status(),
        "jobs": jobs,
        "folders": folders,
        "latest": folder_exporter_admin.latest_commit_info(),
        "repo_url": folder_exporter_admin.REPO_URL,
    })


@login_required
def config_edit_user(request, pk):
    """Superuser-only: a full editing screen for one account (on request, 2026-09-04: "give
    superuser the ability to modify existing user profile such as change email and
    password... add an edit button... super admin can delete user, modify profile as well as
    change password"). Profile fields (e-mail, first/last name) are handled entirely here --
    genuinely new capability, no existing screen touched it. Password reset and delete are the
    SAME actions the Roles console's own POST handler already offers (action=
    reset_password/delete_user, posted to roles_console -- that endpoint's own logic is
    untouched even though the UI that used to trigger it moved here, see config_users) --
    reused as-is, not reimplemented, so this is a roomier front door onto identical,
    already-tested server-side logic rather than a second copy of it.

    Deliberately NOT relaxed to the Administrator role -- see AccountManagementAccess's own
    docstring on why resetting a password is account takeover, a different kind of power from
    managing roles, and was kept superuser-only on request (2026-09-04) even while building
    this screen."""
    target = get_object_or_404(get_user_model(), pk=pk)
    if not is_superuser(request.user):
        messages.error(request, "Only a superuser may edit accounts.")
        return redirect("config_users")

    if request.method == "POST" and request.POST.get("action") == "update_profile":
        email = (request.POST.get("email") or "").strip()
        if email:
            try:
                validate_email(email)
            except ValidationError:
                messages.error(request, "That doesn't look like a valid e-mail address.")
                return redirect("config_edit_user", pk=target.pk)
        target.email = email
        target.first_name = (request.POST.get("first_name") or "").strip()
        target.last_name = (request.POST.get("last_name") or "").strip()
        target.save(update_fields=["email", "first_name", "last_name"])
        messages.success(request, "Profile saved.")
        return redirect("config_edit_user", pk=target.pk)

    return render(request, "reports/config_edit_user.html", {
        "target": target,
        "passwords_are_local": not keycloak_mod.enabled(),
        "deletable": (target.pk != request.user.pk
                      and not (target.is_superuser and _other_superusers(target) == 0)),
    })


@login_required
def system_settings(request):
    """Administrator-only: the Prometheus/Grafana the dashboard fetches from (overrides
    config.ini), plus which AI provider (if any) the Automated Reports engine's narrative
    layer calls (2026-09-07 -- see reports/ai_narrative.py's own docstring). The two API key
    fields follow the standard "blank means unchanged" convention rather than ever
    re-displaying the real secret: a blank submission keeps whatever's already encrypted at
    rest, a non-blank one replaces it."""
    denied = _require_admin(request)
    if denied:
        return denied
    sc = SystemConfig.get()
    if request.method == "POST":
        form = SystemConfigForm(request.POST, instance=sc)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.narrative_provider = request.POST.get("narrative_provider", "") or ""
            anthropic_key = request.POST.get("anthropic_api_key", "").strip()
            if anthropic_key:
                obj.anthropic_api_key_encrypted = crypto.encrypt(anthropic_key)
            copilot_key = request.POST.get("copilot_api_key", "").strip()
            if copilot_key:
                obj.copilot_api_key_encrypted = crypto.encrypt(copilot_key)
            obj.updated_by = request.user
            obj.save()
            messages.success(request, "System settings saved — the next capture/report run uses them.")
            return redirect("system_settings")
    else:
        form = SystemConfigForm(instance=sc)
    defaults = gr.load_config()   # the file-based fallbacks, shown for reference
    return render(request, "reports/settings.html", {
        **_config_context("system_settings"),
        "form": form, "sc": sc,
        "config_prom": defaults.prom, "config_grafana": defaults.grafana,
        "narrative_provider_choices": SystemConfig.NARRATIVE_PROVIDER_CHOICES,
        "anthropic_key_set": bool(sc.anthropic_api_key_encrypted),
        "copilot_key_set": bool(sc.copilot_api_key_encrypted),
    })


@login_required
def grafana_config(request):
    """Administrator-only: edit the WHOLE custom.ini as raw text, kept as DB-versioned
    revisions (see GrafanaConfigRevision) rather than files on disk. The SMTP password line is
    always MASKED in `content` (never the real value) — see grafana_admin.mask_password/
    extract_password/unmask_password. 'Save' only records a revision; 'Save & Apply' unmasks
    the real password back in, rewrites custom.ini, and restarts Grafana."""
    if not is_role_admin(request.user):
        return redirect("report_form")

    current = GrafanaConfigRevision.current()

    if request.method == "POST":
        action = request.POST.get("action")
        form = GrafanaConfigForm(request.POST)
        if action == "restore":
            rev_id = request.POST.get("rev_id")
            restore_rev = get_object_or_404(GrafanaConfigRevision, pk=rev_id)
            form = GrafanaConfigForm(initial={"content": restore_rev.content})
            messages.info(request, f"Loaded the {restore_rev.created_at:%d %b %Y %H:%M} "
                                   "revision — review below, then Save or Save & Apply to "
                                   "make it current.")
        elif form.is_valid():
            data = form.cleaned_data
            content = data["content"]
            submitted_password = grafana_admin.extract_password(content)
            if submitted_password is None or submitted_password == grafana_admin.PASSWORD_PLACEHOLDER:
                # Unchanged — carry the real password forward. On the very first-ever save
                # there's no previous revision to carry it from, so fall back to what's
                # actually in the live file right now.
                if current is not None:
                    password_encrypted = current.smtp_password_encrypted
                else:
                    live_password = grafana_admin.extract_password(grafana_admin.parse_live_config()) or ""
                    password_encrypted = crypto.encrypt(live_password)
                stored_content = content
            else:
                # The admin typed a real new value over the placeholder line — encrypt it, then
                # re-mask before storing so `content` in the DB is NEVER the real password.
                password_encrypted = crypto.encrypt(submitted_password)
                stored_content = grafana_admin.mask_password(content)
            rev = GrafanaConfigRevision(created_by=request.user, note=data["note"],
                                        content=stored_content,
                                        smtp_password_encrypted=password_encrypted)
            rev.save()
            if action == "apply":
                real_content = grafana_admin.unmask_password(
                    rev.content, crypto.decrypt(rev.smtp_password_encrypted))
                ok, message = grafana_admin.write_and_restart(real_content)
                (messages.success if ok else messages.error)(request, message)
            else:
                messages.success(request, "Revision saved (not applied — custom.ini is unchanged).")
            return redirect("grafana_config")
    else:
        initial_content = (current.content if current is not None
                           else grafana_admin.mask_password(grafana_admin.parse_live_config()))
        form = GrafanaConfigForm(initial={"content": initial_content})

    return render(request, "reports/grafana_config.html", {
        **_config_context("grafana_config"),
        "form": form,
        "current": current,
        "history": GrafanaConfigRevision.objects.all()[:20],
        "bootstrapped_from_file": current is None,
        "service_status": grafana_admin.service_status(),
    })


@login_required
def prometheus_config(request):
    """Administrator-only: edit the WHOLE prometheus.yml as raw text, kept as DB-versioned
    revisions (see PrometheusConfigRevision) rather than files on disk. 'Save' only records a
    revision; 'Save & Apply' validates with the real promtool FIRST (see
    prometheus_admin.validate) and only rewrites prometheus.yml + restarts the service if that
    passes — a broken edit never reaches the live file."""
    if not is_role_admin(request.user):
        return redirect("report_form")

    current = PrometheusConfigRevision.current()

    if request.method == "POST":
        action = request.POST.get("action")
        form = PrometheusConfigForm(request.POST)
        if action == "restore":
            rev_id = request.POST.get("rev_id")
            restore_rev = get_object_or_404(PrometheusConfigRevision, pk=rev_id)
            form = PrometheusConfigForm(initial={"content": restore_rev.content})
            messages.info(request, f"Loaded the {restore_rev.created_at:%d %b %Y %H:%M} "
                                   "revision — review below, then Save or Save & Apply to "
                                   "make it current.")
        elif form.is_valid():
            data = form.cleaned_data
            rev = PrometheusConfigRevision(
                created_by=request.user, note=data["note"], content=data["content"])
            rev.save()
            if action == "apply":
                ok, message = prometheus_admin.write_and_restart(rev.content)
                (messages.success if ok else messages.error)(request, message)
            else:
                messages.success(request, "Revision saved (not applied — prometheus.yml is unchanged).")
            return redirect("prometheus_config")
    else:
        initial = {"content": current.content if current is not None
                   else prometheus_admin.parse_live_config()}
        form = PrometheusConfigForm(initial=initial)

    return render(request, "reports/prometheus_config.html", {
        **_config_context("prometheus_config"),
        "form": form,
        "current": current,
        "history": PrometheusConfigRevision.objects.all()[:20],
        "bootstrapped_from_file": current is None,
        "service_status": prometheus_admin.service_status(),
        "rule_files": prometheus_admin.RULE_FILES,
        "active_file": "prometheus.yml",
    })


@login_required
def prometheus_rule_file(request, filename):
    """Administrator-only: edit one of prometheus.yml's rule_files (alerts.yml,
    t24_services.yml, folder_exporter_rules.yml) as raw text — a sub-page of the Prometheus
    config screen (see the tab strip in prometheus_config.html/prometheus_rule_file.html).
    Same DB-versioned/validate-before-apply shape as prometheus_config, but validated with
    `promtool check rules` (standalone rule syntax check) instead of `check config`."""
    if not is_role_admin(request.user):
        return redirect("report_form")
    if filename not in prometheus_admin.RULE_FILES:
        raise Http404(f"not a recognised rule file: {filename}")

    current = PrometheusRuleFileRevision.current(filename)

    if request.method == "POST":
        action = request.POST.get("action")
        form = PrometheusConfigForm(request.POST)
        if action == "restore":
            rev_id = request.POST.get("rev_id")
            restore_rev = get_object_or_404(PrometheusRuleFileRevision, pk=rev_id, filename=filename)
            form = PrometheusConfigForm(initial={"content": restore_rev.content})
            messages.info(request, f"Loaded the {restore_rev.created_at:%d %b %Y %H:%M} "
                                   "revision — review below, then Save or Save & Apply to "
                                   "make it current.")
        elif form.is_valid():
            data = form.cleaned_data
            rev = PrometheusRuleFileRevision(
                created_by=request.user, note=data["note"], filename=filename,
                content=data["content"])
            rev.save()
            if action == "apply":
                ok, message = prometheus_admin.write_rule_file_and_restart(filename, rev.content)
                (messages.success if ok else messages.error)(request, message)
            else:
                messages.success(request, f"Revision saved (not applied — {filename} is unchanged).")
            return redirect("prometheus_rule_file", filename=filename)
    else:
        initial = {"content": current.content if current is not None
                   else prometheus_admin.parse_live_rule_file(filename)}
        form = PrometheusConfigForm(initial=initial)

    return render(request, "reports/prometheus_rule_file.html", {
        **_config_context("prometheus_config"),
        "form": form,
        "current": current,
        "filename": filename,
        "history": PrometheusRuleFileRevision.objects.filter(filename=filename)[:20],
        "bootstrapped_from_file": current is None,
        "service_status": prometheus_admin.service_status(),
        "rule_files": prometheus_admin.RULE_FILES,
        "active_file": filename,
    })


@login_required
def profile(request):
    """View / edit the current user's profile (auth fields + extended profile)."""
    prof, _ = UserProfile.objects.get_or_create(user=request.user)
    if request.method == "POST":
        aform = UserAccountForm(request.POST, instance=request.user)
        pform = ProfileForm(request.POST, instance=prof)
        if aform.is_valid() and pform.is_valid():
            aform.save()
            pform.save()
            messages.success(request, "Profile saved.")
            return redirect("profile")
    else:
        aform = UserAccountForm(instance=request.user)
        pform = ProfileForm(instance=prof)
    roles = list(request.user.groups.values_list("name", flat=True))
    return render(request, "reports/profile.html",
                  {"aform": aform, "pform": pform, "profile": prof, "roles": roles})


@login_required
def no_role(request):
    """Signed-in user with no role: explain, and let them REQUEST one or more roles."""
    my_roles = set(request.user.groups.values_list("name", flat=True))
    pending = set(request.user.role_requests.filter(status="pending").values_list("role", flat=True))

    if request.method == "POST":
        created = 0
        for r in request.POST.getlist("roles"):
            if r in SELECTABLE_ROLE_NAMES and r not in my_roles and r not in pending:
                RoleRequest.objects.create(user=request.user, role=r)
                created += 1
        if created:
            messages.success(request, f"Requested {created} role(s). An administrator will review it.")
        else:
            messages.error(request, "Select at least one new role to request.")
        return redirect("no_role")

    roles = [{"name": r, "has": r in my_roles, "pending": r in pending} for r in SELECTABLE_ROLE_NAMES]
    return render(request, "reports/no_role.html", {"roles": roles, "has_any": bool(my_roles)})


def _other_superusers(exclude) -> int:
    """How many superusers would remain if `exclude` were deleted.

    Guards the one irreversible mistake this console can make. Deleting the last superuser
    leaves an app whose account tools nobody can reach — recoverable only from a shell on
    the server, which is exactly the situation a self-service console exists to avoid.
    """
    return (get_user_model().objects
            .filter(is_superuser=True, is_active=True)
            .exclude(pk=exclude.pk).count())


def _grant_role(user, role, keycloak):
    """Grant a single role — in Keycloak (the store) when enabled, else the local group mirror."""
    if keycloak.enabled():
        keycloak.add_user_role(user.get_username(), role)
        keycloak.sync_user_roles(user)
    else:
        grp, _ = Group.objects.get_or_create(name=role)
        user.groups.add(grp)


@login_required
def roles_console(request):
    """Administrator view: approve/reject role requests and manage every user's roles."""
    if not is_role_admin(request.user):
        return redirect("report_form")

    if request.method == "POST":
        from . import keycloak
        action = request.POST.get("action")
        if action == "decide":
            req = get_object_or_404(RoleRequest, pk=request.POST.get("request_id"))
            decision = request.POST.get("decision")
            if decision == "approve" and req.role in ROLE_NAMES:
                _grant_role(req.user, req.role, keycloak)
                req.status = "approved"
            elif decision == "reject":
                req.status = "rejected"
            req.decided_at, req.decided_by = timezone.now(), request.user
            req.save()
            messages.success(request, f"{req.user.get_username()} · {req.role}: {req.status}.")
        elif action == "set_roles":
            user = get_object_or_404(get_user_model(), pk=request.POST.get("user_id"))
            selected = {r for r in request.POST.getlist("roles") if r in ROLE_NAMES}
            if keycloak.enabled():
                keycloak.set_user_roles(user.get_username(), selected)   # Keycloak is the store
                keycloak.sync_user_roles(user)                           # mirror back to groups
            else:
                for r in ROLE_NAMES:
                    grp, _ = Group.objects.get_or_create(name=r)
                    user.groups.add(grp) if r in selected else user.groups.remove(grp)
            messages.success(request, f"Updated roles for {user.get_username()}.")

        # ---- account actions: superuser only ------------------------------------------
        # These act on the ACCOUNT rather than on its roles, so they are gated on
        # is_superuser rather than on the Administrator role. Every guard below is
        # enforced HERE, not in the template: hiding a button is presentation, and this
        # is the layer a crafted POST actually reaches.
        elif action in ("reset_password", "delete_user"):
            if not is_superuser(request.user):
                messages.error(request, "Only a superuser may reset passwords or delete accounts.")
                return redirect("roles_console")

            target = get_object_or_404(get_user_model(), pk=request.POST.get("user_id"))

            if action == "reset_password":
                if keycloak.enabled():
                    # The password lives in Keycloak, not here. Writing to the local hash
                    # would silently do nothing at login and look like it worked.
                    messages.error(request, "Passwords are managed in Keycloak — reset it there.")
                    return redirect("roles_console")
                pw1 = request.POST.get("new_password") or ""
                pw2 = request.POST.get("new_password2") or ""
                if pw1 != pw2:
                    messages.error(request, "The two passwords did not match — nothing was changed.")
                    return redirect("roles_console")
                try:
                    validate_password(pw1, target)
                except ValidationError as exc:
                    messages.error(request, " ".join(exc.messages))
                    return redirect("roles_console")
                target.set_password(pw1)
                target.save(update_fields=["password"])
                # Changing a password does not, by itself, end that account's live sessions.
                # Django's session auth hash is derived from the password, so every existing
                # session for this user stops validating on its next request — which is the
                # behaviour we want and the reason nothing else has to be cleaned up here.
                messages.success(
                    request,
                    f"Password reset for {target.get_username()}. Their existing sessions are now invalid.")

            else:   # delete_user
                # The self-guard below is what actually keeps at least one superuser alive:
                # a superuser deleting ANOTHER superuser always leaves themselves, and they
                # cannot delete themselves, so the population can never reach zero. The
                # last-superuser check after it is therefore unreachable today and kept as
                # defence in depth — if the self-guard is ever relaxed (say, to allow
                # deleting your own account), it becomes the thing standing between this
                # console and an app whose account tools nobody can reach.
                if target.pk == request.user.pk:
                    messages.error(request, "You cannot delete the account you are signed in as.")
                    return redirect("roles_console")
                if target.is_superuser and _other_superusers(target) == 0:
                    messages.error(
                        request,
                        f"{target.get_username()} is the only superuser left. Grant superuser to "
                        "another account first, or this app can no longer manage its own accounts.")
                    return redirect("roles_console")
                # Deletion is irreversible and there is no undo in this UI, so the username
                # has to be typed back. A misplaced click cannot satisfy this.
                if (request.POST.get("confirm_username") or "").strip() != target.get_username():
                    messages.error(request, "Type the username exactly to confirm deletion.")
                    return redirect("roles_console")
                name = target.get_username()
                target.delete()
                messages.success(request, f"Deleted the account {name}.")

        return redirect("roles_console")

    return render(request, "reports/config_roles.html", {
        **_config_context("config_roles"),
        **_role_assignments_context(request),
        **_role_scopes_context(),
        "default_open": "assignments",
    })


def _role_assignments_context(request) -> dict:
    """Who holds which role, and pending requests -- read-side only, reused by every entry
    point onto the combined Roles page (see config_roles' own docstring). Account-level fields
    (is_superuser/deletable/can_manage_accounts/passwords_are_local) used to live on these rows
    too, back when Roles also rendered the account-actions "Manage" disclosure -- moved out
    with that disclosure to Configuration > Users (2026-09-04: "make user management a screen
    on its own, separate it from roles"), so this context is role-assignment-only now."""
    pending = RoleRequest.objects.filter(status="pending").select_related("user")
    users = get_user_model().objects.all().prefetch_related("groups").order_by("username")
    user_rows = [{"u": u, "roles": set(u.groups.values_list("name", flat=True))} for u in users]
    return {"pending": pending, "user_rows": user_rows, "role_names": ROLE_NAMES}


def csrf_failure(request, reason="", template_name="reports/csrf_failure.html"):
    """Replaces Django's bare yellow "CSRF verification failed" page (see CSRF_FAILURE_VIEW).

    A rejected token here almost always means the admin's page went stale — the 15-minute
    idle timeout logged them out and the re-login rotated the csrftoken cookie — so the
    useful response is a way back to a fresh report, not a dead end.
    """
    return render(request, template_name, {"reason": reason}, status=403)

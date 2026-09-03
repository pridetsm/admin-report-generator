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
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

import generate_report as gr   # to show the config.ini defaults on the settings page

from pathlib import Path

from . import (alerting, backup_policy_admin, connect, crypto, folders, grafana_admin, network,
               network_sod, promconfig, prometheus_admin, scripts, snmp_admin)
from . import keycloak as keycloak_mod
from .directory import search_directory
from .forms import (GrafanaConfigForm, PrometheusConfigForm, ProfileForm, SystemConfigForm,
                    UserAccountForm)
from .models import (AlertGroup, BackupPolicyRevision, GeneratedScript, GrafanaConfigRevision,
                     PrometheusConfigRevision,
                     PrometheusRuleFileRevision, ReportSubmission, RoleRequest, RoleScope,
                     SnmpConfigRevision, SystemConfig, UserProfile)
from .roles import (ALL_ROLES, ALL_ROLES_DESCRIPTION, ALL_ROLES_ICON, ALL_ROLES_LABEL,
                    ROLE_DESCRIPTIONS, ROLE_HOME, ROLE_NAMES, ROLE_PAGES,
                    SESSION_KEY as ROLE_SESSION_KEY, roles_without_screens,
                    active_role, held_roles, is_infra_admin, is_network_admin, is_role_admin,
                    effective_roles, is_security_admin, reports_for,
                    role_icon, role_screens,
                    is_superuser, is_system_admin)
from .services import (
    OsInventoryUnavailable,
    build_os_inventory,
    default_os_inventory_filename,
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


@never_cache
@login_required
def network_dashboard(request):
    """Network Analyses Dashboard — the network admin's landing screen.

    The counterpart to the System Analyses Dashboard: that one lists business systems, this
    one lists network devices. Same shape, same grid, different inventory — a network admin
    should not have to read past RTGS and Temenos to reach a switch.

    One tile today, because one device is monitored. It is still a picker rather than a
    straight redirect to the report: the grid is where the second and third device land when
    the firewall and the wireless controller are onboarded, and a screen that silently
    becomes a list later is less confusing than one that appears from nowhere.
    """
    if not is_network_admin(request.user):
        return redirect("report_form")
    try:
        devices = network.device_inventory()
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    # A device already chosen means a report is open — surfaced the same way the systems
    # picker surfaces one, so the only way forward is not "start again and lose the answers".
    open_seconds = _open_report_seconds(request, "network")
    open_keys = (request.session.get("network_devices") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/network_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_interfaces": sum(d["iface_count"] for d in devices),
        "reachable_count": sum(1 for d in devices if d["reachable"]),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


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
        wanted = [r for r in request.POST.getlist("request_role") if r in ROLE_NAMES]
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
        # EVERY role in the catalogue, each with its standing. The first-login screen already
        # lists them all; showing only what you hold here made the app look like it had two
        # different ideas of how many roles exist.
        "roles": [{"name": r,
                   "description": ROLE_DESCRIPTIONS.get(r, ""),
                   "icon": role_icon(r),
                   "pages": role_screens(r),
                   "held": r in held,
                   "pending": r in pending} for r in ROLE_NAMES],
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
_OPEN_UNTIL = {"systems": "report_expires_at", "network": "network_expires_at",
              "infra": "infra_report_expires_at"}

#: session keys an estate's open report claims, cleared together once it lapses or is closed.
_ESTATE_SESSION_KEYS = {
    "systems": {"report_systems", "snapshot_token", "report_expires_at"},
    "network": {"network_devices", "network_token", "network_expires_at"},
    "infra":   {"infra_report_systems", "infra_snapshot_token", "infra_report_expires_at"},
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
        return redirect("roles_console" if is_role_admin(request.user) else "role_empty")
    return render(request, "reports/reports.html", {
        "options": [{"key": r.key, "label": r.label, "blurb": r.blurb,
                     "url": reverse(r.url_name), "icon": r.icon, "initial": r.label[:1]}
                    for r in available],
    })


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
        return response

    return render(request, "reports/os_inventory.html", {
        "default_theme": getattr(getattr(request.user, "profile", None),
                                 "default_report_theme", "dark"),
    })




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
    report_content = {
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
    return response


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
def network_report(request):
    """The Network Admin Report for the SELECTED devices.

    Mirrors the systems flow deliberately. POST (from the device picker) records the choice
    and redirects to GET — Post/Redirect/Get, so a browser refresh never re-submits the
    selection — and GET renders the report scoped to those devices.

    Arriving with no selection sends the admin to the picker rather than quietly reporting on
    everything: which devices a report covers is the admin's statement, not a default.
    """
    if not is_network_admin(request.user):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = {d["key"] for d in network.DEVICES}
        keys = [k for k in keys if k in known]
        if not keys:
            messages.error(request, "Select at least one device to include in the report.")
            return redirect("network_dashboard")
        request.session["network_devices"] = keys
        request.session.pop("network_token", None)   # new selection -> fresh capture
        return redirect("network_report")

    keys = request.session.get("network_devices")
    if not keys:
        return redirect("network_dashboard")

    force = request.GET.get("fresh") == "1"
    snapshot = None
    token = request.session.get("network_token", "")
    if not force and token:
        snapshot = cache.get(_cache_key(token))

    if snapshot is None:
        token = uuid.uuid4().hex
        try:
            snapshot = network.capture_snapshot(token, only=set(keys))
        except network.NetworkUnavailable as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
        if not snapshot.systems:                # the selection no longer resolves
            messages.error(request, "Those devices are no longer being monitored. Please choose again.")
            request.session.pop("network_devices", None)
            return redirect("network_dashboard")
        # Alphabetical, same as the systems flow (see report()) and for the same reason: sort
        # once, HERE, before caching, so the page render and network_generate()'s enumerate()
        # over this same cached object agree on the same order.
        snapshot.systems.sort(key=lambda s: s.name.lower())
        cache.set(_cache_key(token), snapshot, settings.SNAPSHOT_TTL)
        request.session["network_token"] = token
        request.session["network_expires_at"] = time.time() + settings.SNAPSHOT_TTL

    # Anchor the countdown to the capture time so a refresh continues it (never restarts) —
    # the same reasoning report()'s equivalent line uses. A cached snapshot reused across
    # requests had been showing the full TTL on every load instead of what was actually left.
    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))

    # The SAME annotation screen the systems report uses. One device is one "system" and its
    # faults are its flags, so the template needs no network special-casing — which is the
    # point: an admin who has written a system report already knows how to write this one.
    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "selected_count": len(snapshot.systems),
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_filename": network.network_report_filename(
            getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")),
        "alpha_grouped": True,
        "letter_index": sorted({s.name[0].upper() for s in snapshot.systems if s.name}),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,
        "report_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        # the shared screen's nouns and destinations, so a network admin is not handed the
        # systems screen with a switch on it
        # Still the Network Admin role/routes (see network_report's own docstring) -- this is
        # a wording-only rename: what started as switch monitoring is now mostly HCI Cluster
        # infrastructure data, so the displayed title says so. Kept under Network Admin for
        # now (this remains the place to SELECT and ANNOTATE these devices); Infrastructure
        # Admin's OWN report (infra_form/infra_report/infra_generate) now reads the same live
        # data read-only, through the new tree-nested template -- see
        # network.build_infrastructure_report's module docstring.
        "dash_title": "Infrastructure Analyses Dashboard",
        "subject": "device",
        "draft_key": "draft:network:" + ",".join(sorted(keys)),
        "picker_url": reverse("network_dashboard"),
        "generate_url": reverse("network_generate"),
        "generate_default": reverse("generate"),
    })


@login_required
@require_POST
def network_generate(request):
    """Build the Network Admin Report from the reviewed snapshot — the systems generate flow,
    for network gear. Answers are namespaced the same way (fix__<device>__<flag>), so the
    shared form template needs no branch."""
    if not is_network_admin(request.user):
        return redirect("report_form")

    token = request.POST.get("token", "") or request.session.get("network_token", "")
    snapshot = cache.get(_cache_key(token)) if token else None
    if snapshot is None:
        messages.error(request, "That snapshot has expired. Capture a fresh one.")
        return redirect("network_report")

    theme = request.POST.get("theme", "").strip().lower()
    if theme not in gr.PALETTES:
        # falls back to the admin's saved preference, then dark — the same order the systems
        # flow uses, so the two reports never disagree about what "no choice" means
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
                                annotations=annotations, summary_comment=summary_comment)
    filename = network.network_report_filename(theme, timezone.localtime())

    # Frozen exactly as presented, so History replays it without touching Prometheus.
    report_content = {
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )
    # Left in the cache to lapse at its TTL, for the same reason as the systems flow above:
    # the page stays open after a download, and Generate has to work twice.

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


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
    return resp


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
    """
    if not is_infra_admin(request.user):
        return redirect("report_form")
    try:
        devices = [d for d in network.device_inventory() if d.get("kind") == "windows"]
    except network.NetworkUnavailable as exc:
        return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
    open_seconds = _open_report_seconds(request, "infra")
    open_keys = (request.session.get("infra_report_systems") or []) if open_seconds else []
    by_key = {d["key"]: d for d in devices}
    return render(request, "reports/infra_select.html", {
        "devices": [dict(d, mono_hue=_mono_hue(d["name"])) for d in devices],
        "total_hosts": len(devices),
        "unreachable_count": sum(1 for d in devices if d["known"] and not d["reachable"]),
        "open_report": [by_key[k]["name"] for k in open_keys if k in by_key],
        "open_seconds": open_seconds,
    })


@login_required
def infra_report(request):
    """The annotation screen for the SELECTED infrastructure devices — mirrors network_report
    exactly (device picker -> capture -> the shared form.html annotation screen), not `report`:
    the data here is network.py's Snapshot/SystemVM shape (windows-kind devices), not
    generate_report.py's business-system Store/System shape the plain systems flow expects, so
    this estate posts to its own infra_generate rather than the shared `generate`.

    Session key kept as "infra_report_systems" (now holding device KEYS rather than system
    names) — context.py's back-button override only checks it for truthiness, so renaming it
    would have touched a second file for no behavioural gain.
    """
    if not is_infra_admin(request.user):
        return redirect("report_form")

    if request.method == "POST":
        keys = [k for k in request.POST.getlist("include_device") if k]
        known = {d["key"] for d in network.DEVICES if d.get("kind") == "windows"}
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

    force = request.GET.get("fresh") == "1"
    snapshot = None
    token = request.session.get("infra_snapshot_token", "")
    if not force and token:
        snapshot = cache.get(_cache_key(token))

    if snapshot is None:
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

    report_content = {
        "overview": snapshot.overview,
        "systems": [{
            "name": s.name, "hosts": s.hosts,
            "flags": [{"key": f.key, "text": f.text, "band": f.band, "category": f.category,
                       "answer": annotations.get(s.name, {}).get("flags", {}).get(f.key, "")}
                      for f in s.flags],
            "comment": annotations.get(s.name, {}).get("comment", ""),
        } for s in snapshot.systems],
    }

    ReportSubmission.objects.create(
        generated_by=request.user, author=author, theme=theme,
        annotations=annotations, report_content=report_content,
        immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
    )

    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


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
#      Configuration
#        ├─ Prometheus     global/storage/rules   → Edit raw YAML → rule files
#        ├─ Grafana        custom.ini
#        ├─ SNMP           (awaiting the server-side update)
#        ├─ Topology       systems → hosts, pivoted out of the same prometheus.yml
#        ├─ Backup policy  per-host backup-frequency overrides
#        ├─ Data sources   which Prometheus/Grafana to read
#        └─ Role scopes    which systems each role sees
_CONFIG_CHILDREN = [
    ("config_prometheus", "Prometheus", "Scrape intervals, storage and rule files"),
    ("grafana_config", "Grafana", "custom.ini, versioned and applied"),
    ("config_snmp", "SNMP", "Network device polling"),
    ("config_topology", "Topology", "Which hosts belong to which system"),
    ("config_backup_policy", "Backup policy", "Per-host backup-frequency overrides"),
    ("config_scripts", "Scripts", "Generate the checker scripts hosts run"),
    ("system_settings", "Data sources", "Which Prometheus / Grafana to read"),
    ("config_role_scopes", "Role scopes", "Which systems each role sees"),
    ("config_alert_groups", "Alert groups", "Who gets notified, and when, per system group"),
]


def _config_context(active: str) -> dict:
    return {
        "config_children": [{"url_name": n, "label": lbl, "hint": hint, "active": n == active}
                            for n, lbl, hint in _CONFIG_CHILDREN],
        "yaml_source": promconfig.source_info(),
        "service_status": prometheus_admin.service_status(),
    }


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
    """Every system name in the live prometheus.yml, for the role-scope picker.

    Read through promconfig so this screen and the configuration form always agree on which
    file is the topology. Returns empty — never raises — if the file can't be read, so a
    broken YAML degrades this screen instead of taking it down; the form's own load error
    says what is wrong.
    """
    try:
        return promconfig.system_names(promconfig.load())
    except Exception:      # noqa: BLE001 — surfaced properly on the configuration form
        return []


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
    return render(request, "reports/configuration.html", _config_context("configuration"))


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
    """{instance: {"frequency_days": N, "off_weekdays": [...]}, ...} — sparse: an instance is
    only kept if it has a non-default frequency AND/OR at least one off-weekday checked,
    matching the engine's own sparse-override design (a host absent from the dict just gets
    DEFAULT_BACKUP_MAX_AGE_DAYS and no off-days)."""
    policy: dict = {}
    for inst in all_instances:
        entry: dict = {}
        raw = (post.get(f"freq__{inst}") or "").strip()
        if raw:
            try:
                days = int(raw)
            except ValueError:
                days = None
            if days is not None and days > 0 and days != backup_policy_admin.DEFAULT_FREQUENCY_DAYS:
                entry[backup_policy_admin.FREQUENCY_FIELD] = days
        off_days = sorted({int(d) for d in post.getlist(f"off__{inst}") if d.isdigit() and 0 <= int(d) <= 6})
        if off_days:
            entry[backup_policy_admin.OFF_WEEKDAYS_FIELD] = off_days
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
            hosts.append({
                "label": c.label, "instance": c.instance,
                "days": entry.get(backup_policy_admin.FREQUENCY_FIELD, default_days),
                "off_weekdays": [{"value": i, "label": lbl, "checked": i in off_days}
                                 for i, lbl in enumerate(backup_policy_admin.WEEKDAY_LABELS)],
            })
        groups.append({"name": s.name, "hosts": hosts,
                       "overridden": any(h["days"] != default_days or
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


@never_cache
@login_required
def config_role_scopes(request):
    """Which systems each role's workspace covers — what the role tiles at sign-in select.

    A role with nothing ticked is UNRESTRICTED (it sees the whole estate), so the mapping can
    be filled in one role at a time without hiding systems from anyone in the meantime.
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
            scope.updated_by = request.user
            scope.save()
        messages.success(request, "Role scopes saved — they apply the next time a role is selected.")
        return redirect("config_role_scopes")

    mapped = {s.role: set(s.systems or []) for s in RoleScope.objects.all()}
    rows = [{
        "role": role,
        "icon": role_icon(role),
        "description": ROLE_DESCRIPTIONS.get(role, ""),
        "chosen": mapped.get(role, set()),
        "unscoped": not mapped.get(role),
    } for role in ROLE_NAMES]
    return render(request, "reports/config_role_scopes.html", {
        **_config_context("config_role_scopes"),
        "rows": rows, "systems": systems,
    })


@never_cache
@login_required
def config_alert_groups(request):
    """The catalogue of alert groups, and the bare-name form that creates one.

    A group starts covering NO systems and no stakeholders (see AlertGroup's own docstring for
    why that's the opposite default from Role scopes) — creating one only ever opens its own
    edit screen next, it never itself starts sending anything.
    """
    denied = _require_admin(request)
    if denied:
        return denied
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        if not name:
            messages.error(request, "Give the group a name.")
            return redirect("config_alert_groups")
        if AlertGroup.objects.filter(name=name).exists():
            messages.error(request, f"A group called “{name}” already exists.")
            return redirect("config_alert_groups")
        group = AlertGroup.objects.create(name=name, updated_by=request.user)
        messages.success(request, f"Created “{name}”. Add its systems and stakeholders below.")
        return redirect("config_alert_group_edit", pk=group.pk)

    groups = AlertGroup.objects.all()
    return render(request, "reports/config_alert_groups.html", {
        **_config_context("config_alert_groups"),
        "groups": groups,
    })


@never_cache
@login_required
def config_alert_group_edit(request, pk):
    """One group: which systems it covers, who its stakeholders are, and its own alerting
    policy (minimum severity, re-notify behaviour, which metric categories) — all
    admin-configurable, on purpose, so the organization's own idea of "who owns what" and
    "what to page them for" is never hardcoded here."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(AlertGroup, pk=pk)
    systems = _topology_systems()
    users = get_user_model().objects.filter(is_active=True).order_by("username")
    valid_categories = {k for k, _ in AlertGroup.CATEGORY_CHOICES}

    if request.method == "POST":
        if request.POST.get("action") == "delete":
            name = group.name
            group.delete()
            messages.success(request, f"Removed “{name}” and its notification history.")
            return redirect("config_alert_groups")

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
        candidates = [e.strip() for e in re.split(r"[,\n]", raw) if e.strip()]
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
        group.categories = chosen_categories
        group.emails = sorted(set(valid))
        group.min_severity = request.POST.get("min_severity") or group.min_severity
        raw_interval = (request.POST.get("renotify_interval_minutes") or "").strip()
        if raw_interval.isdigit():
            group.renotify_interval_minutes = int(raw_interval) or None   # 0 -> None ("once")
        else:
            group.renotify_interval_minutes = None
        group.active = request.POST.get("active") == "on"
        group.updated_by = request.user
        group.save()
        group.users.set(get_user_model().objects.filter(pk__in=chosen_user_ids))
        messages.success(request, "Saved.")
        return redirect("config_alert_group_edit", pk=group.pk)

    return render(request, "reports/config_alert_group_edit.html", {
        **_config_context("config_alert_groups"),
        "group": group, "systems": systems, "users": users,
        "chosen_users": set(group.users.values_list("pk", flat=True)),
        "category_grid": _category_grid_rows(group),
        "email_list": "\n".join(group.emails or []),
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

    None of the three ever touch AlertFinding — see send_test_alert's own docstring for why."""
    denied = _require_admin(request)
    if denied:
        return denied
    group = get_object_or_404(AlertGroup, pk=pk)
    taction = request.POST.get("taction")

    if taction == "fire_live":
        ok, msg = alerting.send_test_alert(group)
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
            ok, msg = alerting.send_test_email(group, kind=kind, system=tsys, category=tcat, band=tband)
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
    valid_categories = {k for k, _ in AlertGroup.CATEGORY_CHOICES}
    kind = request.GET.get("kind") if request.GET.get("kind") in ("positive", "resolved") else "positive"
    tsys = request.GET.get("tsys") or (group.systems or [""])[0]
    tcat = request.GET.get("tcat") if request.GET.get("tcat") in valid_categories else next(iter(valid_categories), "")
    tband = request.GET.get("tband") if request.GET.get("tband") in ("red", "amber") else "red"
    if not tsys or not tcat:
        return HttpResponse("Add at least one system before previewing.", content_type="text/plain")
    _subject, _text, html_body = alerting.render_test_email(group, kind=kind, system=tsys,
                                                             category=tcat, band=tband)
    return HttpResponse(html_body)


def _folder_watch_systems(prometheus_yml: str) -> set:
    """System names with at least one folder_exporter target -- i.e. systems that can
    actually produce a "Folder over expected size" finding at all (today: just Temenos,
    confirmed live -- the folder_exporter job's only two targets are both `system: Temenos`).

    A static, local-file read of prometheus.yml's OWN folder_exporter job, not a live
    Prometheus call: a watched folder genuinely IS declared in the topology (unlike a backup
    check, which has no config-side declaration at all and is only ever visible from a live
    capture) -- it just lives under a job type gr.load_topology's own System/Component
    grouping deliberately excludes (a folder watch isn't a "component"), so it needs this
    small, targeted parse instead of reusing that function.
    """
    import yaml
    try:
        with open(prometheus_yml, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except Exception:      # noqa: BLE001 -- same degrade-to-"can't tell" stance as the caller;
        return set()       # a broken topology file already surfaces on Configuration > Topology.
    out = set()
    for job in doc.get("scrape_configs", []) or []:
        if job.get("job_name") != "folder_exporter":
            continue
        for sc in job.get("static_configs", []) or []:
            system = (sc.get("labels", {}) or {}).get("system")
            if system:
                out.add(str(system).strip())
    return out


def _category_grid_rows(group) -> list:
    """[{"system":, "cells": [{"category":, "label":, "checked":, "applicable":}, ...]}, ...]
    for the per-system, per-category "Metrics to alert on" table -- one row per system the
    group covers, one column per AlertGroup.CATEGORY_CHOICES entry.

    `applicable` gates whether the template renders a real checkbox at all for that cell (an
    inapplicable one shows a muted em-dash instead, see config_alert_group_edit.html) --
    still just a topology-derived HINT, not a stored restriction: a system added to this group
    later, or a metric that starts reporting later, can make a cell applicable on a future
    visit with no data lost, since `applicable` is recomputed fresh every render rather than
    saved. Two categories carry a genuine static signal, both pure local-file topology reads
    with no live Prometheus call: `service` from generate_report's own SERVICE_CHECKS
    (surfaced on the System.services topology object), and `folder` from
    _folder_watch_systems above. `backup_uncleared` is unconditionally inapplicable
    everywhere -- a placeholder category with no detection built yet (see its own comment on
    AlertGroup.CATEGORY_CHOICES). Every other category (disk/ram/cpu/unreachable, always
    structurally available; backup/untracked, which have no config-side declaration at all --
    entirely metric-driven, only ever visible from a live capture) is always applicable.
    """
    cfg = gr.load_config()
    try:
        all_systems = {s.name: s for s in gr.load_topology(cfg.prometheus_yml, scope="business")}
    except Exception:      # noqa: BLE001 -- topology load errors already surface properly on
        all_systems = {}   # the Topology config screen itself; this grid degrades to
                            # "everything applicable" rather than failing to render at all.
    folder_systems = _folder_watch_systems(cfg.prometheus_yml)

    chosen_by_system = group.categories or {}
    rows = []
    for sys_name in sorted(group.systems or []):
        sysm = all_systems.get(sys_name)
        allowed = set(chosen_by_system.get(sys_name) or []) or {k for k, _ in AlertGroup.CATEGORY_CHOICES}

        def _applicable(value):
            if value == "service":
                return bool(sysm.services) if sysm else True
            if value == "folder":
                return sys_name in folder_systems
            if value == "backup_uncleared":
                return False   # placeholder category, no detection built anywhere yet
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
def system_settings(request):
    """Administrator-only: the Prometheus/Grafana the dashboard fetches from (overrides config.ini)."""
    denied = _require_admin(request)
    if denied:
        return denied
    sc = SystemConfig.get()
    if request.method == "POST":
        form = SystemConfigForm(request.POST, instance=sc)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.updated_by = request.user
            obj.save()
            messages.success(request, "System settings saved — the next capture uses them.")
            return redirect("system_settings")
    else:
        form = SystemConfigForm(instance=sc)
    defaults = gr.load_config()   # the file-based fallbacks, shown for reference
    return render(request, "reports/settings.html", {
        **_config_context("system_settings"),
        "form": form, "sc": sc,
        "config_prom": defaults.prom, "config_grafana": defaults.grafana,
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
            if r in ROLE_NAMES and r not in my_roles and r not in pending:
                RoleRequest.objects.create(user=request.user, role=r)
                created += 1
        if created:
            messages.success(request, f"Requested {created} role(s). An administrator will review it.")
        else:
            messages.error(request, "Select at least one new role to request.")
        return redirect("no_role")

    roles = [{"name": r, "has": r in my_roles, "pending": r in pending} for r in ROLE_NAMES]
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

    pending = RoleRequest.objects.filter(status="pending").select_related("user")
    users = get_user_model().objects.all().prefetch_related("groups").order_by("username")
    me = request.user
    # `deletable` is computed per row so the template never has to re-derive a rule the view
    # already enforces — the two can then not drift into a button that promises what the
    # POST handler refuses.
    user_rows = [{
        "u": u,
        "roles": set(u.groups.values_list("name", flat=True)),
        "is_superuser": u.is_superuser,
        "is_me": u.pk == me.pk,
        "deletable": (u.pk != me.pk
                      and not (u.is_superuser and _other_superusers(u) == 0)),
    } for u in users]
    return render(request, "reports/roles.html", {
        "pending": pending, "user_rows": user_rows, "role_names": ROLE_NAMES,
        "can_manage_accounts": is_superuser(me),
        # Local password resets are meaningless when Keycloak owns the credential.
        "passwords_are_local": not keycloak_mod.enabled(),
    })


def csrf_failure(request, reason="", template_name="reports/csrf_failure.html"):
    """Replaces Django's bare yellow "CSRF verification failed" page (see CSRF_FAILURE_VIEW).

    A rejected token here almost always means the admin's page went stale — the 15-minute
    idle timeout logged them out and the re-login rotated the csrftoken cookie — so the
    useful response is a way back to a fresh report, not a dead end.
    """
    return render(request, template_name, {"reason": reason}, status=403)

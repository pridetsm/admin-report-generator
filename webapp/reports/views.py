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
import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

import generate_report as gr   # to show the config.ini defaults on the settings page

from . import connect, folders
from .directory import search_directory
from .forms import ProfileForm, SystemConfigForm, UserAccountForm
from .models import ReportSubmission, RoleRequest, SystemConfig, UserProfile
from .roles import ROLE_NAMES, is_role_admin, is_system_admin
from .services import (
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
         "mono_hue": _mono_hue(s["name"])}
        for s in list_systems()
    ]
    return render(request, "reports/select.html", {
        "select_systems": select_systems,
        "recent_hours": _RECENT_REPORT_HOURS,
        "total_hosts": sum(s["hosts"] for s in select_systems),
        "recent_count": sum(1 for s in select_systems if s["reported"]),
    })


@login_required
def report(request):
    """The report / annotation screen for the SELECTED systems.

    POST (from the selection screen): record the chosen systems and redirect to GET
    (Post/Redirect/Get, so a browser refresh never re-submits the selection).

    GET: capture a live snapshot scoped to those systems and render the annotation form. A
    plain refresh reuses the cached snapshot (countdown keeps running); ``?fresh=1`` (the
    Refresh action / auto-refresh on expiry) forces a new scoped capture.
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

    force = request.GET.get("fresh") == "1"
    snapshot = None
    token = request.session.get("snapshot_token", "")
    if not force and token:
        snapshot = cache.get(_cache_key(token))       # None if it lapsed

    if snapshot is None:
        token = uuid.uuid4().hex
        try:
            snapshot = capture_snapshot(token, only=set(names))
        except PrometheusUnavailable as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
        if not snapshot.systems:                      # selection no longer in the topology
            messages.error(request, "None of the selected systems were found. Please choose again.")
            request.session.pop("report_systems", None)
            return redirect("report_form")
        cache.set(_cache_key(token), snapshot, timeout=settings.SNAPSHOT_TTL)
        request.session["snapshot_token"] = token

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
    for svm in snapshot.systems:
        svm.connect_hosts = hosts_by_system.get(svm.name, [])

    return render(request, "reports/form.html", {
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
    cache.delete(_cache_key(token))   # one-shot: a fresh form gets a fresh snapshot

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


@login_required
def system_settings(request):
    """Administrator-only: the Prometheus/Grafana the dashboard fetches from (overrides config.ini)."""
    if not is_role_admin(request.user):
        return redirect("report_form")
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
        "form": form, "sc": sc,
        "config_prom": defaults.prom, "config_grafana": defaults.grafana,
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
        return redirect("roles_console")

    pending = RoleRequest.objects.filter(status="pending").select_related("user")
    users = get_user_model().objects.all().prefetch_related("groups").order_by("username")
    user_rows = [{"u": u, "roles": set(u.groups.values_list("name", flat=True))} for u in users]
    return render(request, "reports/roles.html", {
        "pending": pending, "user_rows": user_rows, "role_names": ROLE_NAMES,
    })


def csrf_failure(request, reason="", template_name="reports/csrf_failure.html"):
    """Replaces Django's bare yellow "CSRF verification failed" page (see CSRF_FAILURE_VIEW).

    A rejected token here almost always means the admin's page went stale — the 15-minute
    idle timeout logged them out and the re-login rotated the csrftoken cookie — so the
    useful response is a way back to a fresh report, not a dead end.
    """
    return render(request, template_name, {"reason": reason}, status=403)

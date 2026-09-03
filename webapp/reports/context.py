"""Template context shared by every page:
  * role-admin flag  (drives admin-only nav)
  * the user's report-theme setting  (for the Settings menu)
  * notifications  (pending role requests, for Administrators)
  * back-nav target  (the current page's PARENT in the nav hierarchy)
"""
import os

from django.conf import settings
from django.urls import NoReverseMatch, reverse

from .models import RoleRequest
from .roles import (ROLE_HOME, ROLE_PAGES, active_role, effective_roles, held_roles,
                    is_infra_admin, is_network_admin, is_role_admin, is_system_admin,
                    reports_for)


def _asset_version() -> str:
    """Cache-buster for app.js / app.css: the newest mtime among them.

    Without it the browser keeps serving a stale app.js — the files carry only Last-Modified,
    so an edit can sit unseen behind the cache and, worse, an OLD copy can keep running its
    listeners alongside the new page's, producing changes that cancel each other out.
    Recomputed per request: DEBUG edits take effect on a normal reload, and in production the
    value only moves when a file actually changes.
    """
    newest = 0.0
    for rel in ("js/app.js", "css/app.css"):
        for base in list(getattr(settings, "STATICFILES_DIRS", [])) + [getattr(settings, "STATIC_ROOT", "")]:
            if not base:
                continue
            try:
                newest = max(newest, os.path.getmtime(os.path.join(str(base), rel)))
            except OSError:
                continue
    return str(int(newest))

# The navigation hierarchy: each page -> its parent page. The canvas Back button walks ONE
# level up this tree (child -> parent -> ... -> home), rather than jumping straight home.
# report_form (home) has no parent, so it shows no Back button.
_NAV_PARENT = {
    # The pickers are the top of each estate, and the step above an estate is choosing which
    # one you are working in. Both therefore lead back to Role Select rather than dead-ending.
    "reports": "role_select",
    # Each picker is a step inside running a report, so Back steps out to the report choice
    # rather than all the way to the role choice.
    "report_form": "reports",
    "network_dashboard": "reports",
    "network_sod_select": "reports",
    "infra_form": "reports",
    "os_inventory": "reports",
    "infra_report": "infra_form",
    # Each report sits under the picker that opened it, so Back steps out of the report
    # rather than dead-ending on it. The network report already worked this way; the systems
    # one had no Back at all and relied solely on the "Change systems" button in its header.
    "report": "report_form",
    "connect": "report_form",
    "folder_watch": "report_form",
    "folder_watch_temenos": "folder_watch",
    "network_report": "network_dashboard",
    # The SOD checklist hangs off its own device picker now, the same shape as the live
    # network report: Back steps out to what was picked, not straight to the tile that
    # opened it.
    "network_sod": "network_sod_select",
    "history": "report_form",
    "submission_detail": "history",
    # Administrator's home page — the same role a picker plays for every other estate
    # (report_form / network_dashboard / infra_form), just without a Reports screen in
    # front of it. It has to lead straight to Role Select for the same reason those do:
    # otherwise the ROLE_HOME fallback below resolves "Administrator's home" to this very
    # page and Back points at the screen you're already standing on.
    "roles_console": "role_select",
    "profile": "report_form",
    # Every Configuration screen nests under the hub (see views._CONFIG_TABS) so the drawer's
    # single "Configuration" entry lights up on all of them and Back always steps up to the hub,
    # not straight to the dashboard.
    "configuration": "report_form",
    "config_prometheus": "configuration",
    "grafana_config": "configuration",
    "config_snmp": "configuration",
    "config_topology": "configuration",
    "config_backup_policy": "configuration",
    "config_scripts": "configuration",
    # a definition and its preview hang off the catalogue, so Back walks
    # preview -> definition -> catalogue -> hub one step at a time
    "config_script_edit": "config_scripts",
    "config_script_preview": "config_script_edit",
    "system_settings": "configuration",
    "config_role_scopes": "configuration",
    "config_alert_groups": "configuration",
    "config_alert_group_edit": "config_alert_groups",
    "config_alert_templates": "configuration",
    # Account creation is an ACCOUNT action (superuser-gated, same as password reset/delete),
    # not a Configuration screen -- it hangs off Roles the same way those two already do,
    # regardless of which page's "Add stakeholder" link happened to reach it.
    "config_create_user": "roles_console",
    # The raw editors are how you edit the SAME file the screen above them presents as fields,
    # so they hang off that screen rather than off the hub — Back from raw YAML returns to
    # Prometheus, the way Temenos returns to Folder Watch.
    "prometheus_config": "config_prometheus",
    "config_yaml": "config_prometheus",
    "prometheus_rule_file": "prometheus_config",
}
#: the tree's root — a parent of everything, so never marked as "the branch you are in"
_NAV_ROOT = "report_form"

_NAV_LABEL = {
    "role_select": "Role Select",
    "reports": "Reports",
    "os_inventory": "OS Inventory",
    "report_form": "System Picker",
    "report": "Report",
    "connect": "Connect",
    "folder_watch": "Folder Watch",
    "folder_watch_temenos": "Temenos",
    "network_dashboard": "Network Device Picker",
    "network_sod_select": "SOD Device Picker",
    "network_sod": "SOD Checklist",
    "role_empty": "Home",
    "network_report": "Core Switch",
    "infra_form": "Infrastructure Picker",
    "infra_report": "Infrastructure Admin Report",
    "history": "History",
    "roles_console": "Roles",
    "configuration": "Configuration",
    "config_prometheus": "Prometheus",
    "config_topology": "Topology",
    "config_scripts": "Scripts",
    "config_script_edit": "Script",
    "config_script_preview": "Preview",
    "config_snmp": "SNMP",
    "config_backup_policy": "Backup policy",
    "config_yaml": "Raw YAML",
    "prometheus_config": "Edit raw YAML",
    "grafana_config": "Grafana",
    "system_settings": "Data sources",
    "config_role_scopes": "Role scopes",
    "config_alert_groups": "Alert groups",
    "config_alert_group_edit": "Alert group",
    "config_alert_templates": "Alert templates",
    "config_create_user": "Add stakeholder",
    "profile": "Profile",
}


def user_of(request):
    return getattr(request, "user", None)


def _current_page(request):
    """(url_name, ancestors) for the page being viewed.

    `ancestors` walks _NAV_PARENT upward, so a child screen also lights its parent — on
    Temenos, Folder Watch is shown as the branch you are inside rather than going dark while
    its own child is open.

    The home screen is dropped from that chain. Every page descends from it, so marking it
    would accent the dashboard on ALL of them, and a marker that is nearly always lit stops
    meaning "you are here". Only real branches get the muted accent.
    """
    match = getattr(request, "resolver_match", None)
    name = getattr(match, "url_name", None) if match else None
    ancestors, cur = set(), name
    seen = set()
    while cur in _NAV_PARENT and cur not in seen:
        seen.add(cur)
        cur = _NAV_PARENT[cur]
        ancestors.add(cur)
    ancestors.discard(_NAV_ROOT)
    return name or "", ancestors


def _back_nav(request):
    """(url, label) of the current page's parent, or (None, None) at the root / unknown page.

    One exception to the static tree: while a report is OPEN, pages whose parent is the
    home screen send you back to that report instead.

    Home is the system PICKER, so the plain tree walked an admin who stepped into History
    mid-report out to a screen whose only offer was to start again — and choosing systems
    there clears the snapshot token, discarding the answers they had already typed. The
    report is what they were doing; the picker is how they began it, and Back should
    retrace the first, not the second.
    """
    match = getattr(request, "resolver_match", None)
    name = getattr(match, "url_name", None) if match else None
    parent = _NAV_PARENT.get(name)
    if not parent:
        return None, None
    scope = effective_roles(request)

    # An OPEN REPORT outranks the tree, for whichever estate the admin is working in. Both
    # pickers discard the answers already typed if you re-select on them, so Back must
    # retrace the report rather than the screen it was started from.
    # ...but never when you are ALREADY on that report: the override would hand its own URL
    # back as "Back", so the button pointed at the page you were standing on and did nothing.
    on_the_open_report = name in ("report", "network_report", "infra_report")
    on_a_picker = name in ("report_form", "network_dashboard", "infra_form")
    # A picker's Back steps OUT of the estate, so the open-report override does not apply
    # there — the picker already offers "Continue that report" in its own widget, and having
    # Back do the same thing would leave no way up at all.
    if (parent in ("report_form", "network_dashboard", "infra_form")
            and not on_the_open_report and not on_a_picker):
        if "Network Admin" in scope and request.session.get("network_devices"):
            try:
                return reverse("network_report"), "Report"
            except NoReverseMatch:
                pass
        if "Infrastructure Admin" in scope and request.session.get("infra_report_systems"):
            try:
                return reverse("infra_report"), "Report"
            except NoReverseMatch:
                pass
        # An empty scope means the user holds no catalogue role at all — the pre-picker
        # world. They keep the original behaviour rather than being narrowed out of it.
        if request.session.get("report_systems") and (not scope or "System Admin" in scope):
            try:
                return reverse("report"), "Report"
            except NoReverseMatch:
                pass

    # Never send anyone to a screen their own role does not show. The tree is rooted at the
    # SYSTEMS dashboard, so without this a network admin's Back led to a systems screen that
    # is not in their menu — the tree describing the app, not the role using it.
    # Role Select no longer auto-applies a single role, so Back to it is a real destination
    # for everyone — including a one-role holder, for whom it is the only route to seeing the
    # other roles and requesting one. The old rule suppressed it here because the picker
    # would have bounced them straight back; it doesn't any more.

    if parent == "report_form" and scope and "System Admin" not in scope:
        home = ROLE_HOME.get(active_role(request))
        if home and home != "report_form":
            try:
                return reverse(home), _NAV_LABEL.get(home, "Back")
            except NoReverseMatch:
                pass
        return None, None

    try:
        return reverse(parent), _NAV_LABEL.get(parent, "Back")
    except NoReverseMatch:
        return None, None


def _home_url(request):
    """Where the persistent Home icon (top-left, on every page) should go.

    _back_nav already sends a Network Admin's Back button to network_dashboard instead of
    the systems screen — Home had the same bug and was simply never given the same fix: it
    was hardcoded to report_form, so a Network Admin (freshly granted the role, without
    having been through role_select this session to set an active_role) clicking Home landed
    back on the System Admin dashboard. report_form carries no role gate of its own, so this
    failed silently rather than erroring — it just showed the wrong screen.

    Mirrors role_select's own single-role auto-apply: a scoped active_role wins outright; an
    unscoped user holding exactly one role gets THAT role's home without needing to have
    visited the picker first; everyone else (no role, or several with none chosen) keeps the
    original report_form default.
    """
    role = active_role(request)
    if not role:
        roles = held_roles(getattr(request, "user", None))
        role = roles[0] if len(roles) == 1 else None
    if role:
        home = ROLE_HOME.get(role)
        if home:
            try:
                return reverse(home)
            except NoReverseMatch:
                pass
    return reverse("report_form")


def role_flags(request):
    user = getattr(request, "user", None)
    admin = is_role_admin(user)
    back_url, back_label = _back_nav(request)
    current_page, current_ancestors = _current_page(request)
    # Nav flags are the CAPABILITY and-ed with the ACTIVE ROLE's scope. The capability half
    # is what keeps a link honest; the scope half is what the picker actually does. With no
    # role selected `scope` holds every role the user has, so the menu is the union — exactly
    # what it was before the picker existed.
    scope = effective_roles(request) if user is not None else set()

    def in_scope(role):
        return role in scope

    ctx = {
        "is_role_admin": admin and in_scope("Administrator"),
        # drives the Folder Watch nav group
        "is_system_admin": is_system_admin(user) and in_scope("System Admin"),
        "is_network_admin": is_network_admin(user) and in_scope("Network Admin"),
        "is_infra_admin": is_infra_admin(user) and in_scope("Infrastructure Admin"),
        "active_role": active_role(request) if user is not None else "",
        # Only offer "switch role" to someone who has somewhere to switch to. The canvas
        # Back button is the one-role holder's route to the picker (see _back_nav).
        "can_switch_role": len(held_roles(user)) > 1,
        # drives the single Reports drawer entry — Administrator has none
        "has_reports": bool(reports_for(effective_roles(request)))
                       if user is not None else False,
        "home_url": _home_url(request) if user is not None else reverse("report_form"),
        "notif_count": 0,
        "notifications": [],
        "notif_unseen": False,   # drives the red dot on the hamburger
        "back_url": back_url,    # parent page for the canvas Back button
        "back_label": back_label,
        # drives the accent marker on the drawer entry for the open screen
        "current_page": current_page,
        "current_ancestors": current_ancestors,
        "asset_v": _asset_version(),   # ?v= on app.js/app.css so edits are never served stale
    }
    if user is not None and getattr(user, "is_authenticated", False):
        prof = getattr(user, "profile", None)
        ctx["report_theme"] = prof.default_report_theme if prof else "dark"
        ctx["display_name"] = (user.get_full_name() or user.get_username())

        # The notifications panel is hidden when acting as another role (it is gated on the
        # SCOPED is_role_admin), so the red dot must follow the same rule. A dot that opens a
        # menu with nothing in it reads as a bug, and worse, trains people to ignore it.
        if admin and ctx["is_role_admin"]:
            pending_qs = RoleRequest.objects.filter(status="pending")
            pending = list(pending_qs.select_related("user")[:8])
            ctx["notif_count"] = pending_qs.count()
            ctx["notifications"] = [
                {
                    "who": (r.user.get_full_name() or r.user.get_username()),
                    "role": r.role,
                    "when": r.created_at,
                }
                for r in pending
            ]
            seen_at = getattr(prof, "notifications_seen_at", None) if prof else None
            ctx["notif_unseen"] = (
                pending_qs.filter(created_at__gt=seen_at).exists() if seen_at
                else pending_qs.exists()
            )
    return ctx

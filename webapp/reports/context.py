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
                    is_network_admin, is_role_admin, is_system_admin)


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
    "connect": "report_form",
    "folder_watch": "report_form",
    "folder_watch_temenos": "folder_watch",
    "network_dashboard": "report_form",
    "network_report": "network_dashboard",
    "history": "report_form",
    "submission_detail": "history",
    "roles_console": "report_form",
    "system_settings": "report_form",
    "profile": "report_form",
}
#: the tree's root — a parent of everything, so never marked as "the branch you are in"
_NAV_ROOT = "report_form"

_NAV_LABEL = {
    "report_form": "Dashboard",
    "connect": "Connect",
    "folder_watch": "Folder Watch",
    "folder_watch_temenos": "Temenos",
    "network_dashboard": "Network Analyses",
    "role_empty": "Home",
    "network_report": "Core Switch",
    "history": "History",
    "roles_console": "Roles",
    "system_settings": "Configuration",
    "profile": "Profile",
}


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
    if parent in ("report_form", "network_dashboard"):
        if "Network Admin" in scope and request.session.get("network_devices"):
            try:
                return reverse("network_report"), "Report"
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
        "active_role": active_role(request) if user is not None else "",
        # Only offer "switch role" to someone who actually has somewhere to switch to.
        "can_switch_role": len(held_roles(user)) > 1,
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

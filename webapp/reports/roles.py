"""The role catalogue and helpers. Roles are Django Groups (so they map 1:1 onto Keycloak
realm roles later). A user may hold several. 'Administrator' is the role that manages roles."""

ROLE_NAMES = [
    "System Admin",
    "Network Admin",
    "Gov Systems Admin",
    "Security Admin",
    "Administrator",
]

ADMIN_ROLE = "Administrator"
SYSTEM_ADMIN_ROLE = "System Admin"
NETWORK_ADMIN_ROLE = "Network Admin"

# Which pages each role unlocks. Anything not listed here is COMMON — the report builder,
# history, connect and the personal pages belong to every role, because they are the job
# everyone signed in to do.
#
# This map drives the menu only. It is NOT the security boundary: the per-view checks
# (is_system_admin and friends) remain exactly as they were, and a role you do not hold
# stays unreachable whatever is selected here. Choosing a role narrows a menu you were
# already entitled to see; it never widens one.
ROLE_PAGES = {
    # The System Analyses Dashboard is the systems people's landing screen — its picker
    # lists business systems, which is not a network admin's job.
    SYSTEM_ADMIN_ROLE:   {"report_form", "report", "generate",
                          "folder_watch", "folder_watch_temenos", "folder_watch_data"},
    # ...and the network people get the matching pair: a device picker and the report it
    # opens, so neither role has to walk past the other's screens to reach its own.
    NETWORK_ADMIN_ROLE:  {"network_dashboard", "network_report"},
    ADMIN_ROLE:          {"roles_console", "system_settings", "grafana_config",
                          "prometheus_config", "prometheus_rule_file"},
    # Two roles exist without an estate yet. Deliberately empty rather than borrowing
    # another role's dashboard: a role with nothing in it should look like one.
    "Gov Systems Admin": set(),
    "Security Admin": set(),
}

# Where each role lands once chosen. Without this, picking Network Admin would drop the user
# on a systems screen their own role no longer shows — the picker would be undone by the
# redirect that follows it.
ROLE_HOME = {
    SYSTEM_ADMIN_ROLE:   "report_form",
    NETWORK_ADMIN_ROLE:  "network_dashboard",
    ADMIN_ROLE:          "roles_console",
    # The roles with no estate yet land on a screen that says so, rather than on History or
    # on another role's dashboard.
    "Gov Systems Admin": "role_empty",
    "Security Admin":    "role_empty",
}

# url_name -> the role that owns it, for the "you are in the wrong role for that page" hint.
PAGE_OWNER = {page: role for role, pages in ROLE_PAGES.items() for page in pages}

# Endpoints that are scoped like a page but are not one — polled by JavaScript, never
# navigated to. They belong in ROLE_PAGES (so a scoped session still reaches its own data)
# but must not be counted when the picker offers "adds N screens", which would otherwise
# promise a screen that does not exist.
# "report"/"generate" are steps INSIDE the dashboard, not separate destinations.
NON_SCREEN_PAGES = {"folder_watch_data", "report", "generate"}


def role_screens(role) -> list:
    """The navigable screens a role adds, for display on the picker."""
    return sorted(ROLE_PAGES.get(role, set()) - NON_SCREEN_PAGES)

# What each role is FOR, in the words of the person choosing it. Shown on the picker
# instead of a screen count: "adds 2 screens" describes the software, and someone deciding
# which hat to put on needs to know whose job it is, not how many pages come with it.
ROLE_DESCRIPTIONS = {
    SYSTEM_ADMIN_ROLE:   "For the team running the bank's business systems — server health, "
                         "system reports and the Temenos interface folders.",
    NETWORK_ADMIN_ROLE:  "For the team running the network — switches, links and the traffic "
                         "moving across them.",
    "Gov Systems Admin": "For the administrators of the government systems estate.",
    "Security Admin":    "For the security team.",
    ADMIN_ROLE:          "For whoever manages people's access — who holds which role, and "
                         "the app's own configuration.",
}

SESSION_KEY = "active_role"


def is_role_admin(user) -> bool:
    """Who may review role requests and manage everyone's roles: an Administrator (or a
    Django superuser, which bootstraps the very first Administrator)."""
    return bool(user and user.is_authenticated
                and (user.is_superuser or user.groups.filter(name=ADMIN_ROLE).exists()))


def is_system_admin(user) -> bool:
    """Who may see Folder Watch and everything under it.

    Deliberately NOT Administrator: that role manages people's roles, which is a different
    job from watching the interface folders. A superuser passes because it holds every role
    by definition. Anyone else does not see the nav entry OR reach the URL — hiding a link
    while leaving the page open is not access control.
    """
    return bool(user and user.is_authenticated
                and (user.is_superuser or user.groups.filter(name=SYSTEM_ADMIN_ROLE).exists()))


def is_superuser(user) -> bool:
    """Who may reset another account's password or delete it outright.

    Deliberately NOT a Group like the others. The four roles say what part of the REPORTING
    app you may use; this says you may act on the accounts themselves, which is a different
    kind of power — a mis-set role is an inconvenience, a deleted account is not recoverable
    from this UI. Tying it to Django's is_superuser flag also means it cannot be handed out
    by the very console it guards: granting it takes shell access (`manage.py shell`) or an
    existing superuser in Django's own admin, so the audience stays deliberately small.

    Administrator is not enough on purpose. That role manages who holds which role; this one
    can delete the person.
    """
    return bool(user and user.is_authenticated and user.is_superuser)


def is_network_admin(user) -> bool:
    """Who may see the Network Analyses Dashboard and the device reports under it.

    Network Admin only. An earlier draft also let System Admin in, on the argument that the
    people who deploy the monitoring stack get asked why a panel is empty — but the two roles
    have since been separated deliberately, systems on one side and network on the other, and
    a System Admin holding a menu full of switch screens is exactly what that separation is
    for. A platform admin who genuinely needs the network screens should be granted the
    Network Admin role, which is one tick in the Roles console and leaves a record.

    A superuser passes, holding every role by definition.
    """
    return bool(user and user.is_authenticated
                and (user.is_superuser
                     or user.groups.filter(name=NETWORK_ADMIN_ROLE).exists()))


def held_roles(user) -> list:
    """Every role this user could act as, in the catalogue's own order.

    A superuser is offered all of them. That is not a shortcut: is_superuser already passes
    every gate in the app, so the roles it can act as ARE all of them, and a picker that
    showed a superuser an empty list would be describing a restriction that does not exist.
    """
    if not (user and user.is_authenticated):
        return []
    if user.is_superuser:
        return list(ROLE_NAMES)
    held = set(user.groups.values_list("name", flat=True))
    return [r for r in ROLE_NAMES if r in held]


def active_role(request) -> str:
    """The role currently selected, or "" when none is.

    "" means UNSCOPED — every role the user holds is in effect and the menu shows the union,
    which is how the app behaved before the picker existed. Kept as a real state rather than
    forcing a choice on every request: a bookmark, a deep link, or an API-ish call should not
    dead-end at a chooser.

    A selection that is no longer held (the role was revoked while signed in) is discarded
    rather than trusted.
    """
    chosen = (request.session.get(SESSION_KEY) or "").strip()
    if not chosen:
        return ""
    if chosen not in held_roles(getattr(request, "user", None)):
        request.session.pop(SESSION_KEY, None)
        return ""
    return chosen


def effective_roles(request) -> set:
    """The roles that shape the MENU right now: the selected one, or all held if unscoped."""
    chosen = active_role(request)
    return {chosen} if chosen else set(held_roles(getattr(request, "user", None)))


def page_in_scope(request, url_name: str) -> bool:
    """Whether `url_name` belongs to the active role. Common pages always do."""
    owner = PAGE_OWNER.get(url_name)
    if owner is None:
        return True
    return owner in effective_roles(request)


def roles_without_screens() -> list:
    """Roles that exist but own nothing yet — the ones whose landing screen says so."""
    return [r for r in ROLE_NAMES if not ROLE_PAGES.get(r)]

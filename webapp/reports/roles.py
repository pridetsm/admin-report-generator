"""The role catalogue and helpers. Roles are Django Groups (so they map 1:1 onto Keycloak
realm roles later). A user may hold several. 'Administrator' is the role that manages roles."""

ROLE_NAMES = [
    "System Admin",
    "Network Admin",
    "Infrastructure Admin",
    "Gov Systems Admin",
    "Security Admin",
    "Management",
    "Sub Admin",
    "Administrator",
]

ADMIN_ROLE = "Administrator"
SYSTEM_ADMIN_ROLE = "System Admin"
NETWORK_ADMIN_ROLE = "Network Admin"
INFRA_ADMIN_ROLE = "Infrastructure Admin"
SECURITY_ADMIN_ROLE = "Security Admin"
MANAGEMENT_ROLE = "Management"
# A "weaker admin" (2026-09-18, on request: "create a weaker admin role to give access to
# certain things... someone to access their own alert group... and modify it but not be able
# to remove people") -- unlike every OTHER role above, which only ever picks which screens/
# systems a user sees, Sub Admin can be granted a real (if narrow) EDITING power over specific
# objects it's personally a stakeholder on. See RoleScope.can_edit_own_alert_groups and
# can_edit_alert_group's own docstring below for the actual mechanism -- this constant is just
# the role name, the power itself is opt-in per role on Role Scopes, not hardcoded to this one
# name, so a future second "weaker admin" variant can reuse the same flag.
SUB_ADMIN_ROLE = "Sub Admin"

#: ROLE_NAMES minus the ones that make no sense as a self-service tile on role_select/no_role.
#: Sub Admin has no screens of its own to switch into (see its own comment above) -- it is a
#: capability that rides along on whatever role IS active (can_reach_my_alert_groups checks
#: everything the user HOLDS, not the active selection), so offering it as either "switch to
#: this" or "request this" would just be a tile that does nothing when picked. It is still a
#: real ROLE_NAMES entry -- Role assignments/Role scopes both still manage it normally, only
#: the two self-service picker screens skip it.
SELECTABLE_ROLE_NAMES = [r for r in ROLE_NAMES if r != SUB_ADMIN_ROLE]

# Which pages each role unlocks. Anything not listed here is COMMON — the report builder and
# the personal pages belong to every role, because they are the job everyone signed in to do.
#
# History and Connect are the one exception to "not listed = common": they are listed,
# explicitly, on every estate role (System Admin/Network Admin/Infrastructure Admin/Security
# Admin) rather than left common, so they can be witheld from exactly one role without
# touching the others. Administrator configures the app rather than running reports against
# real systems, so a report-history screen and a "connect to a host" screen are both actions
# for an estate it does not have (2026-09-04) — this is the mechanism, not a security boundary
# of its own (see the next paragraph): scoped to Administrator, neither page appears in the
# drawer and a bookmark to either bounces to Role Select via RoleScopeMiddleware, the same as
# any other role-owned page. Gov Systems Admin also does not carry them, unrelated to this
# change: that role owns nothing at all, deliberately (see its own comment below).
#
# This map drives the menu only. It is NOT the security boundary: the per-view checks
# (is_system_admin and friends) remain exactly as they were, and a role you do not hold
# stays unreachable whatever is selected here. Choosing a role narrows a menu you were
# already entitled to see; it never widens one.
ROLE_PAGES = {
    # The System Analyses Dashboard is the systems people's landing screen — its picker
    # lists business systems, which is not a network admin's job.
    # `generate` is deliberately NOT here. Every estate posts its finished report to that one
    # view — infra_report renders form.html with generate_default=reverse("generate") — so
    # owning it as a System Admin page made RoleScopeMiddleware bounce an Infrastructure Admin
    # to the picker at the moment they hit Generate, instead of downloading. It only bit
    # someone who ALSO held System Admin (the middleware stays silent for a role you do not
    # hold), which is every superuser, so it looked intermittent.
    #
    # Common is also the honest description: the view is purely snapshot-driven, and a
    # snapshot can only exist because a role-gated screen captured it. Nothing is widened by
    # letting the download itself belong to everyone.
    # "management_dashboard_alerts" (2026-10-01, moved off Management -- "remove the dashboard
    # from the management role and add it to all other roles") is listed on this role and the
    # four below it (Network/Infrastructure/Security Admin, Administrator) -- the five estate/
    # admin roles the alert data is actually about -- but deliberately NOT Gov Systems Admin
    # (owns nothing, see that role's own comment below) or Sub Admin (not a role you switch
    # into, see SUB_ADMIN_ROLE's own comment), and no longer Management at all (dropped, not
    # kept read-only). roles.can_view_alert_dashboard is the real gate (the view's own check,
    # same "menu narrows, per-view check is the boundary" relationship every other entry here
    # has) -- this set only drives the drawer link / role-screen count / wrong-role bounce.
    SYSTEM_ADMIN_ROLE:   {"reports", "report_form", "report", "history", "submission_detail",
                          "connect", "folder_watch", "folder_watch_temenos", "folder_watch_data",
                          "automated_reports", "automated_report_type", "automated_report_detail",
                          "automated_report_toggle_distribution", "automated_report_download",
                          "backup_history_report", "management_dashboard_alerts"},
    # ...and the network people get the matching pair: a device picker and the report it
    # opens, so neither role has to walk past the other's screens to reach its own.
    # `network_sod_generate` sits alongside its screen for the same reason `generate` is
    # common to the systems estates: the download is a step INSIDE the SOD screen, not a
    # destination of its own, so it is listed in NON_SCREEN_PAGES below and never counted
    # as a screen the role "adds".
    NETWORK_ADMIN_ROLE:  {"reports", "history",
                          "submission_detail", "connect",
                          "network_sod_select", "network_sod", "network_sod_generate",
                          # Active Directory Report (2026-09-11) is owned by Infrastructure
                          # Admin (see that role's own comment below) but Network Admin gets
                          # view access too -- see roles.REPORTS' own entry for the on-tile
                          # ownership hint.
                          "active_directory_form", "active_directory_report",
                          # Networks Report category -- Network Admin's own estate, four SNMP
                          # reports (2026-09-23, split from the old single combined "Switches &
                          # Routers Report" -- see roles.REPORTS' own comment on why). The
                          # "*_generate" screens are deliberately NOT listed, same as
                          # "infra_generate" above -- a POST-only step inside each report, not
                          # a screen of its own.
                          "core_switches_form", "core_switches_report",
                          "routers_form", "routers_report",
                          "wireless_controller_form", "wireless_controller_report",
                          "access_switches_form", "access_switches_report",
                          "firewalls_form", "firewalls_report",
                          "management_dashboard_alerts"},
    # Infrastructure Admin owns the underlying hardware (hyper-converged clusters, standalone
    # DB hosts) — a third estate alongside business systems and network gear. Its own picker,
    # but its "report" reuses the shared `generate` screen directly (see views.infra_report),
    # so that one page belongs to every estate rather than needing an infra_generate twin.
    #
    # Active Directory (Root/Child Domain Controllers, AD Sync & Authentication) was split
    # out of this combined picker into its own report (2026-09-11, on request: "separate the
    # Active Directory section to be its own report under the infrastructure role... the
    # networks role can also have this") -- Infrastructure Admin is its real owner (same
    # "underlying hardware" framing as HCI/Oracle above), Network Admin gets the same page
    # listed on its own role just above. "active_directory_generate" is deliberately NOT
    # listed here, same as "infra_generate"/"generate" above -- a POST-only step inside the
    # report, not a screen of its own.
    INFRA_ADMIN_ROLE:    {"reports", "infra_form", "infra_report", "history",
                          "submission_detail", "connect",
                          "active_directory_form", "active_directory_report",
                          # Networks Report category (2026-09-22, split into four 2026-09-23)
                          # -- Infrastructure Admin gets VIEW access too, same dual-role
                          # precedent as Active Directory Report just above; real ownership
                          # stays with Network Admin (see roles.REPORTS' own entry).
                          "core_switches_form", "core_switches_report",
                          "routers_form", "routers_report",
                          "wireless_controller_form", "wireless_controller_report",
                          "access_switches_form", "access_switches_report",
                          "firewalls_form", "firewalls_report",
                          "management_dashboard_alerts"},
    ADMIN_ROLE:          {"roles_console", "system_settings", "grafana_config",
                          "prometheus_config", "prometheus_rule_file",
                          "configuration", "config_yaml", "config_role_scopes",
                          "config_prometheus", "config_topology", "config_snmp",
                          "config_backup_policy",
                          "config_scripts", "config_script_edit",
                          "config_script_preview", "management_dashboard_alerts"},
    # Security Admin runs the SAME System Health report as System Admin — same picker, same
    # screens — plus its own OS Inventory. Sharing report_form/report between two roles is why
    # PAGE_OWNER became a set: as a single owner, whichever role lost the tie was bounced off
    # a screen that is genuinely theirs.
    SECURITY_ADMIN_ROLE: {"reports", "report_form", "report", "os_inventory",
                          "history", "submission_detail", "connect",
                          "automated_reports", "automated_report_type", "automated_report_detail",
                          "automated_report_toggle_distribution", "automated_report_download",
                          "management_dashboard_alerts"},
    # One role still has no estate. Deliberately empty rather than borrowing another role's
    # dashboard: a role with nothing in it should look like one.
    "Gov Systems Admin": set(),
    # Three overview screens now, not one (2026-09-16, on request: "save current dashboard as
    # is... move it to a page... called Executive - Full... add another such page and make it
    # the landing page... called Executive - Focused"; 2026-09-19, on request: "save the
    # current variation of the focused dashboard as -analytical instead of -focused" -- Focused
    # was redesigned into a plain 2x2 domain grid and its former content preserved as its own
    # page, Analytical; 2026-10-05, on request: "save the current dashboard as -focus....then
    # this new one call it -pretty and make it the landing page" -- same move again, Pretty's
    # cosmetic Needs Attention Now matrix redesign took over the landing slot, Focus is what
    # "Focused" rendered the moment before that; 2026-10-07, on request: "rename this one to
    # Pretty Analytical then duplicate it and remove the domain for which we have nothing
    # monitored i.e security domain...this duplicate make it landing page" -- Pretty's own
    # prior content, Security domain included, preserved verbatim as a 5th page, Pretty
    # Analytical; Pretty itself keeps the landing slot and its original name/URL, now rendering
    # the Security-free variant). Still no Reports/History access: this role's whole job is
    # these five glance-able pages, not generating or reviewing individual reports the way
    # every estate role above does. See views._focus_style_context/
    # _management_dashboard_context for the context builders these five pages share, and
    # management_dashboard_full.html / management_dashboard_focus.html /
    # management_dashboard_pretty.html / management_dashboard_pretty_analytical.html /
    # management_dashboard_analytical.html for how their own content actually differs.
    MANAGEMENT_ROLE: {"management_dashboard_full", "management_dashboard_focus",
                      "management_dashboard_pretty", "management_dashboard_pretty_analytical",
                      "management_dashboard_analytical"},
}

# Where each role lands once chosen. Without this, picking Network Admin would drop the user
# on a systems screen their own role no longer shows — the picker would be undone by the
# redirect that follows it.
# Every role that has reports now lands on the REPORTS screen rather than straight on a
# picker: which report you are running is the choice that comes before which systems it
# covers, and Security Admin has two to choose between.
ROLE_HOME = {
    SYSTEM_ADMIN_ROLE:   "reports",
    NETWORK_ADMIN_ROLE:  "reports",
    INFRA_ADMIN_ROLE:    "reports",
    SECURITY_ADMIN_ROLE: "reports",
    # Administrator configures the app rather than reporting on it, so it has no Reports
    # screen at all and lands on Configuration -- the console it manages the app FROM.
    # Roles moved to live as a Configuration child (2026-09-04); it is one of the things
    # Configuration now leads to rather than the landing page itself.
    ADMIN_ROLE:          "configuration",
    # The role with no estate yet lands on a screen that says so, rather than on History or
    # on another role's dashboard.
    "Gov Systems Admin": "role_empty",
    # Its own dashboard IS its landing page -- there is nothing else to choose between first.
    # Lands on Pretty specifically (2026-09-16, originally Focused; 2026-10-05, Pretty took
    # over the landing slot -- see MANAGEMENT_ROLE's own comment above): Full is reachable from
    # the drawer for when more detail is wanted, but the day-to-day glance is this page.
    MANAGEMENT_ROLE: "management_dashboard_pretty",
}

# url_name -> the roles that own it, for the "you are in the wrong role for that page" hint.
#
# A SET per page, not one role. The System Health report belongs to System Admin and Security
# Admin alike, and a dict comprehension keyed page->role silently kept whichever role came
# last in ROLE_PAGES — so the other one would have been bounced off a screen that is genuinely
# theirs, with a message naming a role they may not even hold.
PAGE_OWNER: dict = {}
for _role, _pages in ROLE_PAGES.items():
    for _page in _pages:
        PAGE_OWNER.setdefault(_page, set()).add(_role)

# Endpoints that are scoped like a page but are not one — polled by JavaScript, never
# navigated to. They belong in ROLE_PAGES (so a scoped session still reaches its own data)
# but must not be counted when the picker offers "adds N screens", which would otherwise
# promise a screen that does not exist.
# "report"/"generate" are steps INSIDE the dashboard, not separate destinations.
#
# "history"/"connect"/"submission_detail" are here for a different reason: they are genuinely
# common utility screens, listed explicitly on four roles' ROLE_PAGES only so Administrator
# (and Gov Systems Admin, which owns nothing at all) can be excluded from them -- see
# ROLE_PAGES' own comment. Counting them as screens "added" by System Admin (or Network/
# Infrastructure/Security Admin) would misrepresent a shared utility as that role's own estate.
NON_SCREEN_PAGES = {"folder_watch_data", "report", "generate", "network_sod_generate",
                    "history", "connect", "submission_detail",
                    "automated_report_type", "automated_report_detail",
                    "automated_report_toggle_distribution", "automated_report_download"}


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
    INFRA_ADMIN_ROLE:    "For the team running the underlying hardware — hyper-converged "
                         "clusters and standalone database hosts, separate from the "
                         "business systems that run on them.",
    "Gov Systems Admin": "For the administrators of the government systems estate.",
    "Security Admin":    "For the security team.",
    MANAGEMENT_ROLE:     "A single at-a-glance overview of the whole monitoring estate — "
                         "estate health, SWIFT transaction volume, and today's alert activity.",
    SUB_ADMIN_ROLE:      "A narrower admin — can edit the alert group(s) they're personally a "
                         "stakeholder on (My Alert Groups), including adding new stakeholders, "
                         "but never removing one or deleting the group. Nothing else in "
                         "Configuration is reachable with this role alone.",
    ADMIN_ROLE:          "For whoever manages people's access — who holds which role, and "
                         "the app's own configuration.",
}

# The glyph on each picker tile, under static/img/roles/. Paired with the description above:
# the sentence says whose job it is, the glyph lets someone who has read it once find their
# own tile again without re-reading all five.
#
# The mapping is by JOB, not by filename — two of them read the opposite way round to what
# their names suggest:
#   * Administrator gets the person-at-a-laptop-in-a-gear, because that role administers
#     PEOPLE (who holds which role), and a figure at a console is what that looks like.
#   * System Admin gets the connected-node graph, because its estate is the interlinked set
#     of business systems — RTGS, Temenos, CMS and the rest — not a single machine.
# The node graph deliberately does NOT go to Network Admin, whose cloud-over-racks glyph
# already says "network"; two link-diagrams side by side would read as one domain split in
# half rather than as two different jobs.
#
# Infrastructure Admin has no entry here deliberately, rather than reusing Network Admin's
# cloud-over-racks glyph for want of a dedicated one — that would read as the same twin
# problem the node graph was kept off Network Admin to avoid. role_icon() falls back to the
# role's initial letter, which is honest rather than borrowed.
ROLE_ICONS = {
    SYSTEM_ADMIN_ROLE:      "img/roles/neural-networks.png",
    NETWORK_ADMIN_ROLE:     "img/roles/network-infrastructure.png",
    # The platform underneath everything else — HCI cluster and Oracle hosts — so the cloud
    # and gear over a machine, rather than another link diagram: this role owns the tin, not
    # the wires between it (Network Admin) or the systems running on it (System Admin).
    "Infrastructure Admin": "img/roles/cloud-computing.png",
    "Gov Systems Admin":    "img/roles/bank.png",
    "Security Admin":       "img/roles/cyber-security.png",
    ADMIN_ROLE:             "img/roles/system-administration.png",
    # 2026-09-16, on request: "added a png for the management role icon" -- the boss's own
    # read-only overview, so a glyph about the estate reporting back to someone rather than
    # any of the hands-on estate icons above.
    MANAGEMENT_ROLE:        "img/roles/management-feedback.png",
}


# The "work across every role I hold" choice on the picker. Stored as the ABSENCE of a
# selection rather than as a value: unscoped is a state the app already had (see active_role),
# so nothing downstream has to learn a sentinel.
ALL_ROLES = "__all__"
ALL_ROLES_LABEL = "Load all my roles"
ALL_ROLES_DESCRIPTION = ("Every role you hold at once — the menu shows all their screens "
                         "together. Pick a single role instead to narrow it to that estate.")
# Its own glyph (overlapping circles), so the tile is a peer of the role tiles rather than the
# odd one out. Deliberately NOT one of the five role glyphs: borrowing one would make this read
# as that role's twin.
ALL_ROLES_ICON = "img/roles/all-roles.png"


def role_icon(role: str) -> str:
    """The tile glyph for a role, or "" for one added outside this catalogue.

    Empty rather than a stand-in image: the picker falls back to the role's initial, which
    is always correct, instead of labelling an unknown role with someone else's symbol.
    """
    return ROLE_ICONS.get(role, "")


SESSION_KEY = "active_role"


def is_role_admin(user) -> bool:
    """Who may review role requests and manage everyone's roles: an Administrator (or a
    Django superuser, which bootstraps the very first Administrator)."""
    return bool(user and user.is_authenticated
                and (user.is_superuser or user.groups.filter(name=ADMIN_ROLE).exists()))


def can_edit_alert_group(user, group) -> bool:
    """Who may open a specific AlertGroup's own edit screen: a full Administrator always, OR a
    Sub-Admin-shaped user -- holds a role whose RoleScope has can_edit_own_alert_groups=True,
    AND is personally one of THIS group's own stakeholders (group.users). The membership check
    IS the scope for this permission -- no separate system-list needed the way Role Scopes'
    own `systems` field scopes a role's dashboard, since "which alert groups" already means
    "the ones I'm a stakeholder on," not a fixed list an Administrator would have to maintain
    per person.

    Deliberately takes the OBJECT, not just the role, unlike every other is_*/can_* check in
    this module -- those all answer "can this role reach this SCREEN", this answers "can this
    user touch this specific ROW", the actual new permission shape Sub Admin introduces
    (2026-09-18, on request: "create a weaker admin role to give access to certain things...
    someone to access their own alert group any alert group they are a part off and modify
    it")."""
    if is_role_admin(user):
        return True
    if not (user and user.is_authenticated):
        return False
    from .models import RoleScope   # local: models.py doesn't import this module, but keep
                                    # the app-loading-order discipline every other Django
                                    # model import in this file's siblings already follows.
    empowered_roles = set(RoleScope.objects.filter(can_edit_own_alert_groups=True)
                          .values_list("role", flat=True))
    if not empowered_roles or not user.groups.filter(name__in=empowered_roles).exists():
        return False
    return group.users.filter(pk=user.pk).exists()


def can_delete_alert_group(user) -> bool:
    """Deleting a group (and its notification history) stays full-Administrator-only, even for
    a user who can_edit_alert_group() their own group -- Sub Admin's own power is deliberately
    "add, never remove/destroy," and a delete is the most irreversible remove there is."""
    return is_role_admin(user)


def can_reach_my_alert_groups(user) -> bool:
    """Nav-gate for the "My Alert Groups" screen: a full Administrator always (it already
    reaches every group via Configuration > Alerting, but the direct link still works
    sensibly for them too), OR someone who HOLDS a role with can_edit_own_alert_groups=True
    AND is actually a stakeholder on at least one group.

    Deliberately checks everything the user HOLDS (user.groups), not the active role SCOPE
    the way every other nav flag in context.py does (is_system_admin(user) and
    in_scope("System Admin")) -- Sub Admin is not an estate you switch into (see
    SUB_ADMIN_ROLE's own comment: it has no screens of its own and no tile on the role
    picker), it is a capability that rides along on top of whatever role IS active. Scoping
    this to the active role was the original bug (2026-09-18): Innocent Nyama, holding both
    System Admin and Sub Admin, never saw "My Alert Groups" while working as System Admin,
    since Sub Admin dropped out of effective_roles() the moment a specific role was picked.
    can_edit_alert_group() already got this right (it checks user.groups directly) -- this
    now matches it."""
    if is_role_admin(user):
        return True
    if not (user and user.is_authenticated):
        return False
    from .models import RoleScope
    empowered_roles = set(RoleScope.objects.filter(can_edit_own_alert_groups=True)
                          .values_list("role", flat=True))
    if not empowered_roles or not user.groups.filter(name__in=empowered_roles).exists():
        return False
    return user.alert_groups.exists()


def is_system_admin(user) -> bool:
    """Who may see Folder Watch and everything under it.

    Deliberately NOT Administrator: that role manages people's roles, which is a different
    job from watching the interface folders. A superuser passes because it holds every role
    by definition. Anyone else does not see the nav entry OR reach the URL — hiding a link
    while leaving the page open is not access control.
    """
    return bool(user and user.is_authenticated
                and (user.is_superuser or user.groups.filter(name=SYSTEM_ADMIN_ROLE).exists()))


def is_security_admin(user) -> bool:
    """Who may run the OS Inventory report.

    Its own gate rather than reusing is_system_admin: the two roles share the System Health
    report, but the inventory is the security team's, and a shared helper would have silently
    handed it to System Admin the day it was written. A superuser passes, holding every role
    by definition.
    """
    return bool(user and user.is_authenticated
                and (user.is_superuser
                     or user.groups.filter(name=SECURITY_ADMIN_ROLE).exists()))


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


def is_management(user) -> bool:
    """Who may see the Executive Dashboard -- a read-only overview, not an estate role, so it
    gets its own gate rather than folding into any admin role above. A superuser passes,
    holding every role by definition."""
    return bool(user and user.is_authenticated
                and (user.is_superuser or user.groups.filter(name=MANAGEMENT_ROLE).exists()))


def can_view_alert_dashboard(user) -> bool:
    """Who may see Executive - Alerts (2026-10-01, moved off Management entirely -- "remove
    the dashboard from the management role and add it to all other roles"): the five estate/
    admin roles whose own work the alert data is actually about -- System/Network/
    Infrastructure/Security Admin, and Administrator. Deliberately NOT Gov Systems Admin (owns
    nothing, see ROLE_PAGES' own comment on that role) or Sub Admin (not a role you switch
    into, see SUB_ADMIN_ROLE's own comment), and no longer Management (dropped on request, not
    kept as read-only). A superuser passes, holding every role by definition."""
    return bool(user and user.is_authenticated
                and (user.is_superuser
                     or user.groups.filter(name__in=[
                         SYSTEM_ADMIN_ROLE, NETWORK_ADMIN_ROLE, INFRA_ADMIN_ROLE,
                         SECURITY_ADMIN_ROLE, ADMIN_ROLE]).exists()))


def is_infra_admin(user) -> bool:
    """Who may see the Infrastructure Admin picker/report — the hardware estate (HCI
    clusters, standalone DB hosts) that generate_report.load_topology's scope="infra" reads.

    Same shape as is_network_admin: a dedicated role rather than folded into System Admin,
    so a system admin's menu stays full of business systems and does not also fill up with
    the clusters those systems happen to run on. A superuser passes, holding every role by
    definition.
    """
    return bool(user and user.is_authenticated
                and (user.is_superuser
                     or user.groups.filter(name=INFRA_ADMIN_ROLE).exists()))


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
    owners = PAGE_OWNER.get(url_name)
    if not owners:
        return True
    return bool(owners & effective_roles(request))


def roles_without_screens() -> list:
    """Roles that exist but own nothing yet — the ones whose landing screen says so."""
    return [r for r in ROLE_NAMES if not ROLE_PAGES.get(r)]


# ---------------------------------------------------------------------------------------
#  The reports each role can run — the tiles on the Reports screen.
# ---------------------------------------------------------------------------------------
#  A report is a different thing from a role's screen list: System Health is ONE report that
#  two roles run, and Security Admin runs two reports off one estate. Deriving the tiles from
#  ROLE_PAGES would have shown a tile per screen instead, which is how you end up offering
#  "Report" and "System Picker" as if they were two things to choose between.
class ReportOption:
    def __init__(self, key, label, blurb, url_name, roles, icon="", category=""):
        self.key = key
        self.label = label
        self.blurb = blurb
        self.url_name = url_name       # where the tile goes: usually a picker
        self.roles = set(roles)
        # Flat line art, so the template masks it and paints the role-icon gradient through
        # it — otherwise these would read as a different, monochrome set beside the coloured
        # role tiles they deliberately echo.
        self.icon = icon
        # `category` (2026-09-22, for the new "Networks Report" family): "" means ungrouped --
        # renders in the flat list exactly as every report did before this field existed, so
        # no existing ReportOption call site needed to change. A truthy category renders under
        # its own heading on the Reports screen instead (see views.reports' own grouping).
        self.category = category


REPORTS = [
    ReportOption(
        "system_health", "System Health Report",
        "Live health of the business systems — disks, memory, services, backups and "
        "certificates, with your comments against each finding.",
        "report_form", {SYSTEM_ADMIN_ROLE, SECURITY_ADMIN_ROLE},
        "img/reports/system-health.png"),
    # Sits right next to System Health Report on request (2026-10-06, "add a report ... right
    # next to systems admin report"). Reuses System Health's own icon (no bespoke art exists
    # for this one yet) -- same estate, same role, immediately adjacent in this list so the
    # two tiles render next to each other (tile order follows list order, views.reports).
    ReportOption(
        "backup_history", "Backup History Report",
        "A date range in, a day-by-day audit out: was each system's backup reachable and "
        "current, the real filename and timestamp where recorded, and which report — "
        "admin-signed where one exists — that day traces back to.",
        "backup_history_report", {SYSTEM_ADMIN_ROLE},
        "img/reports/system-health.png"),
    # The "Networks Report" category, under the full 39-device SNMPv3 estate (core switch
    # included -- see network.DEVICES' own comment on the 38-device block). Used to be one
    # combined "Switches & Routers Report" tile; split into four narrower ones (2026-09-23,
    # on request: "create a seperate core switches report and a seperate routers report ...
    # this current report rename it to Access switches", then "the one without poe wireless
    # controller... put it in its own report called wireless controller"). All four owned by
    # Network Admin (this is squarely their estate); Infrastructure Admin gets view access
    # too, the same dual-role precedent the Active Directory Report entry below established.
    ReportOption(
        "core_switches", "Core Switches Report",
        "Per-device health for the core switches (HQ, DR, BYO) — CPU, memory, temperature, "
        "PSU/fan, uptime, interface bandwidth and errors, OSPF adjacency, and storage.",
        "core_switches_form", {NETWORK_ADMIN_ROLE, INFRA_ADMIN_ROLE},
        "img/reports/network.png", category="Networks Report"),
    ReportOption(
        "routers", "Routers Report",
        "Per-device health for the router estate — CPU, memory, temperature, PSU/fan, "
        "uptime, interface bandwidth and errors, OSPF adjacency, and storage.",
        "routers_form", {NETWORK_ADMIN_ROLE, INFRA_ADMIN_ROLE},
        "img/reports/network.png", category="Networks Report"),
    ReportOption(
        "wireless_controller", "Wireless Controller Report",
        "Per-device health for the wireless LAN controller — CPU, memory, temperature, "
        "uptime, interface bandwidth and errors, and storage. No PoE/PSU/fan readings — "
        "the WLC is virtual.",
        "wireless_controller_form", {NETWORK_ADMIN_ROLE, INFRA_ADMIN_ROLE},
        "img/reports/network.png", category="Networks Report"),
    ReportOption(
        "access_switches", "Access Switches Report",
        "Per-device health for the access switch estate — CPU, memory, temperature, "
        "PSU/fan, uptime, interface bandwidth and errors, access-point/uplink ports, "
        "OSPF adjacency, and storage, device by device.",
        "access_switches_form", {NETWORK_ADMIN_ROLE, INFRA_ADMIN_ROLE},
        "img/reports/network.png", category="Networks Report"),
    # A fifth Networks Report member (2026-09-29, on request: "add these firewalls to a new
    # firewall report which is part of the network reports group"). None of its four devices
    # answer SNMP yet, on request added anyway ("firewalls not yet on snmp but just add them
    # for now") -- kept from ever showing as a false "unreachable" on the alert poller or the
    # Executive Dashboard's Network tile by DEVICES' own "kind": "Firewall" (see
    # network.firewall_device_keys' own comment); this report's own picker still shows them,
    # honestly, as unreachable until SNMP is fixed on them.
    ReportOption(
        "firewalls", "Firewall Report",
        "Per-device health for the firewall estate — interface bandwidth and errors, "
        "device by device. Not yet on SNMP; devices here may show as unreachable until "
        "that is fixed.",
        "firewalls_form", {NETWORK_ADMIN_ROLE, INFRA_ADMIN_ROLE},
        "img/reports/network.png", category="Networks Report"),
    # The morning checklist, a different thing from the live Network Report above: that one
    # is captured from Prometheus, this one is worked through by hand across the SolarWinds,
    # Cisco WLC, Perfstack and Radware consoles. Both belong to Network Admin, which is why
    # the Reports screen earns its keep for this role too rather than going straight through.
    # Goes to its OWN picker first, same as the Network Report's tile does — the estate is
    # fixed morning to morning, but the picker is still how an engineer excludes a device
    # under maintenance rather than staring at a field for it.
    #
    # The glyph is the Network Admin ROLE icon (img/roles/network-infrastructure.png), not
    # one of the img/reports/ set — none of those four were free, and this one's own name
    # already matches the report's ("Network Infrastructure"). It is visually distinct from
    # the Network Report's tile (a node graph, not a rack-and-cloud), so the two never read
    # as duplicates side by side, and its transparent background masks through .grad-glyph
    # exactly like the others — the accent gradient replaces its own baked-in blue rather
    # than clashing with it.
    ReportOption(
        "network_sod", "Network Infrastructure SOD Report",
        "The start-of-day checklist — core switches, firewalls, internet circuits, WLAN "
        "controllers and the Radware WAF, captured each morning by the on-duty engineer.",
        "network_sod_select", {NETWORK_ADMIN_ROLE}, "img/reports/network-sod.png"),
    ReportOption(
        "infrastructure", "Cluster Health Report",
        "The hardware underneath the systems — hyper-converged clusters and standalone "
        "database hosts.",
        "infra_form", {INFRA_ADMIN_ROLE}, "img/reports/infrastructure.png"),
    # Split out of the Infrastructure Admin Report above (2026-09-11, on request: "separate
    # the Active Directory section to be its own report under the infrastructure role... the
    # networks role can also have this"). Infrastructure Admin is the real owner (Root/Child
    # DCs and AD Sync/PTA are hardware hosts, same estate as HCI/Oracle above); the blurb
    # names that explicitly rather than building a second role-conditional-label mechanism
    # like _automated_reports_label's -- that one exists because ONE feature needs a
    # DIFFERENT NAME per viewing role, which isn't the case here: both roles see the same
    # name, just one of them is a guest. Icon supplied 2026-09-11 (a folder/directory-tree
    # glyph) -- flat art on a transparent background, same as every other file in img/reports/,
    # so .grad-glyph's own CSS mask recolours it through the app's accent gradient exactly like
    # the rest regardless of whatever colour the source PNG itself was drawn in (mask-image
    # reads the alpha channel, not the RGB values).
    ReportOption(
        "active_directory", "Active Directory Report",
        "Domain controllers and AD-adjacent servers — Root/Child DCs, AD Sync & "
        "Authentication, and NTP time-sync health. Owned by Infrastructure Admin; Network "
        "Admin has view access too.",
        "active_directory_form", {INFRA_ADMIN_ROLE, NETWORK_ADMIN_ROLE},
        "img/reports/active-directory.png"),
    ReportOption(
        "os_inventory", "OS Inventory Report",
        "Every monitored host's operating system, patch level against the newest build in "
        "this estate, and vendor support status.",
        "os_inventory", {SECURITY_ADMIN_ROLE}, "img/reports/os-inventory.png"),
    # Automated Reports (New Promt.txt, section 17): six scheduled trend/analysis report
    # types built on top of the same System Health data these two roles already run reports
    # against -- not a new estate, so it shares their existing tile screen rather than
    # getting one of its own.
    ReportOption(
        "automated_reports", "Automated Reports",
        "Scheduled trend analysis — recurring issues, system attention, administrator "
        "comment themes and anomaly history, generated automatically from the same "
        "monitoring data.",
        "automated_reports", {SYSTEM_ADMIN_ROLE, SECURITY_ADMIN_ROLE},
        "img/reports/automated-reports.png"),
]


def reports_for(roles) -> list:
    """The reports available to a set of roles, in catalogue order.

    Takes the EFFECTIVE roles (see effective_roles), so an unscoped session sees everything
    it could run rather than nothing.
    """
    wanted = set(roles or ())
    return [r for r in REPORTS if r.roles & wanted]


def role_has_reports(role: str) -> bool:
    """Whether a single role has any — drives whether Reports appears in its drawer."""
    return any(role in r.roles for r in REPORTS)

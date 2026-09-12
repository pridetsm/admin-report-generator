"""The role catalogue and helpers. Roles are Django Groups (so they map 1:1 onto Keycloak
realm roles later). A user may hold several. 'Administrator' is the role that manages roles."""

ROLE_NAMES = [
    "System Admin",
    "Network Admin",
    "Infrastructure Admin",
    "Gov Systems Admin",
    "Security Admin",
    "Administrator",
]

ADMIN_ROLE = "Administrator"
SYSTEM_ADMIN_ROLE = "System Admin"
NETWORK_ADMIN_ROLE = "Network Admin"
INFRA_ADMIN_ROLE = "Infrastructure Admin"
SECURITY_ADMIN_ROLE = "Security Admin"

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
    SYSTEM_ADMIN_ROLE:   {"reports", "report_form", "report", "history", "submission_detail",
                          "connect", "folder_watch", "folder_watch_temenos", "folder_watch_data",
                          "automated_reports", "automated_report_type", "automated_report_detail",
                          "automated_report_toggle_distribution", "automated_report_download"},
    # ...and the network people get the matching pair: a device picker and the report it
    # opens, so neither role has to walk past the other's screens to reach its own.
    # `network_sod_generate` sits alongside its screen for the same reason `generate` is
    # common to the systems estates: the download is a step INSIDE the SOD screen, not a
    # destination of its own, so it is listed in NON_SCREEN_PAGES below and never counted
    # as a screen the role "adds".
    NETWORK_ADMIN_ROLE:  {"reports", "network_dashboard", "network_report", "history",
                          "submission_detail", "connect",
                          "network_sod_select", "network_sod", "network_sod_generate",
                          # Active Directory Report (2026-09-11) is owned by Infrastructure
                          # Admin (see that role's own comment below) but Network Admin gets
                          # view access too -- see roles.REPORTS' own entry for the on-tile
                          # ownership hint.
                          "active_directory_form", "active_directory_report"},
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
                          "active_directory_form", "active_directory_report"},
    ADMIN_ROLE:          {"roles_console", "system_settings", "grafana_config",
                          "prometheus_config", "prometheus_rule_file",
                          "configuration", "config_yaml", "config_role_scopes",
                          "config_prometheus", "config_topology", "config_snmp",
                          "config_backup_policy",
                          "config_scripts", "config_script_edit",
                          "config_script_preview"},
    # Security Admin runs the SAME System Health report as System Admin — same picker, same
    # screens — plus its own OS Inventory. Sharing report_form/report between two roles is why
    # PAGE_OWNER became a set: as a single owner, whichever role lost the tie was bounced off
    # a screen that is genuinely theirs.
    SECURITY_ADMIN_ROLE: {"reports", "report_form", "report", "os_inventory",
                          "history", "submission_detail", "connect",
                          "automated_reports", "automated_report_type", "automated_report_detail",
                          "automated_report_toggle_distribution", "automated_report_download"},
    # One role still has no estate. Deliberately empty rather than borrowing another role's
    # dashboard: a role with nothing in it should look like one.
    "Gov Systems Admin": set(),
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
    def __init__(self, key, label, blurb, url_name, roles, icon=""):
        self.key = key
        self.label = label
        self.blurb = blurb
        self.url_name = url_name       # where the tile goes: usually a picker
        self.roles = set(roles)
        # Flat line art, so the template masks it and paints the role-icon gradient through
        # it — otherwise these would read as a different, monochrome set beside the coloured
        # role tiles they deliberately echo.
        self.icon = icon


REPORTS = [
    ReportOption(
        "system_health", "System Health Report",
        "Live health of the business systems — disks, memory, services, backups and "
        "certificates, with your comments against each finding.",
        "report_form", {SYSTEM_ADMIN_ROLE, SECURITY_ADMIN_ROLE},
        "img/reports/system-health.png"),
    ReportOption(
        "network", "Network Report",
        "Switches and links — port state, optics, PSU and fan health, and the traffic "
        "moving across them.",
        "network_dashboard", {NETWORK_ADMIN_ROLE}, "img/reports/network.png"),
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
        "infrastructure", "Infrastructure Admin Report",
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

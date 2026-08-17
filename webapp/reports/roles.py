"""The role catalogue and helpers. Roles are Django Groups (so they map 1:1 onto Keycloak
realm roles later). A user may hold several. 'Administrator' is the role that manages roles."""

ROLE_NAMES = [
    "System Admin",
    "Network Admin",
    "Gov Systems Admin",
    "Administrator",
]

ADMIN_ROLE = "Administrator"

# Sentinel stored in the session when the user picks the "Load all my roles" tile: work
# across every role they hold at once, instead of one role's slice of the estate.
ALL_ROLES = "__all__"
ALL_ROLES_LABEL = "All my roles"          # how the active scope reads once chosen ("Working as …")
ALL_ROLES_TILE_LABEL = "Load all my roles"   # how the tile that chooses it reads

# Tile presentation for the role-selection screen: the icon (static/img/roles/) and the
# one-line description of what that role's workspace covers.
ROLE_META = {
    "System Admin": {
        "icon": "roles/system-administration.png",
        "blurb": "Servers, services, disks and backups across the core banking estate.",
    },
    "Network Admin": {
        "icon": "roles/network-infrastructure.png",
        "blurb": "Links, reachability, reverse proxies and web/TLS endpoints.",
    },
    "Gov Systems Admin": {
        "icon": "roles/bank.png",
        "blurb": "Government and national payment systems (RTGS, CSD, CEPECS, CEBAS).",
    },
    "Administrator": {
        "icon": "roles/cyber-security.png",
        "blurb": "Full oversight — plus roles, access requests and system configuration.",
    },
}
ALL_ROLES_META = {
    "icon": "roles/neural-networks.png",
    "blurb": "One combined workspace spanning every system your roles can see.",
}

_FALLBACK_ICON = "roles/system-administration.png"


def role_meta(role: str) -> dict:
    """Icon + blurb for a role tile; falls back gracefully for roles added outside the
    catalogue (e.g. a Keycloak realm role that has no entry here yet)."""
    meta = ROLE_META.get(role)
    if meta:
        return dict(meta, name=role)
    return {"name": role, "icon": _FALLBACK_ICON, "blurb": ""}


def user_roles(user) -> list:
    """The roles this user holds, catalogue order first then any extras, alphabetically."""
    if not (user and getattr(user, "is_authenticated", False)):
        return []
    held = set(user.groups.values_list("name", flat=True))
    known = [r for r in ROLE_NAMES if r in held]
    return known + sorted(held - set(ROLE_NAMES))


def is_role_admin(user) -> bool:
    """Who may review role requests and manage everyone's roles: an Administrator (or a
    Django superuser, which bootstraps the very first Administrator)."""
    return bool(user and user.is_authenticated
                and (user.is_superuser or user.groups.filter(name=ADMIN_ROLE).exists()))

"""Keycloak = the role store (authentication stays with the vault /api/auth endpoint).

Roles are the four names in roles.ROLE_NAMES, held as Keycloak REALM roles. This module talks
to Keycloak's admin REST API (client-credentials service account) to read/write a user's roles;
Django groups are kept as a local MIRROR of those Keycloak roles so the role gate and the
Administrator console keep working off groups.

Config-driven via config.ini [keycloak] (secret from env KEYCLOAK_CLIENT_SECRET). While
enabled=false the whole module no-ops and the app manages roles in Django groups directly.
Standard library only (urllib).
"""
from __future__ import annotations

import configparser
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from django.contrib.auth.models import Group

import generate_report as gr   # for DEFAULT_CONFIG path

from .roles import ROLE_NAMES


@dataclass
class KeycloakConfig:
    enabled: bool = False
    base_url: str = ""          # e.g. https://keycloak.rbz.co.zw
    realm: str = ""
    client_id: str = ""         # a confidential client whose service account can manage users
    client_secret: str = ""
    verify_tls: bool = True
    timeout: int = 8

    @property
    def ready(self) -> bool:
        return bool(self.enabled and self.base_url and self.realm and self.client_id and self.client_secret)


def load_config() -> KeycloakConfig:
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(str(gr.DEFAULT_CONFIG))
    except Exception:      # noqa: BLE001
        return KeycloakConfig()
    if not cp.has_section("keycloak"):
        return KeycloakConfig()
    s = cp["keycloak"]
    return KeycloakConfig(
        enabled=s.getboolean("enabled", fallback=False),
        base_url=s.get("base_url", "").strip().rstrip("/"),
        realm=s.get("realm", "").strip(),
        client_id=s.get("client_id", "").strip(),
        client_secret=os.environ.get("KEYCLOAK_CLIENT_SECRET", s.get("client_secret", "")),
        verify_tls=s.getboolean("verify_tls", fallback=True),
        timeout=s.getint("timeout", fallback=8),
    )


def enabled() -> bool:
    return load_config().ready


# --------------------------------------------------------------------------- HTTP
def _ctx(cfg):
    c = ssl.create_default_context()
    if not cfg.verify_tls:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


def _token(cfg: KeycloakConfig) -> str:
    url = f"{cfg.base_url}/realms/{cfg.realm}/protocol/openid-connect/token"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=cfg.timeout, context=_ctx(cfg)) as r:
        return json.loads(r.read().decode())["access_token"]


def _api(cfg, token, method, path, body=None):
    url = f"{cfg.base_url}/admin/realms/{cfg.realm}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=cfg.timeout, context=_ctx(cfg)) as r:
        txt = r.read().decode()
        return json.loads(txt) if txt.strip() else None


def _user_id(cfg, token, username):
    res = _api(cfg, token, "GET",
               "/users?exact=true&username=" + urllib.parse.quote(username))
    return res[0]["id"] if res else None


# --------------------------------------------------------------------- role reads/writes
def get_user_roles(username: str) -> list:
    """The user's assigned realm roles, restricted to our catalogue. [] on any error/absence."""
    cfg = load_config()
    if not cfg.ready:
        return []
    try:
        token = _token(cfg)
        uid = _user_id(cfg, token, username)
        if not uid:
            return []
        assigned = _api(cfg, token, "GET", f"/users/{uid}/role-mappings/realm") or []
        names = {r["name"] for r in assigned}
        return [r for r in ROLE_NAMES if r in names]
    except Exception:      # noqa: BLE001
        return []


def set_user_roles(username: str, wanted: set) -> bool:
    """Make the user's Keycloak realm roles (within our catalogue) match `wanted`. True on success."""
    cfg = load_config()
    if not cfg.ready:
        return False
    wanted = {r for r in wanted if r in ROLE_NAMES}
    try:
        token = _token(cfg)
        uid = _user_id(cfg, token, username)
        if not uid:
            return False
        current = {r for r in get_user_roles(username)}
        to_add = wanted - current
        to_remove = current - wanted
        for name in to_add:
            rep = _api(cfg, token, "GET", "/roles/" + urllib.parse.quote(name))
            _api(cfg, token, "POST", f"/users/{uid}/role-mappings/realm", [rep])
        for name in to_remove:
            rep = _api(cfg, token, "GET", "/roles/" + urllib.parse.quote(name))
            _api(cfg, token, "DELETE", f"/users/{uid}/role-mappings/realm", [rep])
        return True
    except Exception:      # noqa: BLE001
        return False


def add_user_role(username: str, role: str) -> bool:
    return set_user_roles(username, set(get_user_roles(username)) | {role})


# ------------------------------------------------------------------- local group mirror
def _mirror_to_groups(django_user, role_names):
    """Set the user's Django groups (within our catalogue) to match `role_names`."""
    role_names = {r for r in role_names if r in ROLE_NAMES}
    for r in ROLE_NAMES:
        grp, _ = Group.objects.get_or_create(name=r)
        if r in role_names:
            django_user.groups.add(grp)
        else:
            django_user.groups.remove(grp)


def sync_user_roles(django_user) -> None:
    """Pull the user's roles from Keycloak into their Django groups (the local mirror).
    No-op if Keycloak is disabled; on a Keycloak error it leaves existing groups untouched."""
    cfg = load_config()
    if not cfg.ready:
        return
    try:
        token = _token(cfg)
        uid = _user_id(cfg, token, django_user.get_username())
        if uid is None:
            return   # user not in Keycloak — don't wipe anything
        assigned = _api(cfg, token, "GET", f"/users/{uid}/role-mappings/realm") or []
        names = {r["name"] for r in assigned if r["name"] in ROLE_NAMES}
        _mirror_to_groups(django_user, names)
    except Exception:      # noqa: BLE001
        return

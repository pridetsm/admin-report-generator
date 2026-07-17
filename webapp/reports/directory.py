"""HTTP JSON authentication against the org auth endpoint (e.g. vault.rbz.co.zw:7272).

The endpoint takes a JSON body {"username": ..., "password": ...} and reports whether the
credentials are valid. We add an auth backend that POSTs to it (kept alongside the local
ModelBackend, so the built-in 'admin' still works), provisioning a Django user on success.
Driven by config.ini [auth]; no-ops until enabled=true, so local login is unaffected meanwhile.

Uses only the standard library (urllib) — no extra dependency.

Note: this endpoint AUTHENTICATES only; it is not a directory, so the recipient type-ahead has
no source here and returns []. The curated recipient list remains the source for e-mailing.
"""
from __future__ import annotations

import configparser
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

import generate_report as gr   # for DEFAULT_CONFIG path (send_report/config.ini)


@dataclass
class AuthConfig:
    enabled: bool = False
    url: str = ""
    success_field: str = ""     # JSON key that must be truthy for success (also requires HTTP 2xx)
    email_field: str = ""       # response key carrying the user's e-mail
    name_field: str = ""        # response key carrying a single display name (split into first/last)
    first_name_field: str = ""  # response key for the first name (preferred over name_field)
    last_name_field: str = ""   # response key for the last name
    department_field: str = ""  # response key for the department -> profile.department
    dn_field: str = ""          # response key for the LDAP distinguished name -> profile.distinguished_name
    verify_tls: bool = False
    timeout: int = 8

    @property
    def ready(self) -> bool:
        return bool(self.enabled and self.url)


# account-status flags the endpoint may return; any present-and-false rejects the login
_ACCOUNT_FLAGS = ("enabled", "accountNonLocked", "accountNonExpired", "credentialsNonExpired")


def load_auth_config() -> AuthConfig:
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(str(gr.DEFAULT_CONFIG))
    except Exception:      # noqa: BLE001
        return AuthConfig()
    if not cp.has_section("auth"):
        return AuthConfig()
    s = cp["auth"]
    return AuthConfig(
        enabled=s.getboolean("enabled", fallback=False),
        url=s.get("url", "").strip(),
        success_field=s.get("success_field", "").strip(),
        email_field=s.get("email_field", "").strip(),
        name_field=s.get("name_field", "").strip(),
        first_name_field=s.get("first_name_field", "").strip(),
        last_name_field=s.get("last_name_field", "").strip(),
        department_field=s.get("department_field", "").strip(),
        dn_field=s.get("dn_field", "").strip(),
        verify_tls=s.getboolean("verify_tls", fallback=False),
        timeout=s.getint("timeout", fallback=8),
    )


def _split_name(display: str):
    display = (display or "").strip()
    if not display:
        return "", ""
    parts = display.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


class HttpAuthBackend(BaseBackend):
    """POST {username, password} to the auth endpoint; provision a Django user on success."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password:
            return None
        cfg = load_auth_config()
        if not cfg.ready:
            return None                      # not configured -> let ModelBackend try (local login)

        payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        req = urllib.request.Request(
            cfg.url, data=payload, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        ctx = ssl.create_default_context()
        if not cfg.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        status, body = None, ""
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout, context=ctx) as resp:
                status = getattr(resp, "status", None)
                if status is None:
                    status = resp.getcode()
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:      # 401/403 etc. = bad credentials
            status = exc.code
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:      # noqa: BLE001
                body = ""
        except Exception:          # noqa: BLE001 — network/TLS error = auth failure, fall through
            return None

        try:
            data = json.loads(body) if body else {}
        except Exception:          # noqa: BLE001
            data = {}
        if not isinstance(data, dict):
            data = {}

        ok = status is not None and 200 <= status < 300         # e.g. this API: 200 ok / 403 bad creds
        if cfg.success_field:
            ok = ok and bool(data.get(cfg.success_field))
        if not ok:
            return None
        # honour account-status flags if the endpoint returns them (locked/disabled -> deny)
        if any(flag in data and not data.get(flag) for flag in _ACCOUNT_FLAGS):
            return None

        email = str(data.get(cfg.email_field, "")) if cfg.email_field else ""
        if cfg.first_name_field or cfg.last_name_field:
            first = str(data.get(cfg.first_name_field, "")) if cfg.first_name_field else ""
            last = str(data.get(cfg.last_name_field, "")) if cfg.last_name_field else ""
        else:
            first, last = _split_name(str(data.get(cfg.name_field, "")) if cfg.name_field else "")

        User = get_user_model()
        user, _ = User.objects.get_or_create(
            username=username, defaults={"email": email, "is_active": True})
        changed = False
        for field, value in (("email", email), ("first_name", first), ("last_name", last)):
            if value and getattr(user, field) != value:
                setattr(user, field, value)
                changed = True
        if not user.is_active:
            user.is_active = True
            changed = True
        if changed:
            user.save()

        # fill the extended profile from the directory response (first login / on refresh).
        # use the reverse accessor (a profile is auto-created by signal) so the in-memory user
        # reflects the update immediately.
        from .models import UserProfile
        profile = getattr(user, "profile", None) or UserProfile.objects.create(user=user)
        dept = str(data.get(cfg.department_field, "")) if cfg.department_field else ""
        dn = str(data.get(cfg.dn_field, "")) if cfg.dn_field else ""
        pchanged = False
        if dept and profile.department != dept:
            profile.department, pchanged = dept, True
        if dn and profile.distinguished_name != dn:
            profile.distinguished_name, pchanged = dn, True
        if profile.source != "ldap":
            profile.source, pchanged = "ldap", True
        if pchanged:
            profile.save()

        # roles live in Keycloak (auth is here, role management is there) — mirror them in
        from . import keycloak
        if keycloak.enabled():
            keycloak.sync_user_roles(user)
        return user

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


def search_directory(q: str, limit: int = 10) -> list:
    """The auth endpoint is not a directory, so there's no search source — recipients stay
    curated (admin list). Kept so the type-ahead wiring degrades gracefully to []."""
    return []

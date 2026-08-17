"""Grafana config management: read the live custom.ini for the first-ever edit-screen load,
render a GrafanaConfigRevision back into that same file, and restart the service.

Grafana itself runs as the NSSM-wrapped 'Grafana' Windows service (LocalSystem — same account
this webapp's own service runs as, so no extra permissions are needed to write its config or
restart it). CONFIG_PATH is custom.ini specifically, never defaults.ini (Grafana's own 105KB
shipped reference of every possible setting) — custom.ini is the small file of overrides this
install actually uses.
"""
from __future__ import annotations

import configparser
import subprocess
from pathlib import Path
from typing import Tuple

from . import crypto
from .models import GrafanaConfigRevision

CONFIG_PATH = Path(r"C:\Program Files\GrafanaLabs\grafana\conf\custom.ini")
SERVICE_NAME = "Grafana"


def parse_live_config() -> dict:
    """Read custom.ini off disk into the same field names GrafanaConfigRevision/the form use —
    used ONLY to prefill the edit screen the very first time, before any revision exists yet.
    The password is deliberately left out: the form's password field always starts blank."""
    cp = configparser.ConfigParser()
    cp.read(CONFIG_PATH, encoding="utf-8")
    server = cp["server"] if cp.has_section("server") else {}
    security = cp["security"] if cp.has_section("security") else {}
    smtp = cp["smtp"] if cp.has_section("smtp") else {}
    alerting = cp["alerting"] if cp.has_section("alerting") else {}
    return {
        "protocol": server.get("protocol", "https"),
        "cert_file": server.get("cert_file", ""),
        "cert_key": server.get("cert_key", ""),
        "root_url": server.get("root_url", ""),
        "allow_embedding": security.get("allow_embedding", "true").strip().lower() == "true",
        "smtp_enabled": smtp.get("enabled", "true").strip().lower() == "true",
        "smtp_host": smtp.get("host", ""),
        "smtp_user": smtp.get("user", ""),
        "smtp_skip_verify": smtp.get("skip_verify", "false").strip().lower() == "true",
        "smtp_from_address": smtp.get("from_address", ""),
        "smtp_from_name": smtp.get("from_name", ""),
        "smtp_ehlo_identity": smtp.get("ehlo_identity", ""),
        "smtp_starttls_policy": smtp.get("starttls_policy", "Always"),
        "execute_alerts": alerting.get("execute_alerts", "true").strip().lower() == "true",
    }


def _bool(v: bool) -> str:
    return "true" if v else "false"


def render_custom_ini(rev: GrafanaConfigRevision) -> str:
    """The exact structure/section headers/comments of the live custom.ini this session found
    on disk, with values substituted from `rev`. Not a generic configparser dump (which would
    drop every comment and reflow the file) — a template, so a diff against the previous file
    is just the values that actually changed."""
    password = crypto.decrypt(rev.smtp_password_encrypted)
    return f"""#################################### Server ####################################
[server]
protocol = {rev.protocol}
# same self-signed cert as Prometheus (C:\\metrics\\prometheus\\web-config.yml) — CN=prometheus.internal,
# so browsers will still warn on hostname mismatch until it's swapped for a real cert.
cert_file = {rev.cert_file}
cert_key = {rev.cert_key}
# The public facing domain name used to access grafana from a browser
root_url = {rev.root_url}

#################################### Security ####################################
[security]
# allow browsers to render Grafana in a <frame>, <iframe>, <embed> or <object>
allow_embedding = {_bool(rev.allow_embedding)}

#################################### SMTP / Emailing ####################################
[smtp]
enabled = {_bool(rev.smtp_enabled)}
host = {rev.smtp_host}
user = {rev.smtp_user}
# Note: Grafana does not need the username without domain, include full email
password = {password}
;cert_file =
;key_file =
skip_verify = {_bool(rev.smtp_skip_verify)}
from_address = {rev.smtp_from_address}
from_name = {rev.smtp_from_name}
ehlo_identity = {rev.smtp_ehlo_identity}
starttls_policy = {rev.smtp_starttls_policy}


#################################### Alerts / Notifications ####################################
[alerting]
# Whether Grafana should send notifications
execute_alerts = {_bool(rev.execute_alerts)}"""


def service_status() -> str:
    """'Running' / 'Stopped' / etc, or 'unknown' if the PowerShell call itself fails."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-Service {SERVICE_NAME}).Status"],
            capture_output=True, text=True, timeout=15)
        status = result.stdout.strip()
        return status or "unknown"
    except Exception:
        return "unknown"


def write_and_restart(rev: GrafanaConfigRevision) -> Tuple[bool, str]:
    """Overwrite custom.ini from `rev` and restart the Grafana service. Returns (ok, message)
    — message is either a short success note or the captured PowerShell error, for display."""
    try:
        CONFIG_PATH.write_text(render_custom_ini(rev), encoding="utf-8")
    except OSError as exc:
        return False, f"Could not write {CONFIG_PATH}: {exc}"

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"Restart-Service {SERVICE_NAME}"],
            capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "custom.ini was rewritten, but the restart command timed out after 30s."

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return False, f"custom.ini was rewritten, but the restart failed: {detail}"
    return True, f"custom.ini rewritten and {SERVICE_NAME} restarted."

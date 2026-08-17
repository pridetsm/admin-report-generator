"""Grafana config management: read the live custom.ini for the first-ever edit-screen load,
mask/unmask the SMTP password so it never round-trips to the browser or sits in the DB in the
clear, and restart the service.

Grafana itself runs as the NSSM-wrapped 'Grafana' Windows service (LocalSystem — same account
this webapp's own service runs as, so no extra permissions are needed to write its config or
restart it). CONFIG_PATH is custom.ini specifically, never defaults.ini (Grafana's own 105KB
shipped reference of every possible setting) — custom.ini is the small file of overrides this
install actually uses, and the only file an admin is meant to hand-edit (defaults.ini is
overwritten on every Grafana upgrade, which is why custom.ini exists as a separate overlay).

The edit screen is a raw-text editor of the WHOLE custom.ini (not a field per setting) so any
directive can be added, not just the ones already present today — see PrometheusConfigRevision
for why prometheus.yml took the same approach. The one wrinkle text-editing a file with a
plaintext password in it: the password line is MASKED with a placeholder everywhere except at
the moment the live file is actually written (see mask_password/extract_password/unmask_password
and how views.grafana_config uses them).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional, Tuple

CONFIG_PATH = Path(r"C:\Program Files\GrafanaLabs\grafana\conf\custom.ini")
SERVICE_NAME = "Grafana"

# Never a value someone would plausibly type as a real password — safe to use as a sentinel.
PASSWORD_PLACEHOLDER = "{{KEEP-EXISTING-PASSWORD}}"
_PASSWORD_RE = re.compile(r"^(password\s*=\s*)(.*)$", re.MULTILINE)


def parse_live_config() -> str:
    """The live file's exact RAW text (password included) — callers mask it themselves before
    ever showing it anywhere. Used for the very first edit-screen load, before any revision
    exists yet, and to seed the real password baseline for that first save."""
    return CONFIG_PATH.read_text(encoding="utf-8")


def mask_password(content: str) -> str:
    """Replace the real `password = ...` value with the placeholder. Idempotent — masking an
    already-masked text is a no-op."""
    return _PASSWORD_RE.sub(lambda m: m.group(1) + PASSWORD_PLACEHOLDER, content, count=1)


def extract_password(content: str) -> Optional[str]:
    """The current value of the `password = ...` line (could BE the placeholder — callers check
    for that), or None if the line isn't present at all."""
    m = _PASSWORD_RE.search(content)
    return m.group(2).strip() if m else None


def unmask_password(content: str, real_password: str) -> str:
    """Substitute the placeholder back with the real value. Only ever called at the moment the
    live file is actually written — never for anything stored in the DB or shown in a browser."""
    return content.replace(PASSWORD_PLACEHOLDER, real_password, 1)


def service_status() -> str:
    """'Running' / 'Stopped' / etc, or 'unknown' if the PowerShell call itself fails."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-Service {SERVICE_NAME}).Status"],
            capture_output=True, text=True, timeout=15)
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def write_and_restart(full_content: str) -> Tuple[bool, str]:
    """Overwrite custom.ini with `full_content` (the REAL, unmasked text — callers must unmask
    first) and restart the Grafana service. Returns (ok, message)."""
    try:
        CONFIG_PATH.write_text(full_content, encoding="utf-8")
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

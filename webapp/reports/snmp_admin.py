"""SNMP config management: the `auths:` section of the snmp_exporter's snmp.yml — the
SNMPv3/v2/v1 credential profiles prometheus.yml's snmp/snmp_hardware/snmp_system jobs
reference by name (see `auth: [RBZ_v3]` etc.) — read for the first-ever edit-screen load,
mask/unmask each profile's secret fields so they never round-trip to the browser or sit in
the DB in the clear, and rewrite just that section on Save & Apply.

snmp.yml is NOT edited as a whole file the way custom.ini/prometheus.yml are. Its `modules:`
key is ~2MB of generator output (the file's own first line: "WARNING: This file was
auto-generated using snmp_exporter generator, manual changes will be lost") — round-tripping
it through a YAML load/dump would risk silently reformatting content nothing here should ever
touch, and loading the whole file just to reach a 20-line section takes several seconds even
with the fast C loader. So this module works with the `auths:` block's TEXT directly: it is
always the first top-level key, terminated by the `modules:` key that follows it, and is
sliced out/spliced back in as a string — the other ~2MB is read and rewritten byte-for-byte,
never parsed.

The exporter itself is not deployed as a service yet (Phase 2c) — SERVICE_NAME is what it
will run as once it is, so write_and_restart already does the right thing (write the file,
report the restart failure honestly) the moment that service exists.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, Tuple

import yaml

SNMP_YML_PATH = Path(
    r"C:\Users\Administrator\Desktop\snmp_exporter-0.30.1.windows-amd64\snmp.yml")
SERVICE_NAME = "SNMPExporter"

# Never a value someone would plausibly type as a real secret — safe to use as a sentinel.
PASSWORD_PLACEHOLDER = "{{KEEP-EXISTING-SECRET}}"
# Fields snmp_exporter auth profiles use for a real shared secret: `community` (v1/v2),
# `password` (v3 auth), `priv_password` (v3 privacy). Masked wherever they appear, in any
# profile — never hardcoded to "RBZ_v3" specifically, so a profile added later is covered too.
SECRET_FIELDS = {"community", "password", "priv_password"}

_AUTHS_BLOCK_RE = re.compile(r"^auths:\n.*?(?=^modules:\n)", re.MULTILINE | re.DOTALL)


def _auths_block_match(text: str) -> re.Match:
    m = _AUTHS_BLOCK_RE.search(text)
    if not m:
        raise ValueError(
            f"{SNMP_YML_PATH}: no 'auths:' section found immediately before 'modules:' — "
            "the file may have been regenerated in a different shape.")
    return m


def parse_live_auths() -> Dict[str, dict]:
    """{profile_name: {field: value, ...}} parsed from JUST the live auths: block — the
    ~2MB modules: section is never parsed. Raises ValueError if the block can't be found."""
    text = SNMP_YML_PATH.read_text(encoding="utf-8")
    block = _auths_block_match(text).group(0)
    doc = yaml.safe_load(block) or {}
    return doc.get("auths") or {}


def mask_profiles(profiles: Dict[str, dict]) -> Dict[str, dict]:
    """Replace every SECRET_FIELDS value with the placeholder. Idempotent."""
    return {name: {k: (PASSWORD_PLACEHOLDER if k in SECRET_FIELDS and v else v)
                   for k, v in fields.items()}
            for name, fields in profiles.items()}


def render_auths_block(profiles: Dict[str, dict]) -> str:
    """{profile_name: {...}} (REAL values — callers unmask first) -> the 'auths:\\n...' text
    this module splices into the live file. sort_keys=False keeps a profile's fields in the
    order the admin screen shows them, so a diff of the file reads the way the form does."""
    return yaml.safe_dump({"auths": profiles}, default_flow_style=False, sort_keys=False)


def write_auths_and_restart(profiles: Dict[str, dict]) -> Tuple[bool, str]:
    """Splice REAL (unmasked) `profiles` into the live snmp.yml's auths: block — the
    modules: section and everything else in the file is carried through byte-for-byte —
    and restart the exporter service. Returns (ok, message)."""
    try:
        text = SNMP_YML_PATH.read_text(encoding="utf-8")
        match = _auths_block_match(text)
    except (OSError, ValueError) as exc:
        return False, str(exc)

    new_block = render_auths_block(profiles)
    new_text = text[:match.start()] + new_block + "\n" + text[match.end():]

    try:
        SNMP_YML_PATH.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return False, f"Could not write {SNMP_YML_PATH}: {exc}"

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"Restart-Service {SERVICE_NAME}"],
            capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "snmp.yml was rewritten, but the restart command timed out after 30s."

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return False, f"snmp.yml was rewritten, but the restart failed: {detail}"
    return True, f"snmp.yml rewritten and {SERVICE_NAME} restarted."


def service_status() -> str:
    """'Running' / 'Stopped' / etc, or 'unknown' — including while the exporter has no
    service registered yet, which fails the same PowerShell call the same harmless way."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-Service {SERVICE_NAME}).Status"],
            capture_output=True, text=True, timeout=15)
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"

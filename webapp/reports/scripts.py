"""Generating the agent-side checker scripts from a stored definition.

These are the scripts that run ON the monitored hosts and publish metrics into an exporter's
textfile collector — the other half of the monitoring stack from the report engine, which only
ever reads what they publish. Until now each new host meant forking the previous host's script
by hand ("Fork of check_backup_smarthr.ps1", per check_backup_bsa.ps1's own header), which is
how a fleet of near-identical scripts drifts: one gets a fix, its siblings don't, and nobody
can tell which is which.

So: the definition lives in the database, the script is generated from it, and regenerating is
how you change one. The generated file says so in its header, because a file that can be
overwritten must warn the person reading it.

WHAT IS TEMPLATED, AND WHAT IS NOT
    The template is the PROVEN script with its parameter defaults replaced by tokens. The body
    is copied verbatim from the script running in production — not re-derived, not "improved".
    Generating a subtly different implementation of a check that already works would be the
    worst possible outcome here, because the difference would show up as wrong numbers in a
    report rather than as an error.

METRIC SCHEMA IS FIXED, NOT A PARAMETER
    backup_file / _count / _success / _timestamp_seconds are what generate_report.py scans
    for, and the textfile collector refuses two .prom files in one directory that describe the
    same metric differently. So the names are baked into the template and no field can reach
    them.

SECRETS
    Never stored in the definition's parameters and never written into a file that could be
    committed. A secret lives encrypted in the database (reports/crypto.py, keyed off
    SECRET_KEY) and is substituted into the script only at the moment it is written to the
    configuration folder — which is gitignored, exactly like deploy/. The form shows a
    placeholder rather than the value, so an existing secret survives an edit without ever
    being sent back to the browser.

    No type needs one today; backup checks read a folder. The plumbing is here because the
    first type that does need one (a COB or SWIFT check querying T24) must not be the moment
    anyone reaches for the expedient answer of pasting a password into a parameter.
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Dict, List

from django.conf import settings

from . import crypto

TEMPLATE_DIR = Path(__file__).resolve().parent / "script_templates"

#: Shown instead of a stored secret. Posting it back means "keep what is already there", so a
#: secret can survive an edit without the browser ever having seen it.
SECRET_PLACEHOLDER = "{{KEEP-EXISTING-SECRET}}"

#: Tokens are @@NAME@@ rather than {name}: PowerShell format strings ('{0}' -f ...) and shell
#: ${VAR} expansions are all over these templates, so anything Python's own formatting would
#: touch is a landmine.
_TOKEN_RE = re.compile(r"@@([A-Z0-9_]+)@@")

_SLUG_RE = re.compile(r"[^a-z0-9]+")


class ScriptError(RuntimeError):
    """Raised when a definition cannot be rendered or written."""


def configuration_dir() -> Path:
    """Where generated scripts are written.

    configuration/generated/ at the repo root — the generated/ subfolder specifically, and
    gitignored. configuration/ itself is committed: it holds the reference SAMPLES for every
    file the Configuration menu manages (see its README). Real generated output sitting beside
    those samples, tracked, is exactly what that folder is documented not to contain.

    Overridable for a deployment that keeps generated scripts elsewhere.
    """
    override = getattr(settings, "SCRIPT_OUTPUT_DIR", "")
    if override:
        return Path(override)
    return Path(settings.BASE_DIR).parent / "configuration" / "generated"


def slugify(name: str) -> str:
    """A filename-safe stem. Empty in -> 'script', so a filename is never just an extension."""
    return _SLUG_RE.sub("_", (name or "").strip().lower()).strip("_") or "script"


# ---- field specs ------------------------------------------------------------------------
class Field:
    """One parameter on the definition form.

    `token` is the @@NAME@@ it fills in the template. `secret` fields never round-trip to the
    browser and are stored encrypted; everything else is plain JSON on the definition.
    """

    def __init__(self, name, label, token, default="", hint="", kind="text",
                 choices=(), secret=False):
        self.name = name
        self.label = label
        self.token = token
        self.default = default
        self.hint = hint
        self.kind = kind                  # text | number | select
        self.choices = list(choices)
        self.secret = secret


_WINDOWS_BACKUP_FIELDS = [
    Field("backup_root", "Backup folder", "BACKUP_ROOT", r"E:\BACKUP",
          "The folder the backup job writes into, on the monitored host."),
    Field("file_glob", "Backup filename pattern", "FILE_GLOB", "*_FULL_*.bak",
          "Glob for the files that count. Narrow it so a DIFF or LOG backup isn't mistaken "
          "for the full one."),
    Field("textfile_dir", "Exporter textfile directory", "TEXTFILE_DIR",
          r"C:\Program Files\windows_exporter\textfile_inputs",
          "windows_exporter's textfile_inputs on that host."),
    Field("out_file", "Output .prom filename", "OUT_FILE", "backup_file.prom",
          "One per host. Two scripts writing the same name in one directory overwrite "
          "each other."),
    Field("time_field", "Freshness signal", "TIME_FIELD", "LastWriteTime",
          "LastWriteTime is when the backup finished being written. Use CreationTime only "
          "if the file is copied in by a move that preserves it.",
          kind="select", choices=["LastWriteTime", "CreationTime"]),
    Field("min_bytes", "Minimum size (bytes)", "MIN_BYTES", "1",
          "Rejects 0-byte and partial backups.", kind="number"),
    Field("max_age_days", "Freshness window (days)", "MAX_AGE_DAYS", "1",
          "1 = the usual today-or-yesterday check. Raise it for a system that doesn't back "
          "up daily — BSA runs every third day, so 1 would report NO BACKUP on the two days "
          "in between while the policy is being met.", kind="number"),
]

_LINUX_BACKUP_FIELDS = [
    Field("backup_root", "Backup folder", "BACKUP_ROOT", "/var/backups",
          "The folder the backup job writes into, on the monitored host."),
    Field("file_glob", "Backup filename pattern", "FILE_GLOB", "*.dmp",
          "Glob for the files that count."),
    Field("textfile_dir", "Exporter textfile directory", "TEXTFILE_DIR",
          "/var/lib/node_exporter/textfile_collector",
          "node_exporter's textfile collector directory on that host."),
    Field("out_file", "Output .prom filename", "OUT_FILE", "backup_file.prom",
          "One per host."),
    Field("min_bytes", "Minimum size (bytes)", "MIN_BYTES", "1",
          "Rejects 0-byte and partial backups.", kind="number"),
    Field("max_age_days", "Freshness window (days)", "MAX_AGE_DAYS", "1",
          "1 = the usual today-or-yesterday check.", kind="number"),
    Field("cron_schedule", "Cron schedule", "CRON_SCHEDULE", "30 2 * * *",
          "Five cron fields. Run it AFTER the backup window.", kind="text"),
]


class ScriptType:
    def __init__(self, key, label, blurb, fields, files, available=True, unavailable_note=""):
        self.key = key
        self.label = label
        self.blurb = blurb
        self.fields = fields
        self.files = files                # {template filename: output filename pattern}
        self.available = available
        self.unavailable_note = unavailable_note


SCRIPT_TYPES: Dict[str, ScriptType] = {
    "backup_windows": ScriptType(
        "backup_windows", "Backup checker (Windows)",
        "Reports whether a fresh backup file exists, via windows_exporter's textfile collector.",
        _WINDOWS_BACKUP_FIELDS,
        {"backup_windows.ps1": "check_backup_@@SLUG@@.ps1",
         "backup_windows.bat": "run_@@SLUG@@.bat"},
    ),
    "backup_linux": ScriptType(
        "backup_linux", "Backup checker (Linux)",
        "The same check and the same metrics, via node_exporter's textfile collector.",
        _LINUX_BACKUP_FIELDS,
        # the cron file keeps the bare slug: it lands at /etc/cron.d/<slug>, where an
        # extension or a doubled-up suffix reads as noise in a directory of job names
        {"backup_linux.sh": "check_backup_@@SLUG@@.sh",
         "backup_linux.cron": "@@SLUG@@"},
    ),
    # Registered so the catalogue is honest about what exists, but not generatable: these
    # publish cob_time and swift_transactions_total, and where those numbers come from is
    # specific to how T24/SWIFT are queried here. Guessing would produce a script that runs
    # cleanly and reports the wrong thing, which is worse than one that does not exist.
    "cob": ScriptType(
        "cob", "COB time (Temenos)",
        "Publishes cob_time — when the T24 close-of-business finished.",
        [], {}, available=False,
        unavailable_note="Waiting on the working script from the server, so the generated one "
                         "matches what runs today rather than guessing at the data source.",
    ),
    "swift": ScriptType(
        "swift", "SWIFT transactions",
        "Publishes swift_transactions_total — the SWIFT message count.",
        [], {}, available=False,
        unavailable_note="Waiting on the working script from the server, so the generated one "
                         "matches what runs today rather than guessing at the data source.",
    ),
}


def available_types() -> List[ScriptType]:
    return [t for t in SCRIPT_TYPES.values() if t.available]


def get_type(key: str) -> ScriptType:
    try:
        return SCRIPT_TYPES[key]
    except KeyError:
        raise ScriptError(f"Unknown script type: {key!r}") from None


# ---- rendering --------------------------------------------------------------------------
def _substitute(text: str, values: Dict[str, str]) -> str:
    """Replace every @@TOKEN@@. An unknown token is an error, not a silent empty string —
    a script with a blank path in it would run and quietly monitor nothing."""
    missing: List[str] = []

    def repl(m):
        key = m.group(1)
        if key not in values:
            missing.append(key)
            return m.group(0)
        return str(values[key])

    out = _TOKEN_RE.sub(repl, text)
    if missing:
        raise ScriptError("Template refers to unknown field(s): " + ", ".join(sorted(set(missing))))
    return out


def render(script_type: str, name: str, system: str, params: Dict[str, str],
           secrets: Dict[str, str] | None = None,
           generated_at: datetime.datetime | None = None) -> Dict[str, str]:
    """{output filename: contents} for one definition. Pure — writes nothing."""
    stype = get_type(script_type)
    if not stype.available:
        raise ScriptError(f"{stype.label} cannot be generated yet. {stype.unavailable_note}")

    slug = slugify(name)
    stamp = (generated_at or datetime.datetime.now()).strftime("%d %b %Y %H:%M")
    values: Dict[str, str] = {
        "SLUG": slug,
        "SYSTEM": system or name,
        "GENERATED_AT": stamp,
        "EXPORTER": "windows_exporter" if script_type.endswith("windows") else "node_exporter",
    }
    for field in stype.fields:
        raw = params.get(field.name, field.default)
        values[field.token] = "" if raw is None else str(raw)
    for key, value in (secrets or {}).items():
        values[f"SECRET_{key.upper()}"] = value

    # filenames first: templates refer to each other by name (the .bat launches the .ps1)
    names = {tpl: _substitute(pattern, values) for tpl, pattern in stype.files.items()}
    for tpl, out_name in names.items():
        if tpl.endswith(".ps1"):
            values["PS1_NAME"] = out_name
        elif tpl.endswith(".sh"):
            values["SH_NAME"] = out_name
        elif tpl.endswith(".cron"):
            values["CRON_NAME"] = out_name
    values["LOG_NAME"] = f"{slug}_last.log"

    rendered: Dict[str, str] = {}
    for tpl, out_name in names.items():
        source = (TEMPLATE_DIR / tpl).read_text(encoding="utf-8")
        rendered[out_name] = _substitute(source, dict(values, FILENAME=out_name))
    return rendered


def write(definition) -> List[str]:
    """Render a GeneratedScript and write its files into the configuration folder.

    Returns the paths written. Files land in a per-type sub-folder so a folder listing says
    what each script is for without opening it.
    """
    secrets = definition.secret_values()
    files = render(definition.script_type, definition.name, definition.system,
                   definition.parameters or {}, secrets)
    target = configuration_dir() / definition.script_type
    try:
        target.mkdir(parents=True, exist_ok=True)
        written = []
        for filename, content in files.items():
            path = target / filename
            # newline="" keeps the template's own line endings: a .sh with CRLF fails on
            # Linux with a confusing "bad interpreter" error
            path.write_text(content, encoding="utf-8", newline="")
            written.append(str(path))
    except OSError as exc:
        raise ScriptError(f"Could not write to {target}: {exc}") from exc
    return sorted(written)


# ---- secrets ----------------------------------------------------------------------------
def merge_secrets(existing_encrypted: str, posted: Dict[str, str]) -> str:
    """Encrypt the posted secrets, carrying forward any the form sent back as the placeholder.

    The placeholder is how "leave this one alone" is expressed, so editing a definition never
    requires re-typing a secret and the real value never travels to the browser.
    """
    import json

    current = {}
    if existing_encrypted:
        try:
            current = json.loads(crypto.decrypt(existing_encrypted) or "{}")
        except ValueError:
            current = {}
    for key, value in (posted or {}).items():
        if value == SECRET_PLACEHOLDER:
            continue                      # keep what is already stored
        if value:
            current[key] = value
        else:
            current.pop(key, None)        # cleared
    return crypto.encrypt(json.dumps(current)) if current else ""

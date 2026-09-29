"""folder_exporter status/mapping for its own Configuration screen (2026-09-12, on request:
"I also dont see the folder exporter config in administrator role"). Read-only throughout,
deliberately: this component is a small single-author public GitHub project
(https://github.com/pridetsm/folder_exporter) with no releases, no tags, and no signing --
"latest version" only ever means "whatever's on main right now." Automating clone+build+
install from a web request would mean executing unverified code as a privileged Windows
service, and this same service is what every one of this app's own scheduled jobs (alert/
event pollers, automated reports) runs through -- so this screen only ever detects and
guides (the exact commands to paste into an elevated console), never executes anything
itself. See config_folder_exporter's own docstring for the superuser-only gate this implies.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import yaml

GMS_DIR = Path(r"C:\Users\Administrator\Desktop\admin-report-generator\deploy\gms")
EXE_PATH = GMS_DIR / "folder_exporter.exe"
CONFIG_PATH = GMS_DIR / "folder_exporter.yml"
SERVICE_NAME = "folder_exporter"
REPO_URL = "https://github.com/pridetsm/folder_exporter"

_COMMIT_CACHE: dict = {}
_COMMIT_CACHE_TTL = 300   # 5 minutes -- one admin occasionally loading this screen, no need
                          # for Django's cache framework on this single-process deployment.


def is_installed() -> bool:
    return EXE_PATH.exists()


def installed_version() -> str | None:
    """`folder_exporter.exe --version` output, or None if not installed / the call fails."""
    if not is_installed():
        return None
    try:
        result = subprocess.run([str(EXE_PATH), "--version"],
                                capture_output=True, text=True, timeout=10)
        return (result.stdout or result.stderr).strip() or None
    except Exception:
        return None


def installed_mtime() -> datetime | None:
    if not is_installed():
        return None
    return datetime.fromtimestamp(EXE_PATH.stat().st_mtime)


def service_status() -> str:
    """'running' / 'stopped' / 'not installed' / 'unknown' -- a REAL 3-state check, unlike
    prometheus_admin.service_status()/snmp_admin.service_status(), which both collapse "no
    such service" and "PowerShell itself errored" into the same "unknown" (left as-is there;
    those services are assumed always-installed in this app, so that ambiguity is tolerable
    for them but not here, where "not installed yet" is a real, expected state this screen
    must show correctly)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"try {{ (Get-Service {SERVICE_NAME} -ErrorAction Stop).Status }} "
             f"catch [Microsoft.PowerShell.Commands.ServiceCommandException] "
             f"{{ Write-Output 'NOT_INSTALLED' }}"],
            capture_output=True, text=True, timeout=15)
        out = result.stdout.strip()
        if out == "NOT_INSTALLED":
            return "not installed"
        if out:
            return out.lower()
        return "unknown"
    except Exception:
        return "unknown"


def read_jobs_and_folders() -> tuple[list[dict], list[dict]]:
    """Straight off the live folder_exporter.yml -- this screen never writes it, so there is
    no revision system here the way Prometheus/SNMP/Grafana config have; it just reflects
    whatever's already true on disk right now."""
    if not CONFIG_PATH.exists():
        return [], []
    try:
        doc = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        return [], []
    jobs = [{"name": j.get("name", ""), "cron": j.get("cron", ""),
            "command": j.get("command", "")} for j in (doc.get("jobs") or [])]
    folders = [{"name": f.get("name", ""), "path": f.get("path", ""),
               "scan_interval_seconds": f.get("scan_interval_seconds"),
               "recursive": f.get("recursive")}
              for f in (doc.get("folders") or [])]
    return jobs, folders


def extract_version(text: str) -> str | None:
    m = re.search(r"\d+\.\d+\.\d+", text or "")
    return m.group(0) if m else None


def latest_commit_info() -> dict:
    """The latest commit on the public repo's main branch -- the closest thing to a "latest
    version" this project has, since it publishes no releases or tags. Cached briefly to
    avoid hitting GitHub's unauthenticated rate limit on every page load."""
    now = time.time()
    cached = _COMMIT_CACHE.get("data")
    if cached and now - _COMMIT_CACHE.get("fetched_at", 0) < _COMMIT_CACHE_TTL:
        return cached

    req = urllib.request.Request(
        "https://api.github.com/repos/pridetsm/folder_exporter/commits/main",
        headers={"Accept": "application/vnd.github+json",
                "User-Agent": "rbz-monitoring-console"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        subject = body["commit"]["message"].splitlines()[0]
        data = {
            "ok": True,
            "subject": subject,
            "date": body["commit"]["committer"]["date"],
            "sha": body["sha"][:7],
            "version": extract_version(subject),
        }
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError, OSError) as exc:
        data = {"ok": False, "error": str(exc)}

    _COMMIT_CACHE["data"] = data
    _COMMIT_CACHE["fetched_at"] = now
    return data

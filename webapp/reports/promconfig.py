"""The abstraction layer over ``prometheus.yml``.

The Configuration form is a *view of this file*, not a second copy of it: everything it shows
is read straight from the YAML on every request, and saving writes the YAML back. Nothing is
mirrored into the database, so the file and the form can never drift apart.

Why it exists: hand-editing prometheus.yml is where the syntax errors come from — a mis-indented
target, an unquoted duration, a stray tab. Here the admin fills in labelled fields; this module
does the YAML. Values are validated *before* anything is written, the previous file is copied to
a timestamped ``.bak`` alongside it, and the write itself is atomic (temp file + os.replace), so
a failed save can never leave a half-written config behind.

What is editable vs preserved:
  editable   global intervals · storage retention · rule files · scrape jobs (name, intervals,
             metrics path, scheme) · target groups (targets + labels)
  preserved  anything else a job carries — ``params``, ``relabel_configs``, ``tls_config``,
             ``basic_auth``, … — kept byte-for-byte in meaning and shown read-only in the form,
             so this simplified view can never silently drop a key it doesn't model.

Comments inside the body are NOT preserved (PyYAML round-trips values, not trivia); the leading
header comment block is carried over, and the .bak file holds the original verbatim.
"""
from __future__ import annotations

import datetime
import os
import re
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

import generate_report as gr

# ---- validation ------------------------------------------------------------------------
# Prometheus durations: 30s, 15m, 1h, 30d, and combinations like 1h30m.
_DURATION_RE = re.compile(r"^(\d+(ms|[smhdwy]))+$")
_LABEL_KEY_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_JOB_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_PATH_RE = re.compile(r"^/\S*$")

# The three labels the report engine reads (see prometheus.sample.yml): they get their own
# labelled fields in the form instead of being buried in a generic key/value list. `app` joins
# them because every real target group in this estate carries it.
WELL_KNOWN_LABELS = ("app", "system", "display", "role")

# Job keys this form models directly; everything else on a job is preserved untouched.
_MANAGED_JOB_KEYS = ("job_name", "scrape_interval", "scrape_timeout",
                     "metrics_path", "scheme", "static_configs")

_HEADER_STAMP_RE = re.compile(r"^#\s*Last saved from the Admin Report Generator.*$\n?", re.M)


class ConfigError(RuntimeError):
    """Raised when prometheus.yml cannot be read or parsed."""


# ---- YAML dumping that looks like a hand-written prometheus.yml -------------------------
class _FlowList(list):
    """A list rendered inline — ``targets: ["a:9100", "b:9100"]`` — as Prometheus configs
    conventionally write target lists."""


class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        # indent sequences under their key (`- foo` nested), matching the usual house style
        return super().increase_indent(flow, False)


_Dumper.add_representer(
    _FlowList,
    lambda dumper, data: dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=True),
)


# ---- reading ---------------------------------------------------------------------------
def yaml_path() -> Path:
    """The topology file the report engine itself reads (config.ini ``[prometheus] yml``).

    ``settings.PROMETHEUS_YML`` (env ``PROMETHEUS_YML``) overrides it, for deployments that keep
    the file somewhere else than config.ini says — and for tests, which point it at a fixture.
    """
    from django.conf import settings
    override = getattr(settings, "PROMETHEUS_YML", "")
    return Path(override) if override else Path(gr.load_config().prometheus_yml)


def read_text(path: Optional[Path] = None) -> str:
    p = Path(path or yaml_path())
    try:
        return p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read {p}: {exc}") from exc


def load(path: Optional[Path] = None) -> dict:
    """Parse the file into a plain dict. Raises ConfigError on unreadable/invalid YAML."""
    text = read_text(path)
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{Path(path or yaml_path()).name} is not valid YAML: {exc}") from exc
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise ConfigError("The top level of prometheus.yml must be a mapping.")
    return doc


def header_comment(text: str) -> str:
    """The leading comment/blank block, carried across a save so the file keeps its banner."""
    lines: List[str] = []
    for raw in text.splitlines():
        if raw.strip() == "" or raw.lstrip().startswith("#"):
            lines.append(raw)
        else:
            break
    while lines and lines[-1].strip() == "":
        lines.pop()
    return ("\n".join(lines) + "\n") if lines else ""


def file_info(path: Optional[Path] = None) -> dict:
    p = Path(path or yaml_path())
    try:
        st = p.stat()
        return {"path": str(p), "exists": True, "size": st.st_size,
                "modified": datetime.datetime.fromtimestamp(st.st_mtime)}
    except OSError:
        return {"path": str(p), "exists": False, "size": 0, "modified": None}


def backups(path: Optional[Path] = None, limit: int = 8) -> List[dict]:
    """Recent timestamped backups written by save(), newest first."""
    p = Path(path or yaml_path())
    try:
        found = sorted(p.parent.glob(f"{p.name}.*.bak"), reverse=True)
    except OSError:
        return []
    out = []
    for b in found[:limit]:
        try:
            st = b.stat()
        except OSError:
            continue
        out.append({"name": b.name, "size": st.st_size,
                    "modified": datetime.datetime.fromtimestamp(st.st_mtime)})
    return out


# ---- doc -> form model -----------------------------------------------------------------
def _kv_rows(mapping: Optional[dict]) -> List[dict]:
    return [{"i": i, "key": str(k), "value": "" if v is None else str(v)}
            for i, (k, v) in enumerate((mapping or {}).items())]


def _preserved_yaml(job: dict) -> str:
    """The keys this form doesn't model, re-rendered as YAML for the read-only 'Advanced' box."""
    extra = {k: v for k, v in job.items() if k not in _MANAGED_JOB_KEYS}
    if not extra:
        return ""
    return yaml.dump(extra, Dumper=_Dumper, sort_keys=False, default_flow_style=False,
                     width=100, allow_unicode=True).rstrip()


def to_view(doc: dict) -> dict:
    """Turn the parsed YAML into the flat, labelled structure the template renders."""
    glob = doc.get("global") or {}
    storage = ((doc.get("storage") or {}).get("tsdb") or {})

    jobs = []
    for ji, job in enumerate(doc.get("scrape_configs") or []):
        job = job or {}
        groups = []
        for gi, sc in enumerate(job.get("static_configs") or []):
            sc = sc or {}
            labels = dict(sc.get("labels") or {})
            known = {k: str(labels.pop(k)) for k in WELL_KNOWN_LABELS if labels.get(k) is not None}
            groups.append({
                "i": gi,
                "targets_text": "\n".join(str(t) for t in (sc.get("targets") or [])),
                "targets_count": len(sc.get("targets") or []),
                "known": {k: known.get(k, "") for k in WELL_KNOWN_LABELS},
                "extra": _kv_rows(labels),
            })
        jobs.append({
            "i": ji,
            "job_name": job.get("job_name") or "",
            "scrape_interval": job.get("scrape_interval") or "",
            "scrape_timeout": job.get("scrape_timeout") or "",
            "metrics_path": job.get("metrics_path") or "",
            "scheme": job.get("scheme") or "",
            "groups": groups,
            "targets_count": sum(g["targets_count"] for g in groups),
            "preserved": _preserved_yaml(job),
        })

    return {
        "global": {
            "scrape_interval": glob.get("scrape_interval") or "",
            "evaluation_interval": glob.get("evaluation_interval") or "",
            "scrape_timeout": glob.get("scrape_timeout") or "",
            "external_labels": _kv_rows(glob.get("external_labels")),
        },
        "storage_out_of_order": storage.get("out_of_order_time_window") or "",
        "rule_files_text": "\n".join(str(r) for r in (doc.get("rule_files") or [])),
        "jobs": jobs,
        "systems": system_names(doc),
    }


def view_from_post(post, original: dict) -> dict:
    """The same shape as to_view(), but rebuilt from the RAW submitted fields.

    Used to re-render a form that failed validation, so the admin gets their own typing back —
    complete with the value that was rejected — instead of the file's values reappearing and
    quietly discarding the edit.
    """
    jobs = []
    original_jobs = original.get("scrape_configs") or []
    for (ji,) in _indexes(post, r"^job__(\d+)__name$"):
        groups = []
        for (gi,) in _indexes(post, rf"^sc__{ji}__(\d+)__targets$"):
            prefix = f"sc__{ji}__{gi}"
            targets_text = post.get(f"{prefix}__targets") or ""
            extra = []
            for (n,) in _indexes(post, rf"^{re.escape(prefix)}__xkey__(\d+)$"):
                extra.append({"i": n,
                              "key": post.get(f"{prefix}__xkey__{n}") or "",
                              "value": post.get(f"{prefix}__xval__{n}") or ""})
            groups.append({
                "i": gi,
                "targets_text": targets_text,
                "targets_count": len([t for t in targets_text.splitlines() if t.strip()]),
                "known": {k: (post.get(f"{prefix}__l_{k}") or "") for k in WELL_KNOWN_LABELS},
                "extra": extra,
            })
        base = original_jobs[ji] if ji < len(original_jobs) and original_jobs[ji] else {}
        jobs.append({
            "i": ji,
            "job_name": post.get(f"job__{ji}__name") or "",
            "scrape_interval": post.get(f"job__{ji}__scrape_interval") or "",
            "scrape_timeout": post.get(f"job__{ji}__scrape_timeout") or "",
            "metrics_path": post.get(f"job__{ji}__metrics_path") or "",
            "scheme": post.get(f"job__{ji}__scheme") or "",
            "groups": groups,
            "targets_count": sum(g["targets_count"] for g in groups),
            "preserved": _preserved_yaml(base),
        })

    ext = []
    for (n,) in _indexes(post, r"^g_extlabel_key__(\d+)$"):
        ext.append({"i": n,
                    "key": post.get(f"g_extlabel_key__{n}") or "",
                    "value": post.get(f"g_extlabel_val__{n}") or ""})
    return {
        "global": {
            "scrape_interval": post.get("g_scrape_interval") or "",
            "evaluation_interval": post.get("g_evaluation_interval") or "",
            "scrape_timeout": post.get("g_scrape_timeout") or "",
            "external_labels": ext,
        },
        "storage_out_of_order": post.get("storage_ooo_window") or "",
        "rule_files_text": post.get("rule_files") or "",
        "jobs": jobs,
        "systems": system_names(original),
    }


def system_names(doc: dict) -> List[str]:
    """Every distinct `system` label in the file — the estate the report groups hosts by.
    Uses the engine's own skip-list so the list matches what the dashboard actually shows."""
    names = set()
    for job in doc.get("scrape_configs") or []:
        for sc in (job or {}).get("static_configs") or []:
            system = str(((sc or {}).get("labels") or {}).get("system") or "").strip()
            if system and system.lower() not in gr.SKIP_SYSTEMS:
                names.add(system)
    return sorted(names)


# ---- form model -> doc -----------------------------------------------------------------
def _indexes(post, pattern: str) -> List[int]:
    """The numeric indexes present in POST for a field-name pattern, in order.

    Rows are addressed by their ORIGINAL index (new ones get indexes above the current max),
    so deleting a row in the browser just leaves a gap — no renumbering, no mis-mapping.
    """
    rx = re.compile(pattern)
    found = set()
    for key in post:
        m = rx.match(key)
        if m:
            found.add(tuple(int(g) for g in m.groups()))
    return sorted(found)


def _duration(value: str, field: str, errors: List[str]) -> Optional[str]:
    value = (value or "").strip()
    if not value:
        return None
    if not _DURATION_RE.match(value):
        errors.append(f"{field}: “{value}” is not a Prometheus duration (e.g. 15s, 5m, 1h, 30d).")
        return None
    return value


def _labels_from(post, prefix: str, where: str, errors: List[str]) -> dict:
    labels: dict = {}
    for key in WELL_KNOWN_LABELS:
        val = (post.get(f"{prefix}__l_{key}") or "").strip()
        if val:
            labels[key] = val
    for (n,) in _indexes(post, rf"^{re.escape(prefix)}__xkey__(\d+)$"):
        k = (post.get(f"{prefix}__xkey__{n}") or "").strip()
        v = (post.get(f"{prefix}__xval__{n}") or "").strip()
        if not k and not v:
            continue
        if not _LABEL_KEY_RE.match(k):
            errors.append(f"{where}: “{k}” is not a valid label name "
                          "(letters, digits and underscore; cannot start with a digit).")
            continue
        labels[k] = v
    return labels


def parse_post(post, original: dict) -> Tuple[dict, List[str]]:
    """Rebuild the whole document from the submitted fields.

    Starts from `original` so unmodelled top-level keys (and unmodelled per-job keys) survive
    untouched, then overwrites only what the form owns. Returns (doc, errors); when errors is
    non-empty the caller must NOT write — nothing has been touched at that point.
    """
    errors: List[str] = []
    doc = dict(original)

    # ---- global ----
    glob = dict(original.get("global") or {})
    for field, label in (("scrape_interval", "Scrape interval"),
                         ("evaluation_interval", "Evaluation interval"),
                         ("scrape_timeout", "Scrape timeout")):
        raw = (post.get(f"g_{field}") or "").strip()
        if not raw:                                   # cleared in the form -> drop the key
            glob.pop(field, None)
            continue
        val = _duration(raw, f"Global · {label}", errors)
        if val:
            glob[field] = val
    ext: dict = {}
    for (n,) in _indexes(post, r"^g_extlabel_key__(\d+)$"):
        k = (post.get(f"g_extlabel_key__{n}") or "").strip()
        v = (post.get(f"g_extlabel_val__{n}") or "").strip()
        if not k and not v:
            continue
        if not _LABEL_KEY_RE.match(k):
            errors.append(f"Global · external label “{k}” is not a valid label name.")
            continue
        ext[k] = v
    if ext:
        glob["external_labels"] = ext
    else:
        glob.pop("external_labels", None)
    if glob:
        doc["global"] = glob
    else:
        doc.pop("global", None)

    # ---- storage ----
    ooo = _duration(post.get("storage_ooo_window", ""), "Storage · out-of-order window", errors)
    storage = dict(original.get("storage") or {})
    tsdb = dict(storage.get("tsdb") or {})
    if ooo:
        tsdb["out_of_order_time_window"] = ooo
    else:
        tsdb.pop("out_of_order_time_window", None)
    if tsdb:
        storage["tsdb"] = tsdb
    else:
        storage.pop("tsdb", None)
    if storage:
        doc["storage"] = storage
    else:
        doc.pop("storage", None)

    # ---- rule files ----
    rules = [ln.strip() for ln in (post.get("rule_files", "") or "").splitlines() if ln.strip()]
    if rules:
        doc["rule_files"] = rules
    else:
        doc.pop("rule_files", None)

    # ---- scrape jobs ----
    original_jobs = original.get("scrape_configs") or []
    jobs: List[dict] = []
    seen_names: set = set()
    for (ji,) in _indexes(post, r"^job__(\d+)__name$"):
        base = dict(original_jobs[ji]) if ji < len(original_jobs) and original_jobs[ji] else {}
        name = (post.get(f"job__{ji}__name") or "").strip()
        where = f"Job “{name}”" if name else f"Job #{ji + 1}"
        if not name:
            errors.append(f"{where}: a job name is required.")
        elif not _JOB_NAME_RE.match(name):
            errors.append(f"{where}: job names may use letters, digits and _ . : - only.")
        elif name in seen_names:
            errors.append(f"Job “{name}”: duplicated — every job_name must be unique.")
        seen_names.add(name)

        job: dict = {"job_name": name}
        for field, label in (("scrape_interval", "scrape interval"),
                             ("scrape_timeout", "scrape timeout")):
            val = _duration(post.get(f"job__{ji}__{field}", ""), f"{where} · {label}", errors)
            if val:
                job[field] = val
        mpath = (post.get(f"job__{ji}__metrics_path") or "").strip()
        if mpath:
            if not _PATH_RE.match(mpath):
                errors.append(f"{where}: metrics path must start with “/” (e.g. /metrics).")
            else:
                job["metrics_path"] = mpath
        scheme = (post.get(f"job__{ji}__scheme") or "").strip().lower()
        if scheme:
            if scheme not in ("http", "https"):
                errors.append(f"{where}: scheme must be http or https.")
            else:
                job["scheme"] = scheme

        groups: List[dict] = []
        for (gi,) in _indexes(post, rf"^sc__{ji}__(\d+)__targets$"):
            prefix = f"sc__{ji}__{gi}"
            gwhere = f"{where} · target group #{gi + 1}"
            targets: List[str] = []
            for raw in (post.get(f"{prefix}__targets") or "").splitlines():
                t = raw.strip()
                if not t or t.startswith("#"):
                    continue
                if re.search(r"\s", t):
                    errors.append(f"{gwhere}: “{t}” contains a space — one target per line.")
                    continue
                targets.append(t)
            labels = _labels_from(post, prefix, gwhere, errors)
            if not targets:
                if labels:
                    errors.append(f"{gwhere}: has labels but no targets — add a target or "
                                  "remove the group.")
                continue                      # empty group: silently dropped
            group: dict = {"targets": _FlowList(targets)}
            if labels:
                group["labels"] = labels
            groups.append(group)

        # rebuild in the file's own key order, keeping any unmodelled keys (params,
        # relabel_configs, tls_config, …) exactly where and as they were
        rebuilt: dict = {}
        for key in base:
            if key == "static_configs":
                if groups:                      # every group removed -> drop the empty key
                    rebuilt["static_configs"] = groups
            elif key in _MANAGED_JOB_KEYS:
                if key in job:
                    rebuilt[key] = job[key]
            else:
                rebuilt[key] = base[key]
        for key, val in job.items():
            rebuilt.setdefault(key, val)
        if groups and "static_configs" not in rebuilt:
            rebuilt["static_configs"] = groups
        jobs.append(rebuilt)

    if not jobs:
        errors.append("At least one scrape job is required.")
    doc["scrape_configs"] = jobs
    return doc, errors


# ---- writing ---------------------------------------------------------------------------
def _flow_targets(doc: dict) -> dict:
    """Render every ``targets:`` list inline, the way Prometheus configs are usually written."""
    for job in doc.get("scrape_configs") or []:
        for sc in (job or {}).get("static_configs") or []:
            if isinstance(sc, dict) and isinstance(sc.get("targets"), list):
                sc["targets"] = _FlowList(sc["targets"])
    return doc


def dump(doc: dict, header: str = "", *, author: str = "") -> str:
    """Render the document back to YAML text (stamp + preserved header block + body)."""
    body = yaml.dump(_flow_targets(doc), Dumper=_Dumper, sort_keys=False,
                     default_flow_style=False, width=100, allow_unicode=True)
    head = _HEADER_STAMP_RE.sub("", header or "").rstrip()
    stamp = (f"# Last saved from the Admin Report Generator on "
             f"{datetime.datetime.now():%d %b %Y %H:%M}" + (f" by {author}" if author else ""))
    parts = [stamp] + ([head] if head else []) + [""]
    return "\n".join(parts) + "\n" + body


def save(doc: dict, *, path: Optional[Path] = None, header: str = "",
         author: str = "") -> Optional[str]:
    """Validate, back up, and atomically replace prometheus.yml. Returns the backup filename.

    The rendered text is re-parsed before anything is written, so a document that would not
    load back cannot reach the file.
    """
    p = Path(path or yaml_path())
    text = dump(doc, header, author=author)
    try:
        yaml.safe_load(text)                                   # never write what won't parse
    except yaml.YAMLError as exc:                              # pragma: no cover — defensive
        raise ConfigError(f"Refusing to save — the generated YAML is invalid: {exc}") from exc

    backup_name = None
    if p.exists():
        backup = p.with_name(f"{p.name}.{datetime.datetime.now():%Y%m%d-%H%M%S}.bak")
        shutil.copy2(p, backup)
        backup_name = backup.name

    tmp = p.with_name(f".{p.name}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, p)                                     # atomic on POSIX and Windows
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise ConfigError(f"Could not write {p}: {exc}") from exc
    return backup_name


def reload_prometheus(base_url: str, timeout: int = 8) -> Tuple[bool, str]:
    """Ask the running Prometheus to re-read its config (POST /-/reload).

    Returns (ok, message). A 404/405 means the server was started without
    ``--web.enable-lifecycle``; that is a configuration fact worth reporting plainly rather
    than an error to retry.
    """
    url = (base_url or "").rstrip("/") + "/-/reload"
    req = urllib.request.Request(url, method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if 200 <= resp.status < 300:
                return True, f"Prometheus reloaded its configuration ({url} → {resp.status})."
            return False, f"{url} returned HTTP {resp.status}."
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405):
            return False, ("Prometheus refused the reload — its lifecycle API is disabled. "
                           "Start Prometheus with --web.enable-lifecycle, or reload it on the "
                           "server (systemctl reload prometheus).")
        return False, f"{url} returned HTTP {exc.code}."
    except Exception as exc:                                   # noqa: BLE001 — shown to the admin
        return False, f"Could not reach {url}: {exc}"

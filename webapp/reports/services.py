"""Integration seam between Django and the report engine (send_report/generate_report.py).

The engine is imported once (send_report/ is on sys.path via settings). Everything here is a
thin wrapper: capture a live Prometheus snapshot, compute the per-system flagged items the
form asks about, and render the final .xlsx with the admin's answers baked in.

DATA SOURCE DECISION: metrics come from Prometheus LIVE (the engine's capture()), not from the
MSSQL ingestion DB. A report is a point-in-time snapshot of *now*; the DB is a 5-minute-polled
downstream mirror better suited to the historical/trend features that come later.
"""
from __future__ import annotations

import datetime
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from django.conf import settings

import generate_report as gr   # from send_report/ (on sys.path)


# ---- view models (plain, template-friendly) --------------------------------------------
@dataclass
class FlagVM:
    key: str
    text: str
    band: str          # "red" | "amber"
    category: str      # disk | ram | cpu | service | backup | unreachable | untracked


@dataclass
class SystemVM:
    name: str
    hosts: int
    flags: List[FlagVM]

    @property
    def red(self) -> int:
        return sum(1 for f in self.flags if f.band == "red")

    @property
    def amber(self) -> int:
        return sum(1 for f in self.flags if f.band == "amber")

    @property
    def healthy(self) -> bool:
        return not self.flags


@dataclass
class Snapshot:
    """Everything the form needs, plus the raw engine objects (kept for generation)."""
    token: str
    captured_at: datetime.datetime
    prom_url: str
    systems: List[SystemVM]
    overview: dict = field(default_factory=dict)   # the same summary the email presents
    # raw engine objects, cached so generation reuses the EXACT snapshot the admin reviewed
    _store: object = None
    _systems: object = None
    _cfg: object = None

    @property
    def grafana_url(self) -> str:
        return getattr(self._cfg, "grafana", "") or ""

    @property
    def hosts_count(self) -> int:
        return sum(s.hosts for s in self.systems)

    @property
    def immediate_count(self) -> int:
        return sum(s.red for s in self.systems)

    @property
    def watch_count(self) -> int:
        return sum(s.amber for s in self.systems)


class PrometheusUnavailable(RuntimeError):
    """Raised when the Prometheus endpoint can't be reached for a capture."""


def build_overview(store, systems, cfg) -> dict:
    """The same at-a-glance / two-band KPI summary + alert banners the e-mail presents
    (mirrors mail_report.render_html), computed with the identical engine helpers so the
    numbers match. Returned as plain dicts the template renders natively (theme-aware)."""
    thr = cfg.overview_threshold
    hosts = sum(len(s.components) for s in systems)
    nsvc = sum(len(v) for v in store.services.values()) + len(store.links)
    down = gr.services_down(store)   # PromQL service checks + down web-link probes (see gr.services_down)
    ram_hosts, _ = gr.ram_pressure(store, systems, thr, thr)
    cpu_hosts, _ = gr.cpu_pressure(store, systems, thr, thr)
    dh_hosts, dh_disks, dh_state = gr.disk_high(store, systems, thr, cfg.chip_red)
    nmiss = len(gr.backup_missing(store, systems))
    n_untracked = len(gr.backup_untracked(store, systems))
    n_tracked = len(systems) - n_untracked
    cert_expired, cert_expiring = gr.cert_rollup(store)
    ur = gr.unreachable(store, systems)
    nearfull = gr.disk_near_full(store, systems, cfg.chip_red)
    n_https = sum(1 for u in store.links if u.lower().startswith("https"))
    n_http = sum(1 for u in store.links if u.lower().startswith("http://"))

    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    cob = "N/A" if cob_missing else f"{store.cob / 60:.1f} min"
    swift = f"{store.swift:.0f}" if store.swift is not None else "—"
    bad = lambda n: "good" if not n else "bad"
    warn = lambda n: "good" if not n else "warn"
    web_state = "good" if n_http == 0 else ("bad" if n_http > n_https else "warn")

    glance = [
        {"label": "Systems", "value": len(systems), "state": "info"},
        {"label": "Hosts", "value": hosts, "state": "info"},
        {"label": "Services", "value": nsvc, "state": "info"},
        {"label": "SWIFT txns", "value": swift, "state": "info"},
        {"label": "COB · T24", "value": cob, "state": "info"},
    ]
    immediate = [
        {"label": "Missing backups", "value": nmiss, "state": gr.backup_missing_band(nmiss)},
        {"label": "Unreachable", "value": len(ur), "state": bad(len(ur))},
        {"label": "Services down", "value": down, "state": bad(down)},
        {"label": "Expired certs", "value": len(cert_expired), "state": bad(len(cert_expired))},
    ]
    watch = [
        {"label": "High CPU", "value": cpu_hosts, "sub": "hosts", "state": warn(cpu_hosts)},
        {"label": "High RAM", "value": ram_hosts, "sub": "hosts", "state": warn(ram_hosts)},
        {"label": f"High disk ≥{thr}%", "value": dh_hosts,
         "sub": f"{dh_disks} disk{'' if dh_disks == 1 else 's'}", "state": dh_state},
        {"label": "Web encryption", "value": f"{n_https} | {n_http}", "sub": "https | http", "state": web_state},
        {"label": "Backup tracking", "value": f"{n_tracked} | {n_untracked}",
         "sub": "tracked | untracked", "state": warn(n_untracked)},
    ]

    banners = []
    # LDAP / auth service down — highest priority, listed first (mirrors the xlsx + email).
    ldap_dependents = gr.ldap_alert(store, systems)
    if ldap_dependents:
        banners.append({"band": "red",
                        "head": f"LDAP / auth service down — {len(ldap_dependents)} dependent system(s) affected",
                        "detail": "Users cannot sign in to: " + ", ".join(ldap_dependents)})
    if nearfull:
        byhost: dict = {}
        for s, lbl, mp, used in nearfull:
            byhost.setdefault(f"{s} · {lbl}", []).append(f"{mp} {used:.0f}%")
        banners.append({"band": "red",
                        "head": f"Disk near-full — {len(nearfull)} disk(s) on {len(byhost)} host(s)",
                        "detail": "   ·   ".join(f"{h} ({', '.join(v)})" for h, v in byhost.items())})
    if ur:
        bysys: dict = {}
        for s, lbl, _ in ur:
            bysys.setdefault(s, []).append(lbl)
        banners.append({"band": "red",
                        "head": f"Unreachable — {len(ur)} component(s) across {len(bysys)} system(s)",
                        "detail": "   ·   ".join(f"{s} ({', '.join(l)})" for s, l in bysys.items())})
    if cert_expired or cert_expiring:
        bits = ([f"{len(cert_expired)} expired"] if cert_expired else []) + \
               ([f"{len(cert_expiring)} expiring ≤30d"] if cert_expiring else [])
        banners.append({"band": "red" if cert_expired else "amber",
                        "head": "SSL certs — " + ", ".join(bits),
                        "detail": "   ·   ".join([f"{h} (EXPIRED)" for h, _ in cert_expired] +
                                                 [f"{h} ({cd:.0f}d)" for h, cd in cert_expiring])})
    if cob_missing and datetime.date.today().weekday() != 0:   # 0 = Monday (Sunday: no COB)
        banners.append({"band": "amber",
                        "head": "COB — close-of-business may not have run yesterday",
                        "detail": "COB time is out of range; confirm the T24 COB completed. "
                                  "(On Mondays this is expected and not flagged.)"})

    return {"glance": glance, "immediate": immediate, "watch": watch, "banners": banners}


def list_systems() -> List[dict]:
    """The system name + host count from the topology (prometheus.yml) WITHOUT any live capture.
    This is a plain file read, so the selection screen can be rendered on every landing without
    touching Prometheus — the expensive capture is deferred until the admin actually proceeds."""
    cfg = gr.load_config()
    systems = gr.load_topology(cfg.prometheus_yml)
    return [{"name": s.name, "hosts": len(s.components)} for s in systems]


def _scope_links_to_systems(store, systems) -> None:
    """Web links (blackbox HTTP probes) are captured GLOBALLY by the engine, independent of the
    systems list. When a report is scoped to a subset, drop every link not owned by one of those
    systems (per gr.assign_link — the same attribution the report itself uses) so link-derived
    KPIs (Web encryption, SSL certs) and the report's link sections don't leak other systems'
    endpoints. Mutates store.links in place."""
    store.links = {u: d for u, d in store.links.items()
                   if gr.assign_link(u, systems) is not None}


def capture_snapshot(token: str, only: Optional[set] = None) -> Snapshot:
    """Load config + topology, capture a FRESH set of live metrics from Prometheus, and compute
    the per-system flagged items. `only` (a set of system names) scopes the capture to just those
    systems — so we only pay for what the admin selected. Raises PrometheusUnavailable if the
    endpoint is unreachable."""
    cfg = gr.load_config()
    # runtime overrides an Administrator set in the app (which Prometheus/Grafana to use)
    from .models import SystemConfig
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url
    if sc.grafana_url:
        cfg.grafana = sc.grafana_url
    systems = gr.load_topology(cfg.prometheus_yml)
    if only is not None:
        want = {n for n in only}
        systems = [s for s in systems if s.name in want]
    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    try:
        prom.ping()
    except Exception as exc:                              # noqa: BLE001 — surfaced to the view
        raise PrometheusUnavailable(f"{cfg.prom}: {exc}") from exc
    store = gr.capture(prom, systems, cfg)
    if only is not None:
        _scope_links_to_systems(store, systems)

    svms: List[SystemVM] = []
    for sysm in systems:
        flags = [FlagVM(f.key, f.text, f.band, f.category)
                 for f in gr.flagged_for_system(store, sysm, cfg)]
        svms.append(SystemVM(name=sysm.name, hosts=len(sysm.components), flags=flags))

    return Snapshot(
        token=token,
        captured_at=datetime.datetime.now(),
        prom_url=cfg.prom,
        systems=svms,
        overview=build_overview(store, systems, cfg),
        _store=store,
        _systems=systems,
        _cfg=cfg,
    )


def build_report(snapshot: Snapshot, *, theme: str, author: str,
                 annotations: Dict[str, dict], summary_comment: str) -> bytes:
    """Render the .xlsx (chosen theme) from the snapshot with the admin's inputs injected.
    The snapshot is already scoped to the admin's selected systems (see capture_snapshot)."""
    return gr.build_report_bytes(
        snapshot._store, snapshot._systems, snapshot._cfg,
        theme=theme if theme in gr.PALETTES else "dark",
        author=author,
        annotations=annotations,
        summary_comment=summary_comment,
    )


def default_report_filename(theme: str, when: Optional[datetime.datetime] = None) -> str:
    when = when or datetime.datetime.now()
    return f"System Admin Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


class EmailNotConfigured(RuntimeError):
    """Raised when SMTP settings are missing/incomplete in config.ini."""


def email_report(snapshot: Snapshot, data: bytes, *, recipients: List[str],
                 author: str, filename: str) -> str:
    """E-mail the generated report (attached) with the standard HTML summary, stamped with
    the author as the sender. Reuses mail_report (SMTP + templating). Returns the subject.
    Raises EmailNotConfigured / the underlying SMTP error on failure."""
    import os
    import pathlib
    import tempfile

    import mail_report as mr   # send_report/mail_report.py (on sys.path)

    cfg = snapshot._cfg
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        raise EmailNotConfigured("No SMTP host configured in send_report/config.ini ([smtp]).")

    mailcfg["grafana"] = cfg.grafana
    mailcfg["prom"] = snapshot.prom_url
    mailcfg["elevated"] = cfg.overview_threshold
    mailcfg["author"] = author                       # shown in the e-mail header
    if author:
        mailcfg["from_name"] = f"{author} · System Admin Report"   # who it's from, in the inbox

    unreach, crit, warn, nodata = mr.analyse(snapshot._store, snapshot._systems, cfg)
    html_body = mr.render_html(snapshot._store, snapshot._systems, unreach, crit, warn, nodata, mailcfg)
    text_body = mr.plain_summary(unreach, crit, warn, nodata)
    sev = (f"{len(unreach)} unreachable" if unreach else
           (f"{len(crit)} critical" if crit else (f"{len(warn)} warnings" if warn else "all healthy")))
    subject = f"System Admin Report — {datetime.date.today():%d %b %Y} — {sev}"
    if author:
        subject += f" — by {author}"

    # write the attachment to a temp dir with its proper name (mr.send_email uses path.name)
    tmpdir = tempfile.mkdtemp(prefix="report_")
    path = pathlib.Path(tmpdir) / filename
    try:
        path.write_bytes(data)
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, path)
    finally:
        try:
            path.unlink()
            os.rmdir(tmpdir)
        except OSError:
            pass
    return subject


def _config_recipient_options() -> List[dict]:
    """Bootstrap fallback: recipients from config.ini [recipients] (to = defaults)."""
    import configparser
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(str(gr.DEFAULT_CONFIG))
    except Exception:      # noqa: BLE001
        return []
    if not cp.has_section("recipients"):
        return []
    to = [e.strip() for e in cp["recipients"].get("to", "").split(",") if e.strip()]
    choices = [e.strip() for e in cp["recipients"].get("choices", "").split(",") if e.strip()]
    seen: dict = {}
    for e in to:
        seen[e] = True
    for e in choices:
        seen.setdefault(e, False)
    return [{"email": e, "label": e, "checked": chk} for e, chk in seen.items()]


def recipient_options() -> List[dict]:
    """Selectable recipients for the send dialog as [{email, label, checked}, ...].
       Curated in the DB (admin: Reports › Email recipients); falls back to config.ini
       while the DB list is empty, so it works before anyone curates it."""
    from .models import EmailRecipient
    rows = list(EmailRecipient.objects.filter(active=True))
    if rows:
        return [{"email": r.email, "label": r.label, "checked": r.default_selected} for r in rows]
    return _config_recipient_options()


def default_recipients() -> str:
    """Comma-separated pre-selected recipients (DB defaults, or config.ini fallback)."""
    from .models import EmailRecipient
    if EmailRecipient.objects.filter(active=True).exists():
        return ", ".join(EmailRecipient.objects.filter(active=True, default_selected=True)
                         .values_list("email", flat=True))
    try:
        import mail_report as mr
        return ", ".join(mr.load_mail_config(str(gr.DEFAULT_CONFIG)).get("recipients", []))
    except Exception:      # noqa: BLE001 — config optional; empty is fine
        return ""

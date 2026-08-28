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
from typing import Dict, List, Optional, Tuple

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
    # auto-captured, recurring explanations (e.g. a policy-expected backup gap) — pre-filled
    # into the comment box (see notes_text) so the admin isn't re-typing the same explanation
    # every report; never a Fix/Resolved item like .flags.
    notes: List[str] = field(default_factory=list)

    @property
    def red(self) -> int:
        return sum(1 for f in self.flags if f.band == "red")

    @property
    def amber(self) -> int:
        return sum(1 for f in self.flags if f.band == "amber")

    @property
    def healthy(self) -> bool:
        return not self.flags

    @property
    def notes_text(self) -> str:
        return "\n\n".join(self.notes)


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
    def comment_groups(self) -> List[Tuple[str, List[str]]]:
        """Systems grouped by IDENTICAL Comment-box text (SystemVM.notes_text) -- the same
        grouping generate_report.py's xlsx Summary Notes table uses, so the web form can show
        (and let the admin bulk-edit) the same compiled view before ever submitting. A flagged
        system with nothing yet (empty notes_text) is excluded, matching what its own Comment
        box shows: nothing, awaiting a real answer, not a fabricated one."""
        groups: List[Tuple[str, List[str]]] = []
        seen: Dict[str, int] = {}
        for s in self.systems:
            text = s.notes_text
            if not text:
                continue
            if text in seen:
                groups[seen[text]][1].append(s.name)
            else:
                seen[text] = len(groups)
                groups.append((text, [s.name]))
        return groups

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
    nsvc = gr.total_services(store)
    down = gr.services_down(store)   # PromQL service checks + down web-link probes (see gr.services_down)
    ram_hosts, _ = gr.ram_pressure(store, systems, thr, thr)
    cpu_hosts, _ = gr.cpu_pressure(store, systems, thr, thr)
    dh_hosts, dh_disks, dh_state = gr.disk_high(store, systems, thr, cfg.chip_red)
    dh_total = gr.total_disks(store, systems)
    miss = gr.backup_missing(store, systems)
    nmiss = len(miss)
    n_untracked = len(gr.backup_untracked_unexplained(store, systems))
    n_tracked = len(systems) - n_untracked
    cert_expired, cert_expiring = gr.cert_rollup(store)
    ur = gr.unreachable(store, systems)
    nearfull = gr.disk_near_full(store, systems, cfg.chip_red)
    n_https = sum(1 for u in store.links if u.lower().startswith("https"))
    n_http = sum(1 for u in store.links if u.lower().startswith("http://"))

    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    cob = "N/A" if cob_missing else f"{store.cob / 60:.1f} min"
    swift_missing = store.swift is None or (isinstance(store.swift, float) and math.isnan(store.swift))
    swift = f"{store.swift:.0f}" if store.swift is not None else "N/A"
    bad = lambda n: "good" if not n else "bad"
    warn = lambda n: "good" if not n else "warn"
    web_state = "good" if n_http == 0 else ("bad" if n_http > n_https else "warn")

    linux_pct, win_pct = gr.platform_host_pcts(systems)
    glance = [
        {"label": "Systems", "value": len(systems), "state": "info"},
        {"label": "Hosts", "value": hosts, "state": "info"},
        # One combined tile, not two — matches the shape every other pair-of-numbers tile in
        # this report uses (glance has no "sub" line, so the order lives in the label itself).
        {"label": "Linux | Windows", "value": f"{linux_pct}% | {win_pct}%", "state": "info"},
        {"label": "Services", "value": nsvc, "state": "info"},
        {"label": "SWIFT txns", "value": swift, "state": "info"},
        {"label": "COB · T24", "value": cob, "state": "info"},
    ]
    immediate = [
        # missing out of TRACKED hosts (an untracked host isn't judged either way — see the
        # separate Backup tracking tile for those).
        {"label": "Missing backups", "value": f"{nmiss} | {gr.backup_tracked_hosts(store, systems)}",
         "sub": "missing | tracked", "state": gr.backup_missing_band(nmiss)},
        # unreachable/down out of the TOTAL we monitor, so the count never reads as if fewer
        # components/services exist just because some are currently failing.
        {"label": "Unreachable components", "value": f"{len(ur)} | {hosts}",
         "sub": "unreachable | total", "state": bad(len(ur))},
        {"label": "Services down", "value": f"{down} | {nsvc}",
         "sub": "down | total", "state": bad(down)},
        {"label": "Expired certs", "value": f"{len(cert_expired)} | {gr.cert_monitored(store)}",
         "sub": "expired | total", "state": bad(len(cert_expired))},
    ]
    watch = [
        # Every tile reads "affected | total" so a count can never be mistaken for the whole
        # estate: 3 is alarming out of 5 hosts and unremarkable out of 56, and the tile has to
        # say which without the reader going to look it up.
        {"label": "High CPU", "value": f"{cpu_hosts} | {hosts}", "sub": "hosts | total",
         "state": warn(cpu_hosts)},
        {"label": "High RAM", "value": f"{ram_hosts} | {hosts}", "sub": "hosts | total",
         "state": warn(ram_hosts)},
        {"label": f"High disk ≥{thr}%", "value": f"{dh_hosts} | {hosts}",
         "sub": f"hosts | total · {dh_disks} | {dh_total} disks", "state": dh_state},
        # https out of ALL monitored endpoints, not https vs http — the old pair made a fully
        # encrypted estate read "12 | 0", which looks like half a number rather than a pass.
        {"label": "Web encryption", "value": f"{n_https} | {n_https + n_http}",
         "sub": "https | total", "state": web_state},
        {"label": "Backup tracking", "value": f"{n_tracked} | {len(systems)}",
         "sub": "tracked | total", "state": warn(n_untracked)},
    ]

    banners = []
    # LDAP / auth service down — highest priority, listed first (mirrors the xlsx + email).
    ldap_dependents = gr.ldap_alert(store, systems)
    if ldap_dependents:
        banners.append({"severity": "imminent",
                        "head": f"LDAP / auth service down — {len(ldap_dependents)} dependent system(s) affected",
                        "rows": [{"label": "Cannot sign in", "values": ", ".join(ldap_dependents)}]})
    if nearfull:
        byhost: dict = {}
        for s, lbl, mp, used in nearfull:
            byhost.setdefault(f"{s} · {lbl}", []).append(f"{mp} {used:.0f}%")
        banners.append({"severity": "critical",
                        "head": f"Disk near-full — {len(nearfull)} disk(s) on {len(byhost)} host(s)",
                        "rows": [{"label": h, "values": ", ".join(v)}
                                 for h, v in sorted(byhost.items())]})
    if miss:
        bysys: dict = {}
        for s, lbl, reason in miss:
            bysys.setdefault(s, []).append(f"{lbl} ({reason})")
        banners.append({"severity": "critical",
                        "head": f"Missing backups — {len(miss)} host(s) with no fresh backup",
                        "rows": [{"label": h, "values": ", ".join(v)}
                                 for h, v in sorted(bysys.items())]})
    untracked = gr.backup_untracked_unexplained(store, systems)
    if untracked:
        # Warning, not critical: a blind spot ("we can't tell"), not an active failure
        # ("it's broken") — nothing here is judged missing, since nothing is being watched.
        banners.append({"severity": "warning",
                        "head": f"Backups untracked — {len(untracked)} system(s) with no backup check at all",
                        # one row per system, matching every other banner
                        "rows": [{"label": s, "values": "no backup check on any host"}
                                 for s in sorted(untracked)]})
    if ur:
        bysys: dict = {}
        for s, lbl, _ in ur:
            bysys.setdefault(s, []).append(lbl)
        # Always IMMINENT: an unreachable component is not a metric out of range, it is the
        # loss of our ability to see one. Every other finding is at least still being measured.
        banners.append({"severity": "imminent",
                        "head": f"Unreachable — {len(ur)} component(s) across {len(bysys)} system(s)",
                        "rows": [{"label": s, "values": ", ".join(l)}
                                 for s, l in sorted(bysys.items())]})
    down_detail = gr.services_down_detail(store, systems)
    if down_detail:
        bysys: dict = {}
        for s, name in down_detail:
            bysys.setdefault(s, []).append(name)
        banners.append({"severity": "critical",
                        "head": f"Services down — {len(down_detail)} service(s)/link(s) across "
                                f"{len(bysys)} system(s)",
                        "rows": [{"label": s, "values": ", ".join(sorted(names))}
                                 for s, names in sorted(bysys.items())]})
    if cert_expired or cert_expiring:
        bits = ([f"{len(cert_expired)} expired"] if cert_expired else []) + \
               ([f"{len(cert_expiring)} expiring ≤30d"] if cert_expiring else [])
        banners.append({"severity": "critical" if cert_expired else "warning",
                        "head": "SSL certs — " + ", ".join(bits),
                        "rows": ([{"label": "Expired",
                                   "values": ", ".join(h for h, _ in cert_expired)}] if cert_expired else []) +
                                ([{"label": "Expiring ≤30d",
                                   "values": ", ".join(f"{h} ({cd:.0f}d)" for h, cd in cert_expiring)}]
                                 if cert_expiring else [])})
    http_links = gr.http_links_detail(store, systems)
    if http_links:
        # Warning, not critical: an unencrypted link isn't down, it's a standing exposure.
        bysys: dict = {}
        for s, name in http_links:
            bysys.setdefault(s, []).append(name)
        banners.append({"severity": "warning",
                        "head": f"Plain HTTP — {len(http_links)} link(s) not using HTTPS",
                        "rows": [{"label": s, "values": ", ".join(sorted(names))}
                                 for s, names in sorted(bysys.items())]})
    over_folders = gr.folder_over_expected_detail(store, systems)
    if over_folders:
        # Always warning, never critical, however far over expected the folder grows — see
        # FOLDER_EXPECTED_GB's docstring: this is "keep an eye on it", not an outage.
        bysys: dict = {}
        for s, name, expected, actual in over_folders:
            bysys.setdefault(s, []).append(f"{name} ({actual:.1f} GB, expected {expected:.1f} GB)")
        banners.append({"severity": "warning",
                        "head": f"Folder over expected size — {len(over_folders)} folder(s) on "
                                f"{len(bysys)} system(s)",
                        "rows": [{"label": s, "values": ", ".join(v)}
                                 for s, v in sorted(bysys.items())]})
    if cob_missing and datetime.date.today().weekday() != 0:   # 0 = Monday (Sunday: no COB)
        # If the T24 database component is itself unreachable, an abnormal COB reading isn't
        # evidence COB failed to run — it means we can't tell, because the exporter that would
        # report it can't be reached. Say that, not "may not have run".
        if any(s == "Temenos" and "DB" in lbl for s, lbl, _ in ur):
            banners.append({"severity": "warning",
                            "head": "COB — could not be calculated, T24 database is unreachable",
                            "detail": "The T24 database component is unreachable, so COB time could "
                                      "not be calculated for the previous day — this is not evidence "
                                      "that COB itself failed to run. Restore connectivity to the T24 "
                                      "database first, then re-check COB."})
        else:
            banners.append({"severity": "warning",
                            "head": "COB — close-of-business may not have run yesterday",
                            "detail": "COB time is out of range; confirm the T24 COB completed. "
                                      "(On Mondays this is expected and not flagged.)"})
    # SWIFT transaction count missing WHILE the T24 application component is down — that's not
    # evidence no SWIFT transactions occurred, it means we can't tell, because the exporter
    # that would report it can't be reached. Only flagged in this specific case; a blank SWIFT
    # count while T24 App is up is left unflagged, same as COB's DB-reachable case.
    if swift_missing and any(s == "Temenos" and "App" in lbl for s, lbl, _ in ur):
        banners.append({"severity": "warning",
                        "head": "SWIFT — could not be calculated, T24 application is down",
                        "detail": "The T24 application component is down, so SWIFT transaction "
                                  "count could not be calculated for the current period — this is "
                                  "not evidence that no SWIFT transactions occurred. Restore the "
                                  "T24 application first, then re-check SWIFT."})

    # One vocabulary for the screen and the workbook. `band` is derived from the severity
    # rather than set by hand, so a banner cannot end up amber on screen and red in the file.
    for b in banners:
        sev = b.get("severity") or {"red": "critical", "amber": "warning"}.get(b.get("band"), "warning")
        b["severity"] = sev
        b["sev_label"] = gr.SEVERITY[sev]["label"]
        b["band"] = {"imminent": "critical", "critical": "red", "warning": "amber"}[sev]
        b.setdefault("rows", [])
    banners.sort(key=lambda b: gr.SEVERITY[b["severity"]]["rank"])   # imminent first

    return {"glance": glance, "immediate": immediate, "watch": watch, "banners": banners}


def list_systems(*, infra: bool = False) -> List[dict]:
    """The system name + host count from the topology (prometheus.yml) WITHOUT any live capture.
    This is a plain file read, so the selection screen can be rendered on every landing without
    touching Prometheus — the expensive capture is deferred until the admin actually proceeds.

    `infra=True` returns Infrastructure Admin's own estate (hyper-converged clusters,
    standalone DB hosts) instead of the business-systems topology — see
    gr.load_topology's `scope` and webapp/reports/views.infra_form."""
    cfg = gr.load_config()
    systems = gr.load_topology(cfg.prometheus_yml, scope="infra" if infra else "business")
    return [{"name": s.name, "hosts": len(s.components),
             # "windows" / "linux" / "hybrid" / "" — derived from the scrape job, so it costs
             # the same file read the rest of this function already paid for.
             "platform": gr.platform_of_system(s.components)}
            for s in systems]


def _scope_links_to_systems(store, systems) -> None:
    """Web links (blackbox HTTP probes) are captured GLOBALLY by the engine, independent of the
    systems list. When a report is scoped to a subset, drop every link not owned by one of those
    systems (per gr.assign_link — the same attribution the report itself uses) so link-derived
    KPIs (Web encryption, SSL certs) and the report's link sections don't leak other systems'
    endpoints. Mutates store.links in place."""
    store.links = {u: d for u, d in store.links.items()
                   if gr.assign_link(u, systems) is not None}


def capture_snapshot(token: str, only: Optional[set] = None, *, infra: bool = False) -> Snapshot:
    """Load config + topology, capture a FRESH set of live metrics from Prometheus, and compute
    the per-system flagged items. `only` (a set of system names) scopes the capture to just those
    systems — so we only pay for what the admin selected. Raises PrometheusUnavailable if the
    endpoint is unreachable.

    `infra=True` loads Infrastructure Admin's own estate instead of the business-systems
    topology — see list_systems."""
    cfg = gr.load_config()
    # runtime overrides an Administrator set in the app (which Prometheus/Grafana to use)
    from .models import SystemConfig
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url
    if sc.grafana_url:
        cfg.grafana = sc.grafana_url
    systems = gr.load_topology(cfg.prometheus_yml, scope="infra" if infra else "business")
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
        notes = (gr.backup_policy_notes_for_system(store, sysm) + gr.cob_policy_notes_for_system(sysm)
                 + gr.ram_policy_notes_for_system(sysm))
        if not flags and not notes:   # nothing flagged, nothing policy-explained -- see NO_ISSUES_COMMENT
            notes = [gr.NO_ISSUES_COMMENT]
        svms.append(SystemVM(name=sysm.name, hosts=len(sysm.components), flags=flags, notes=notes))

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


class OsInventoryUnavailable(RuntimeError):
    """Raised when the OS inventory cannot be built — unreachable Prometheus, or the `os`
    collector not enabled on the exporters so no host reports a version at all."""


def build_os_inventory(theme: str = "dark") -> Tuple[bytes, int, int, int]:
    """The OS Inventory workbook, as bytes, plus (hosts, end-of-life, extended-support).

    Estate-wide by design: an inventory that covered only the systems someone happened to
    tick would answer "what is the oldest OS we run" with a number that depends on the
    ticking. generate_os_inventory.fetch() reads every host Prometheus knows about.

    Thin wrapper over send_report/generate_os_inventory.py, the same shape as build_report's
    wrapper over the daily report — the engine stays the single source of truth for what a
    report contains, and the webapp only decides when to run it and who may.
    """
    import datetime as _dt
    import io

    import generate_os_inventory as osi

    cfg = gr.load_config()
    from .models import SystemConfig
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url

    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    try:
        prom.ping()
    except Exception as exc:                      # noqa: BLE001 — surfaced to the admin
        raise OsInventoryUnavailable(f"{cfg.prom}: {exc}") from exc

    today = _dt.date.today()
    hosts = osi.fetch(prom)
    if not hosts:
        raise OsInventoryUnavailable(
            "No windows_os_info or node_os_info series came back — the `os` collector is "
            "probably not enabled on the exporters.")
    osi.annotate(hosts, today)

    with gr.palette(theme if theme in gr.PALETTES else "dark"):
        workbook = osi.Report(hosts, cfg.prom, today).build()

    buf = io.BytesIO()
    workbook.save(buf)
    eol = sum(1 for h in hosts if h.band == "red")
    extended = sum(1 for h in hosts if h.band == "amber")
    return buf.getvalue(), len(hosts), eol, extended


def default_os_inventory_filename(when=None) -> str:
    import datetime as _dt

    when = when or _dt.datetime.now()
    return f"OS Inventory - {when:%Y-%m-%d %H%M}.xlsx"

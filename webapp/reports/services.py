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
    band: str          # "red" | "amber" | "note"
    category: str      # disk | ram | cpu | service | degraded | backup | unreachable | untracked


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
    # folder-monitoring Flags computed in capture_snapshot (see its own comment), carried
    # forward so build_report can hand them to gr.build_report_bytes's extra_flags_by_system --
    # without this the xlsx would silently recompute flags from scratch and never see them,
    # even though this same Snapshot's own .systems (the web preview) already does.
    _folder_flags: Dict[str, list] = field(default_factory=dict)

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

    # Queue folders drained (2026-09-08, on request) -- T24's payment/interface message queues
    # (see webapp/reports/folders.py's own "Payment & interface queues" watch group), scoped to
    # whichever systems THIS report actually covers (the same "don't leak systems outside the
    # scope" discipline every other tile above already follows) rather than the whole estate.
    # Degrades to 0 | 0 (a neutral "good" reading, not a false alarm) if Folder Watch itself
    # can't be reached this run -- a second live-data source going down must not also break
    # this report's own overview tiles.
    from . import folders as folder_watch
    try:
        fw_data = folder_watch.snapshot()
    except folder_watch.FolderWatchUnavailable:
        fw_data = None
    sysnames = {s.name for s in systems}
    queue_folders_here = ([f for f in fw_data["folders"]
                           if f["watch_type"] == "queue" and f.get("system") in sysnames]
                          if fw_data else [])
    n_queue = len(queue_folders_here)
    # "undrained" means aged PAST the folder monitoring screen's own established amber/red
    # limit (folders.verdict(), DrainageThresholdConfig) -- NOT merely "not yet idle" (2026-10-07,
    # on real complaint: "how can you say file undrained after 47 seconds" -- this used to be
    # `n_queue - n_drained` with n_drained counting only state=="idle", so ANY file still
    # sitting there counted as undrained the instant it landed, even a few seconds old and
    # nowhere near its real 5/10-minute amber/red threshold. A "green" folder (files waiting,
    # all fresh) is the NORMAL in-flight state a queue spends most of its time in, not a
    # problem -- counting it here contradicted the exact same folders.verdict() this tile is
    # supposed to be summarising, and the same real distinction
    # alerting.undrained_folder_flags_by_system already draws (amber/red only, never green).
    n_undrained = sum(1 for f in queue_folders_here if f["state"] in ("amber", "red"))

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
        # "Undrained queues", not "Queue folders drained" (2026-09-16, on request: "this needs
        # to be undrained queues so that 0 meant healthy" -- the positive "drained | total"
        # framing this tile used to have reads great in an e-mail's own text, but every OTHER
        # tile on the Executive Dashboard turns its own numerator into a mini-bar's fill width,
        # where a bigger number always means "worse". A positive-framed numerator inverts that:
        # a fully healthy estate (5 drained of 5) drew a nearly-full bar, the same visual an
        # actually-broken tile would draw. Counting the problem instead (0 undrained of 5) makes
        # 0 the small/healthy bar every other tile already promises.
        # `warn`, not `bad`: the finer red/amber verdict already happens once, correctly, via
        # the flagged-metric mechanism (reports.alerting.undrained_folder_flags_by_system) --
        # this tile is a glance-level count, not a second independently-computed severity
        # judgement.
        {"label": "Undrained queues", "value": f"{n_undrained} | {n_queue}",
         "sub": "undrained | total", "state": warn(n_undrained)},
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
        # "Unencrypted links", not "Web encryption" (2026-09-16, on request: "should be
        # unencrypted links or something so that 0 means healthy" -- same mini-bar-inversion
        # reasoning as "Undrained queues" above: a fully-encrypted estate used to read
        # "12 | 12", drawing a full bar for a perfect score. Counting the plain-HTTP endpoints
        # instead makes 0 the small/healthy bar.
        {"label": "Unencrypted links", "value": f"{n_http} | {n_https + n_http}",
         "sub": "http | total", "state": web_state},
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


def live_prom_client(*, infra: bool = False):
    """cfg + a connected gr.Prometheus client + topology, WITHOUT capturing a single metric --
    the same first few lines capture_snapshot always pays for, split out on its own for callers
    that only need to run their OWN live query_range calls (report_charts.resource_percent_
    series, 2026-09-08: "shouldn't it be the percentage reading... wouldn't it be easier to
    read" -- the Hourly Activity chart's per-system RAM/CPU/Disk lines need a live historical %
    reading, not a fresh full capture() of every metric across every system).

    Returns (prom, cfg, systems). No ping() -- unlike capture_snapshot, a caller here runs its
    own query_range per chart and can fail that one chart gracefully (see resource_percent_
    series' own try/except) rather than refusing the whole report over one slow ping."""
    cfg = gr.load_config()
    from .models import SystemConfig
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url
    if sc.grafana_url:
        cfg.grafana = sc.grafana_url
    systems = gr.load_topology(cfg.prometheus_yml, scope="infra" if infra else "business")
    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    return prom, cfg, systems


def _scope_links_to_systems(store, systems) -> None:
    """Web links (blackbox HTTP probes) are captured GLOBALLY by the engine, independent of the
    systems list. When a report is scoped to a subset, drop every link not owned by one of those
    systems (per gr.assign_link — the same attribution the report itself uses) so link-derived
    KPIs (Web encryption, SSL certs) and the report's link sections don't leak other systems'
    endpoints. Mutates store.links in place."""
    store.links = {u: d for u, d in store.links.items()
                   if gr.assign_link(u, systems) is not None}


def queue_waiting_folder_flags_by_system(cfg, covered_systems: set) -> Dict[str, list]:
    """Dashboard-only, NOTE-band Flag objects for a queue folder sitting in folders.py's own
    "green" state -- files waiting, all of them still fresh, genuinely healthy, NOT the same
    thing as alerting.undrained_folder_flags_by_system's red/amber output (2026-10-07, on
    request: "managerial dashboard still not telling us which folder did not drain" -- traced
    to a real mismatch: the "Undrained queues" dashboard tile counts ANY non-idle queue folder
    (n_queue - n_drained, services.py's own glance tile, "drained" meaning literally
    state=="idle"), but the per-system Flag list the dashboard's click-to-expand detail reads
    from only ever contained red/amber flags -- a green-state folder was never flagged at all,
    so a tile correctly reading "1 | 5" could expand to an empty popup with no way to see which
    folder. Confirmed live, 2026-10-07: PAYNET.IN, 6 files, 45 minutes old, state=green,
    counted in the tile's own "1" but absent from every per-system flag list.

    Deliberately SEPARATE from alerting.undrained_folder_flags_by_system, never merged into it
    and never called from alerting.py's own run_alert_cycle -- a green/healthy folder must
    never become a real alert-pipeline flag (band="note" is explicitly excluded from real
    notification eligibility, same "note" band reasoning network.py's own cluster-discard notes
    already use) or a Fix-needed item in the xlsx report; this exists ONLY to give the
    dashboard's own exception-detail popup something real to show for every number the tile
    itself already claims, via _exception_detail's own word-match against Flag.band/category/
    text (views.py's own accepted-band set includes "note" for exactly this reason -- see that
    function's own comment).

    The TILE'S OWN "N | total" count no longer includes green folders at all (same day,
    separate real bug: "how can you say file undrained after 47 seconds" -- n_queue/n_undrained
    in build_overview now only count state in amber/red, the same aged-past-its-established-
    limit test alerting.undrained_folder_flags_by_system already applies, instead of the old
    n_queue - n_drained which counted anything merely non-idle). This function's own job is
    now purely "give a curious admin something to see if they open the popup anyway" --
    it no longer owes the tile's own number an explanation, since the tile never claims a
    green folder as a problem in the first place."""
    from . import folders

    eligible = folders.folder_watch_systems(cfg.prometheus_yml) & covered_systems
    if not eligible:
        return {}
    try:
        data = folders.snapshot()
    except folders.FolderWatchUnavailable:
        return {}
    out: Dict[str, list] = {}
    for f in data["folders"]:
        if f["state"] != "green":
            continue
        if f["watch_type"] in ("logfiles", "backup", "logs"):
            continue
        text = (f"{f['name']} on {f['host']}: {f['files']} file(s) waiting, oldest "
               f"{f['age_text']} old (fresh, still within normal processing time)")
        flag = gr.Flag(key=f"undrained_ok:{f['key']}", text=text,
                       band="note", category="undrained_folders")
        for sysname in eligible:
            out.setdefault(sysname, []).append(flag)
    return out


def mute_reason_notes_for_system(sysm_name: str, flags: "List[FlagVM]") -> List[str]:
    """Automated Comment-box notes explaining WHY a currently-muted finding isn't being raised
    as a fresh issue here either (2026-10-07, on request: "add automated comments for all
    issues muted from alerts for recurrance in the system admin report... create a pipe line
    where all such issues muted will also propagate the mute reason as the comment"). Mirrors
    backup_policy_notes_for_system/cob_policy_notes_for_system/ram_policy_notes_for_system's
    own non-actionable shape (never a Flag, just pre-filled explanatory text) -- this is the
    4th note source folded into capture_snapshot's own `notes` list, not a parallel mechanism.

    Reuses alerting._active_silences()/_silenced() verbatim -- the SAME real matching
    (exact (system, flag_key), or category-wide with flag_key blank) AND the SAME escalation
    valve (SILENCE_ESCALATE_AFTER: a silence that stopped self-resolving and has stayed open
    too long no longer counts as muted) a real AlertGroup's own notification pipeline already
    uses to decide whether to suppress an e-mail. Deliberately NOT a second, hand-rolled
    version of "is this silenced" -- the one place that decision is made must stay the one
    place it's made, or this report and the real alert could disagree about a finding's state.

    One note per DISTINCT silence that actually covers one of THIS system's CURRENT flags, not
    one note per flag -- several flags sharing one category-wide silence collapse into a
    single explanatory line, the same "one line per real reason" shape every other note-
    generator here already uses."""
    if not flags:
        return []

    from django.utils import timezone

    from . import alerting
    from .models import IssueOccurrence

    exact_silences, category_silences = alerting._active_silences()
    if not exact_silences and not category_silences:
        return []

    open_started_by_key = {r.flag_key: r.started_at for r in
                           IssueOccurrence.objects.filter(system=sysm_name, resolved_at__isnull=True)}
    now = timezone.now()

    covered: Dict[int, tuple] = {}   # silence.pk -> (silence, [flag_text, ...]), first-seen order
    for f in flags:
        if not alerting._silenced(sysm_name, f.key, f.category, exact_silences,
                                  category_silences, open_started_by_key, now):
            continue
        silence = exact_silences.get((sysm_name, f.key)) or category_silences.get((sysm_name, f.category))
        if silence is None:
            continue
        covered.setdefault(silence.pk, (silence, []))[1].append(f.text)

    notes = []
    for silence, flag_texts in covered.values():
        scope = "; ".join(flag_texts) if silence.flag_key else f"{silence.category} (all components)"
        reason = silence.reason.strip() or "no reason given"
        expires = timezone.localtime(silence.expires_at).strftime("%d %b %Y")
        notes.append(f"{scope} — Muted until {expires}: {reason}")
    return notes


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

    # Folder-monitoring issues (2026-09-07, on request: "a lot of folder issues fly under the
    # radar admins need to answer for those errors and warnings as well") -- reuses the EXACT
    # SAME transformation reports.alerting's own alert-poller uses (folder_size_flags_by_system/
    # undrained_folder_flags_by_system/backup_uncleared_folder_flags_by_system), so a folder
    # issue reads identically whether it triggered an e-mail or is being seen here for the
    # first time. generate_report.py itself can't do this (it has no Django dependency, and
    # reports.folders -- which these three functions read -- is Django-side; see alerting.py's
    # own module docstring for the same reasoning), so it happens at this integration seam
    # instead, same as alerting.py's own run_alert_cycle does it.
    #
    # Business scope only: folders.py's own system-eligibility functions
    # (folder_watch_systems/backup_drainage_systems) are business-system concepts --
    # Infrastructure Admin's estate (infra=True) has no folder-watch equivalent.
    folder_flags_by_sys: Dict[str, list] = {}
    if not infra:
        from . import alerting

        all_names = {s.name for s in systems}
        for sysname, flags in alerting.folder_size_flags_by_system(store, systems).items():
            folder_flags_by_sys.setdefault(sysname, []).extend(flags)
        for sysname, flags in alerting.undrained_folder_flags_by_system(cfg, all_names).items():
            folder_flags_by_sys.setdefault(sysname, []).extend(flags)
        for sysname, flags in alerting.backup_uncleared_folder_flags_by_system(cfg, all_names).items():
            folder_flags_by_sys.setdefault(sysname, []).extend(flags)
        # NOTE-band only (never real alerting) -- see queue_waiting_folder_flags_by_system's
        # own docstring: gives the "Undrained queues" dashboard tile real detail for the
        # green-state (healthy, fresh files) folders its own count already includes but
        # alerting.undrained_folder_flags_by_system above never flags.
        for sysname, flags in queue_waiting_folder_flags_by_system(cfg, all_names).items():
            folder_flags_by_sys.setdefault(sysname, []).extend(flags)

    svms: List[SystemVM] = []
    for sysm in systems:
        flags = [FlagVM(f.key, f.text, f.band, f.category)
                 for f in gr.flagged_for_system(store, sysm, cfg)
                 + folder_flags_by_sys.get(sysm.name, [])]
        notes = (gr.backup_policy_notes_for_system(store, sysm) + gr.cob_policy_notes_for_system(sysm)
                 + gr.ram_policy_notes_for_system(sysm) + mute_reason_notes_for_system(sysm.name, flags))
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
        _folder_flags=folder_flags_by_sys,
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
        extra_flags_by_system=snapshot._folder_flags,
    )


def default_report_filename(theme: str, when: Optional[datetime.datetime] = None) -> str:
    when = when or datetime.datetime.now()
    return f"System Admin Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


class EmailNotConfigured(RuntimeError):
    """Raised when SMTP settings are missing/incomplete in config.ini."""


def email_report(snapshot: Snapshot, data: bytes, *, recipients: List[str],
                 author: str, filename: str, subject_prefix: str = "") -> str:
    """E-mail the generated report (attached) with the standard HTML summary, stamped with
    the author as the sender. Reuses mail_report (SMTP + templating). Returns the subject.
    Raises EmailNotConfigured / the underlying SMTP error on failure.

    `subject_prefix` (2026-09-22, for reports.views._send_system_admin_report_test) -- the
    established way this app marks a synthetic test send is a "[SYNTHETIC TEST]" SUBJECT
    prefix (see e.g. _send_narrative_report_test/_send_xlsx_report_test's own AD branch), NOT
    an altered `author`/from_name: `author` also becomes mail["from_name"] below, and
    mail_report.send_email's From header goes through formataddr, so a bracketed marker
    there is no longer a parsing hazard the way it was before that fix -- but stuffing a
    "[SYNTHETIC TEST]" marker into `author` would still show up as the "By" field inside the
    xlsx itself (author is also passed to build_report), which is wrong: a test send's report
    content should look identical to a real one, only the envelope should say TEST."""
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
    if subject_prefix:
        subject = f"{subject_prefix} {subject}"

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


class BackupHistoryUnavailable(RuntimeError):
    """Raised when NEITHER tier has anything for the requested range -- no instance has ever
    recorded backup_check_ok/backup_file_count inside it, AND no system_admin ReportSubmission
    with a "Missing backups" tile exists inside it either (e.g. a range entirely before
    2026-07-18, when the whole system was first deployed)."""


def earliest_backup_metric_date():
    """The oldest calendar day the per-instance metric tier (reachable / current-backup-
    available / filename+timestamp) can show anything for -- the real archived start of
    backup_check_ok, not a guessed/hardcoded constant. None if the archive is completely
    empty. Internal boundary build_backup_history_report uses to decide, per day, which of
    its two tiers to use -- see earliest_backup_history_date for the combined, user-facing
    floor."""
    from .models import MetricSample

    earliest = (MetricSample.objects.filter(metric_key__startswith="backup_check_ok:")
               .order_by("taken_at").values_list("taken_at", flat=True).first())
    return earliest.date() if earliest else None


def earliest_backup_snapshot_date():
    """The oldest calendar day ANY system_admin ReportSubmission carries a real "Missing
    backups" overview tile -- the coarser report-snapshot fallback tier's own floor (2026-10-06,
    on request, after the user pointed out this KPI has always been saved: "if everything is
    captured then so is backup info[,] the field is called missing backups"). Confirmed live:
    present on the very first system_admin submission ever, 2026-07-18. None if no system_admin
    submission anywhere carries the tile at all."""
    from .models import ReportSubmission

    for sub in (ReportSubmission.objects.filter(report_content__kind="system_admin")
               .order_by("created_at").iterator()):
        for t in sub.report_content.get("overview", {}).get("immediate", []):
            if t.get("label") == "Missing backups":
                return sub.created_at.date()
    return None


def earliest_backup_history_date():
    """The oldest calendar day the Backup History Report can show ANYTHING for, across BOTH
    tiers -- single source of truth for the date picker's own floor (views.
    backup_history_report) and the server-side range check. The per-instance metric tier and
    the coarser report-snapshot tier have different floors (2026-09-15 vs 2026-07-18 real,
    confirmed live) -- this is always the EARLIER of the two, since build_backup_history_report
    itself falls back to the snapshot tier for any day before the metric tier's own floor.
    None only if NEITHER tier has anything at all."""
    dates = [d for d in (earliest_backup_metric_date(), earliest_backup_snapshot_date()) if d]
    return min(dates) if dates else None


def _bh_day_bounds(day):
    """One calendar day's [start, end] as UTC-aware datetimes -- MetricSample.taken_at is
    stored UTC (metric_history's own capture timestamp), so this is the same convention every
    archived sample already uses, not a new one invented here."""
    start = datetime.datetime.combine(day, datetime.time.min, tzinfo=datetime.timezone.utc)
    end = datetime.datetime.combine(day, datetime.time.max, tzinfo=datetime.timezone.utc)
    return start, end


def _bh_report_for_day(day):
    """(report_id, status_label, author) for one calendar day -- prefers a real admin-authored
    ReportSubmission; falls back to the "Automated" one and says so explicitly; says plainly
    when neither exists. Never silently blank (2026-10-06, on request: "prefer reports
    generated byt admins but if not possible say this and fallback to automated report")."""
    from .models import ReportSubmission

    admin_sub = (ReportSubmission.objects.filter(created_at__date=day).exclude(author="Automated")
                .order_by("created_at").first())
    if admin_sub:
        return admin_sub.pk, "Admin-generated", admin_sub.author
    auto_sub = (ReportSubmission.objects.filter(created_at__date=day, author="Automated")
               .order_by("created_at").first())
    if auto_sub:
        return auto_sub.pk, "No admin report this day — showing automated report instead", "Automated"
    return None, "No report generated this day", ""


def _bh_missing_backups_for_day(day):
    """(value, state, report_id, report_status, author) from that day's own System Admin
    Report "Missing backups" overview tile -- the SAME real KPI System Health Report has
    always shown (generate_report.backup_missing_band), already saved verbatim into every
    system_admin ReportSubmission.report_content since day one (confirmed live, 2026-10-06:
    present on the very first submission, 2026-07-18). None if no system_admin report exists
    that day at all. This is coarser than the metric-archive tier above (one estate-wide
    count, not per-instance reachable/available, and no filename/timestamp) but genuinely
    extends real coverage back to 2026-07-18 -- well before the metric archive's own
    2026-09-15 floor -- using data that was ALREADY captured, not reconstructed or guessed."""
    from .models import ReportSubmission

    def _tile(sub):
        for t in sub.report_content.get("overview", {}).get("immediate", []):
            if t.get("label") == "Missing backups":
                return t
        return None

    admin_sub = (ReportSubmission.objects.filter(
        created_at__date=day, report_content__kind="system_admin").exclude(author="Automated")
                .order_by("created_at").first())
    if admin_sub:
        tile = _tile(admin_sub)
        if tile:
            return tile["value"], tile["state"], admin_sub.pk, "Admin-generated", admin_sub.author
    auto_sub = (ReportSubmission.objects.filter(
        created_at__date=day, report_content__kind="system_admin", author="Automated")
               .order_by("created_at").first())
    if auto_sub:
        tile = _tile(auto_sub)
        if tile:
            return (tile["value"], tile["state"], auto_sub.pk,
                    "No admin report this day — showing automated report instead", "Automated")
    return None


def build_backup_history_report(date_from, date_to, theme: str = "dark") -> Tuple[bytes, int, int, int, list]:
    """The Backup History workbook, as bytes, plus (days, no_backup_count, no_report_count,
    rows) -- `rows` is the FULL computed table, one plain dict per (day, instance), the same
    data written into the xlsx. The caller saves this verbatim into ReportSubmission.
    report_content (2026-10-06, on request, stated repeatedly: "the postgres db should be the
    hub for every report created, automatic or otherwise[,] the whole report as is should be
    recreatable" -- see every OTHER report's own report_content docstring for the same
    standing contract; a report_content of only {"kind", "date_from", "date_to"} would NOT
    satisfy this, since it points back at the archive instead of holding the report itself).

    date_from/date_to are inclusive datetime.date values. TWO tiers, chosen per day:

    Tier 1 (day >= earliest_backup_metric_date()) -- one row per (day, instance), for every
    instance the archive has EVER recorded backup_check_ok/backup_file_count for inside this
    range (discovered from the archive itself -- reports/metric_registry.py's own
    backup_check_ok/backup_file_count entries -- never a hardcoded topology list, so a host
    added or retired later is handled honestly with no manual update here). Two separate,
    deliberately NOT-conflated facts per day (confirmed live, 2026-10-06, by reading
    backup_monitor/check_backup_bsa.ps1 directly): "reachable" (backup_check_ok -- could the
    checker even see the backup folder/share) and "backup available" (backup_file_count > 0 --
    did a CURRENT backup, per that host's own configured policy, actually exist). A host can
    be fully reachable with zero fresh backups; collapsing the two into one flag would hide
    exactly that case. Filenames/timestamps come from the `backup_file` registry entry added
    alongside this report -- no retroactive history before whenever that entry first started
    capturing, so any day before ITS OWN earliest row is labelled "Not archived for this date"
    rather than a misleading blank/"missing" cell.

    Tier 2 (day < earliest_backup_metric_date()) -- one coarser, estate-wide row per day,
    from that day's own System Admin Report "Missing backups" snapshot (see
    _bh_missing_backups_for_day). Real data, already captured since day one (2026-07-18,
    confirmed live) -- added 2026-10-06 after the user pointed out this KPI has always existed
    ("if everything is captured then so is backup info[,] the field is called missing
    backups"). No per-instance breakdown and no filename/timestamp at this tier -- said
    plainly in the row itself, never faked to look like Tier 1's own detail.
    """
    import io

    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    from .models import MetricSample

    metric_floor = earliest_backup_metric_date()
    snapshot_floor = earliest_backup_snapshot_date()
    if (metric_floor is None or metric_floor > date_to) and (snapshot_floor is None or snapshot_floor > date_to):
        raise BackupHistoryUnavailable(
            "No backup data exists for this date range at all — not in the metric archive "
            f"({'starts ' + metric_floor.isoformat() if metric_floor else 'empty'}) or in any "
            f"report snapshot ({'starts ' + snapshot_floor.isoformat() if snapshot_floor else 'empty'}).")

    # The per-instance metric tier only covers the part of the range on/after its own floor --
    # discover instances from THAT sub-range only, so a range entirely before it (handled
    # below by the coarser report-snapshot tier instead) doesn't wrongly come up empty here.
    metric_tier_start = max(date_from, metric_floor) if metric_floor else None
    instances = []
    if metric_tier_start and metric_tier_start <= date_to:
        range_start, _ = _bh_day_bounds(metric_tier_start)
        _, range_end = _bh_day_bounds(date_to)
        instances = sorted({
            key.split(":", 1)[1]
            for key in MetricSample.objects.filter(
                metric_key__startswith="backup_check_ok:", taken_at__gte=range_start, taken_at__lte=range_end,
            ).values_list("metric_key", flat=True).distinct()
        })

    # Real system/component labels off the SAME topology every other report already resolves
    # against (2026-10-06, on request: "use system topology to better identify and label this
    # ... refered to individual host as if there where systems") -- instance:port alone reads
    # as network trivia; "RTGS — Backend" is what the rest of the app already calls this host
    # everywhere else. scope="all" since a backup-checked instance can belong to any of the
    # three estates (business/infra/AD), not just System Admin's own. Falls back to the raw
    # instance string (never hidden) for anything genuinely outside this topology (e.g. a
    # device this estate-wide YAML doesn't cover at all) -- labelled honestly, not guessed.
    cfg = gr.load_config()
    instance_labels = {
        c.instance: f"{sysm.name} — {c.label}"
        for sysm in gr.load_topology(cfg.prometheus_yml, scope="all")
        for c in sysm.components
    }

    def _instance_label(instance):
        label = instance_labels.get(instance)
        return f"{label} ({instance})" if label else instance

    instances.sort(key=_instance_label)   # group/display by real system name, not raw IP order

    earliest_file_row = (MetricSample.objects.filter(metric_key__startswith="backup_file:")
                         .order_by("taken_at").values_list("taken_at", flat=True).first())
    rollout_date = earliest_file_row.date() if earliest_file_row else None

    def _last_value(key, instance, day):
        # Reads the Postgres archive ONLY, never live Prometheus (2026-10-06, on request:
        # "stop using prometheus as a database" -- historical_query.series() falls back to a
        # live prom.query_range() for anything inside the last live_window_days, which is
        # exactly the dependency this report must not have; a day's reading here is only ever
        # as fresh as the last hourly capture into MetricSample, never fresher).
        start, end = _bh_day_bounds(day)
        return (MetricSample.objects.filter(
            metric_key=f"{key}:{instance}", taken_at__gte=start, taken_at__lte=end,
        ).order_by("-taken_at").values_list("value", flat=True).first())

    def _files_for(instance, day):
        # Strip the KNOWN prefix rather than splitting generically -- historical_query.py's own
        # docstring flags exactly this hazard: instance can itself contain a colon ("host:port"),
        # so a blind key.split(":") would cut the instance's own colon instead of the one
        # separating it from the filename.
        start, end = _bh_day_bounds(day)
        prefix = f"backup_file:{instance}:"
        rows = (MetricSample.objects.filter(
            metric_key__startswith=prefix, taken_at__gte=start, taken_at__lte=end,
        ).values_list("metric_key", "value"))
        seen = {}
        for key, mtime in rows:
            filename = key[len(prefix):]
            seen[filename] = mtime        # last-written mtime wins if it somehow changed intraday
        return sorted(seen.items())

    rows = []
    no_backup_count = 0
    no_report_count = 0

    with gr.palette(theme if theme in gr.PALETTES else "dark"):
        Theme = gr.Theme
        thin = Side(style="thin", color=Theme.BORDER)
        cell_border = Border(thin, thin, thin, thin)

        def _cell(ws, r, c, v="", font=None, bg=None, al="left", bordered=False,
                 wrap=False, valign="center"):
            x = ws.cell(row=r, column=c)
            x.value = v
            x.font = font or Theme.font()
            x.fill = Theme.fill(bg if bg is not None else Theme.BG)
            x.alignment = Alignment(horizontal=al, vertical=valign, wrap_text=wrap)
            if bordered:
                x.border = cell_border
            return x

        def _merge(ws, r, c1, c2, v, font, bg=None, al="left"):
            for c in range(c1, c2 + 1):
                _cell(ws, r, c, v if c == c1 else "", font, bg, al)
            ws.merge_cells(start_row=r, start_column=c1, end_row=r, end_column=c2)

        def _chip(ws, r, c, text, band, valign="center"):
            # band is "green"/"amber"/"red" (Theme.CHIP's own vocabulary) or None for a
            # genuinely unknown/not-applicable reading -- plain muted text, no colour, since
            # "we don't know" is not the same claim as "red" and must never look like one.
            if band is None:
                _cell(ws, r, c, text, Theme.font(9, False, Theme.SUB), bg=Theme.CARD,
                     al="center", bordered=True, valign=valign)
            else:
                fg, bg = Theme.CHIP[band]
                _cell(ws, r, c, text, Theme.font(9, True, fg), bg=bg, al="center",
                     bordered=True, valign=valign)

        def _report_header_text(date_str, report_id, report_status, report_author):
            # "Generated by:" is ALWAYS present and ALWAYS labelled (2026-10-06, on request,
            # after the admin name was only shown conditionally before: "you did not include
            # the name of the admin that generated the report") -- never a bare report_status
            # sentence that happens to omit the word "admin" on an automated day; the reader
            # should never have to infer whether this field exists from its absence.
            if report_id is None:
                return f"{date_str}  ·  No report generated this day"
            who = report_author if (report_author and report_author != "Automated") else "Automated"
            return f"{date_str}  ·  Report #{report_id}  ·  Generated by: {who}"

        COLS = ["System", "Reachable", "Backup available", "Filename(s)", "Last backup timestamp"]
        LEFT, RIGHT = 2, 2 + len(COLS) - 1   # margin column A reserved, content starts at B

        wb = Workbook()
        ws = wb.active
        ws.title = "Backup History"
        ws.sheet_view.showGridLines = False
        ws.column_dimensions["A"].width = 3
        widths = [38, 11, 16, 34, 20]
        for letter, w in zip([get_column_letter(c) for c in range(LEFT, RIGHT + 1)], widths):
            ws.column_dimensions[letter].width = w

        day = date_from
        row_i = 0

        def _blank_row(ws, r, span_to=14):
            for c in range(1, span_to):
                _cell(ws, r, c)

        while day <= date_to:
            date_str = day.strftime("%Y-%m-%d")
            if metric_floor is not None and day >= metric_floor:
                # Tier 1: per-instance, from the continuous metric archive.
                report_id, report_status, report_author = _bh_report_for_day(day)
                if report_id is None:
                    no_report_count += 1

                row_i += 1
                _cell(ws, row_i, 1)
                _merge(ws, row_i, LEFT, RIGHT,
                      _report_header_text(date_str, report_id, report_status, report_author),
                      Theme.font(13, True, Theme.CYAN), bg=Theme.HDR)
                ws.row_dimensions[row_i].height = 22

                row_i += 1
                _cell(ws, row_i, 1)
                for i, h in enumerate(COLS):
                    _cell(ws, row_i, LEFT + i, h, Theme.font(9, True, Theme.CYAN),
                         bg=Theme.HDR, al="center", bordered=True)
                head_row = row_i

                for instance in instances:
                    row_i += 1
                    _cell(ws, row_i, 1)
                    reachable = _last_value("backup_check_ok", instance, day)
                    available = _last_value("backup_file_count", instance, day)
                    if available is not None and available <= 0:
                        no_backup_count += 1

                    file_count = 1
                    if rollout_date is None or day < rollout_date:
                        filenames_text, ts_text = "Not archived for this date", ""
                    else:
                        files = _files_for(instance, day)
                        if files:
                            # Stacked top-down, one file per line (2026-10-06, on request:
                            # "you cant just list all backup file sequentially the xlsx cells
                            # do not stretch that far ahead....list top down instead") -- a
                            # single "; "-joined line was the original bug: it just runs off
                            # the edge of the cell instead of wrapping, however many files a
                            # busy day happened to produce. wrap_text + a row height sized to
                            # the real count (set below) is what actually makes this readable.
                            filenames_text = "\n".join(name for name, _mtime in files)
                            ts_text = "\n".join(
                                datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
                                .strftime("%Y-%m-%d %H:%M") for _name, mtime in files)
                            file_count = len(files)
                        else:
                            filenames_text, ts_text = "No fresh file recorded", ""

                    reachable_text = "Yes" if reachable and reachable >= 1 else ("No" if reachable is not None else "No data")
                    reachable_band = None if reachable is None else ("green" if reachable >= 1 else "red")
                    available_text = ("Yes" if (available is not None and available > 0) else
                                      ("No" if available is not None else "No data"))
                    available_band = None if available is None else ("green" if available > 0 else "red")
                    system_label = _instance_label(instance)
                    rows.append({
                        "date": date_str, "instance": instance, "system_label": system_label,
                        "reachable": reachable_text, "backup_available": available_text,
                        "filenames": filenames_text, "timestamps": ts_text,
                        "report_id": report_id, "report_status": report_status,
                        "report_author": report_author,
                    })

                    zebra = Theme.CARD if (row_i - head_row) % 2 == 0 else Theme.BG
                    _cell(ws, row_i, LEFT, system_label, Theme.font(9), bg=zebra,
                         bordered=True, valign="top")
                    _chip(ws, row_i, LEFT + 1, reachable_text, reachable_band, valign="top")
                    _chip(ws, row_i, LEFT + 2, available_text, available_band, valign="top")
                    _cell(ws, row_i, LEFT + 3, filenames_text, Theme.font(9, False, Theme.GREY),
                         bg=zebra, bordered=True, wrap=True, valign="top")
                    _cell(ws, row_i, LEFT + 4, ts_text, Theme.font(9, False, Theme.GREY),
                         bg=zebra, bordered=True, wrap=True, valign="top")
                    # Tall enough for every file's own line, capped so one unusually busy day
                    # can't blow the sheet's own proportions out -- 10 lines visible, "+N more"
                    # said plainly rather than silently truncating the real list.
                    visible = min(file_count, 10)
                    ws.row_dimensions[row_i].height = max(14, visible * 14)
                    if file_count > 10:
                        extra = file_count - 10
                        filenames_text = filenames_text + f"\n…(+{extra} more)"
                        ws.cell(row=row_i, column=LEFT + 3).value = filenames_text
            else:
                # Tier 2: coarser, estate-wide fallback from that day's own System Admin
                # Report "Missing backups" snapshot -- see _bh_missing_backups_for_day's own
                # docstring for why (real data, already captured, back to 2026-07-18 -- well
                # before the metric archive's 2026-09-15 floor). One row per day, not per
                # instance: this tier has no per-system breakdown and no filename/timestamp,
                # said plainly rather than faked to look like Tier 1's own detail.
                snap = _bh_missing_backups_for_day(day)
                if snap is None:
                    no_report_count += 1
                    available_text, available_band = "No data", None
                    report_id, report_status, report_author = None, "No report generated this day", ""
                else:
                    value, state, report_id, report_status, report_author = snap
                    available_text = f"{value} missing (estate-wide count)"
                    available_band = {"good": "green", "bad": "red"}.get(state, "amber")
                    if state != "good":
                        no_backup_count += 1

                row_i += 1
                _cell(ws, row_i, 1)
                _merge(ws, row_i, LEFT, RIGHT,
                      _report_header_text(date_str, report_id, report_status, report_author),
                      Theme.font(13, True, Theme.CYAN), bg=Theme.HDR)
                ws.row_dimensions[row_i].height = 22

                row_i += 1
                _cell(ws, row_i, 1)
                for i, h in enumerate(COLS):
                    _cell(ws, row_i, LEFT + i, h, Theme.font(9, True, Theme.CYAN),
                         bg=Theme.HDR, al="center", bordered=True)

                row_i += 1
                _cell(ws, row_i, 1)
                rows.append({
                    "date": date_str, "instance": "(estate-wide total)",
                    "reachable": "—", "backup_available": available_text,
                    "filenames": "Not tracked at this grain (pre-archive snapshot only)", "timestamps": "",
                    "report_id": report_id, "report_status": report_status,
                    "report_author": report_author,
                })
                _cell(ws, row_i, LEFT, "(estate-wide total)", Theme.font(9), bg=Theme.CARD, bordered=True)
                _chip(ws, row_i, LEFT + 1, "—", None)
                _chip(ws, row_i, LEFT + 2, available_text, available_band)
                _cell(ws, row_i, LEFT + 3, "Not tracked at this grain (pre-archive snapshot only)",
                     Theme.font(9, False, Theme.GREY), bg=Theme.CARD, bordered=True)
                _cell(ws, row_i, LEFT + 4, "", Theme.font(9, False, Theme.GREY), bg=Theme.CARD, bordered=True)

            row_i += 1
            _blank_row(ws, row_i)
            day += datetime.timedelta(days=1)

        ws.freeze_panes = None

        buf = io.BytesIO()
        wb.save(buf)

    days_count = (date_to - date_from).days + 1
    return buf.getvalue(), days_count, no_backup_count, no_report_count, rows


def default_backup_history_filename(when=None) -> str:
    import datetime as _dt

    when = when or _dt.datetime.now()
    return f"Backup History Report - {when:%Y-%m-%d %H%M}.xlsx"


def mark_xlsx_download(response):
    """Sets the short-lived cookie static/js/app.js's download-spinner polls for (2026-10-06,
    on request: "the system acts as if nothing is happening... we need an actual spinner" --
    see that file's own comment for why a plain cookie-poll, not a JS event, is the only
    reliable way to detect a form-POST-triggered file download reaching the browser). Call on
    every xlsx HttpResponse right before returning it. 20s max-age matches the JS poll's own
    give-up timeout -- stale on purpose, so a cookie left over from an aborted/slow previous
    download can never be mistaken for the current one finishing instantly."""
    response.set_cookie("xlsx_dl_done", "1", max_age=20, path="/", samesite="Lax")
    return response

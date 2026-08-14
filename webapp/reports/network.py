"""Network Admin Report — phase 1.

The admins specified the metrics they want. Most are not being collected yet, so this
module does two things at once: it renders what IS there, and it states plainly what is
not, with the reason and what collecting it would take.

WHY IT IS BUILT THAT WAY
    A report that silently omits the metrics it cannot get looks complete. A network admin
    would read "no errors" off an Errors panel that is empty because nothing counts errors,
    and that is worse than no panel at all — it is a false all-clear on the exact question
    they asked. So every requested metric appears, and every one carries its state.

WHAT IS ACTUALLY COLLECTED TODAY
    The `snmp` job polls one device (the core switch) with snmp_exporter's `if_mib_v3`
    module, which yields exactly three series of interest:

        ifOperStatus   per-interface link state       (1 up, 2 down)
        ifInOctets     32-bit inbound byte counter
        ifOutOctets    32-bit outbound byte counter

    Nothing else the admins listed is polled: no CPU, memory, uptime, temperature, fans or
    PSU (vendor MIBs, not IF-MIB), no error or discard counters, no ifHighSpeed, no
    ifAdminStatus, no BGP/OSPF, no connection counts, no wireless client counts.

TWO LIMITS THAT AFFECT THE NUMBERS ON SCREEN, NOT JUST THE GAPS
    * 32-bit counters wrap, and EVERY wrap loses traffic. ifInOctets holds 4.29 GB before
      rolling over — of the order of 35-50 s on the busiest port here (it runs near 1 Gbps
      line rate; the page computes the exact figure from the live peak),
      against a 15 s scrape interval. rate() handles the rollover the only way it can: it
      sees the value drop, assumes a counter restart at zero, and discards everything the
      counter held above that point. And if enough traffic passes that the counter lands
      HIGHER than where it started, there is no drop to detect at all and a full 4.29 GB
      disappears with nothing to signal it. Note this is not the "multiple wraps between
      scrapes" edge case people usually cite — a single wrap already under-reports. This is
      exactly what the 64-bit ifHC* counters exist to fix, which is why the admins asked for
      them by name. Until they are polled, throughput here is a floor, not a measurement.
    * There is no ifHighSpeed, so percentage utilisation cannot be derived at all. A port
      doing 900 Mbps is either bored or saturated depending on whether it is a 10 G or a
      1 G link, and nothing collected today distinguishes them.
"""
from __future__ import annotations

import time
from typing import Dict, Optional

import generate_report as gr

# How far back the throughput rate is averaged. Long enough to survive a missed scrape,
# short enough to still reflect the current load.
RATE_WINDOW = "5m"

# The `snmp` job declares no scrape_interval of its own, so it inherits Prometheus's global
# 15s. Used only to say how often the 32-bit counters wrap relative to sampling. If the
# server's global interval changes, change this — it is a statement about the scrape config,
# which this app cannot read.
SCRAPE_INTERVAL = 15

# The device count is small today (one core switch) but the interface count is not, so the
# tables show the busiest and the broken rather than all 311 rows.
TOP_INTERFACES = 15


# ---------------------------------------------------------------------------------------
#  The catalogue: every metric the network admins asked for, and its state.
#
#  `promql` is filled in for what is live. For what is not, `needs` says what would have to
#  change to collect it — these are the phase-2 work items, written where they cannot drift
#  away from the report that reveals the gap.
# ---------------------------------------------------------------------------------------
CATALOGUE = [
    # ---- 1. System & Hardware Health --------------------------------------------------
    dict(section="System & Hardware Health", name="CPU usage",
         what="How hard the device's processor is working. High CPU causes slow performance "
              "or lost connections.",
         state="missing", oid="—",
         needs="A vendor MIB module. CPU is not in IF-MIB: Cisco exposes it via "
               "CISCO-PROCESS-MIB (cpmCPUTotal5minRev), other vendors differ. Needs a new "
               "snmp_exporter module built for this switch's vendor."),
    dict(section="System & Hardware Health", name="Memory (RAM)",
         what="How much memory is in use. High memory usage can cause memory leaks or "
              "device crashes.",
         state="missing", oid="—",
         needs="Vendor MIB, as above (CISCO-MEMORY-POOL-MIB or equivalent)."),
    dict(section="System & Hardware Health", name="Device uptime",
         what="How long the device has been powered on. Helps detect unexpected reboots.",
         state="missing", oid="sysUpTime",
         needs="The cheapest gap to close: sysUpTime is standard SNMPv2-MIB, available on "
               "every device, and only needs adding to the module's walk."),
    dict(section="System & Hardware Health", name="Temperature & fans",
         what="Internal heat levels and fan speeds, to prevent hardware burnouts.",
         state="missing", oid="entPhySensorValue",
         needs="ENTITY-SENSOR-MIB is the standard route and is widely supported; some "
               "vendors only populate their own MIB."),
    dict(section="System & Hardware Health", name="Power supplies",
         what="Whether redundant power sources are working.",
         state="missing", oid="entPhySensorValue / vendor",
         needs="ENTITY-MIB / ENTITY-SENSOR-MIB, or the vendor's environment MIB."),

    # ---- 2. Interface Performance & Bandwidth -----------------------------------------
    dict(section="Interface Performance & Bandwidth", name="Inbound traffic",
         what="Data arriving on each interface.",
         state="degraded", oid="ifInOctets (32-bit)",
         promql="rate(ifInOctets[%s]) * 8" % RATE_WINDOW,
         needs="Collected, but from the 32-bit counter, which wraps in well under a "
               "minute at this switch's observed rates — see the traffic panel for the "
               "figure computed from the current peak. Every wrap loses traffic, so what "
               "is shown is a FLOOR. Poll the 64-bit ifHCInOctets instead — the admins "
               "asked for it by name."),
    dict(section="Interface Performance & Bandwidth", name="Outbound traffic",
         what="Data leaving each interface.",
         state="degraded", oid="ifOutOctets (32-bit)",
         promql="rate(ifOutOctets[%s]) * 8" % RATE_WINDOW,
         needs="As above — switch to ifHCOutOctets."),
    dict(section="Interface Performance & Bandwidth", name="Port speed",
         what="The interface's maximum capacity, used with traffic to give a percentage.",
         state="missing", oid="ifHighSpeed",
         needs="Without it there is no denominator, so no % utilisation anywhere in this "
               "report. In IF-MIB and trivial to add."),
    dict(section="Interface Performance & Bandwidth", name="Operational status",
         what="Whether a port is physically up or down.",
         state="live", oid="ifOperStatus", promql="ifOperStatus"),
    dict(section="Interface Performance & Bandwidth", name="Admin status",
         what="Whether a port was deliberately enabled or disabled by an admin.",
         state="missing", oid="ifAdminStatus",
         needs="In IF-MIB alongside ifOperStatus. Without it a down port cannot be told "
               "from a deliberately shut one, so every shut port reads as a fault."),
    dict(section="Interface Performance & Bandwidth", name="Interface errors",
         what="Bad packets from faulty cables or hardware.",
         state="missing", oid="ifInErrors / ifOutErrors",
         needs="In IF-MIB. The Errors panel is empty because nothing counts them — not "
               "because there are none."),
    dict(section="Interface Performance & Bandwidth", name="Interface discards",
         what="Packets dropped when the port buffer overflows — congestion.",
         state="missing", oid="ifInDiscards / ifOutDiscards",
         needs="In IF-MIB, same walk as the error counters."),

    # ---- 3. Protocol & Network State ---------------------------------------------------
    dict(section="Protocol & Network State", name="Routing status (BGP / OSPF)",
         what="Whether sessions to other networks or ISPs are alive.",
         state="missing", oid="bgpPeerState / ospfNbrState",
         needs="BGP4-MIB / OSPF-MIB modules. Only meaningful on devices that route — the "
               "core switch may not, so confirm which devices these belong to."),
    dict(section="Protocol & Network State", name="Active connections",
         what="Firewall and VPN connection counts, to catch a device being overwhelmed.",
         state="missing", oid="vendor firewall MIB",
         needs="A firewall is not in scope yet: only the core switch is polled. Needs the "
               "firewall added as an SNMP target first."),
    dict(section="Protocol & Network State", name="Connected devices (Wi-Fi)",
         what="How many users are on each wireless access point.",
         state="missing", oid="vendor wireless MIB",
         needs="No wireless controller is polled yet. Needs the WLC added as a target."),
]


class NetworkUnavailable(RuntimeError):
    """Prometheus itself could not be reached."""


def _prometheus():
    cfg = gr.load_config()
    try:
        from .models import SystemConfig
        sc = SystemConfig.get()
        if sc.prometheus_url:
            cfg.prom = sc.prometheus_url
    except Exception:                       # noqa: BLE001
        pass
    return gr.Prometheus(cfg.prom, cfg.http_timeout, getattr(cfg, "verify_tls", True)), cfg.prom


def _fmt_bps(bits: Optional[float]) -> str:
    if bits is None:
        return "—"
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if abs(bits) < 1000 or unit == "Gbps":
            return f"{bits:.0f} {unit}" if unit == "bps" else f"{bits:.1f} {unit}"
        bits /= 1000.0
    return f"{bits:.1f} Gbps"


def _iface_label(labels: Dict[str, str]) -> str:
    """What to call an interface.

    ifDescr is not collected, so there is nothing to call it but its index. Said plainly —
    "ifIndex 103" is at least honestly unhelpful, where "Interface 103" would imply a name
    the report does not actually have.
    """
    for key in ("ifDescr", "ifAlias", "ifName"):
        if labels.get(key):
            return labels[key]
    idx = labels.get("ifIndex", "?")
    return f"ifIndex {idx}"


def collect(only: Optional[set] = None) -> dict:
    """Gather the report. `only` is a set of DEVICE KEYS, scoping it to the admin's choice.

    Scoping happens on the `instance` label rather than by filtering after the fact, so a
    report that says it covers the core switch cannot quietly include a second device that
    happens to share the SNMP job.
    """
    prom, prom_url = _prometheus()
    wanted = None
    if only is not None:
        wanted = {d["target"] for d in DEVICES if d["key"] in only}

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                   # noqa: BLE001 — a missing metric is not fatal
            return []

    try:
        prom.query("vector(1)")
    except Exception as exc:                # noqa: BLE001
        raise NetworkUnavailable(f"{prom_url}: {exc}") from exc

    oper = q("ifOperStatus")
    if wanted is not None:
        oper = [r for r in oper if r["labels"].get("instance") in wanted]
    def _rates(expr):
        # Keyed by (instance, ifIndex): ifIndex is only unique WITHIN a device, so keying on
        # it alone would blend two switches' port 1 the moment a second device is onboarded.
        out = {}
        for r in q(expr):
            inst = r["labels"].get("instance")
            if wanted is not None and inst not in wanted:
                continue
            out[(inst, r["labels"].get("ifIndex"))] = r["value"] * 8
        return out

    rate_in = _rates(f"rate(ifInOctets[{RATE_WINDOW}])")
    rate_out = _rates(f"rate(ifOutOctets[{RATE_WINDOW}])")

    devices = sorted({r["labels"].get("instance", "") for r in oper if r["labels"].get("instance")})
    system = next((r["labels"].get("system") for r in oper if r["labels"].get("system")), "")

    interfaces = []
    for r in oper:
        lbl = r["labels"]
        idx = (lbl.get("instance"), lbl.get("ifIndex"))
        status = int(r["value"])
        interfaces.append({
            "index": lbl.get("ifIndex"),
            "name": _iface_label(lbl),
            "device": lbl.get("instance", ""),
            # IF-MIB ifOperStatus: 1 up, 2 down, 3 testing, 4 unknown, 5 dormant,
            # 6 notPresent, 7 lowerLayerDown. Anything but 1 is not carrying traffic.
            "status": status,
            "up": status == 1,
            "status_text": {1: "up", 2: "down", 3: "testing", 4: "unknown",
                            5: "dormant", 6: "not present", 7: "lower layer down"}.get(status, str(status)),
            "in_bps": rate_in.get(idx),
            "out_bps": rate_out.get(idx),
            "in_text": _fmt_bps(rate_in.get(idx)),
            "out_text": _fmt_bps(rate_out.get(idx)),
            "total_bps": (rate_in.get(idx) or 0) + (rate_out.get(idx) or 0),
        })

    up = [i for i in interfaces if i["up"]]
    down = [i for i in interfaces if not i["up"]]
    busiest = sorted((i for i in up if i["total_bps"]), key=lambda i: -i["total_bps"])[:TOP_INTERFACES]
    carrying = [i for i in up if i["total_bps"] > 0]

    # Bar geometry belongs here, not in the template. Template arithmetic has bitten this
    # codebase before (a chart that rendered 1000px tall from `{{ rows|length }}00px`).
    #
    # The scale is RELATIVE, and must be labelled as such on the page: with no ifHighSpeed
    # there is no capacity to be a share OF, so a full bar means "the heaviest thing here",
    # never "saturated".
    #
    # Bars are scaled against the largest SINGLE-DIRECTION figure among the rows shown, not
    # against the busiest port's in+out total. Scaling to the total means no individual bar
    # can ever reach full width (the busiest port's own two bars merely sum to it), so the
    # visual maximum is a length nothing occupies and every bar reads shorter than it should.
    # With this denominator the longest bar is exactly full, and "full" has a stated meaning:
    # the heaviest single direction on the busiest ports.
    bar_max = max((max(i["in_bps"] or 0, i["out_bps"] or 0) for i in busiest), default=0)
    total_peak = busiest[0]["total_bps"] if busiest else 0
    for i in busiest:
        i["in_pct"] = round(((i["in_bps"] or 0) / bar_max) * 100, 1) if bar_max else 0
        i["out_pct"] = round(((i["out_bps"] or 0) / bar_max) * 100, 1) if bar_max else 0
        # The table column is a different question — how this port's TOTAL load compares to
        # the busiest port's total — so it keeps the total-based denominator.
        i["share_pct"] = round((i["total_bps"] / total_peak) * 100, 1) if total_peak else 0

    # Down ports are only worth listing while ifAdminStatus is missing — with it, the list
    # would be "down but NOT administratively shut", which is the actionable subset. Say so
    # rather than presenting 65 rows as if they were all faults.
    down_sorted = sorted(down, key=lambda i: int(i["index"]) if str(i["index"]).isdigit() else 0)

    # How long a 32-bit octet counter survives at the fastest rate actually observed here.
    # Computed, never hardcoded: the peak moves with the traffic, and a stale constant on a
    # page whose whole point is "this number is under-reported" would be its own small lie.
    #   2^32 bytes = 4.295 GB. seconds-to-wrap = 4.295e9 / bytes-per-second.
    peak_bps = max((max(i["in_bps"] or 0, i["out_bps"] or 0) for i in interfaces), default=0)
    wrap_seconds = (2 ** 32) / (peak_bps / 8) if peak_bps else None

    live = sum(1 for m in CATALOGUE if m["state"] == "live")
    degraded = sum(1 for m in CATALOGUE if m["state"] == "degraded")
    missing = sum(1 for m in CATALOGUE if m["state"] == "missing")

    return {
        "ok": True,
        "now": time.time(),
        "now_text": time.strftime("%d %b %Y, %H:%M:%S"),
        "prom_url": prom_url,
        "rate_window": RATE_WINDOW,
        "devices": devices,
        "device_count": len(devices),
        # the inventory entries actually covered, so the report can name them
        "device_rows": [d for d in DEVICES
                        if (only is None or d["key"] in only) and d["target"] in set(devices)],
        "system": system,
        "interfaces": interfaces,
        "iface_count": len(interfaces),
        "up_count": len(up),
        "down_count": len(down),
        "carrying_count": len(carrying),
        "busiest": busiest,
        "down_ports": down_sorted,
        "top_n": TOP_INTERFACES,
        "total_in_bps": sum(i["in_bps"] or 0 for i in interfaces),
        "total_out_bps": sum(i["out_bps"] or 0 for i in interfaces),
        "total_in_text": _fmt_bps(sum(i["in_bps"] or 0 for i in interfaces)),
        "total_out_text": _fmt_bps(sum(i["out_bps"] or 0 for i in interfaces)),
        "catalogue": CATALOGUE,
        "count_live": live,
        "count_degraded": degraded,
        "count_missing": missing,
        "count_total": len(CATALOGUE),
        "peak_bps_text": _fmt_bps(peak_bps),
        "wrap_seconds": round(wrap_seconds) if wrap_seconds else None,
        "scrape_interval_s": SCRAPE_INTERVAL,
        # How many scrapes the counter survives on the busiest port. Not a safety margin:
        # EVERY wrap loses traffic regardless of where it lands relative to a scrape (see
        # the module docstring), so this only says how OFTEN the loss happens.
        "wraps_per_scrapes": (round(wrap_seconds / SCRAPE_INTERVAL, 1)
                              if wrap_seconds else None),
        # No ifDescr is collected, so every interface is a bare number. Worth stating on the
        # page: it is the difference between a usable report and a puzzle.
        "has_names": any(i["name"] and not i["name"].startswith("ifIndex") for i in interfaces),
    }


# ---------------------------------------------------------------------------------------
#  The device inventory behind the Network Analyses Dashboard.
#
#  The systems picker reads its list from systems_config.yml. Network devices have no such
#  file yet, so the inventory is declared here — one entry, the core switch, which is the
#  only device under monitoring today. Written as a LIST rather than a constant so adding
#  the firewall or the wireless controller later is an append, not a rewrite.
#
#  `system` is the label the SNMP job attaches (see the `snmp` job in prometheus.yml). It is
#  deliberately NOT a system in systems_config.yml: the business-systems picker and this one
#  answer different questions, and a switch appearing among RTGS and Temenos would be a
#  category error on the systems admin's screen.
# ---------------------------------------------------------------------------------------
DEVICES = [
    {
        "key": "core-switch",
        "name": "Core Switch",
        "kind": "Switch",
        "target": "10.100.210.253",
        "system": "RBZ Network",
        "module": "if_mib_v3",
        "report": "network_report",
    },
]


def device_inventory() -> list:
    """The devices for the picker, each with its live reachability and interface count.

    Reachability comes from Prometheus's own `up` for the snmp job rather than from whether
    any metric happens to exist: a device that stopped answering keeps its last series for a
    while, so "has data" and "is being scraped successfully" are not the same claim.
    """
    prom, prom_url = _prometheus()

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                   # noqa: BLE001
            return []

    up_by_target = {r["labels"].get("instance", ""): r["value"] for r in q('up{job="snmp"}')}
    counts, ups = {}, {}
    for r in q("ifOperStatus"):
        inst = r["labels"].get("instance", "")
        counts[inst] = counts.get(inst, 0) + 1
        if int(r["value"]) == 1:
            ups[inst] = ups.get(inst, 0) + 1

    out = []
    for d in DEVICES:
        t = d["target"]
        scraped = up_by_target.get(t)
        out.append(dict(d,
                        reachable=(scraped == 1.0),
                        # None (not 0) when Prometheus has no `up` for it at all — "unknown"
                        # and "down" are different answers and must not render alike.
                        known=(scraped is not None),
                        iface_count=counts.get(t, 0),
                        iface_up=ups.get(t, 0)))
    return out


# =======================================================================================
#  The Network Admin Report as a SNAPSHOT — the same shape the systems flow uses.
#
#  The systems report renders reports/form.html from a Snapshot of SystemVMs, each carrying
#  FlagVMs. Rather than write a second annotation screen, the network flow builds the same
#  objects from network data and renders the same template: one device is one "system", its
#  faults are its flags. The admin gets the identical screen with network names in it.
#
#  The flags below are derived ONLY from what is actually collected. Nothing here invents a
#  band for a metric that is not polled — an amber row for "CPU unknown" would put a fault on
#  screen that no measurement supports.
# =======================================================================================
def _device_flags(dev: dict, data: dict) -> list:
    """The flagged items for one device, worst first.

    `band` is "red" (immediate) or "amber" (watch), matching the systems report exactly so
    the counts, chips and colours all behave without special-casing.
    """
    from .services import FlagVM

    flags = []
    ifaces = [i for i in data["interfaces"] if i["device"] == dev["target"]]

    if not dev.get("known"):
        flags.append(FlagVM("snmp_unscraped", f"{dev['name']} has never been scraped by Prometheus",
                            "red", "unreachable"))
    elif not dev.get("reachable"):
        flags.append(FlagVM("snmp_down", f"{dev['name']} is not answering SNMP", "red", "unreachable"))

    down = [i for i in ifaces if not i["up"]]
    if down:
        # AMBER, not red. Without ifAdminStatus a deliberately shut port looks exactly like a
        # failed one, and on a 311-port switch most of these are simply unused. Calling that
        # an incident every day is how a report teaches people to ignore it.
        flags.append(FlagVM(
            "links_down",
            f"{len(down)} of {len(ifaces)} interfaces are not up "
            f"(admin status is not collected, so shut ports cannot be told from failed ones)",
            "amber", "service"))

    # The counter-width problem is a defect in the MEASUREMENT, and belongs on the report as
    # one — an admin reading these numbers has to know they are a floor.
    if data.get("wrap_seconds"):
        flags.append(FlagVM(
            "counter_width",
            f"Throughput is under-reported: the 32-bit octet counters wrap about every "
            f"{data['wrap_seconds']}s at the current peak of {data['peak_bps_text']}. "
            f"Poll ifHCInOctets/ifHCOutOctets to fix it.",
            "amber", "untracked"))

    missing = [m["name"] for m in CATALOGUE if m["state"] == "missing"]
    if missing:
        flags.append(FlagVM(
            "metrics_missing",
            f"{len(missing)} of {len(CATALOGUE)} requested metrics are not collected: "
            + ", ".join(missing[:4]) + ("…" if len(missing) > 4 else ""),
            "amber", "untracked"))
    return flags


def _network_overview(data: dict, devices: list) -> dict:
    """The at-a-glance / immediate / watch bands, in the shape reports/form.html renders.

    Same three-band layout as the systems overview so the screen is genuinely the same one,
    with the rows that a network estate actually has.
    """
    unreachable = [d for d in devices if d.get("known") and not d.get("reachable")]
    unscraped = [d for d in devices if not d.get("known")]
    down = data["down_count"]
    missing = sum(1 for m in CATALOGUE if m["state"] == "missing")
    bad = lambda n: "good" if not n else "bad"
    warn = lambda n: "good" if not n else "warn"
    return {
        "glance": [
            {"label": "Devices", "value": len(devices), "state": "info"},
            {"label": "Interfaces", "value": data["iface_count"], "state": "info"},
            {"label": "Links up", "value": data["up_count"], "state": "info"},
            {"label": "Carrying traffic", "value": data["carrying_count"], "state": "info"},
            {"label": "Throughput in", "value": data["total_in_text"], "state": "info"},
        ],
        "immediate": [
            {"label": "Not responding", "value": len(unreachable), "state": bad(len(unreachable))},
            {"label": "Never scraped", "value": len(unscraped), "state": bad(len(unscraped))},
        ],
        "watch": [
            {"label": "Links not up", "value": down, "sub": "interfaces", "state": warn(down)},
            {"label": "Metrics not collected", "value": missing,
             "sub": f"of {len(CATALOGUE)} requested", "state": warn(missing)},
            {"label": "Counter width", "value": "32-bit", "sub": "under-reports throughput",
             "state": "warn"},
        ],
        "banners": [],
    }


def capture_snapshot(token: str, only: Optional[set] = None):
    """A Snapshot of the selected network devices, interchangeable with the systems one.

    Raises NetworkUnavailable when Prometheus cannot be reached, mirroring
    services.capture_snapshot raising PrometheusUnavailable — the view handles them the same.
    """
    import datetime

    from .services import Snapshot, SystemVM

    data = collect(only=only)
    rows = data["device_rows"] or [d for d in DEVICES if only is None or d["key"] in only]
    inv = {d["target"]: d for d in device_inventory() if only is None or d["key"] in only}

    svms = []
    for dev in rows:
        live = inv.get(dev["target"], dict(dev, known=False, reachable=False))
        svms.append(SystemVM(name=dev["name"],
                             hosts=len([i for i in data["interfaces"] if i["device"] == dev["target"]]),
                             flags=_device_flags(live, data)))

    snap = Snapshot(
        token=token,
        captured_at=datetime.datetime.now(),
        prom_url=data["prom_url"],
        systems=svms,
        overview=_network_overview(data, list(inv.values())),
    )
    # carried for the report screen and for generation; the systems flow parks its engine
    # objects on the same attributes.
    snap._store = data
    snap._systems = rows
    return snap


def network_report_filename(theme: str = "dark", when=None) -> str:
    """Named like the systems report, theme and all, so the two sit together in a folder."""
    import datetime
    when = when or datetime.datetime.now()
    return f"Network Admin Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def build_report(snapshot, *, theme: str = "dark", author: str,
                 annotations: dict, summary_comment: str) -> bytes:
    """Render the network report as .xlsx, in the SAME theme as the systems report.

    Written directly rather than through gr.build_report_bytes: that builder reads the
    engine's Store — node_exporter disks, windows services, certificates — none of which a
    switch has, and feeding it a fabricated Store to borrow the layout would mean inventing
    the very fields this report exists to say are missing.

    The COLOURS, though, are not reinvented. They come from gr.PALETTES via gr.palette(), the
    same swap the systems build uses, so "dark" and "light" mean exactly one thing in this app
    and an adjustment to either palette reaches both reports without being copied across.
    """
    import io

    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side

    if theme not in gr.PALETTES:
        theme = "dark"

    with gr.palette(theme):
        T = gr.Theme
        # openpyxl wants RRGGBB; the engine stores its colours as 00RRGGBB
        rgb = lambda c: str(c)[-6:]
        BG, CARD, HDR = rgb(T.BG), rgb(T.CARD), rgb(T.HDR)
        BORDER, INK, GREY = rgb(T.BORDER), rgb(T.WHITE), rgb(T.GREY)
        CYAN, SUB = rgb(T.CYAN), rgb(T.SUB)
        CHIP = {k: (rgb(v[0]), rgb(v[1])) for k, v in T.CHIP.items()}

        edge = Side(style="thin", color=BORDER)
        box = Border(left=edge, right=edge, top=edge, bottom=edge)
        page = PatternFill("solid", fgColor=BG)
        card = PatternFill("solid", fgColor=CARD)
        head = PatternFill("solid", fgColor=HDR)

        wb = Workbook()
        ws = wb.active
        ws.title = "Network Admin Report"
        ws.sheet_view.showGridLines = False
        ws.sheet_properties.tabColor = CYAN
        for col, width in zip("ABCDEF", (34, 15, 62, 12, 34, 4)):
            ws.column_dimensions[col].width = width

        LAST = 6

        def paint(row):
            """Fill the row with the page colour.

            The canvas is painted rather than left to Excel's default white: on the dark
            theme an unpainted sheet frames the report in white and the whole thing reads as
            broken. The systems report paints for the same reason.
            """
            for c in range(1, LAST + 1):
                ws.cell(row, c).fill = page

        r = 1
        paint(r)
        ws.cell(r, 1, "NETWORK ADMIN REPORT").font = Font(bold=True, size=16, color=CYAN)
        r += 1
        paint(r)
        ws.cell(r, 1, snapshot.captured_at.strftime("Captured %d %b %Y at %H:%M")).font = Font(color=SUB, size=10)
        r += 1
        paint(r)
        ws.cell(r, 1, f"By {author}").font = Font(color=SUB, size=10)
        r += 1
        paint(r)
        r += 1

        def band(title, rows):
            nonlocal r
            paint(r)
            ws.cell(r, 1, title.upper()).font = Font(bold=True, size=10, color=INK)
            for c in range(1, LAST):
                ws.cell(r, c).fill = head
                ws.cell(r, c).border = box
            r += 1
            for item in rows:
                paint(r)
                for c in range(1, LAST):
                    ws.cell(r, c).fill = card
                ws.cell(r, 1, item["label"]).font = Font(color=GREY, size=10)
                v = ws.cell(r, 2, item["value"])
                v.font = Font(bold=True, size=10,
                              color={"bad": CHIP["red"][0], "warn": CHIP["amber"][0],
                                     "good": CHIP["green"][0]}.get(item.get("state"), INK))
                if item.get("sub"):
                    ws.cell(r, 3, item["sub"]).font = Font(color=SUB, size=9)
                r += 1
            paint(r)
            r += 1

        ov = snapshot.overview or {}
        band("At a glance", ov.get("glance", []))
        band("Immediate attention", ov.get("immediate", []))
        band("Watch list", ov.get("watch", []))

        for sysvm in snapshot.systems:
            paint(r)
            ws.cell(r, 1, sysvm.name.upper()).font = Font(bold=True, size=12, color=CYAN)
            ws.cell(r, 2, f"{sysvm.hosts} interfaces").font = Font(color=SUB, size=10)
            r += 1

            paint(r)
            for label, col in (("Finding", 1), ("Band", 2), ("Detail", 3),
                               ("Fixed?", 4), ("Comment", 5)):
                h = ws.cell(r, col, label)
                h.font = Font(bold=True, size=9, color=SUB)
                h.fill = head
                h.border = box
            r += 1

            ann = annotations.get(sysvm.name, {})
            if not sysvm.flags:
                paint(r)
                ws.cell(r, 1, "No findings — every collected metric is within limits").font = Font(
                    color=CHIP["green"][0], size=10)
                r += 1
            for flag in sysvm.flags:
                paint(r)
                fg, bgc = CHIP["red" if flag.band == "red" else "amber"]
                for col in range(1, 6):
                    cell = ws.cell(r, col)
                    cell.fill = card
                    cell.border = box
                ws.cell(r, 1, flag.key).font = Font(color=GREY, size=10)
                b = ws.cell(r, 2, "Immediate" if flag.band == "red" else "Watch")
                b.font = Font(bold=True, size=10, color=fg)
                b.fill = PatternFill("solid", fgColor=bgc)
                d = ws.cell(r, 3, flag.text)
                d.font = Font(color=INK, size=10)
                d.alignment = Alignment(wrap_text=True, vertical="top")
                ws.cell(r, 4, ann.get("flags", {}).get(flag.key, "")).font = Font(size=10, color=INK)
                r += 1
            if ann.get("comment"):
                paint(r)
                for col in range(1, 6):
                    ws.cell(r, col).fill = card
                ws.cell(r, 1, "Comment").font = Font(bold=True, size=9, color=SUB)
                cm = ws.cell(r, 3, ann["comment"])
                cm.font = Font(color=INK, size=10)
                cm.alignment = Alignment(wrap_text=True, vertical="top")
                r += 1
            paint(r)
            r += 1

        if summary_comment:
            paint(r)
            ws.cell(r, 1, "SUMMARY").font = Font(bold=True, size=10, color=INK)
            r += 1
            paint(r)
            sc = ws.cell(r, 1, summary_comment)
            sc.font = Font(color=INK, size=10)
            sc.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
            r += 2

        # The caveats belong IN the artifact. A spreadsheet outlives the screen it was made on,
        # and these numbers are wrong in a specific, knowable way its reader has to be told.
        paint(r)
        ws.cell(r, 1, "HOW TO READ THESE NUMBERS").font = Font(bold=True, size=10, color=INK)
        r += 1
        for line in (
            "Throughput is a FLOOR, not a measurement: only 32-bit octet counters are polled "
            "and every counter wrap loses traffic.",
            "No percentage utilisation appears anywhere - port speed (ifHighSpeed) is not "
            "collected, so there is no capacity to compare against.",
            "Interfaces are identified by index because ifDescr is not collected.",
            "Ports that are not up cannot be told apart from ports an admin deliberately shut "
            "(ifAdminStatus is not collected).",
        ):
            paint(r)
            cell = ws.cell(r, 1, "• " + line)
            cell.font = Font(color=SUB, size=9)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
            ws.row_dimensions[r].height = 26
            r += 1

        # a painted margin below the content, so the themed canvas does not stop mid-page
        for _ in range(8):
            paint(r)
            r += 1

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()

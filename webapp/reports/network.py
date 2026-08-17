"""Network Admin Report — phase 2.

The admins specified the metrics they want. This module does two things at once: it
renders what IS there, and it states plainly what is not, with the reason and what
collecting it would take.

WHY IT IS BUILT THAT WAY
    A report that silently omits the metrics it cannot get looks complete. A network admin
    would read "no errors" off an Errors panel that is empty because nothing counts errors,
    and that is worse than no panel at all — it is a false all-clear on the exact question
    they asked. So every requested metric appears, and every one carries its state.

WHAT IS ACTUALLY COLLECTED TODAY (phase 2 — the exporter is a real service now)
    The core switch (a Cisco Catalyst 9400 stack, IOS-XE 17.9.4a) is polled with
    snmp_exporter's stock `if_mib` + `cisco_device` + `system` modules, plus two modules
    added this phase (`ospf_nbr`, `table_capacity`) for what those didn't cover:

        ifOperStatus / ifAdminStatus      per-interface link + admin state
        ifHCInOctets / ifHCOutOctets      64-bit counters (no wrap at this switch's rates)
        ifHighSpeed                       capacity, so % utilisation is real, not guessed
        ifInErrors/Discards, ifOut...     rate()'d, never a raw counter
        ifDescr / ifName (as labels)      real interface names, not bare index numbers
        cpmCPUTotal5minRev, ciscoMemoryPoolUsed/Free, sysUpTime
        entSensorValue                    filtered by entSensorType: 8=celsius (temperature),
                                          14=dBm (optical Tx/Rx power, /100 — see collect())
        cefcFRUPowerOperStatus            PSU/fan/linecard/supervisor state (EnumAsStateSet —
                                          see collect() for why it needs `== 1` filtering)
        ospfNbrState / ospfNbrEvents      OSPF neighbour adjacency (confirmed live: 3
                                          neighbours, all Full, across many VLANs)
        dot1dTpFdbPort, ipNetToMediaIfIndex   MAC / ARP table entry counts (count() at query
                                              time — no per-table hardware MAX from SNMP, so
                                              % used is not computed)

    Confirmed genuinely NOT applicable, not just uncollected: BGP (bgpLocalAs=0, walked
    directly via BGP4-MIB — this device does not speak BGP). Still genuinely missing, and
    would need real new infrastructure, not just a module: firewall/VPN connection counts
    (no firewall onboarded), Wi-Fi client counts (no WLC onboarded), PoE budget, config
    backup/lifecycle, licence/EOL tracking, and NetFlow.
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
               "snmp_exporter module built for this switch's vendor.",
         probe="cpmCPUTotal5minRev"),
    dict(section="System & Hardware Health", name="Memory (RAM)",
         what="How much memory is in use. High memory usage can cause memory leaks or "
              "device crashes.",
         state="missing", oid="—",
         needs="Vendor MIB, as above (CISCO-MEMORY-POOL-MIB or equivalent).",
         probe="ciscoMemoryPoolUsed"),
    dict(section="System & Hardware Health", name="Device uptime",
         what="How long the device has been powered on. Helps detect unexpected reboots.",
         state="missing", oid="sysUpTime",
         needs="The cheapest gap to close: sysUpTime is standard SNMPv2-MIB, available on "
               "every device, and only needs adding to the module's walk.",
         probe="sysUpTime"),
    dict(section="System & Hardware Health", name="Temperature",
         what="Internal heat levels, to prevent hardware burnouts.",
         state="missing", oid="entPhySensorValue",
         needs="Confirmed live via ENTITY-SENSOR-MIB (entSensorType=8, celsius).",
         probe="entSensorValue"),
    dict(section="Interface Performance & Bandwidth", name="Optical Tx/Rx power",
         what="Per-interface transceiver signal strength — a slow decline warns of a "
              "failing optic before the link actually drops.",
         state="missing", oid="entPhySensorValue (entSensorType=14, dBm)",
         needs="Confirmed live via the SAME ENTITY-SENSOR-MIB walk as Temperature above "
               "(entSensorType=14 rather than 8) — no separate module needed, only "
               "per-sensor-type filtering on the report side.",
         probe="entSensorValue"),
    dict(section="System & Hardware Health", name="Power supplies & fans",
         what="Whether redundant power sources and fans are working.",
         state="missing", oid="cefcFRUPowerOperStatus",
         needs="Confirmed live via CISCO-ENTITY-FRU-CONTROL-MIB (this platform does not "
               "populate the older CISCO-ENVMON-MIB).",
         probe="cefcFRUPowerOperStatus"),

    # ---- 2. Interface Performance & Bandwidth -----------------------------------------
    dict(section="Interface Performance & Bandwidth", name="Inbound traffic",
         what="Data arriving on each interface.",
         state="degraded", oid="ifInOctets (32-bit)",
         promql="rate(ifInOctets[%s]) * 8" % RATE_WINDOW,
         needs="Collected, but from the 32-bit counter, which wraps in well under a "
               "minute at this switch's observed rates — see the traffic panel for the "
               "figure computed from the current peak. Every wrap loses traffic, so what "
               "is shown is a FLOOR. Poll the 64-bit ifHCInOctets instead — the admins "
               "asked for it by name.",
         probe="ifHCInOctets"),
    dict(section="Interface Performance & Bandwidth", name="Outbound traffic",
         what="Data leaving each interface.",
         state="degraded", oid="ifOutOctets (32-bit)",
         promql="rate(ifOutOctets[%s]) * 8" % RATE_WINDOW,
         needs="As above — switch to ifHCOutOctets.",
         probe="ifHCOutOctets"),
    dict(section="Interface Performance & Bandwidth", name="Port speed",
         what="The interface's maximum capacity, used with traffic to give a percentage.",
         state="missing", oid="ifHighSpeed",
         needs="Without it there is no denominator, so no % utilisation anywhere in this "
               "report. In IF-MIB and trivial to add.",
         probe="ifHighSpeed"),
    dict(section="Interface Performance & Bandwidth", name="Operational status",
         what="Whether a port is physically up or down.",
         state="live", oid="ifOperStatus", promql="ifOperStatus",
         probe="ifOperStatus"),
    dict(section="Interface Performance & Bandwidth", name="Admin status",
         what="Whether a port was deliberately enabled or disabled by an admin.",
         state="missing", oid="ifAdminStatus",
         needs="In IF-MIB alongside ifOperStatus. Without it a down port cannot be told "
               "from a deliberately shut one, so every shut port reads as a fault.",
         probe="ifAdminStatus"),
    dict(section="Interface Performance & Bandwidth", name="Interface errors",
         what="Bad packets from faulty cables or hardware.",
         state="missing", oid="ifInErrors / ifOutErrors",
         needs="In IF-MIB. The Errors panel is empty because nothing counts them — not "
               "because there are none.",
         probe="ifInErrors"),
    dict(section="Interface Performance & Bandwidth", name="Interface discards",
         what="Packets dropped when the port buffer overflows — congestion.",
         state="missing", oid="ifInDiscards / ifOutDiscards",
         needs="In IF-MIB, same walk as the error counters.",
         probe="ifInDiscards"),

    # ---- 3. Protocol & Network State ---------------------------------------------------
    dict(section="Protocol & Network State", name="OSPF adjacencies",
         what="Whether OSPF neighbour relationships to other routing devices are Full.",
         state="missing", oid="ospfNbrState",
         needs="Confirmed live via OSPF-MIB (this device is an L3 switch actively running "
               "OSPF across multiple interfaces).",
         probe="ospfNbrState"),
    dict(section="Protocol & Network State", name="BGP sessions",
         what="Whether sessions to external networks or ISPs (via BGP) are alive.",
         state="missing", oid="bgpPeerState",
         needs="Confirmed NOT configured on this device (bgpLocalAs=0, walked directly via "
               "BGP4-MIB) — not a collection gap. Only relevant if a device that actually "
               "speaks BGP (e.g. an edge router) is added to the estate.",
         probe="bgpPeerState"),
    dict(section="Protocol & Network State", name="MAC / ARP table size",
         what="How full the switch's MAC address and ARP tables are, against their "
              "hardware limits — a table at capacity silently drops new entries.",
         state="missing", oid="dot1dTpFdbTable / ipNetToMediaTable",
         needs="The entry COUNT is confirmed live via BRIDGE-MIB/IP-MIB (count() over the "
               "walked table). The platform's hardware MAX per table is not — that comes "
               "from the vendor datasheet, not SNMP, so % used cannot be computed yet.",
         probe="dot1dTpFdbPort"),
    dict(section="Protocol & Network State", name="Active connections",
         what="Firewall and VPN connection counts, to catch a device being overwhelmed.",
         state="missing", oid="vendor firewall MIB",
         needs="A firewall is not in scope yet: only the core switch is polled. Needs the "
               "firewall added as an SNMP target first.",
         probe=""),
    dict(section="Protocol & Network State", name="Connected devices (Wi-Fi)",
         what="How many users are on each wireless access point.",
         state="missing", oid="vendor wireless MIB",
         needs="No wireless controller is polled yet. Needs the WLC added as a target.",
         probe=""),
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

    ifAlias (the admin's own description of the port, e.g. "-> ISP-A") beats a generated
    name when set, but nobody has labelled a port on this switch yet, so today every
    interface falls through to ifDescr/ifName — the switch's own name for it (e.g.
    "AppGigabitEthernet1/2/0/1"), not a bare index. The ifIndex fallback below only fires if
    even those are absent, which "Interface 103" would wrongly imply is a real name.
    """
    for key in ("ifAlias", "ifDescr", "ifName"):
        if labels.get(key):
            return labels[key]
    idx = labels.get("ifIndex", "?")
    return f"ifIndex {idx}"


def measure_catalogue(q, wanted_targets=None) -> list:
    """The catalogue with each entry's state MEASURED, not declared.

    The states used to be written into the table by hand, which meant the report kept saying
    "not collected" for a metric the day after it started being collected — and a hardcoded
    claim about someone else's Prometheus config is a claim that goes stale silently.

    Each entry names the metric that would prove it present; if the series exist for the
    devices in scope, it is live. `degraded` is reserved for the one case where the data is
    there but known-wrong: 32-bit octet counters standing in for the 64-bit pair.
    """
    out = []
    for m in CATALOGUE:
        probe = m.get("probe") or ""
        present = False
        if probe:
            rows = q(probe)
            if wanted_targets is not None:
                rows = [r for r in rows if r["labels"].get("instance") in wanted_targets]
            present = bool(rows)
        entry = dict(m)
        if present:
            entry["state"] = "live"
        elif m["name"] in ("Inbound traffic", "Outbound traffic"):
            # the 64-bit counter is absent; fall back to the 32-bit one and say it is a floor
            legacy = "ifInOctets" if "Inbound" in m["name"] else "ifOutOctets"
            rows = q(legacy)
            if wanted_targets is not None:
                rows = [r for r in rows if r["labels"].get("instance") in wanted_targets]
            entry["state"] = "degraded" if rows else "missing"
        else:
            entry["state"] = "missing"
        out.append(entry)
    return out


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

    # 64-bit first. The 32-bit pair wraps in ~35s on a saturated 1G port and every wrap loses
    # traffic, so it is a fallback that has to announce itself — never a silent equivalent.
    rate_in = _rates(f"rate(ifHCInOctets[{RATE_WINDOW}])")
    rate_out = _rates(f"rate(ifHCOutOctets[{RATE_WINDOW}])")
    counters_are_64bit = bool(rate_in or rate_out)
    if not counters_are_64bit:
        rate_in = _rates(f"rate(ifInOctets[{RATE_WINDOW}])")
        rate_out = _rates(f"rate(ifOutOctets[{RATE_WINDOW}])")

    # capacity, admin intent, and the error/discard counters — each optional, each simply
    # absent until the matching module is scraped
    speed = {(r["labels"].get("instance"), r["labels"].get("ifIndex")): r["value"] * 1_000_000
             for r in q("ifHighSpeed")}
    admin = {(r["labels"].get("instance"), r["labels"].get("ifIndex")): int(r["value"])
             for r in q("ifAdminStatus")}
    errs = {}
    for metric, key in (("ifInErrors", "in_err"), ("ifOutErrors", "out_err"),
                        ("ifInDiscards", "in_disc"), ("ifOutDiscards", "out_disc")):
        for r in q(f"increase({metric}[{RATE_WINDOW}])"):
            k = (r["labels"].get("instance"), r["labels"].get("ifIndex"))
            errs.setdefault(k, {})[key] = max(0.0, r["value"])

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
            "speed_bps": speed.get(idx),
            # None when ifAdminStatus is not collected — which is NOT the same as "enabled",
            # and the report must not render it as though it were
            "admin_up": (admin.get(idx) == 1) if idx in admin else None,
            "errors": errs.get(idx, {}),
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

    # % utilisation, at last: a port doing 900 Mbps is bored on a 10G link and saturated on a
    # 1G one, and until ifHighSpeed is collected there is no way to tell which. Computed only
    # where capacity is known, so it is absent rather than guessed.
    for i in interfaces:
        cap = i["speed_bps"]
        # NOT `busiest` — that name already holds the top-N interface list a few lines up,
        # and shadowing it here emptied the traffic table on the report.
        heaviest = max(i["in_bps"] or 0, i["out_bps"] or 0)
        i["util_pct"] = round((heaviest / cap) * 100, 1) if cap else None
    saturated = [i for i in interfaces if (i["util_pct"] or 0) >= 80]

    erroring = [i for i in interfaces if sum(i["errors"].values() or [0]) > 0]

    # Hardware health, from the vendor module. Each is optional; a missing reading is None and
    # renders as "not collected" rather than as a zero, which would read as "cool and idle".
    def _one(expr):
        rows = q(expr)
        if wanted is not None:
            rows = [r for r in rows if r["labels"].get("instance") in wanted]
        return rows

    cpu_rows = _one("cpmCPUTotal5minRev") or _one("cpmCPUTotal1minRev")
    cpu = max((r["value"] for r in cpu_rows), default=None)
    mem_used = sum(r["value"] for r in _one("ciscoMemoryPoolUsed")) or None
    mem_free = sum(r["value"] for r in _one("ciscoMemoryPoolFree")) or None
    mem_pct = round(mem_used / (mem_used + mem_free) * 100, 1) if mem_used and mem_free else None
    up_rows = _one("sysUpTime")
    # sysUpTime is in hundredths of a second (TimeTicks), not seconds
    uptime_days = round(max(r["value"] for r in up_rows) / 100.0 / 86400.0, 1) if up_rows else None
    sensors = _one("entSensorValue")
    temps = [r["value"] for r in sensors
             if r["labels"].get("entSensorType") == "8" and 0 < r["value"] < 200]
    temp_max = max(temps) if temps else None

    # ---- PSU / fan status (CISCO-ENTITY-FRU-CONTROL-MIB) --------------------------------
    # This module exposes cefcFRUPowerOperStatus as EnumAsStateSet: one row per
    # (component, possible state) pair, value 1 on the row naming that component's ACTUAL
    # current state and 0 on every other state for it — so a plain query without the "== 1"
    # filter returns every component many times over (once per state it is NOT in), which
    # looks like "everything is failed" if read as a flat row count. Filtering to just the
    # true row first is what turns this into one row per physical component.
    psu_rows = _one("cefcFRUPowerOperStatus == 1")
    psu_failed = [r for r in psu_rows if r["labels"].get("cefcFRUPowerOperStatus") != "on"]
    psu_total = len(psu_rows)

    # ---- OSPF neighbour adjacency (OSPF-MIB) ---------------------------------------------
    # ospfNbrState: 1 down, 2 attempt, 3 init, 4 twoWay, 5 exchangeStart, 6 exchange,
    # 7 loading, 8 full. 2-Way is the NORMAL steady state for a non-DR/BDR router on a
    # broadcast segment — not a fault, so it is excluded from "down" alongside Full.
    ospf_rows = _one("ospfNbrState")
    ospf_down = [r for r in ospf_rows if int(r["value"]) not in (4, 8)]
    ospf_total = len(ospf_rows)

    # ---- optical Tx/Rx power (ENTITY-SENSOR-MIB, entSensorType 14 = dBm) -----------------
    # Cisco's optical DOM sensors report centi-dBm regardless of what entSensorScale claims
    # for them (a documented quirk, not a guess — dividing by the claimed scale here would
    # produce numbers three orders of magnitude off a real reading).
    optics = []
    for r in sensors:
        if r["labels"].get("entSensorType") != "14":
            continue
        name = r["labels"].get("entPhysicalName", "")
        optics.append({
            "name": name,
            "instance": r["labels"].get("instance"),
            "dbm": r["value"] / 100.0,
            "direction": "Tx" if "Transmit" in name else ("Rx" if "Receive" in name else "?"),
        })
    # No MIB here states the vendor's actual receiver sensitivity floor — this is a
    # conservative, industry-typical figure for SFP/SFP+ optics, not a per-optic vendor
    # value, and is stated as such wherever it is shown.
    OPTICS_RX_MIN_DBM = -20.0
    optics_low = [o for o in optics if o["direction"] == "Rx" and o["dbm"] <= OPTICS_RX_MIN_DBM + 3]

    # ---- MAC / ARP table size (BRIDGE-MIB / IP-MIB) --------------------------------------
    # Entry counts only — the platform's hardware MAX per table is a datasheet figure, not
    # an SNMP one, so % used is deliberately not computed (see the catalogue entry).
    mac_count = len(_one("dot1dTpFdbPort"))
    arp_count = len(_one("ipNetToMediaIfIndex"))

    # How long a 32-bit octet counter survives at the fastest rate actually observed here.
    # Computed, never hardcoded: the peak moves with the traffic, and a stale constant on a
    # page whose whole point is "this number is under-reported" would be its own small lie.
    #   2^32 bytes = 4.295 GB. seconds-to-wrap = 4.295e9 / bytes-per-second.
    peak_bps = max((max(i["in_bps"] or 0, i["out_bps"] or 0) for i in interfaces), default=0)
    wrap_seconds = (2 ** 32) / (peak_bps / 8) if peak_bps else None

    catalogue = measure_catalogue(q, wanted)
    live = sum(1 for m in catalogue if m["state"] == "live")
    degraded = sum(1 for m in catalogue if m["state"] == "degraded")
    missing = sum(1 for m in catalogue if m["state"] == "missing")

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
        "catalogue": catalogue,
        "count_live": live,
        "count_degraded": degraded,
        "count_missing": missing,
        "count_total": len(CATALOGUE),
        "peak_bps_text": _fmt_bps(peak_bps),
        "counters_are_64bit": counters_are_64bit,
        "saturated": saturated,
        "erroring": erroring,
        "has_speed": bool(speed),
        "has_admin": bool(admin),
        "cpu_pct": cpu,
        "mem_pct": mem_pct,
        "uptime_days": uptime_days,
        "temp_max": temp_max,
        "psu_failed": psu_failed,
        "psu_total": psu_total,
        "ospf_rows": ospf_rows,
        "ospf_down": ospf_down,
        "ospf_total": ospf_total,
        "optics": optics,
        "optics_low": optics_low,
        "optics_rx_min_dbm": OPTICS_RX_MIN_DBM,
        "mac_count": mac_count,
        "arp_count": arp_count,
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
        # With ifAdminStatus collected, a port an admin deliberately shut is no longer
        # indistinguishable from one that failed — which is the whole point of the metric.
        # Only the enabled-but-not-up ports are a fault; the shut ones are a decision, and
        # reporting them as incidents daily is how a report teaches people to ignore it.
        failed = [i for i in down if i["admin_up"] is True]
        shut = [i for i in down if i["admin_up"] is False]
        if failed:
            flags.append(FlagVM(
                "links_failed",
                f"{len(failed)} interface(s) are enabled but not up — "
                + ", ".join(i["name"] for i in failed[:6])
                + ("…" if len(failed) > 6 else ""),
                "red", "service"))
        if shut and not failed:
            flags.append(FlagVM(
                "links_shut",
                f"{len(shut)} of {len(ifaces)} interfaces are administratively shut "
                f"(a deliberate decision, not a fault)",
                "amber", "service"))
        if not failed and not shut:
            # admin status unknown for these — say so rather than guessing either way
            flags.append(FlagVM(
                "links_down",
                f"{len(down)} of {len(ifaces)} interfaces are not up "
                f"(admin status is not collected, so shut ports cannot be told from failed ones)",
                "amber", "service"))

    # The counter-width problem is a defect in the MEASUREMENT, and belongs on the report as
    # one — an admin reading these numbers has to know they are a floor.
    if data.get("wrap_seconds") and not data.get("counters_are_64bit"):
        flags.append(FlagVM(
            "counter_width",
            f"Throughput is under-reported: the 32-bit octet counters wrap about every "
            f"{data['wrap_seconds']}s at the current peak of {data['peak_bps_text']}. "
            f"Poll ifHCInOctets/ifHCOutOctets to fix it.",
            "amber", "untracked"))

    # ---- hardware, once the vendor module is scraped -------------------------------
    if data.get("cpu_pct") is not None and data["cpu_pct"] >= 80:
        flags.append(FlagVM("cpu_high", f"CPU at {data['cpu_pct']:.0f}% (5-minute average)",
                            "red" if data["cpu_pct"] >= 90 else "amber", "cpu"))
    if data.get("mem_pct") is not None and data["mem_pct"] >= 80:
        flags.append(FlagVM("mem_high", f"Memory at {data['mem_pct']:.0f}% in use",
                            "red" if data["mem_pct"] >= 90 else "amber", "ram"))
    if data.get("temp_max") is not None and data["temp_max"] >= 60:
        flags.append(FlagVM("temp_high", f"Hottest sensor reading {data['temp_max']:.0f}°C",
                            "red" if data["temp_max"] >= 75 else "amber", "unreachable"))
    if data.get("uptime_days") is not None and data["uptime_days"] < 1:
        # A switch that has just rebooted is the single most useful thing on this page: it
        # explains every other anomaly on it.
        flags.append(FlagVM("recent_reboot",
                            f"Device restarted {data['uptime_days'] * 24:.0f} hours ago",
                            "red", "unreachable"))
    psu_failed = [r for r in data.get("psu_failed", [])
                 if r["labels"].get("instance") == dev["target"]]
    if psu_failed:
        flags.append(FlagVM(
            "psu_fan_failed",
            f"{len(psu_failed)} of {data.get('psu_total', 0)} power/fan component(s) not in "
            f"a normal operating state",
            "red", "unreachable"))
    ospf_down = [r for r in data.get("ospf_down", [])
                if r["labels"].get("instance") == dev["target"]]
    if ospf_down:
        flags.append(FlagVM(
            "ospf_adjacency_lost",
            f"{len(ospf_down)} of {data.get('ospf_total', 0)} OSPF neighbour(s) not Full "
            f"(stuck below the 2-Way/Full states)",
            "red", "service"))
    optics_low = [o for o in data.get("optics_low", []) if o["instance"] == dev["target"]]
    if optics_low:
        worst = min(optics_low, key=lambda o: o["dbm"])
        flags.append(FlagVM(
            "optics_low",
            f"{len(optics_low)} receive optic(s) within 3 dB of a typical SFP sensitivity "
            f"floor ({data.get('optics_rx_min_dbm', 0):.0f} dBm) — worst {worst['name']} at "
            f"{worst['dbm']:.2f} dBm",
            "amber", "service"))

    # ---- interface health, once the counters are collected --------------------------
    sat = [i for i in data.get("saturated", []) if i["device"] == dev["target"]]
    if sat:
        worst = max(sat, key=lambda i: i["util_pct"])
        flags.append(FlagVM(
            "links_saturated",
            f"{len(sat)} interface(s) at or above 80% of capacity — worst {worst['name']} "
            f"at {worst['util_pct']:.0f}% of {_fmt_bps(worst['speed_bps'])}",
            "amber", "service"))
    err = [i for i in data.get("erroring", []) if i["device"] == dev["target"]]
    if err:
        total = sum(sum(i["errors"].values()) for i in err)
        flags.append(FlagVM(
            "iface_errors",
            f"{total:.0f} errors/discards across {len(err)} interface(s) in the last "
            f"{RATE_WINDOW} — faulty cabling, a failing optic, or congestion",
            "amber", "service"))

    missing = [m["name"] for m in data.get("catalogue", CATALOGUE) if m["state"] == "missing"]
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
    psu_failed = len(data.get("psu_failed", []))
    ospf_down = len(data.get("ospf_down", []))
    optics_low = len(data.get("optics_low", []))
    bad = lambda n: "good" if not n else "bad"
    warn = lambda n: "good" if not n else "warn"
    return {
        "glance": [
            {"label": "Devices", "value": len(devices), "state": "info"},
            {"label": "CPU", "value": (f"{data['cpu_pct']:.0f}%" if data.get("cpu_pct") is not None else "—"),
             "state": "info"},
            {"label": "Memory", "value": (f"{data['mem_pct']:.0f}%" if data.get("mem_pct") is not None else "—"),
             "state": "info"},
            {"label": "Uptime", "value": (f"{data['uptime_days']:.0f}d" if data.get("uptime_days") is not None else "—"),
             "state": "info"},
            {"label": "Interfaces", "value": data["iface_count"], "state": "info"},
            {"label": "Links up", "value": data["up_count"], "state": "info"},
            {"label": "Carrying traffic", "value": data["carrying_count"], "state": "info"},
            {"label": "Throughput in", "value": data["total_in_text"], "state": "info"},
            {"label": "OSPF neighbours", "value": f"{data.get('ospf_total', 0) - ospf_down} of {data.get('ospf_total', 0)}",
             "sub": "Full", "state": "info"},
        ],
        "immediate": [
            {"label": "Not responding", "value": len(unreachable), "state": bad(len(unreachable))},
            {"label": "Never scraped", "value": len(unscraped), "state": bad(len(unscraped))},
            {"label": "PSU / fan failed", "value": psu_failed, "sub": f"of {data.get('psu_total', 0)}",
             "state": bad(psu_failed)},
            {"label": "OSPF adjacencies lost", "value": ospf_down, "sub": f"of {data.get('ospf_total', 0)}",
             "state": bad(ospf_down)},
        ],
        "watch": [
            {"label": "Links not up", "value": down, "sub": "interfaces", "state": warn(down)},
            {"label": "At capacity", "value": len(data.get("saturated", [])), "sub": "≥80% used",
             "state": warn(len(data.get("saturated", [])))},
            {"label": "With errors", "value": len(data.get("erroring", [])), "sub": "interfaces",
             "state": warn(len(data.get("erroring", [])))},
            {"label": "Optics near floor", "value": optics_low, "sub": "receive power",
             "state": warn(optics_low)},
            {"label": "MAC / ARP entries", "value": f"{data.get('mac_count', 0)} | {data.get('arp_count', 0)}",
             "sub": "size only — no vendor max yet", "state": "info"},
            {"label": "Metrics not collected", "value": missing,
             "sub": f"of {len(CATALOGUE)} requested", "state": warn(missing)},
            {"label": "Counter width", "value": "32-bit" if not data.get("counters_are_64bit") else "64-bit",
             "sub": ("under-reports throughput" if not data.get("counters_are_64bit") else "accurate"),
             "state": "info" if data.get("counters_are_64bit") else "warn"},
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
        for col, width in zip("BCDEFG", (34, 15, 62, 12, 34, 4)):
            ws.column_dimensions[col].width = width

        FIRST, LAST = 2, 7

        def paint(row):
            """Fill the row with the page colour.

            The canvas is painted rather than left to Excel's default white: on the dark
            theme an unpainted sheet frames the report in white and the whole thing reads as
            broken. The systems report paints for the same reason.
            """
            for c in range(1, LAST + 1):
                ws.cell(row, c).fill = page

        # ---- header: the same crest-then-title block the systems report opens with -------
        # The logo floats over the grid rather than sitting in a cell, exactly as it does
        # there; a missing or unreadable file is not worth failing a report over, so it is
        # skipped with a note and the header renders without it.
        cfg = gr.load_config()
        for row in range(1, 9):
            paint(row)
        try:
            from openpyxl.drawing.image import Image as XLImage
            from openpyxl.drawing.spreadsheet_drawing import AnchorMarker, OneCellAnchor
            from openpyxl.drawing.xdr import XDRPositiveSize2D
            img = XLImage(cfg.logo)
            img.anchor = OneCellAnchor(
                _from=AnchorMarker(col=cfg.logo_from_col, colOff=cfg.logo_from_coloff,
                                   row=cfg.logo_from_row, rowOff=cfg.logo_from_rowoff),
                ext=XDRPositiveSize2D(cx=cfg.logo_cx, cy=cfg.logo_cy))
            ws.add_image(img)
        except Exception as exc:                      # missing/unreadable logo -> carry on
            import sys as _sys
            print(f"[!] logo not embedded ({exc})", file=_sys.stderr)
        for row, ht in {1: 6, 2: 18, 3: 26, 4: 15, 5: 20, 6: 34, 7: 18}.items():
            ws.row_dimensions[row].height = ht
        # column A is the crest gutter, so the title block starts at B — as it does there
        ws.column_dimensions["A"].width = 9

        ws.cell(3, 2, "NETWORK ADMIN REPORT").font = Font(bold=True, size=22, color=INK)
        ws.cell(4, 2, snapshot.captured_at.strftime(
            "snapshot generated %d %b %Y  ·  %H:%M      •      Network Analyses Dashboard")).font =             Font(color=SUB, size=9)
        ws.cell(5, 2, "Static snapshot.   Device telemetry captured by SNMP.").font = Font(color=GREY, size=9)
        ws.cell(7, 2, f"By  {author}").font = Font(color=SUB, size=9)
        r = 9

        def band(title, rows):
            nonlocal r
            paint(r)
            ws.cell(r, FIRST, title.upper()).font = Font(bold=True, size=10, color=INK)
            for c in range(FIRST, LAST):
                ws.cell(r, c).fill = head
                ws.cell(r, c).border = box
            r += 1
            for item in rows:
                paint(r)
                for c in range(FIRST, LAST):
                    ws.cell(r, c).fill = card
                ws.cell(r, FIRST, item["label"]).font = Font(color=GREY, size=10)
                v = ws.cell(r, FIRST + 1, item["value"])
                v.font = Font(bold=True, size=10,
                              color={"bad": CHIP["red"][0], "warn": CHIP["amber"][0],
                                     "good": CHIP["green"][0]}.get(item.get("state"), INK))
                if item.get("sub"):
                    ws.cell(r, FIRST + 2, item["sub"]).font = Font(color=SUB, size=9)
                r += 1
            paint(r)
            r += 1

        ov = snapshot.overview or {}
        band("At a glance", ov.get("glance", []))
        band("Immediate attention", ov.get("immediate", []))
        band("Watch list", ov.get("watch", []))

        for sysvm in snapshot.systems:
            paint(r)
            ws.cell(r, FIRST, sysvm.name.upper()).font = Font(bold=True, size=12, color=CYAN)
            ws.cell(r, FIRST + 1, f"{sysvm.hosts} interfaces").font = Font(color=SUB, size=10)
            r += 1

            paint(r)
            for label, col in (("Finding", FIRST), ("Band", FIRST + 1), ("Detail", FIRST + 2),
                               ("Fixed?", FIRST + 3), ("Comment", FIRST + 4)):
                h = ws.cell(r, col, label)
                h.font = Font(bold=True, size=9, color=SUB)
                h.fill = head
                h.border = box
            r += 1

            ann = annotations.get(sysvm.name, {})
            if not sysvm.flags:
                paint(r)
                ws.cell(r, FIRST, "No findings — every collected metric is within limits").font = Font(
                    color=CHIP["green"][0], size=10)
                r += 1
            for flag in sysvm.flags:
                paint(r)
                fg, bgc = CHIP["red" if flag.band == "red" else "amber"]
                for col in range(FIRST, FIRST + 5):
                    cell = ws.cell(r, col)
                    cell.fill = card
                    cell.border = box
                ws.cell(r, FIRST, flag.key).font = Font(color=GREY, size=10)
                b = ws.cell(r, FIRST + 1, "Immediate" if flag.band == "red" else "Watch")
                b.font = Font(bold=True, size=10, color=fg)
                b.fill = PatternFill("solid", fgColor=bgc)
                d = ws.cell(r, FIRST + 2, flag.text)
                d.font = Font(color=INK, size=10)
                d.alignment = Alignment(wrap_text=True, vertical="top")
                ws.cell(r, FIRST + 3, ann.get("flags", {}).get(flag.key, "")).font = Font(size=10, color=INK)
                r += 1
            if ann.get("comment"):
                paint(r)
                for col in range(FIRST, FIRST + 5):
                    ws.cell(r, col).fill = card
                ws.cell(r, FIRST, "Comment").font = Font(bold=True, size=9, color=SUB)
                cm = ws.cell(r, FIRST + 2, ann["comment"])
                cm.font = Font(color=INK, size=10)
                cm.alignment = Alignment(wrap_text=True, vertical="top")
                r += 1
            paint(r)
            r += 1

        if summary_comment:
            paint(r)
            ws.cell(r, FIRST, "SUMMARY").font = Font(bold=True, size=10, color=INK)
            r += 1
            paint(r)
            sc = ws.cell(r, FIRST, summary_comment)
            sc.font = Font(color=INK, size=10)
            sc.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=FIRST + 4)
            r += 2

        # The caveats belong IN the artifact. A spreadsheet outlives the screen it was made on,
        # and these numbers are wrong in a specific, knowable way its reader has to be told.
        paint(r)
        ws.cell(r, FIRST, "HOW TO READ THESE NUMBERS").font = Font(bold=True, size=10, color=INK)
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
            cell = ws.cell(r, FIRST, "• " + line)
            cell.font = Font(color=SUB, size=9)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=FIRST + 4)
            ws.row_dimensions[r].height = 26
            r += 1

        # a painted margin below the content, so the themed canvas does not stop mid-page
        for _ in range(8):
            paint(r)
            r += 1

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()

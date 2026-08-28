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

import re
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
    # Split the same way _device_flags() already judges these per-device: an interface the
    # switch says is enabled but not carrying traffic is a genuine fault (red, immediate —
    # matches links_failed there); one an admin shut on purpose, or whose admin status isn't
    # collected at all, is a decision or an unknown, not a live incident (watch, amber).
    links_failed = [i for i in down if i["admin_up"] is True]
    links_shut_or_unknown = [i for i in down if i["admin_up"] is not True]

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
    # >=95% is not "worth watching", it is the point real links start dropping packets —
    # matches the systems report's disk_high()'s own near-full/full split (a WATCH-band tile
    # is still allowed to render red when the level itself demands it).
    saturated_critical = [i for i in interfaces if (i["util_pct"] or 0) >= 95]

    erroring = [i for i in interfaces if sum(i["errors"].values() or [0]) > 0]
    # Errors (CRC/framing/etc.) are close to always a real physical fault — a cable, a
    # connector, a failing optic. Discards are frequently a POLICY decision (QoS dropping
    # excess traffic on purpose) and are not inherently a fault the same way, so the two are
    # graded separately rather than one combined "has some non-zero number" bucket.
    err_only = [i for i in interfaces
               if (i["errors"].get("in_err", 0) + i["errors"].get("out_err", 0)) > 0]
    # A high discard volume is still worth escalating even without a true error present —
    # the two thresholds below aren't a precise SLA, just a floor well above the handful of
    # discards a healthy, momentarily-busy link can show, and well below the 200k+/400k+
    # seen on a genuinely congested interface here.
    DISCARD_RED = 1000
    discard_heavy = [i for i in interfaces
                     if (i["errors"].get("in_disc", 0) + i["errors"].get("out_disc", 0)) >= DISCARD_RED]
    # Whatever is left once true errors and heavy discards are accounted for — a light
    # discard count, on its own, worth a watch-band amber rather than red. Computed as its
    # own set (not erroring-count minus the other two) so an interface with BOTH a real
    # error and a heavy discard isn't subtracted twice.
    disc_light = [i for i in erroring if i not in err_only and i not in discard_heavy]

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
    # AT or below the assumed floor is not "approaching" a limit, it is a link the report
    # believes is failing right now — same near-full/full split as the disk and saturation
    # checks. "Low" (amber) is everything within 3 dB of it that is not already there.
    optics_critical = [o for o in optics if o["direction"] == "Rx" and o["dbm"] <= OPTICS_RX_MIN_DBM]
    optics_low = [o for o in optics
                 if o["direction"] == "Rx" and OPTICS_RX_MIN_DBM < o["dbm"] <= OPTICS_RX_MIN_DBM + 3]

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
        "saturated_critical": saturated_critical,
        "erroring": erroring,
        "err_only": err_only,
        "discard_heavy": discard_heavy,
        "disc_light": disc_light,
        "links_failed": links_failed,
        "links_shut_or_unknown": links_shut_or_unknown,
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
        "optics_critical": optics_critical,
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
    # HCI Cluster host — belongs to Infrastructure Admin too (see gr.INFRA_SYSTEMS), but is
    # windows_exporter (CPU/RAM/disk), not SNMP: no interfaces/OSPF/optics/PSU concepts apply
    # to it, so it is kept OUT of collect()'s SNMP-shaped machinery entirely and gathered by
    # the small, separate _windows_metrics() path below instead. `kind: "windows"` is what
    # every branch in this module checks to route it there instead of through the switch's.
    {
        "key": "hci-cluster",
        "name": "HCI Cluster",
        "kind": "windows",
        "target": "10.100.246.3:9182",   # windows_exporter instance label (host:port)
        "system": "HCI Cluster",
        "job": "hci_cluster",            # the prometheus.yml job this target's `up` lives under
        "report": "network_report",
    },
    # Root Domain Controllers (AD forest root, HQ) -- two independent standalone DCs, not a
    # cluster, so unlike HCI Cluster (whose real multi-node data comes from the bespoke,
    # job-scoped _hci_node_metrics()) these need no special-case code at all: each is its own
    # plain kind="windows" entry, picked up by the generic single-target _windows_metrics()
    # path the same way any future standalone Windows device would be. Identified via reverse
    # DNS + windows_exporter's own service list (ADWS/DNS/KDC/Netlogon), confirmed 2026-08-25.
    # windows_exporter runs with --collectors.enabled="service,textfile" on both -- CPU/RAM/
    # disk are meant to arrive via the textfile collector (a script writing a .prom file to
    # its configured directory), not the live cpu/memory/logical_disk collectors this app
    # queries elsewhere, but confirmed live 2026-08-27 that collector reports
    # windows_exporter_collector_success{collector="textfile"}=0 on both hosts -- nothing has
    # been published there yet, so CPU/RAM/disk still read no-data here for now.
    {
        "key": "root-dc-1",
        "name": "RBZHQ-ROOT-01",
        "kind": "windows",
        "target": "10.100.249.200:9182",
        "system": "Root Domain Controllers",
        "job": "root_domain_controllers",
        "report": "network_report",
    },
    {
        "key": "root-dc-2",
        "name": "RBZ-HQ-ROOT-02",
        "kind": "windows",
        "target": "10.100.249.201:9182",
        "system": "Root Domain Controllers",
        "job": "root_domain_controllers",
        "report": "network_report",
    },
]

# volume filter for windows_logical_disk queries -- mirrors generate_report.py's own _VOL
# (kept as a local literal rather than importing gr._VOL: that name is a generate_report.py
# implementation detail, not something this module should depend on staying named that).
_WIN_VOL = 'volume!~"HarddiskVolume.+"'


def _windows_metrics(only: Optional[set] = None) -> Dict[str, dict]:
    """CPU/RAM/disk for windows_exporter-based devices (kind="windows" in DEVICES).

    A Windows host has none of collect()'s SNMP concepts (interfaces, OSPF, optics, PSU), so
    this is a small, separate query path rather than another branch inside that machinery.
    Reuses the exact PromQL generate_report.py's capture() uses for windows_exporter CPU/RAM/
    disk, so a host reads the same way here as it would on the System Admin report.

    Returns {target: {"known":, "reachable":, "cpu_pct":, "mem_pct":, "disks": [...]}}.
    """
    wanted = [d for d in DEVICES if d.get("kind") == "windows" and (only is None or d["key"] in only)]
    if not wanted:
        return {}
    prom, _ = _prometheus()

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                   # noqa: BLE001
            return []

    up: Dict[str, float] = {}
    for job in {d["job"] for d in wanted}:
        for r in q(f'up{{job="{job}"}}'):
            up[r["labels"].get("instance", "")] = r["value"]

    cpu = {r["labels"]["instance"]: r["value"]
          for r in q('100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)')
          if r["labels"].get("instance")}
    mem = {r["labels"]["instance"]: r["value"]
          for r in q("100*(1-windows_memory_physical_free_bytes/windows_memory_physical_total_bytes)")
          if r["labels"].get("instance")}
    used, free, size = {}, {}, {}
    for r in q(f"100*(1-windows_logical_disk_free_bytes{{{_WIN_VOL}}}/windows_logical_disk_size_bytes{{{_WIN_VOL}}})"):
        if r["labels"].get("instance"):
            used.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]
    for r in q(f"windows_logical_disk_free_bytes{{{_WIN_VOL}}}/1024/1024/1024"):
        if r["labels"].get("instance"):
            free.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]
    for r in q(f"windows_logical_disk_size_bytes{{{_WIN_VOL}}}/1024/1024/1024"):
        if r["labels"].get("instance"):
            size.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]

    out = {}
    for d in wanted:
        t = d["target"]
        scraped = up.get(t)
        disks = [{"volume": vol, "used": u,
                  "free": free.get(t, {}).get(vol), "size": size.get(t, {}).get(vol)}
                 for vol, u in used.get(t, {}).items()]
        out[t] = {
            "known": scraped is not None,
            "reachable": scraped == 1.0,
            "cpu_pct": cpu.get(t),
            "mem_pct": mem.get(t),
            "disks": disks,
        }
    return out


# windows_exporter's mscluster_node collector State -- confirmed against this cluster's own
# live data (all 4 nodes read 0 while the cluster is healthy and every device is reachable).
_CLUSTER_NODE_STATE = {-1: "unknown", 0: "up", 1: "down", 2: "paused", 3: "joining"}

# mscluster_resource collector State. 2 (Online) and 3 (Offline) are the two states actually
# seen on this cluster: Offline is NOT necessarily a fault -- most of this estate's Offline
# resources are deliberately-powered-off test/UAT/DR VMs (confirmed against the live name
# list), so it is treated as informational (see the "offline" banner in _network_overview),
# never a red/amber flag. Only a genuine Failed state is flagged.
_CLUSTER_RESOURCE_STATE = {-1: "unknown", 0: "inherited", 1: "initializing", 2: "online",
                          3: "offline", 4: "failed", 128: "pending", 129: "online pending",
                          130: "offline pending"}


def _hci_node_metrics() -> Dict[str, dict]:
    """Per-node CPU/RAM/disk/network/latency for every HCI Cluster node -- queried by JOB
    ("hci_cluster" has 4 targets, see prometheus.yml), not by a single DEVICES target, so it
    naturally covers whichever nodes are actually reporting. up{job="hci_cluster"} names all
    4 configured instances regardless of reachability, so a node with windows_exporter not
    yet installed still gets a row here (known=True, reachable=False, everything else None/
    empty) rather than silently vanishing -- an admin needs to see it is expected but absent.

    Network is summed across a node's NICs (total throughput/errors/discards, not a per-
    adapter breakdown -- the question here is "is this node's networking healthy", the same
    level the switch's own per-device totals answer at). Latency is the average seconds/op
    over RATE_WINDOW, summed across a node's disks -- a per-disk breakdown would be noise at
    this level; "is this node's storage struggling" is the question.

    Returns {target: {"display":, "known":, "reachable":, "cpu_pct":, "mem_pct":,
                       "mem_total_gb":, "disks": [...], "net": {in_bps, out_bps, err_in,
                       err_out, disc_in, disc_out}, "latency": {read_ms, write_ms}}}.
    """
    prom, _ = _prometheus()

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                   # noqa: BLE001
            return []

    up: Dict[str, float] = {}
    display: Dict[str, str] = {}
    for r in q('up{job="hci_cluster"}'):
        inst = r["labels"].get("instance")
        if not inst:
            continue
        up[inst] = r["value"]
        display[inst] = r["labels"].get("display", inst)

    cpu = {r["labels"]["instance"]: r["value"]
          for r in q('100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)')
          if r["labels"].get("instance")}
    mem = {r["labels"]["instance"]: r["value"]
          for r in q("100*(1-windows_memory_physical_free_bytes/windows_memory_physical_total_bytes)")
          if r["labels"].get("instance")}
    # total physical RAM in GB -- a separate raw value from the ratio above, so the Nodes
    # table can show "61% of 64GB" instead of a bare percentage (matches the System Admin
    # report's own Memory panel).
    mem_total = {r["labels"]["instance"]: r["value"]
                for r in q("windows_memory_physical_total_bytes/1024/1024/1024")
                if r["labels"].get("instance")}

    used, free, size = {}, {}, {}
    for r in q(f"100*(1-windows_logical_disk_free_bytes{{{_WIN_VOL}}}/windows_logical_disk_size_bytes{{{_WIN_VOL}}})"):
        if r["labels"].get("instance"):
            used.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]
    for r in q(f"windows_logical_disk_free_bytes{{{_WIN_VOL}}}/1024/1024/1024"):
        if r["labels"].get("instance"):
            free.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]
    for r in q(f"windows_logical_disk_size_bytes{{{_WIN_VOL}}}/1024/1024/1024"):
        if r["labels"].get("instance"):
            size.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]

    def _sum_by_instance(expr):
        out: Dict[str, float] = {}
        for r in q(expr):
            inst = r["labels"].get("instance")
            if inst:
                out[inst] = out.get(inst, 0.0) + r["value"]
        return out

    net_in = _sum_by_instance(f"rate(windows_net_bytes_received_total[{RATE_WINDOW}])")
    net_out = _sum_by_instance(f"rate(windows_net_bytes_sent_total[{RATE_WINDOW}])")
    err_in = _sum_by_instance(f"increase(windows_net_packets_received_errors_total[{RATE_WINDOW}])")
    err_out = _sum_by_instance(f"increase(windows_net_packets_outbound_errors_total[{RATE_WINDOW}])")
    disc_in = _sum_by_instance(f"increase(windows_net_packets_received_discarded_total[{RATE_WINDOW}])")
    disc_out = _sum_by_instance(f"increase(windows_net_packets_outbound_discarded_total[{RATE_WINDOW}])")

    read_lat_sum = _sum_by_instance(f"increase(windows_physical_disk_read_latency_seconds_total[{RATE_WINDOW}])")
    read_ops_sum = _sum_by_instance(f"increase(windows_physical_disk_reads_total[{RATE_WINDOW}])")
    write_lat_sum = _sum_by_instance(f"increase(windows_physical_disk_write_latency_seconds_total[{RATE_WINDOW}])")
    write_ops_sum = _sum_by_instance(f"increase(windows_physical_disk_writes_total[{RATE_WINDOW}])")

    out: Dict[str, dict] = {}
    for inst in up:
        reachable = up[inst] == 1.0
        disks = [{"volume": vol, "used": u,
                  "free": free.get(inst, {}).get(vol), "size": size.get(inst, {}).get(vol)}
                 for vol, u in used.get(inst, {}).items()]
        r_ops, w_ops = read_ops_sum.get(inst, 0.0), write_ops_sum.get(inst, 0.0)
        out[inst] = {
            "display": display.get(inst, inst),
            "known": True,
            "reachable": reachable,
            "cpu_pct": cpu.get(inst),
            "mem_pct": mem.get(inst),
            "mem_total_gb": mem_total.get(inst),
            "disks": disks,
            # None (not 0) when unreachable -- "no traffic measured" is not the same claim as
            # "measured zero traffic", the same distinction CPU/RAM already make via .get()
            # returning None rather than a fabricated 0.
            "net": {
                "in_bps": net_in.get(inst, 0.0) * 8, "out_bps": net_out.get(inst, 0.0) * 8,
                "err_in": err_in.get(inst, 0.0), "err_out": err_out.get(inst, 0.0),
                "disc_in": disc_in.get(inst, 0.0), "disc_out": disc_out.get(inst, 0.0),
            } if reachable else None,
            "latency": {
                "read_ms": (read_lat_sum.get(inst, 0.0) / r_ops * 1000) if r_ops else None,
                "write_ms": (write_lat_sum.get(inst, 0.0) / w_ops * 1000) if w_ops else None,
            },
        }
    return out


def _windows_cluster_metrics(only: Optional[set] = None) -> Dict[str, dict]:
    """Windows Server Failover Cluster health, for windows-kind devices that expose it (the
    exporter's mscluster_* collectors) -- e.g. HCI Cluster. A separate question from
    _windows_metrics()'s CPU/RAM/disk: that answers "is the HOST healthy", this answers "is
    the CLUSTER healthy" -- node up/down state, and resource (mostly VM) state, plus which
    node currently owns each resource group. A future windows-kind device that does NOT run
    this collector simply never appears in the result (see the `if t not in ...: continue`
    below) rather than reading as an empty/broken cluster.

    Returns {target: {"nodes": [(name, state_text, up_bool), ...],
                       "resources": {"online": n, "offline": n, "failed": n, "other": n,
                                     "offline_names": [(resource, group), ...],
                                     "failed_names": [(resource, group), ...]},
                       "owners": {node_name: group_count},
                       "group_owner": {group_name: node_name}}}.
    """
    wanted = [d for d in DEVICES if d.get("kind") == "windows" and (only is None or d["key"] in only)]
    if not wanted:
        return {}
    prom, _ = _prometheus()

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                   # noqa: BLE001
            return []

    nodes_by_target: Dict[str, list] = {}
    for r in q("windows_mscluster_node_state"):
        inst = r["labels"].get("instance")
        if not inst:
            continue
        state = int(r["value"])
        nodes_by_target.setdefault(inst, []).append(
            (r["labels"].get("node", "?"), _CLUSTER_NODE_STATE.get(state, f"state {state}"), state == 0))

    res_by_target: Dict[str, dict] = {}
    for r in q("windows_mscluster_resource_state"):
        inst = r["labels"].get("instance")
        if not inst:
            continue
        state = int(r["value"])
        c = res_by_target.setdefault(inst, {"online": 0, "offline": 0, "failed": 0, "other": 0,
                                            "offline_names": [], "failed_names": []})
        name = r["labels"].get("name", "?")
        group = r["labels"].get("group", "?")
        if state == 2:
            c["online"] += 1
        elif state == 3:
            c["offline"] += 1
            c["offline_names"].append((name, group))   # (resource, group) -- group joins to owners below
        elif state == 4:
            c["failed"] += 1
            c["failed_names"].append((name, group))
        else:
            c["other"] += 1

    owners_by_target: Dict[str, dict] = {}          # {inst: {node: group_count}} -- placement banner
    group_owner_by_target: Dict[str, dict] = {}      # {inst: {group: node}} -- joins a resource to its node
    for r in q("windows_mscluster_resourcegroup_owner_node"):
        inst = r["labels"].get("instance")
        if not inst or r["value"] != 1.0:      # one-hot: only the row naming the ACTUAL owner is 1
            continue
        node = r["labels"].get("node", "?")
        group = r["labels"].get("name", "?")   # this metric's OWN "name" label is the group name
        owners_by_target.setdefault(inst, {})
        owners_by_target[inst][node] = owners_by_target[inst].get(node, 0) + 1
        group_owner_by_target.setdefault(inst, {})[group] = node

    out = {}
    for d in wanted:
        t = d["target"]
        if t not in nodes_by_target and t not in res_by_target:
            continue                          # this windows device has no mscluster collector
        out[t] = {
            "nodes": nodes_by_target.get(t, []),
            "resources": res_by_target.get(t, {"online": 0, "offline": 0, "failed": 0, "other": 0,
                                               "offline_names": [], "failed_names": []}),
            "owners": owners_by_target.get(t, {}),
            "group_owner": group_owner_by_target.get(t, {}),
        }
    return out


# Errors/discards over RATE_WINDOW that are worth a watch-band flag -- same reasoning
# collect()'s DISCARD_RED uses for the switch: a handful is normal background noise, this
# floor is well above that and well below genuine sustained congestion.
_NODE_ERR_RED = 100
_NODE_DISC_RED = 1000
_NODE_LATENCY_AMBER_MS = 15    # disk I/O latency worth watching
_NODE_LATENCY_RED_MS = 40      # disk I/O latency indicating real storage trouble


def _windows_device_flags(dev: dict, m: dict, cluster: Optional[dict] = None,
                          nodes: Optional[Dict[str, dict]] = None) -> list:
    """The flagged items for one windows_exporter device — same red/amber vocabulary and
    80%/90% thresholds _device_flags() uses for the switch, so the two device kinds read
    alike on the same report.

    `cluster` (see _windows_cluster_metrics) adds two REAL faults on top of CPU/RAM/disk: a
    cluster node that is down, and a resource in a genuine Failed state. An Offline resource
    is deliberately NOT flagged here — see _CLUSTER_RESOURCE_STATE's docstring; it only
    appears in the informational banner _network_overview() builds.

    `nodes` (see _hci_node_metrics), when given, replaces the single-target CPU/RAM/disk
    checks below with the SAME checks run per NODE across the whole cluster (plus network
    errors/discards and disk latency, which a single-target device has no equivalent of) --
    so a hot node 3 shows up even while node 1 (the device's own primary target) is fine.
    """
    from .services import FlagVM

    if not m.get("known"):
        return [FlagVM("win_unscraped", f"{dev['name']} has never been scraped by Prometheus",
                       "red", "unreachable")]
    if not m.get("reachable"):
        return [FlagVM("win_down", f"{dev['name']} is not answering", "red", "unreachable")]
    flags = []
    if nodes:
        for target, n in sorted(nodes.items(), key=lambda kv: kv[1].get("display", kv[0])):
            label = n.get("display", target)
            if not n.get("reachable"):
                flags.append(FlagVM(f"node_down:{target}", f"{label} is not answering",
                                    "red", "unreachable"))
                continue
            cpu = n.get("cpu_pct")
            if cpu is not None and cpu >= 80:
                flags.append(FlagVM(f"node_cpu:{target}", f"{label} · CPU at {cpu:.0f}%",
                                    "red" if cpu >= 90 else "amber", "cpu"))
            mem = n.get("mem_pct")
            if mem is not None and mem >= 80:
                flags.append(FlagVM(f"node_mem:{target}", f"{label} · Memory at {mem:.0f}% in use",
                                    "red" if mem >= 90 else "amber", "ram"))
            for disk in n.get("disks", []):
                used = disk.get("used")
                if used is not None and used >= 80:
                    flags.append(FlagVM(f"node_disk:{target}:{disk['volume']}",
                                        f"{label} · {disk['volume']} at {used:.0f}% used",
                                        "red" if used >= 90 else "amber", "disk"))
            net = n.get("net") or {}
            err = net.get("err_in", 0) + net.get("err_out", 0)
            if err >= _NODE_ERR_RED:
                flags.append(FlagVM(f"node_net_err:{target}",
                                    f"{label} · {err:.0f} network error(s) in the last {RATE_WINDOW}",
                                    "red", "unreachable"))
            disc = net.get("disc_in", 0) + net.get("disc_out", 0)
            if disc >= _NODE_DISC_RED:
                flags.append(FlagVM(f"node_net_disc:{target}",
                                    f"{label} · {disc:.0f} discard(s) in the last {RATE_WINDOW}",
                                    "amber", "unreachable"))
            lat = n.get("latency") or {}
            worst_ms = max((v for v in (lat.get("read_ms"), lat.get("write_ms")) if v is not None), default=None)
            if worst_ms is not None and worst_ms >= _NODE_LATENCY_AMBER_MS:
                flags.append(FlagVM(f"node_latency:{target}",
                                    f"{label} · disk latency {worst_ms:.1f}ms",
                                    "red" if worst_ms >= _NODE_LATENCY_RED_MS else "amber", "disk"))
    else:
        cpu = m.get("cpu_pct")
        if cpu is not None and cpu >= 80:
            flags.append(FlagVM("cpu_high", f"CPU at {cpu:.0f}% (5-minute average)",
                                "red" if cpu >= 90 else "amber", "cpu"))
        mem = m.get("mem_pct")
        if mem is not None and mem >= 80:
            flags.append(FlagVM("mem_high", f"Memory at {mem:.0f}% in use",
                                "red" if mem >= 90 else "amber", "ram"))
        for disk in m.get("disks", []):
            used = disk.get("used")
            if used is not None and used >= 80:
                flags.append(FlagVM(f"disk_high:{disk['volume']}",
                                    f"{disk['volume']} at {used:.0f}% used",
                                    "red" if used >= 90 else "amber", "disk"))
    if cluster:
        for name, state_text, up in cluster.get("nodes", []):
            if not up:
                flags.append(FlagVM(f"cluster_node_down:{name}",
                                    f"Cluster node {name} is {state_text}", "red", "unreachable"))
        for name, _group in cluster.get("resources", {}).get("failed_names", []):
            flags.append(FlagVM(f"cluster_resource_failed:{name}",
                                f"Cluster resource '{name}' is in a Failed state", "red", "service"))
    return flags


def device_inventory() -> list:
    """The devices for the picker, each with its live reachability and interface count.

    Reachability comes from Prometheus's own `up` for the snmp job rather than from whether
    any metric happens to exist: a device that stopped answering keeps its last series for a
    while, so "has data" and "is being scraped successfully" are not the same claim. Windows
    devices (kind="windows") use their own job's `up` instead -- a different scrape job than
    the SNMP switch -- via _windows_metrics(), and carry no interface count (0).
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

    wm = _windows_metrics()   # every windows-kind device, unscoped -- the picker always lists all

    out = []
    for d in DEVICES:
        t = d["target"]
        if d.get("kind") == "windows":
            m = wm.get(t, {"known": False, "reachable": False})
            out.append(dict(d, reachable=m["reachable"], known=m["known"],
                            iface_count=0, iface_up=0))
        else:
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
    optics_critical = [o for o in data.get("optics_critical", []) if o["instance"] == dev["target"]]
    if optics_critical:
        worst = min(optics_critical, key=lambda o: o["dbm"])
        flags.append(FlagVM(
            "optics_critical",
            f"{len(optics_critical)} receive optic(s) AT or BELOW a typical SFP sensitivity "
            f"floor ({data.get('optics_rx_min_dbm', 0):.0f} dBm) — worst {worst['name']} at "
            f"{worst['dbm']:.2f} dBm — this link is expected to be dropping frames now",
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
    # >=95% is not "worth watching" — it is where real links start dropping packets.
    sat_critical = [i for i in data.get("saturated_critical", []) if i["device"] == dev["target"]]
    if sat_critical:
        worst = max(sat_critical, key=lambda i: i["util_pct"])
        flags.append(FlagVM(
            "links_saturated_critical",
            f"{len(sat_critical)} interface(s) at or above 95% of capacity — worst {worst['name']} "
            f"at {worst['util_pct']:.0f}% of {_fmt_bps(worst['speed_bps'])} — packets are likely "
            f"being dropped now",
            "red", "service"))
    sat = [i for i in data.get("saturated", []) if i["device"] == dev["target"]
          and i not in data.get("saturated_critical", [])]
    if sat:
        worst = max(sat, key=lambda i: i["util_pct"])
        flags.append(FlagVM(
            "links_saturated",
            f"{len(sat)} interface(s) at or above 80% of capacity — worst {worst['name']} "
            f"at {worst['util_pct']:.0f}% of {_fmt_bps(worst['speed_bps'])}",
            "amber", "service"))
    # Errors are close to always a real physical fault (cabling, a connector, a failing
    # optic) — any is worth a red flag, unlike discards, which are frequently a QoS policy
    # choice and only escalate once the volume is heavy (see DISCARD_RED in collect()).
    err_only = [i for i in data.get("err_only", []) if i["device"] == dev["target"]]
    if err_only:
        total = sum(i["errors"].get("in_err", 0) + i["errors"].get("out_err", 0) for i in err_only)
        flags.append(FlagVM(
            "iface_errors",
            f"{total:.0f} error(s) across {len(err_only)} interface(s) in the last "
            f"{RATE_WINDOW} — almost always faulty cabling, a connector, or a failing optic",
            "red", "service"))
    discard_heavy = [i for i in data.get("discard_heavy", []) if i["device"] == dev["target"]]
    if discard_heavy:
        total = sum(i["errors"].get("in_disc", 0) + i["errors"].get("out_disc", 0) for i in discard_heavy)
        flags.append(FlagVM(
            "iface_discards_heavy",
            f"{total:.0f} discard(s) across {len(discard_heavy)} interface(s) in the last "
            f"{RATE_WINDOW} — congestion or a QoS policy actively dropping traffic",
            "red", "service"))
    disc_light = [i for i in data.get("disc_light", []) if i["device"] == dev["target"]]
    if disc_light:
        total = sum(sum(i["errors"].values()) for i in disc_light)
        flags.append(FlagVM(
            "iface_discards",
            f"{total:.0f} discard(s) across {len(disc_light)} interface(s) in the last "
            f"{RATE_WINDOW} — often a QoS policy dropping excess traffic on purpose, worth "
            f"confirming rather than assuming a fault",
            "amber", "service"))

    missing = [m["name"] for m in data.get("catalogue", CATALOGUE) if m["state"] == "missing"]
    if missing:
        flags.append(FlagVM(
            "metrics_missing",
            f"{len(missing)} of {len(CATALOGUE)} requested metrics are not collected: "
            + ", ".join(missing[:4]) + ("…" if len(missing) > 4 else ""),
            "amber", "untracked"))
    return flags


def _network_overview(data: dict, devices: list, win_metrics: Optional[list] = None,
                      win_cluster: Optional[list] = None,
                      hci_nodes: Optional[Dict[str, dict]] = None) -> dict:
    """The at-a-glance / immediate / watch bands, in the shape reports/form.html renders.

    Same three-band layout as the systems overview so the screen is genuinely the same one,
    with the rows that a network estate actually has.
    """
    unreachable = [d for d in devices if d.get("known") and not d.get("reachable")]
    unscraped = [d for d in devices if not d.get("known")]
    dev_total = len(devices)
    iface_total = data["iface_count"]
    missing = sum(1 for m in CATALOGUE if m["state"] == "missing")
    psu_failed, psu_total = len(data.get("psu_failed", [])), data.get("psu_total", 0)
    ospf_down_n, ospf_total = len(data.get("ospf_down", [])), data.get("ospf_total", 0)
    optics_total = len(data.get("optics", []))
    optics_low_n = len(data.get("optics_low", []))
    optics_critical_n = len(data.get("optics_critical", []))
    links_failed_n = len(data.get("links_failed", []))
    links_shut_n = len(data.get("links_shut_or_unknown", []))
    sat_n = len(data.get("saturated", []))
    sat_critical_n = len(data.get("saturated_critical", []))
    err_only_n = len(data.get("err_only", []))
    discard_heavy_n = len(data.get("discard_heavy", []))
    disc_light_n = len(data.get("disc_light", []))
    bad = lambda n: "good" if not n else "bad"
    warn = lambda n: "good" if not n else "warn"

    # Every immediate/watch tile reads "affected | total", the identical shape the systems
    # report's tiles use (High CPU: "hosts | total", not a bare percentage) — a count alone
    # can't be judged (12 is alarming out of 20 interfaces, unremarkable out of 300), and the
    # reader should not have to hold the denominator in their head or go find it above.
    #
    # Each tile below was asked the same question _device_flags() already answers per finding:
    # is this a live fault (a component is failed/down/gone right now — immediate, red) or a
    # level that's merely bad (a percentage or a rate crossing a threshold — watch), and for
    # levels, is the READING itself severe enough to render red even while the TILE stays in
    # the watch row — exactly how the systems report's High Disk works (near-full is still red,
    # it just isn't a Missing-Backups-style outage). A tile that only ever shows amber
    # regardless of how bad the number gets was the bug: "60 interfaces down" and "1 interface
    # down" read the same colour before this pass.
    #
    # CPU/Memory become "device(s) over threshold | total devices" for the same reason High
    # CPU/High RAM never show a raw percentage on the systems dashboard either — the
    # percentage itself lives on the per-device Health section. With one device monitored
    # today this reads as "0 | 1" or "1 | 1"; it is written as a device count rather than
    # hardcoded to one so onboarding a second device grows the denominator for free.
    cpu_pct = data.get("cpu_pct")
    mem_pct = data.get("mem_pct")
    # win_metrics folds in windows-kind devices (e.g. HCI Cluster) alongside the switch's own
    # cpu_pct/mem_pct scalars above, so onboarding one doesn't leave High CPU/Memory blind to
    # it — those tiles would otherwise only ever describe the switch, the one device collect()
    # actually measures.
    win_metrics = win_metrics or []
    cpu_state = ("bad" if (cpu_pct is not None and cpu_pct >= 90)
                        or any((m.get("cpu_pct") or 0) >= 90 for m in win_metrics)
                 else warn((cpu_pct is not None and cpu_pct >= 80)
                           or any((m.get("cpu_pct") or 0) >= 80 for m in win_metrics)))
    mem_state = ("bad" if (mem_pct is not None and mem_pct >= 90)
                        or any((m.get("mem_pct") or 0) >= 90 for m in win_metrics)
                 else warn((mem_pct is not None and mem_pct >= 80)
                           or any((m.get("mem_pct") or 0) >= 80 for m in win_metrics)))
    cpu_over = (1 if (cpu_pct is not None and cpu_pct >= 80) else 0) + \
               sum(1 for m in win_metrics if (m.get("cpu_pct") or 0) >= 80)
    mem_over = (1 if (mem_pct is not None and mem_pct >= 80) else 0) + \
               sum(1 for m in win_metrics if (m.get("mem_pct") or 0) >= 80)

    # A device that is fully unreachable has no throughput being measured AT ALL, imprecisely
    # or otherwise — "Not responding" above already says the real thing. Saying "Understated"
    # here too would read as a second, unrelated problem instead of the same one.
    fully_dark = dev_total > 0 and (len(unreachable) + len(unscraped)) >= dev_total
    if fully_dark:
        accuracy = {"label": "Throughput accuracy", "value": "No data",
                   "sub": "device unreachable — see above", "state": "info"}
    else:
        accuracy = {
            "label": "Throughput accuracy",
            "value": "Accurate" if data.get("counters_are_64bit") else "Understated",
            "sub": ("64-bit counters" if data.get("counters_are_64bit")
                    else "32-bit counters — wrap and lose data on a fast link"),
            "state": "info" if data.get("counters_are_64bit") else "warn",
        }

    # ---- Windows Server Failover Cluster health (e.g. HCI Cluster) -- see
    # _windows_cluster_metrics(). This screen shows TILES ONLY -- the detail that used to
    # render as banners here (which devices, which nodes, which resources, by name) now lives
    # in build_report()'s xlsx as real tables, sourced from the same snapshot._wc/_hci_nodes
    # (see capture_snapshot). This dashboard exists to capture admin sign-off on flagged
    # anomalies (each device's own Findings table, still below, is untouched by this); it is
    # not itself a report. Nothing here renders at all when no windows device in scope
    # exposes cluster metrics (win_cluster empty) -- an empty "0 | 0" tile would read as a
    # broken cluster rather than as "not applicable".
    cluster_glance, cluster_immediate, cluster_watch = [], [], []
    win_cluster = win_cluster or []
    if win_cluster:
        cnodes = [n for wc in win_cluster for n in wc.get("nodes", [])]
        cnodes_up = sum(1 for _, _, up in cnodes if up)
        cres = {"online": 0, "offline": 0, "failed": 0, "other": 0}
        for wc in win_cluster:
            r = wc.get("resources") or {}
            for k in ("online", "offline", "failed", "other"):
                cres[k] += r.get(k, 0)
        cres_total = cres["online"] + cres["offline"] + cres["failed"] + cres["other"]

        cluster_glance = [
            {"label": "Cluster nodes", "value": f"{cnodes_up} | {len(cnodes)}",
             "sub": "up | total", "state": "info"},
            {"label": "Cluster resources", "value": f"{cres['online']} | {cres_total}",
             "sub": f"online | total ({cres['offline']} offline — see the xlsx report)",
             "state": "info"},
        ]
        cluster_immediate = [
            {"label": "Cluster nodes down", "value": f"{len(cnodes) - cnodes_up} | {len(cnodes)}",
             "sub": "nodes | total", "state": bad(len(cnodes) - cnodes_up)},
            {"label": "Cluster resources failed", "value": f"{cres['failed']} | {cres_total}",
             "sub": "failed | total", "state": bad(cres["failed"])},
        ]

    # Per-node CPU/Storage/Network/Latency rollup tiles -- see _hci_node_metrics. Per-node
    # DETAIL (which node, what value) is an xlsx table now, not a banner; only the aggregate
    # tiles stay here.
    hci_nodes = hci_nodes or {}
    if hci_nodes:
        reporting = [n for n in hci_nodes.values() if n.get("reachable")]

        def _avg(key):
            vals = [n[key] for n in reporting if n.get(key) is not None]
            return sum(vals) / len(vals) if vals else None

        cluster_glance += [
            {"label": "Cluster CPU (avg)",
             "value": (f"{_avg('cpu_pct'):.0f}%" if _avg("cpu_pct") is not None else "—"),
             "sub": f"across {len(reporting)} reporting node(s)", "state": "info"},
        ]
        # Cluster Memory is graded, never a plain glance readout: 70-80% is a watch-band
        # finding, above 80% escalates to immediate -- below 70% it doesn't appear at all
        # (nothing to say). Same "affected | total" tile shape everywhere else here uses.
        avg_mem = _avg("mem_pct")
        if avg_mem is not None and avg_mem >= 70:
            tile = {"label": "Cluster Memory (avg)", "value": f"{avg_mem:.0f}%",
                   "sub": f"across {len(reporting)} reporting node(s)",
                   "state": "bad" if avg_mem > 80 else "warn"}
            (cluster_immediate if avg_mem > 80 else cluster_watch).append(tile)
        used_gb = sum(d.get("size", 0) * (d.get("used") or 0) / 100 for n in reporting for d in n.get("disks", [])
                      if d.get("size") is not None)
        total_gb = sum(d.get("size", 0) for n in reporting for d in n.get("disks", []) if d.get("size") is not None)
        if total_gb:
            cluster_glance.append({"label": "Cluster storage", "value": f"{used_gb:.0f} / {total_gb:.0f} GB",
                                   "sub": "used | total, summed across nodes", "state": "info"})
        total_in = sum((n.get("net") or {}).get("in_bps", 0) for n in reporting)
        total_out = sum((n.get("net") or {}).get("out_bps", 0) for n in reporting)
        cluster_glance.append({"label": "Cluster throughput in", "value": _fmt_bps(total_in),
                               "sub": "summed across nodes", "state": "info"})
        cluster_glance.append({"label": "Cluster throughput out", "value": _fmt_bps(total_out),
                               "sub": "summed across nodes", "state": "info"})
        total_err = sum((n.get("net") or {}).get("err_in", 0) + (n.get("net") or {}).get("err_out", 0)
                        for n in reporting)
        total_disc = sum((n.get("net") or {}).get("disc_in", 0) + (n.get("net") or {}).get("disc_out", 0)
                         for n in reporting)
        cluster_immediate.append({"label": "Cluster network errors",
                                  "value": f"{total_err:.0f} | {RATE_WINDOW}",
                                  "sub": "summed across nodes", "state": bad(total_err)})
        cluster_immediate.append({"label": "Cluster network discards",
                                  "value": f"{total_disc:.0f} | {RATE_WINDOW}",
                                  "sub": "summed across nodes", "state": warn(total_disc)})
        worst_latency = max((v for n in reporting for v in
                            ((n.get("latency") or {}).get("read_ms"), (n.get("latency") or {}).get("write_ms"))
                            if v is not None), default=None)
        cluster_glance.append({"label": "Cluster disk latency (worst)",
                               "value": (f"{worst_latency:.1f}ms" if worst_latency is not None else "—"),
                               "sub": "slowest node/op, read or write", "state": "info"})

    return {
        "glance": [
            {"label": "Devices", "value": len(devices), "state": "info"},
            {"label": "Throughput in", "value": data["total_in_text"], "state": "info"},
            {"label": "MAC / ARP entries", "value": f"{data.get('mac_count', 0)} | {data.get('arp_count', 0)}",
             "sub": "entry count, not % of capacity", "state": "info"},
        ] + cluster_glance,
        "immediate": [
            {"label": "Not responding", "value": f"{len(unreachable)} | {dev_total}",
             "sub": "devices | total", "state": bad(len(unreachable))},
            {"label": "Never monitored", "value": f"{len(unscraped)} | {dev_total}",
             "sub": "devices | total", "state": bad(len(unscraped))},
            {"label": "PSU / fan failed", "value": f"{psu_failed} | {psu_total}",
             "sub": "failed | total", "state": bad(psu_failed)},
            {"label": "OSPF adjacencies lost", "value": f"{ospf_down_n} | {ospf_total}",
             "sub": "down | total", "state": bad(ospf_down_n)},
            # Moved out of the old combined "Links not up" watch tile: enabled-but-not-up is
            # not a level to keep an eye on, it is the same live fault _device_flags() already
            # flags red (links_failed) — an admin-shut port is a decision, not this.
            {"label": "Links failed", "value": f"{links_failed_n} | {iface_total}",
             "sub": "enabled but down | total", "state": bad(links_failed_n)},
            # Any real error (not a discard) is close to always a physical fault, the same
            # reasoning _device_flags()'s iface_errors flag uses to go straight to red.
            {"label": "Interfaces with errors", "value": f"{err_only_n} | {iface_total}",
             "sub": "true errors | total", "state": bad(err_only_n)},
        ] + cluster_immediate,
        "watch": [
            {"label": "High CPU", "value": f"{cpu_over} | {dev_total}",
             "sub": "devices | total", "state": cpu_state},
            {"label": "High Memory", "value": f"{mem_over} | {dev_total}",
             "sub": "devices | total", "state": mem_state},
            # What's left after Links failed above: admin-shut on purpose, or down with
            # ifAdminStatus unknown so shut can't be told from failed — a decision or an
            # unknown, not a live incident.
            {"label": "Links shut / unclear", "value": f"{links_shut_n} | {iface_total}",
             "sub": "interfaces | total", "state": warn(links_shut_n)},
            {"label": "At capacity", "value": f"{sat_n} | {iface_total}",
             "sub": "interfaces ≥80% | total",
             "state": "bad" if sat_critical_n else warn(sat_n)},
            # Heavy discards (>=1000 in the window) escalate on their own — a QoS policy
            # occasionally shaving a handful of packets is normal; hundreds of thousands is
            # active, ongoing congestion, whatever set the policy. Light discards stay amber.
            {"label": "Heavy discards", "value": f"{discard_heavy_n} | {iface_total}",
             "sub": "interfaces | total", "state": bad(discard_heavy_n)},
            {"label": "Some discards", "value": f"{disc_light_n} | {iface_total}",
             "sub": "interfaces | total", "state": warn(disc_light_n)},
            {"label": "Optics near floor", "value": f"{optics_critical_n + optics_low_n} | {optics_total}",
             "sub": "receive optics | total",
             "state": "bad" if optics_critical_n else warn(optics_low_n)},
            {"label": "Metrics not collected", "value": f"{missing} | {len(CATALOGUE)}",
             "sub": "metrics | total requested", "state": warn(missing)},
            accuracy,
        ] + cluster_watch,
        # This screen is tiles only now -- see the module docstring at the top of this
        # function. Detail (which device, which node, which resource) lives in the xlsx.
        "banners": [],
    }


def capture_snapshot(token: str, only: Optional[set] = None):
    """A Snapshot of the selected network devices, interchangeable with the systems one.

    SNMP devices (the switch) go through collect()'s machinery, which is SNMP-shaped
    throughout (interfaces, OSPF, optics, PSU) and does not apply to a windows_exporter
    device — those (kind="windows", e.g. HCI Cluster) are gathered separately by
    _windows_metrics()/_windows_device_flags() and merged into the same systems list, so the
    report reads as one estate regardless of which mechanism actually measured each row.

    Raises NetworkUnavailable when Prometheus cannot be reached, mirroring
    services.capture_snapshot raising PrometheusUnavailable — the view handles them the same.
    """
    import datetime

    from .services import Snapshot, SystemVM

    data = collect(only=only)
    # excludes windows-kind here too: a windows device never produces ifOperStatus rows, so it
    # would otherwise slip into this SNMP fallback (used when device_rows comes back empty)
    # and get scored by _device_flags() against the SWITCH's data -- wrongly silent on its own
    # real CPU/RAM/disk state.
    rows = data["device_rows"] or [d for d in DEVICES
                                   if d.get("kind") != "windows" and (only is None or d["key"] in only)]
    inv = {d["target"]: d for d in device_inventory() if only is None or d["key"] in only}

    svms = []
    for dev in rows:
        live = inv.get(dev["target"], dict(dev, known=False, reachable=False))
        svms.append(SystemVM(name=dev["name"],
                             hosts=len([i for i in data["interfaces"] if i["device"] == dev["target"]]),
                             flags=_device_flags(live, data)))

    win_devices = [d for d in DEVICES if d.get("kind") == "windows" and (only is None or d["key"] in only)]
    win_keys = {d["key"] for d in win_devices}
    wm = _windows_metrics(win_keys) if win_devices else {}
    wc = _windows_cluster_metrics(win_keys) if win_devices else {}
    # job-scoped (not per-DEVICES-target), so it naturally covers all 4 HCI Cluster nodes --
    # only queried when the hci-cluster device is actually in scope for this report.
    hci_nodes = _hci_node_metrics() if any(d["key"] == "hci-cluster" for d in win_devices) else {}
    for dev in win_devices:
        m = wm.get(dev["target"], {"known": False, "reachable": False})
        nodes = hci_nodes if dev["key"] == "hci-cluster" else None
        svms.append(SystemVM(name=dev["name"], hosts=(len(nodes) if nodes else 1),
                             flags=_windows_device_flags(dev, m, wc.get(dev["target"]), nodes)))

    snap = Snapshot(
        token=token,
        captured_at=datetime.datetime.now(),
        prom_url=data["prom_url"],
        systems=svms,
        overview=_network_overview(data, list(inv.values()), win_metrics=list(wm.values()),
                                   win_cluster=list(wc.values()), hci_nodes=hci_nodes),
    )
    # carried for the report screen and for generation; the systems flow parks its engine
    # objects on the same attributes. _hci_nodes/_wc are network-specific additions: the web
    # screen shows tiles only now (see _network_overview), the DETAIL these used to power as
    # banners now renders as real tables in build_report()'s xlsx instead, from this same
    # data -- not recomputed from a second query, so the xlsx never disagrees with what the
    # admin reviewed on screen.
    snap._store = data
    snap._systems = rows + win_devices
    snap._hci_nodes = hci_nodes
    snap._wc = wc
    # Raw per-target CPU/RAM/disk (see _windows_metrics) -- stashed for the same reason
    # _hci_nodes/_wc are: build_infrastructure_report()'s tree-nested tables read exact
    # numbers, not just the derived flag TEXT _windows_device_flags() produces, and they must
    # come from THIS snapshot rather than a fresh query so the xlsx never disagrees with what
    # the admin reviewed and annotated on screen.
    snap._wm = wm
    return snap


def network_report_filename(theme: str = "dark", when=None) -> str:
    """Named like the systems report, theme and all, so the two sit together in a folder."""
    import datetime
    when = when or datetime.datetime.now()
    return f"Infrastructure Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


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
        ws.title = "Infrastructure Report"
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

        ws.cell(3, 2, "INFRASTRUCTURE REPORT").font = Font(bold=True, size=22, color=INK)
        ws.cell(4, 2, snapshot.captured_at.strftime(
            "snapshot generated %d %b %Y  ·  %H:%M      •      Infrastructure Analyses Dashboard")).font =             Font(color=SUB, size=9)
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

        def pct_band(v):
            return None if v is None else ("red" if v >= cfg.chip_red else
                                           "amber" if v >= cfg.chip_amber else None)

        def table(title, headers, rows):
            """A real, multi-column data table -- header row + data rows -- for the detail
            that used to render as a banner (see _network_overview's docstring): who/what,
            not a passive summary. Same visual language the tile bands (`band`) and the
            per-device Findings table below already use: HDR-filled title/header, CARD-filled
            data rows, thin borders throughout. `rows` is a list of rows, each a list of
            (text, chip_band_or_None) pairs, one per header -- chip_band colours that cell
            the same red/amber/green a percentage chip gets anywhere else in this app.
            """
            nonlocal r
            paint(r)
            ws.cell(r, FIRST, title.upper()).font = Font(bold=True, size=10, color=INK)
            for c in range(FIRST, LAST):
                ws.cell(r, c).fill = head
                ws.cell(r, c).border = box
            r += 1
            paint(r)
            cols = list(range(FIRST, FIRST + len(headers)))
            for h, c in zip(headers, cols):
                cell = ws.cell(r, c, h)
                cell.font = Font(bold=True, size=9, color=SUB)
                cell.fill = head
                cell.border = box
            for c in range(FIRST + len(headers), LAST):
                ws.cell(r, c).fill = head
                ws.cell(r, c).border = box
            r += 1
            for row_vals in rows:
                paint(r)
                for c in range(FIRST, LAST):
                    ws.cell(r, c).fill = card
                    ws.cell(r, c).border = box
                for (text, chip_band), c in zip(row_vals, cols):
                    cell = ws.cell(r, c, text)
                    if chip_band:
                        fg, bg = CHIP[chip_band]
                        cell.font = Font(bold=True, size=10, color=fg)
                        cell.fill = PatternFill("solid", fgColor=bg)
                    else:
                        cell.font = Font(size=10, color=INK)
                r += 1
            paint(r)
            r += 1

        ov = snapshot.overview or {}
        band("At a glance", ov.get("glance", []))
        band("Immediate attention", ov.get("immediate", []))
        band("Watch list", ov.get("watch", []))

        # "N interfaces" describes the switch; a windows_exporter device (e.g. HCI Cluster)
        # has no interface count in this report's sense, so it gets the same "host(s)"
        # wording reports/form.html already uses for it on the live screen.
        win_names = {d["name"] for d in DEVICES if d.get("kind") == "windows"}
        hci_nodes = getattr(snapshot, "_hci_nodes", None) or {}
        wc = getattr(snapshot, "_wc", None) or {}
        for sysvm in snapshot.systems:
            paint(r)
            ws.cell(r, FIRST, sysvm.name.upper()).font = Font(bold=True, size=12, color=CYAN)
            sub = (f"{sysvm.hosts} host{'s' if sysvm.hosts != 1 else ''}" if sysvm.name in win_names
                   else f"{sysvm.hosts} interfaces")
            ws.cell(r, FIRST + 1, sub).font = Font(color=SUB, size=10)
            r += 1

            # HCI Cluster gets real tables here -- Nodes/Drives/Network/Cluster Resources --
            # the detail that used to render as banners on the web screen (see
            # _network_overview's docstring: that screen is tiles-only now, capturing admin
            # sign-off on flagged anomalies, not a second report). Sourced from the exact
            # snapshot the admin reviewed (snapshot._hci_nodes/_wc), not a fresh query, so
            # the xlsx can never disagree with what was on screen. Only rendered for the
            # device that actually has this data -- the switch's own card is untouched.
            if sysvm.name == "HCI Cluster" and hci_nodes:
                node_order = sorted(hci_nodes.items(), key=lambda kv: kv[1].get("display", kv[0]))

                def _row(label, *cells):
                    return [(label, None)] + list(cells)

                def _down(label, n_cells):
                    return _row(label, *[("not answering", "red")] * n_cells)

                nodes_rows = []
                for target, n in node_order:
                    label = n.get("display", target)
                    if not n.get("reachable"):
                        nodes_rows.append(_down(label, 2))
                        continue
                    cpu, mem, mem_total = n.get("cpu_pct"), n.get("mem_pct"), n.get("mem_total_gb")
                    if mem is None:
                        mem_text = "—"
                    elif mem_total is not None:
                        mem_text = f"{mem:.0f}% · {mem_total:.0f}GB"
                    else:
                        mem_text = f"{mem:.0f}%"
                    nodes_rows.append(_row(label,
                        (f"{cpu:.0f}%" if cpu is not None else "—", pct_band(cpu)),
                        (mem_text, pct_band(mem))))
                table("Nodes", ("Host", "CPU %", "RAM %"), nodes_rows)

                drives_rows = []
                for target, n in node_order:
                    label = n.get("display", target)
                    if not n.get("reachable"):
                        drives_rows.append(_down(label, 4))
                        continue
                    disks = n.get("disks", [])
                    if not disks:
                        drives_rows.append(_row(label, ("—", None), ("—", None), ("—", None), ("—", None)))
                    for d in disks:
                        used = d.get("used")
                        free = d.get("free")
                        size = d.get("size")
                        drives_rows.append(_row(
                            label, (d.get("volume", "—"), None),
                            (f"{used:.0f}%" if used is not None else "—", pct_band(used)),
                            (f"{free:.1f}" if free is not None else "—", None),
                            (f"{size:.0f}" if size is not None else "—", None)))
                table("Drives", ("Host", "Volume", "Used %", "Free GB", "Size GB"), drives_rows)

                network_rows = []
                for target, n in node_order:
                    label = n.get("display", target)
                    if not n.get("reachable"):
                        network_rows.append(_down(label, 4))
                        continue
                    net = n.get("net") or {}
                    err = net.get("err_in", 0) + net.get("err_out", 0)
                    disc = net.get("disc_in", 0) + net.get("disc_out", 0)
                    network_rows.append(_row(
                        label, (_fmt_bps(net.get("in_bps", 0)), None), (_fmt_bps(net.get("out_bps", 0)), None),
                        (f"{err:.0f}", "red" if err >= _NODE_ERR_RED else None),
                        (f"{disc:.0f}", "amber" if disc >= _NODE_DISC_RED else None)))
                table(f"Network (errors/discards over {RATE_WINDOW})",
                     ("Host", "In", "Out", "Errors", "Discards"), network_rows)

                latency_rows = []
                for target, n in node_order:
                    label = n.get("display", target)
                    if not n.get("reachable"):
                        latency_rows.append(_down(label, 2))
                        continue
                    lat = n.get("latency") or {}
                    read_ms, write_ms = lat.get("read_ms"), lat.get("write_ms")
                    latency_rows.append(_row(
                        label,
                        (f"{read_ms:.1f}ms" if read_ms is not None else "—",
                         "red" if (read_ms or 0) >= _NODE_LATENCY_RED_MS else
                         "amber" if (read_ms or 0) >= _NODE_LATENCY_AMBER_MS else None),
                        (f"{write_ms:.1f}ms" if write_ms is not None else "—",
                         "red" if (write_ms or 0) >= _NODE_LATENCY_RED_MS else
                         "amber" if (write_ms or 0) >= _NODE_LATENCY_AMBER_MS else None)))
                table("Disk latency (avg ms/op)", ("Host", "Read", "Write"), latency_rows)

                # Cluster state: node up/down and clustered resource (mostly VM) counts, plus
                # WHICH resources are offline/failed, grouped by owning node -- the same join
                # (resource -> group -> owner) the old banners used, now a table.
                cnodes = [n for w in wc.values() for n in w.get("nodes", [])]
                cres = {"online": 0, "offline": 0, "failed": 0, "other": 0}
                offline_pairs, failed_pairs, group_owner = [], [], {}
                for w in wc.values():
                    res = w.get("resources") or {}
                    for k in ("online", "offline", "failed", "other"):
                        cres[k] += res.get(k, 0)
                    offline_pairs += res.get("offline_names", [])
                    failed_pairs += res.get("failed_names", [])
                    group_owner.update(w.get("group_owner") or {})
                if cnodes:
                    nstate_rows = [_row(name,
                                        (state_text, None if up else "red"))
                                  for name, state_text, up in sorted(cnodes)]
                    table("Cluster nodes (state)", ("Node", "State"), nstate_rows)
                if cres["online"] or cres["offline"] or cres["failed"] or cres["other"]:
                    total = sum(cres.values())
                    table("Cluster resources (summary)", ("Online", "Offline", "Failed", "Other"), [[
                        (f"{cres['online']} / {total}", None),
                        (f"{cres['offline']} / {total}", None),
                        (f"{cres['failed']} / {total}", "red" if cres["failed"] else None),
                        (f"{cres['other']} / {total}", None),
                    ]])

                def _by_node(pairs):
                    by_node: Dict[str, list] = {}
                    for name, group in pairs:
                        by_node.setdefault(group_owner.get(group, "Unknown"), []).append(name)
                    return [_row(node, (", ".join(sorted(names)), None))
                           for node, names in sorted(by_node.items())]

                if failed_pairs:
                    table("Cluster resources — Failed", ("Node", "Failed resources"), _by_node(failed_pairs))
                if offline_pairs:
                    table("Cluster resources — Offline (informational, not a fault)",
                         ("Node", "Offline resources"), _by_node(offline_pairs))

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


# =======================================================================================
#  The Infrastructure Report — Infrastructure Admin's OWN report (see views.infra_report/
#  infra_generate), reading the SAME annotated Snapshot build_report() above reads for the
#  Network Report, rendered through the NEW tree-nested template (infrastructure_report.py,
#  ported from the Infrastructure Report dashboard design) instead of the flat band/table
#  layout. Never a fresh query -- see capture_snapshot's own docstring -- so this xlsx can
#  never disagree with what the admin reviewed and annotated on screen.
#
#  Infrastructure Admin's estate is DISPLAY-ONLY here: ownership of these devices (who may
#  select and annotate them) stays with Network Admin -- see DEVICES' own comments on
#  root-dc-1/root-dc-2 and hci-cluster. This only reads the Snapshot capture_snapshot()
#  already built for whichever role captured it.
#
#  Services are deliberately NOT rendered here (every DeviceGroup.services stays empty, so
#  infrastructure_report.write_section skips that panel entirely): capture_snapshot() does
#  not query the windows_exporter service collector today (see DEVICES' root-dc-1/2 comment
#  -- confirmed present on Prometheus, but nothing here reads it yet), and inventing a fresh
#  query for it would break the one-snapshot-in / one-report-out guarantee this module keeps
#  everywhere else. The standalone infrastructure report CLI, which captures independently
#  per run, does query it -- see standalone/infrastructure admin report/generate_report.py.
# =======================================================================================
def infrastructure_report_filename(theme: str = "dark", when=None) -> str:
    """Same family name as network_report_filename -- see its own docstring -- so every
    report this app produces for this estate sits together in a folder."""
    import datetime
    when = when or datetime.datetime.now()
    return f"Infrastructure Admin Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


#: flag.text already carries its own label for these -- see _windows_device_flags: the "nodes"
#: branch (node_*) prefixes every text with the node's own display name, and win_down/
#: win_unscraped are written with the device's name baked in before any branching happens.
#: Every OTHER flag (cpu_high/mem_high/disk_high, cluster_node_down/cluster_resource_failed)
#: carries no name at all, so _infra_notes prefixes those with the device/group name itself.
_INFRA_LABELED_FLAG_PREFIXES = ("win_down", "win_unscraped", "node_")

#: The tree-nested Infrastructure Report already nests each HCI node under its "HCI Cluster
#: Host" parent section, so the "HCI Cluster Node N (...)" wrapper prometheus.yml's `display`
#: label bakes into every metric/flag naming a node is redundant everywhere it shows up in this
#: report -- not just the section titles (see build_infrastructure_report's children loop) but
#: every row entry too: CPU/RAM node names, disk host names, notes, and banner rows. Strips it
#: down to the bare hostname/IP inside the parens; text with no match passes through unchanged.
_HCI_NODE_LABEL_RE = re.compile(r"HCI Cluster Node \d+ \(([^)]+)\)")


def _infra_short_node(text: str) -> str:
    return _HCI_NODE_LABEL_RE.sub(r"\1", text)


def _infra_notes(sysvm, comment: str, flag_answers: dict) -> tuple:
    """A device's flags -> NoteRow list + (critical, warning) counts, for one DeviceGroup.

    The admin's one free-text comment for this device lands on the LAST row -- write_notes()
    (infrastructure_report.py) renders every non-empty NoteRow.comment as one "Comment"
    section below the flagged-metric rows, so one row carrying it is enough for it to show;
    putting it on every row would repeat the same paragraph once per flag.
    """
    import infrastructure_report as ir

    if not sysvm.flags:
        return [ir.NoteRow(ir.SENTINEL_NOTE, comment=comment)], 0, 0
    rows, critical, warning = [], 0, 0
    last = len(sysvm.flags) - 1
    for i, flag in enumerate(sysvm.flags):
        if flag.band == "red":
            critical += 1
        else:
            warning += 1
        text = (flag.text if flag.key.startswith(_INFRA_LABELED_FLAG_PREFIXES)
               else f"{sysvm.name} · {flag.text}")
        text = _infra_short_node(text)
        rows.append(ir.NoteRow(
            flagged_metric=text,
            fix_needed=flag_answers.get(flag.key, ""),
            comment=comment if i == last else "",
        ))
    return rows, critical, warning


def _infra_cpu_ram_disks(m: dict, label: str):
    """One windows_exporter target's raw metrics (see _windows_metrics/_hci_node_metrics) ->
    (CpuRam-or-None, [DiskRow, ...]). None for CpuRam when the target has never been
    reachable -- there is no percentage to show, not a fabricated 0%."""
    import infrastructure_report as ir

    if not m.get("reachable"):
        return None, []
    cpu_ram = None
    if m.get("cpu_pct") is not None or m.get("mem_pct") is not None:
        mem_total = m.get("mem_total_gb")
        cpu_ram = ir.CpuRam(
            node=label, cpu_pct=m.get("cpu_pct") or 0.0, ram_pct=m.get("mem_pct") or 0.0,
            ram_size=f"{mem_total:.0f}GB" if mem_total is not None else None)
    disks = [ir.DiskRow(host=label, used_pct=d["used"], size_gb=round(d["size"]), mount=d["volume"])
            for d in m.get("disks", []) if d.get("used") is not None and d.get("size") is not None]
    return cpu_ram, disks


# CPU/RAM/Disk on the Root DCs comes from windows_exporter's textfile collector, not yet
# publishing (see the note this module builds for them). But the OTHER enabled collector,
# `service`, is scraping right now -- a host with no resource metrics is not the same as a
# host with no metrics at all. These are the AD Domain Controller role's own core services,
# confirmed present on both root DCs via windows_exporter's own service list: (metric `name`
# label, matched case-insensitively -- observed as "w32time" on one DC and "W32Time" on the
# other -> friendly display name).
_AD_SERVICES = [
    ("ADWS", "ADWS (AD Web Services)"),
    ("DNS", "DNS Server"),
    ("DFSR", "DFSR (SYSVOL replication)"),
    ("Kdc", "Kerberos KDC"),
    ("Netlogon", "Netlogon"),
    ("IsmServ", "Intersite Messaging"),
    ("W32Time", "Windows Time"),
]


def _ad_service_states(targets: list) -> Dict[str, dict]:
    """{target: {service_key: running_bool}} for _AD_SERVICES, one query across every target
    and service name. A service absent from the result (host unreachable, or genuinely not
    installed) is left out of the inner dict entirely -- not the same claim as "confirmed
    stopped", so the caller can skip it rather than guess.

    state="running" MUST be in the query: windows_exporter's windows_service_state emits one
    series per (instance, name, state) -- continue pending/pause pending/paused/running/start
    pending/stop pending/stopped -- with value 1 on whichever state is currently active and 0
    on every other, so exactly one of those seven is always 1 for any service that exists at
    all. `max by (instance, name)` alone (an earlier version of this query) therefore always
    returns 1 regardless of which state that is -- it can tell "installed" from "not
    installed" but never "running" from "stopped", silently reporting stopped services as
    running (confirmed live 2026-08-28: SmbWitness genuinely stopped on the HCI cluster host,
    state="stopped" value 1 / state="running" value 0, yet the old query still returned 1).
    Pinning state="running" makes the value itself mean what running_bool claims."""
    if not targets:
        return {}
    prom, _ = _prometheus()
    # No re.escape() here: PromQL label-matcher strings consume a backslash as a STRING escape
    # before RE2 ever sees the regex, so `\.` (what re.escape gives a dotted IP) comes back as
    # "unknown escape sequence" -- confirmed live. `.` un-escaped just means "any character" in
    # the regex, harmless for these fixed, internally-configured name/IP:port values.
    names_re = "|".join(k for k, _ in _AD_SERVICES)
    targets_re = "|".join(targets)
    try:
        rows = prom.query(
            f'windows_service_state{{state="running", '
            f'name=~"(?i)^({names_re})$", instance=~"{targets_re}"}}')
    except Exception:                       # noqa: BLE001
        rows = []
    by_lower = {k.lower(): k for k, _ in _AD_SERVICES}
    out: Dict[str, dict] = {t: {} for t in targets}
    for r in rows:
        inst = r["labels"].get("instance")
        key = by_lower.get(r["labels"].get("name", "").lower())
        if inst in out and key:
            out[inst][key] = r["value"] >= 1
    return out


# Failover Clustering + Hyper-V core services -- the same "role's own core services"
# curation _AD_SERVICES applies to the domain controllers, sized to what a hyper-converged
# node actually needs to keep VMs available: cluster membership (ClusSvc) and the two
# Hyper-V services that own a VM's lifecycle (vmms) and its actual compute (vmcompute), plus
# the newer cloud-managed control-plane service (HvHost) Azure Stack HCI/Azure Local nodes
# run alongside them. All four confirmed RUNNING live on the one HCI node currently reporting
# (HRE-HCIHOST-01, 2026-08-28) -- the cluster's other 3 configured nodes are not yet up (see
# _hci_node_metrics), so nothing to confirm against there yet; their rows simply come back
# empty until they start reporting, same as CPU/RAM/disk already do for them.
#
# Two more candidates -- SmbWitness (SMB Witness, transparent failover for clustered file
# shares) and TieringEngineService (Storage Spaces tiering) -- were checked on the same node
# and found STOPPED. Left out rather than guessed into "expected running": unlike the four
# above, there is no confirmation yet from the infrastructure admins that this cluster
# actually uses CSV/S2D tiering, so a stopped state here could be either a real fault or a
# feature this cluster was never configured to use -- see _ad_service_states' own docstring
# for why state="running" (not a bare max-by) is what makes any of this trustworthy at all.
_HCI_SERVICES = [
    ("ClusSvc", "Cluster Service"),
    ("vmms", "Hyper-V Virtual Machine Management"),
    ("vmcompute", "Hyper-V Host Compute Service"),
    ("HvHost", "Hyper-V Host Service"),
]


def _hci_service_states(targets: list) -> Dict[str, dict]:
    """{target: {service_key: running_bool}} for _HCI_SERVICES -- same query shape (and same
    state="running" requirement) as _ad_service_states, see its own docstring."""
    if not targets:
        return {}
    prom, _ = _prometheus()
    names_re = "|".join(k for k, _ in _HCI_SERVICES)
    targets_re = "|".join(targets)
    try:
        rows = prom.query(
            f'windows_service_state{{state="running", '
            f'name=~"(?i)^({names_re})$", instance=~"{targets_re}"}}')
    except Exception:                       # noqa: BLE001
        rows = []
    by_lower = {k.lower(): k for k, _ in _HCI_SERVICES}
    out: Dict[str, dict] = {t: {} for t in targets}
    for r in rows:
        inst = r["labels"].get("instance")
        key = by_lower.get(r["labels"].get("name", "").lower())
        if inst in out and key:
            out[inst][key] = r["value"] >= 1
    return out


def build_infrastructure_report(snapshot, *, theme: str = "dark", author: str,
                                annotations: dict, summary_comment: str) -> bytes:
    """Map the annotated Snapshot into a ReportData tree and render it via
    infrastructure_report.build_report(). See this section's module docstring above."""
    import infrastructure_report as ir

    wm = getattr(snapshot, "_wm", None) or {}
    hci_nodes = getattr(snapshot, "_hci_nodes", None) or {}
    wc = getattr(snapshot, "_wc", None) or {}
    by_name = {d["name"]: d for d in DEVICES}

    groups = []
    # "Root Domain Controllers" and "Child Domain Controllers" are two DIFFERENT DEVICES
    # `system` values -- only Root exists today (root-dc-1/2), Child is expected to gain
    # entries later. Each becomes its OWN top-level group (siblings of HCI Cluster Host, same
    # indentation), not nested under a shared "Active Directory" umbrella -- there is no
    # umbrella-level data that isn't already the sum of one tier's own hosts, so the extra
    # nesting level bought nothing but an indent HCI Cluster Host doesn't also pay.
    for tier_label, tier_system in (("Root Domain Controllers", "Root Domain Controllers"),
                                    ("Child Domain Controllers", "Child Domain Controllers")):
        tier_hosts = [s for s in snapshot.systems
                     if by_name.get(s.name, {}).get("system") == tier_system]
        if not tier_hosts:
            continue
        # Each DC gets its OWN section (child), not one Services table combining both -- a
        # shared table only ever distinguished rows by suffixing the hostname onto every
        # service name. Same parent+children shape as HCI Cluster Host/its nodes below, except
        # the parent's OWN Services table is deliberately left empty -- unlike HCI (one cluster,
        # services genuinely describe the shared resource), each DC's services are entirely its
        # own; a rolled-up copy at the parent said nothing an admin couldn't already read on
        # that DC's own section, just repeated once more with its name pasted onto every row.
        # The parent still carries an aggregate CPU/RAM/Disk view across its own tier's hosts
        # (same aggregate-across-hosts pattern every multi-host system card in this app uses),
        # and each DC's own comment/flag answers land on ITS OWN section (annotations are
        # already keyed per host, sysvm.name) instead of being merged into one shared list.
        cpu_ram, disks, children = [], [], []
        critical = warning = 0
        ad_svc_states = _ad_service_states([by_name[s.name]["target"] for s in tier_hosts])
        for sysvm in tier_hosts:
            dev = by_name[sysvm.name]
            m = wm.get(dev["target"], {"known": False, "reachable": False})
            cr, dk = _infra_cpu_ram_disks(m, sysvm.name)
            if cr:
                cpu_ram.append(cr)
            disks += dk
            host_services = [ir.ServiceRow(display_name, "RUNNING" if running else "DOWN")
                             for key, display_name in _AD_SERVICES
                             for running in [ad_svc_states.get(dev["target"], {}).get(key)]
                             if running is not None]
            ann = annotations.get(sysvm.name, {})
            rows, c, w = _infra_notes(sysvm, ann.get("comment", ""), ann.get("flags", {}))
            if cr is None and m.get("reachable"):
                # Reachable, but with no CPU/RAM/Disk data at all -- these hosts expose that
                # via windows_exporter's textfile collector, not the live collectors this app
                # queries elsewhere (see DEVICES' own root-dc-1/2 comment), and nothing has
                # been published there yet (collector_success=0, confirmed live). Without
                # this note, the host has no CPU/RAM table row to appear in (cpu_ram/disks
                # both end up empty for it) and no flag either (it's not down), so it would
                # otherwise vanish from the report with nothing anywhere naming it --
                # indistinguishable from "not included at all". Prepended ahead of whatever
                # _infra_notes produced so the admin's own comment (if any) is kept, not
                # overwritten. The `service` collector IS live for these hosts though (unlike
                # textfile) -- see the Services table below, not another blank gap.
                rows = [ir.NoteRow(f"Reachable, but CPU/RAM/Disk have not been published yet "
                                   f"(expected via the textfile collector); service status "
                                   f"below is live.")] + rows
            critical += c
            warning += w
            children.append(ir.DeviceGroup(
                title=sysvm.name, services=host_services, cpu_ram=[cr] if cr else [], disks=dk,
                notes=rows, critical=c, warning=w, count=1, count_label="host",
                signed_by=author))
        groups.append(ir.DeviceGroup(
            title=tier_label, cpu_ram=cpu_ram, disks=disks,
            notes=[], children=children, critical=critical, warning=warning,
            count=len(tier_hosts), count_label="host" if len(tier_hosts) == 1 else "hosts",
            signed_by=author))

    hci_sysvm = next((s for s in snapshot.systems if by_name.get(s.name, {}).get("key") == "hci-cluster"), None)
    if hci_sysvm is not None:
        ann = annotations.get(hci_sysvm.name, {})
        notes, critical, warning = _infra_notes(hci_sysvm, ann.get("comment", ""), ann.get("flags", {}))
        # Cluster-level facts from _windows_cluster_metrics (snapshot._wc) -- fetched into this
        # function already but never rendered anywhere until now. Keyed by whichever node's own
        # exporter actually answered the mscluster WMI query (only node 1 is reachable today),
        # so this is the CLUSTER's own view of every member, not just the one node Prometheus
        # can scrape directly -- e.g. it can say nodes 2-4 are still healthy cluster members
        # even while Prometheus itself reports them unreachable. Attached to the PARENT group,
        # not a per-node child, because there is no reliable way to match an mscluster node's
        # hostname (HRE-HCIHOST-02, ...) back to a specific node's own IP-only display label
        # (10.100.246.4, ...) without a confirmed hostname/IP mapping -- guessing that
        # correspondence would risk naming the WRONG node as up/down, worse than not showing it.
        # Failed cluster resources and down cluster nodes are ALREADY in hci_sysvm.flags (see
        # _windows_device_flags' own cluster_node_down/cluster_resource_failed) and so already
        # have their own NoteRow via _infra_notes above -- nothing to add for those. What's
        # missing is the positive case: flags only ever fire on a PROBLEM, so a fully healthy
        # cluster (today: all 4 members up) leaves no mention of node membership anywhere. Add
        # that proactively, queried via whichever node's own exporter actually answered the
        # mscluster WMI call (only node 1 is reachable today) -- the CLUSTER's own view of
        # every member, not just the one node Prometheus can scrape directly.
        wc_target, wc_data = next(iter(wc.items()), (None, None))
        members = (wc_data or {}).get("nodes") or []
        if members:
            queried_via = hci_nodes.get(wc_target, {}).get("display", wc_target)
            parts = ", ".join(f"{name} ({state.upper()})"
                              for name, state, _up in sorted(members))
            notes = [ir.NoteRow(f"Cluster's own view of node membership (queried via "
                                f"{_infra_short_node(queried_via)}): {parts}.")] + notes
        node_order = sorted(hci_nodes.items(), key=lambda kv: kv[1].get("display", kv[0]))
        # The parent "HCI Cluster" row always carries its own CPU/RAM/Disk table -- the same
        # aggregate-across-hosts pattern generate_report.py uses for every multi-host system
        # card (e.g. RTGS, Attendance System: one table listing every host's row) -- so it
        # never sits structurally empty just because it also has per-node children below it.
        # DeviceGroup.is_cluster_host names exactly this shape: a group with BOTH its own
        # data AND children. Per-node children are additionally built once there's more than
        # one node, giving the reachability/critical breakdown a flat host list can't carry.
        cpu_ram, disks, children, parent_services = [], [], [], []
        hci_svc_states = _hci_service_states([target for target, _ in node_order])
        for target, n in node_order:
            # Section title: the full "HCI Cluster Node N (...)" display string, unchanged.
            # Row entries (CPU/RAM, disk, notes, banners): bare hostname/IP -- repeating the
            # "HCI Cluster Node N" wrapper on every row under a section already titled that
            # way is redundant. See _infra_short_node.
            full_label = n.get("display", target)
            label = _infra_short_node(full_label)
            cr, dk = _infra_cpu_ram_disks(n, label)
            if cr:
                cpu_ram.append(cr)
            disks += dk
            # A node not yet reporting (see _hci_node_metrics) has nothing in
            # hci_svc_states[target] at all -- an empty services list, not a table full of
            # "unknown", same as its own empty cpu_ram/disks above.
            node_services = [ir.ServiceRow(display_name, "RUNNING" if running else "DOWN")
                             for key, display_name in _HCI_SERVICES
                             for running in [hci_svc_states.get(target, {}).get(key)]
                             if running is not None]
            # Rolled up onto the parent "HCI Cluster Host" row too, named per node (same
            # "{service} ({host})" shape the Active Directory group's own services use above)
            # -- the parent's CPU/RAM/Disk tables are already an aggregate-across-nodes view,
            # so its services shouldn't sit empty just because the per-node detail lives below.
            parent_services += [ir.ServiceRow(f"{row.name} ({label})", row.status)
                                for row in node_services]
            if len(node_order) > 1:
                child_notes = ([ir.NoteRow(ir.SENTINEL_NOTE)] if n.get("reachable")
                               else [ir.NoteRow(f"{label} is not answering")])
                children.append(ir.DeviceGroup(
                    title=full_label, services=node_services, cpu_ram=[cr] if cr else [], disks=dk,
                    notes=child_notes, critical=0 if n.get("reachable") else 1, count=1,
                    count_label="node", signed_by=author))
        groups.append(ir.DeviceGroup(
            title="HCI Cluster Host", services=parent_services, cpu_ram=cpu_ram, disks=disks,
            notes=notes, children=children,
            critical=critical, warning=warning, count=max(1, len(node_order)),
            count_label="node" if len(node_order) == 1 else "nodes", signed_by=author))

    devices_total = len(snapshot.systems)
    all_disks = [d for g in groups for d in (g.disks + [dd for c in g.children for dd in c.disks])]
    all_cpu_ram = [c for g in groups for c in (g.cpu_ram + [cc for ch in g.children for cc in ch.cpu_ram])]
    cluster_nodes = len(hci_nodes)
    cluster_nodes_down = sum(1 for n in hci_nodes.values() if not n.get("reachable"))
    cres = {"online": 0, "offline": 0, "failed": 0, "other": 0}
    for w in wc.values():
        res = w.get("resources") or {}
        for k in cres:
            cres[k] += res.get(k, 0)

    # Components are counted at the finest tracked granularity: a device with sub-nodes (the
    # HCI Cluster Host) contributes one component PER NODE, not one for the whole device --
    # everything else (Root DCs, ...) is a single component. "Devices down"/"components down"
    # differ the same way: the HCI device counts as one down device even when several of its
    # nodes are down, which understates the real down-count, so the tile below is measured in
    # components (cluster_nodes_down, not a 0/1 per device) rather than devices.
    hci_name = hci_sysvm.name if hci_sysvm is not None else None
    components_total = 0
    components_down = 0
    for s in snapshot.systems:
        if s.name == hci_name:
            components_total += cluster_nodes if cluster_nodes else 1
            components_down += cluster_nodes_down
        else:
            components_total += 1
            if any(f.key.startswith(("win_down", "win_unscraped")) for f in s.flags):
                components_down += 1

    def _tone(count):
        return "red" if count else "green"

    def _watch_tone(count, red_count):
        return "red" if red_count else ("amber" if count else "green")

    storage_critical = sum(1 for d in all_disks if d.used_pct >= 95)
    storage_amber = sum(1 for d in all_disks if 85 <= d.used_pct < 95)
    mem_critical = sum(1 for c in all_cpu_ram if c.ram_pct >= 95)
    cpu_amber = sum(1 for c in all_cpu_ram if c.cpu_pct >= 80)
    cpu_red = sum(1 for c in all_cpu_ram if c.cpu_pct >= 90)
    mem_amber = sum(1 for c in all_cpu_ram if 80 <= c.ram_pct < 95)

    needs_attention = [
        ir.SummaryMetric("COMPONENTS DOWN", components_down, f"down | {components_total} total",
                         _tone(components_down)),
        ir.SummaryMetric("NODES DOWN", cluster_nodes_down, f"down | {cluster_nodes} total",
                         _tone(cluster_nodes_down)),
        ir.SummaryMetric("STORAGE CRITICAL >=95%", storage_critical,
                         f"nodes | {len(all_disks)} total", _tone(storage_critical)),
        ir.SummaryMetric("MEMORY CRITICAL >=95%", mem_critical,
                         f"nodes | {len(all_cpu_ram)} total", _tone(mem_critical)),
    ]
    watch_list = [
        ir.SummaryMetric("HIGH CPU", cpu_amber + cpu_red, f"nodes | {len(all_cpu_ram)} total",
                         _watch_tone(cpu_amber + cpu_red, cpu_red)),
        ir.SummaryMetric("HIGH MEMORY", mem_amber, f"nodes | {len(all_cpu_ram)} total",
                         _watch_tone(mem_amber, 0)),
        ir.SummaryMetric("STORAGE AT CAPACITY >=85%", storage_amber + storage_critical,
                         f"nodes | {len(all_disks)} total",
                         _watch_tone(storage_amber + storage_critical, storage_critical)),
        # Offline is deliberately NOT tracked here (see _CLUSTER_RESOURCE_STATE's own comment:
        # most of this estate's Offline resources are powered-off test/UAT/DR VMs, informational
        # not a fault). Failed is the real signal -- a resource that has exhausted its restart
        # attempts. Kept in THIS panel (not moved to needs_attention) because each panel splits
        # its own width evenly across its tiles (_split_cols) and every tile needs at least 2
        # columns for its own label/total sub-split -- a 5th tile in needs_attention's narrower
        # span doesn't fit (confirmed: raises a merge-range error). _tone still renders this red
        # when any resource has failed, same severity as the banner/flag below, just laid out
        # in this row.
        ir.SummaryMetric("CLUSTER RESOURCES FAILED", cres["failed"],
                         f"resources | {sum(cres.values())} total", _tone(cres["failed"])),
    ]

    # ---- banners: named detail behind the tile counts above, System Admin Report style ----
    # Only ever built from detail this module already has (flag.text, wc's per-resource
    # offline_names/failed_names, per-host disk/cpu_ram rows) -- never a bare count standing
    # in for a name that isn't actually available (see this module's own docstring).
    banners: list = []

    down_rows, seen_down = [], set()
    for s in snapshot.systems:
        for f in s.flags:
            if not f.key.startswith(("win_down", "win_unscraped", "node_down")):
                continue
            text = f.text
            if text.endswith(" is not answering"):
                lbl, detail = text[: -len(" is not answering")], "not answering"
            elif text.endswith(" has never been scraped by Prometheus"):
                lbl, detail = text[: -len(" has never been scraped by Prometheus")], "never scraped by Prometheus"
            else:
                lbl, detail = s.name, text
            lbl = _infra_short_node(lbl)
            if (lbl, detail) in seen_down:
                continue
            seen_down.add((lbl, detail))
            down_rows.append(ir.BannerRow(lbl, detail))
    if down_rows:
        banners.append(ir.Banner(
            "CRITICAL", "COMPONENTS DOWN",
            f"{len(down_rows)} component(s) unreachable",
            rows=down_rows,
            note="These devices/nodes are not responding to monitoring right now -- confirm "
                 "power, network path, and the host agent/exporter service."))

    # offline_names (also in `res`) is deliberately never turned into a row here -- see the
    # CLUSTER RESOURCES FAILED SummaryMetric's own comment above.
    failed_res_rows = []
    for w in wc.values():
        res = w.get("resources") or {}
        group_owner = w.get("group_owner") or {}
        for name, group in res.get("failed_names", []):
            owner = group_owner.get(group)
            detail = f"group {group}" + (f" · owner {owner}" if owner else "")
            failed_res_rows.append(ir.BannerRow(name, detail))
    if failed_res_rows:
        banners.append(ir.Banner(
            "CRITICAL", "CLUSTER RESOURCES FAILED",
            f"{len(failed_res_rows)} resource(s) in a failed state",
            rows=failed_res_rows,
            note="A failed cluster resource has exhausted its restart attempts and needs "
                 "manual intervention in Failover Cluster Manager."))

    storage_critical_rows = [ir.BannerRow(d.host, f"{d.mount}  {d.used_pct:.0f}%")
                             for d in all_disks if d.used_pct >= 95]
    if storage_critical_rows:
        banners.append(ir.Banner(
            "CRITICAL", "DISK NEAR-FULL",
            f"{len(storage_critical_rows)} disk(s) at/over 95%",
            rows=storage_critical_rows,
            note="These volumes are almost full -- an imminent outage that can take the "
                 "service down. Free space or extend the disk now."))

    mem_critical_rows = [ir.BannerRow(c.node, f"RAM {c.ram_pct:.0f}%")
                         for c in all_cpu_ram if c.ram_pct >= 95]
    if mem_critical_rows:
        banners.append(ir.Banner(
            "CRITICAL", "MEMORY CRITICAL",
            f"{len(mem_critical_rows)} node(s) at/over 95% RAM",
            rows=mem_critical_rows,
            note="Memory this high risks paging/swapping and service instability -- "
                 "investigate the top consumer or add memory."))

    cpu_hot_rows = [ir.BannerRow(c.node, f"CPU {c.cpu_pct:.0f}%")
                   for c in all_cpu_ram if c.cpu_pct >= 80]
    if cpu_hot_rows:
        banners.append(ir.Banner(
            "WARNING", "HIGH CPU",
            f"{len(cpu_hot_rows)} node(s) at/over 80% CPU",
            rows=cpu_hot_rows,
            note="Sustained high CPU degrades response times before it causes an outage -- "
                 "watch for a runaway process or plan capacity."))

    mem_warn_rows = [ir.BannerRow(c.node, f"RAM {c.ram_pct:.0f}%")
                     for c in all_cpu_ram if 80 <= c.ram_pct < 95]
    if mem_warn_rows:
        banners.append(ir.Banner(
            "WARNING", "HIGH MEMORY",
            f"{len(mem_warn_rows)} node(s) at/over 80% RAM",
            rows=mem_warn_rows,
            note="Not yet critical, but trending toward it -- worth a look before it becomes "
                 "an imminent issue."))

    storage_warn_rows = [ir.BannerRow(d.host, f"{d.mount}  {d.used_pct:.0f}%")
                         for d in all_disks if 85 <= d.used_pct < 95]
    if storage_warn_rows:
        banners.append(ir.Banner(
            "WARNING", "STORAGE AT CAPACITY",
            f"{len(storage_warn_rows)} disk(s) at/over 85%",
            rows=storage_warn_rows,
            note="Not yet imminent, but these volumes are filling up -- plan space now "
                 "before they reach the near-full threshold."))

    import datetime
    now = datetime.datetime.now()
    data = ir.ReportData(
        generated_at=now.strftime("%d %b %Y  ·  %H:%M"),
        nodes_total=devices_total,
        cluster_count=1 if hci_nodes else 0,
        cluster_nodes=cluster_nodes,
        # Real count, not storage capacity: WSFC's own cluster resource objects (VM roles,
        # disks, IP addresses, network names, ...) -- the same `cres` totals already behind the
        # CLUSTER RESOURCES FAILED tile and the failed-resource banner above. No cluster
        # storage-pool/CSV capacity metric is collected (each node's own windows_logical_disk_
        # size_bytes only sees its local C:, confirmed live), so this tile counts resource
        # objects rather than fabricating a TB figure from data that isn't there.
        cluster_resources_total=sum(cres.values()),
        last_checked=now.strftime("%H:%M"),
        needs_attention=needs_attention,
        watch_list=watch_list,
        summary_notes=([ir.SummaryNote("Infrastructure", summary_comment)]
                       if summary_comment else []),
        groups=groups,
        banners=banners,
        summary_signed_by=author,
        components_total=components_total,
    )

    import io
    buf = io.BytesIO()
    ir.build_report(data, buf)
    return buf.getvalue()

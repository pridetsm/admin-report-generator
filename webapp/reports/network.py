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
from typing import Dict, List, Optional, Tuple

import generate_report as gr

# How far back the throughput rate is averaged. Long enough to survive a missed scrape,
# short enough to still reflect the current load.
RATE_WINDOW = "5m"

# The `snmp` job declares no scrape_interval of its own, so it inherits Prometheus's global
# 15s. Used only to say how often the 32-bit counters wrap relative to sampling. If the
# server's global interval changes, change this — it is a statement about the scrape config,
# which this app cannot read.
SCRAPE_INTERVAL = 15

# The device count used to be one (the core switch); now the Switches & Routers Report scopes
# collect() across 38 more, so this is an estate-wide top-N, not one device's -- bumped from 15
# (2026-09-22) so a couple of very busy devices don't crowd out the rest of the estate's own
# busiest links. Still a cap, not a promise of completeness: tables show the busiest and the
# broken rather than every interface across the whole estate.
TOP_INTERFACES = 25


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
         probe="entSensorValue",
         # Dropped from the Wireless Controller Report (2026-09-29, on request: "all access
         # controllers are virtual, no need to check somethings we were checking for in
         # actuall devices") -- confirmed live: both WLCs return 0 entSensorValue rows, not
         # because collection is broken but because a C9800-CL has no physical chassis to
         # have a temperature sensor ON -- there is nothing to ever collect here, a different
         # claim than "not collected yet". See measure_catalogue's own `report_kind` filtering.
         skip_for={"wireless_controller"}),
    # "Optical Tx/Rx power" entry retired (2026-09-23, on request: "leave out optic details
    # entirely") -- the report no longer collects or shows it, so it no longer belongs in the
    # catalogue of what this report tracks either.
    dict(section="System & Hardware Health", name="Flash / storage",
         what="How full each device's flash partitions are — running out stops a device "
              "writing its own config, crashinfo, or a new IOS image.",
         state="missing", oid="ciscoFlashPartitionTable",
         needs="Confirmed live via CISCO-FLASH-MIB (HOST-RESOURCES-MIB::hrStorageTable is "
               "not implemented on any device tested — 0 PDUs on a switch, the core "
               "switch, or the router).",
         probe='ciscoFlashPartitionRaw{ciscoFlashPartitionColumn="13"}'),
    dict(section="System & Hardware Health", name="Power supplies & fans",
         what="Whether redundant power sources and fans are working.",
         state="missing", oid="cefcFRUPowerOperStatus",
         needs="Confirmed live via CISCO-ENTITY-FRU-CONTROL-MIB (this platform does not "
               "populate the older CISCO-ENVMON-MIB).",
         probe="cefcFRUPowerOperStatus",
         # Dropped from the Wireless Controller Report (2026-09-29, same request/reasoning as
         # Temperature just above) -- confirmed live: 0 rows on both WLCs, a virtual C9800-CL
         # has no physical PSU or fan to ever report on.
         skip_for={"wireless_controller"}),
    dict(section="System & Hardware Health", name="PoE power draw",
         what="How much Power-over-Ethernet each switch is delivering against its budget — "
              "a PoE budget running out silently drops power to phones/APs/cameras "
              "plugged in later. Routers and the WLC have no PoE ports; not applicable to "
              "them.",
         state="missing", oid="POWER-ETHERNET-MIB (pethPsePortPower) / "
                              "CISCO-POWER-ETHERNET-EXT-MIB (cpeExtPsePortPwrAvailable)",
         needs="Confirmed genuinely absent, not a scrape-config gap: neither OID tree "
               "appears anywhere in snmp_exporter's own generated modules: section "
               "(grepped directly). Closing this needs a new snmp_exporter module built "
               "against one of those MIBs — the same kind of work that already closed the "
               "CPU/RAM/temperature/PSU gaps above, just not done yet for PoE.",
         probe="",
         # Dropped from the Core Switches Report (2026-09-24, on request: "remove this
         # metric for core switches PoE power draw") -- core/distribution switches (HQ/DR/
         # BYO) don't power end devices directly, only access switches do; same reasoning
         # already applied to BGP sessions/Active connections/Connected devices above. See
         # measure_catalogue's own `report_kind` filtering. Also dropped from Wireless
         # Controller (2026-09-29) -- this entry's own "what" text already said the WLC has
         # no PoE ports, just wasn't enforced until now ("no need to check somethings we
         # were checking for in actuall devices").
         skip_for={"core_switches", "wireless_controller"}),

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
         probe="bgpPeerState",
         # Dropped from the Core Switches Report (2026-09-24, on request: "for the core
         # switch report drop these metrics no need to check them") -- BGP is a routing
         # concept, not a switching one; still shown on the Routers Report, where it's
         # actually relevant. See measure_catalogue's own `report_kind` filtering.
         skip_for={"core_switches"}),
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
         needs="A firewall is not in scope yet: no firewall device is onboarded to this "
               "estate at all. Needs one added as an SNMP target first.",
         probe="",
         # Dropped from the Core Switches Report (2026-09-24, on request: "for the core
         # switch report drop these metrics no need to check them") -- a core switch is not
         # a firewall; this was never actually about it.
         skip_for={"core_switches"}),
    dict(section="Protocol & Network State", name="Connected devices (Wi-Fi)",
         what="How many users are on each wireless access point.",
         state="missing", oid="vendor wireless MIB",
         needs="Relevant to the Wireless Controller Report, not the switch estate -- the WLC "
               "(hre-wlc-02) is onboarded but this reading isn't collected from it yet.",
         probe="",
         # Dropped from the Core Switches Report (2026-09-24, same request as above) -- a
         # core switch has no Wi-Fi clients of its own to count.
         skip_for={"core_switches"}),
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


def _fmt_duration(seconds: Optional[float]) -> str:
    """Seconds -> the coarsest readable unit ("47m", "2h", "3d") -- used only for the relay
    freshness gap in _windows_device_flags, so an admin reads "no fresh metrics in 47m"
    instead of a bare, harder-to-parse seconds count."""
    if seconds is None:
        return "an unknown duration"
    seconds = max(0, seconds)
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


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


def measure_catalogue(q, wanted_targets=None, report_kind: Optional[str] = None) -> list:
    """The catalogue with each entry's state MEASURED, not declared.

    The states used to be written into the table by hand, which meant the report kept saying
    "not collected" for a metric the day after it started being collected — and a hardcoded
    claim about someone else's Prometheus config is a claim that goes stale silently.

    Each entry names the metric that would prove it present; if the series exist for the
    devices in scope, it is live. `degraded` is reserved for the one case where the data is
    there but known-wrong: 32-bit octet counters standing in for the 64-bit pair.

    `report_kind` (2026-09-24, on request: "for the core switch report drop these metrics no
    need to check them") -- an entry whose own `skip_for` set contains this report's slug
    (e.g. "core_switches") is left out of the returned list entirely, not just hidden: it was
    never applicable to what THIS report covers, so it shouldn't count toward "N metrics not
    collected" here either. None (the default) skips no entries -- every existing caller that
    doesn't pass this keeps seeing the full catalogue, unchanged.
    """
    out = []
    for m in CATALOGUE:
        if report_kind and report_kind in (m.get("skip_for") or ()):
            continue
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


def collect(only: Optional[set] = None, report_kind: Optional[str] = None) -> dict:
    """Gather the report. `only` is a set of DEVICE KEYS, scoping it to the admin's choice.

    Scoping happens on the `instance` label rather than by filtering after the fact, so a
    report that says it covers the core switch cannot quietly include a second device that
    happens to share the SNMP job.

    `report_kind` (2026-09-24) -- passed straight through to measure_catalogue() so a report
    picker can drop CATALOGUE entries that don't apply to it (see that function's own
    `report_kind` comment); it touches nothing else collect() does.
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

    def _one(expr):
        rows = q(expr)
        if wanted is not None:
            rows = [r for r in rows if r["labels"].get("instance") in wanted]
        return rows

    # ---- CDP neighbours (CISCO-CDP-MIB) -- moved ahead of saturated/erroring/etc below
    # (2026-09-23, on request: "we only want to monitor these interfaces not all of
    # them... uplink, accesspoint, links going to other switches (neighboar links)") so
    # `monitored` (below) can scope every interface-shaped finding to just these ports,
    # not every up port. A neighbour's reported platform string identifies what's actually
    # plugged into a port far more reliably than guessing at a fixed port number --
    # confirmed live via the "cisco_cdp" SNMP module (see prometheus.yml's own snmp_cdp job
    # and snmp.yml's own comment on the module). cdpCacheDeviceId/DevicePort/Platform are
    # three separate metric series sharing the same (instance, cdpCacheIfIndex,
    # cdpCacheDeviceIndex) index -- joined here into one row per neighbour.
    cdp_rows: Dict[Tuple[str, str, str], dict] = {}

    def _cdp_key(lbl):
        return (lbl.get("instance"), lbl.get("cdpCacheIfIndex"), lbl.get("cdpCacheDeviceIndex"))

    for r in _one("cdpCacheDeviceId"):
        cdp_rows.setdefault(_cdp_key(r["labels"]), {})["device_id"] = r["labels"].get("cdpCacheDeviceId", "")
    for r in _one("cdpCacheDevicePort"):
        cdp_rows.setdefault(_cdp_key(r["labels"]), {})["device_port"] = r["labels"].get("cdpCacheDevicePort", "")
    for r in _one("cdpCachePlatform"):
        cdp_rows.setdefault(_cdp_key(r["labels"]), {})["platform"] = r["labels"].get("cdpCachePlatform", "")

    _iface_name_by_key = {(i["device"], str(i["index"])): i["name"] for i in interfaces}
    cdp_neighbors = []
    for (instance, if_index, _dev_index), fields in cdp_rows.items():
        if not instance or not if_index:
            continue
        platform = fields.get("platform", "")
        cdp_neighbors.append({
            "instance": instance,
            "if_index": if_index,
            "local_port": _iface_name_by_key.get((instance, if_index), f"ifIndex {if_index}"),
            "device_id": fields.get("device_id", ""),
            "device_port": fields.get("device_port", ""),
            "platform": platform,
            "kind": _cdp_neighbor_kind(platform),
        })

    # The actual monitored scope now (2026-09-23) -- an interface counts only if it is BOTH
    # up AND CDP-identifies as an access point, another switch, or a router (an uplink or a
    # neighbour link to another switch is the same "kind" here -- see _cdp_neighbor_kind's
    # own comment on why "switch" covers both an upstream and a lateral link equally). A
    # host/phone/unknown-vendor neighbour, or a port with no CDP neighbour at all, is no
    # longer part of "monitored" -- same reasoning the original up-only scope already
    # applied to admin-disabled ports, narrowed further now that CDP can say WHY a port
    # matters instead of just whether it is up.
    _monitored_keys = {(n["instance"], n["if_index"]) for n in cdp_neighbors
                       if n["kind"] in ("ap", "switch", "router")}

    # Manually monitored interfaces (2026-09-24) -- see MANUAL_MONITORED_INTERFACES' own
    # comment for why these can never be CDP-scoped. Resolved by NAME against this run's own
    # `interfaces` (not a fixed ifIndex, which can renumber across a device reload) into the
    # live (target, ifIndex) pairs both `_monitored_keys` and the exempt-from-regression set
    # need. `_manual_exempt_keys` is a SUBSET of `_manual_keys` -- only the entries whose
    # down_is_fault is False -- returned separately so capture_snapshot() can keep
    # _update_interface_baseline() from ever raising a regression for one of them.
    _target_by_dev_key = {d["key"]: d["target"] for d in DEVICES}
    _manual_by_target_name = {
        (_target_by_dev_key[dev_key], if_name): cfg
        for (dev_key, if_name), cfg in MANUAL_MONITORED_INTERFACES.items()
        if dev_key in _target_by_dev_key
    }
    _manual_keys = set()
    _manual_exempt_keys = set()
    for i in interfaces:
        cfg = _manual_by_target_name.get((i["device"], i["name"]))
        if cfg is None:
            continue
        key = (i["device"], str(i["index"]))
        _manual_keys.add(key)
        if not cfg.get("down_is_fault", True):
            _manual_exempt_keys.add(key)
    _monitored_keys |= _manual_keys

    monitored = [i for i in up if (i["device"], str(i["index"])) in _monitored_keys]

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
    # Scoped to `monitored` -- up AND CDP-identified as an AP/uplink/neighbour-link (2026-
    # 09-23, on request: "we only want to monitor these interfaces not all of them... uplink,
    # accesspoint, links going to other switches"; narrower than the previous `up`-only scope
    # from 2026-09-22, kept here as the earlier step in the same direction -- a down port, or
    # an up port with no CDP-identified purpose, is not counted, alerted on, or listed as a
    # finding either way).
    saturated = [i for i in monitored if (i["util_pct"] or 0) >= 80]
    # >=95% is not "worth watching", it is the point real links start dropping packets —
    # matches the systems report's disk_high()'s own near-full/full split (a WATCH-band tile
    # is still allowed to render red when the level itself demands it).
    saturated_critical = [i for i in monitored if (i["util_pct"] or 0) >= 95]

    erroring = [i for i in monitored if sum(i["errors"].values() or [0]) > 0]
    # Errors (CRC/framing/etc.) are close to always a real physical fault — a cable, a
    # connector, a failing optic. Discards are frequently a POLICY decision (QoS dropping
    # excess traffic on purpose) and are not inherently a fault the same way, so the two are
    # graded separately rather than one combined "has some non-zero number" bucket.
    err_only = [i for i in monitored
               if (i["errors"].get("in_err", 0) + i["errors"].get("out_err", 0)) > 0]
    # A high discard volume is still worth escalating even without a true error present —
    # the two thresholds below aren't a precise SLA, just a floor well above the handful of
    # discards a healthy, momentarily-busy link can show, and well below the 200k+/400k+
    # seen on a genuinely congested interface here.
    DISCARD_RED = 1000
    discard_heavy = [i for i in monitored
                     if (i["errors"].get("in_disc", 0) + i["errors"].get("out_disc", 0)) >= DISCARD_RED]
    # Whatever is left once true errors and heavy discards are accounted for — a light
    # discard count, on its own, worth a watch-band amber rather than red. Computed as its
    # own set (not erroring-count minus the other two) so an interface with BOTH a real
    # error and a heavy discard isn't subtracted twice.
    disc_light = [i for i in erroring if i not in err_only and i not in discard_heavy]

    # Hardware health, from the vendor module. Each is optional; a missing reading is None and
    # renders as "not collected" rather than as a zero, which would read as "cool and idle".

    # Grouped by `instance` (== a device's `target`) so hardware health can be read PER
    # DEVICE, not just once across the whole queried set -- see cpu_by_device/mem_by_device/
    # uptime_by_device/temp_by_device below. Fixed 2026-09-22, confirmed live: with one device
    # (the core switch) `cpu`/`mem_pct`/`uptime_days`/`temp_max` below were correct BY
    # CONSTRUCTION (max()/sum() over a single-device set is that device's own value) -- but
    # _device_flags() read those same four scalars identically for every device in `rows`,
    # unlike PSU/OSPF/optics a few lines below it, which already filter by `dev["target"]`.
    # Scaling DEVICES to more than one device would have silently given every device the
    # busiest device's own CPU/RAM/temp/uptime. The aggregate scalars are kept too (estate-
    # wide "worst" tiles still legitimately want them) -- only _device_flags' own per-device
    # read needed fixing, not these.
    def _by_device(rows: list) -> Dict[str, list]:
        grouped: Dict[str, list] = {}
        for r in rows:
            grouped.setdefault(r["labels"].get("instance"), []).append(r)
        return grouped

    cpu_rows = _one("cpmCPUTotal5minRev") or _one("cpmCPUTotal1minRev")
    cpu = max((r["value"] for r in cpu_rows), default=None)
    cpu_by_device = {inst: max(r["value"] for r in rs) for inst, rs in _by_device(cpu_rows).items()}

    mem_used_rows = _one("ciscoMemoryPoolUsed")
    mem_free_rows = _one("ciscoMemoryPoolFree")
    mem_used = sum(r["value"] for r in mem_used_rows) or None
    mem_free = sum(r["value"] for r in mem_free_rows) or None
    mem_pct = round(mem_used / (mem_used + mem_free) * 100, 1) if mem_used and mem_free else None
    mem_used_by_device = {inst: sum(r["value"] for r in rs)
                          for inst, rs in _by_device(mem_used_rows).items()}
    mem_free_by_device = {inst: sum(r["value"] for r in rs)
                          for inst, rs in _by_device(mem_free_rows).items()}
    mem_by_device = {inst: round(u / (u + mem_free_by_device[inst]) * 100, 1)
                     for inst, u in mem_used_by_device.items() if mem_free_by_device.get(inst)}

    up_rows = _one("sysUpTime")
    # sysUpTime is in hundredths of a second (TimeTicks), not seconds
    uptime_days = round(max(r["value"] for r in up_rows) / 100.0 / 86400.0, 1) if up_rows else None
    uptime_by_device = {inst: round(max(r["value"] for r in rs) / 100.0 / 86400.0, 1)
                        for inst, rs in _by_device(up_rows).items()}

    sensors = _one("entSensorValue")
    temps = [r["value"] for r in sensors
             if r["labels"].get("entSensorType") == "8" and 0 < r["value"] < 200]
    temp_max = max(temps) if temps else None
    temp_rows = [r for r in sensors
                if r["labels"].get("entSensorType") == "8" and 0 < r["value"] < 200]
    temp_by_device = {inst: max(r["value"] for r in rs) for inst, rs in _by_device(temp_rows).items()}

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

    # ---- Flash/storage partitions (CISCO-FLASH-MIB, ciscoFlashPartitionTable) ------------
    # 2026-09-23, on request: "need to add storage table for all switches" -- HOST-RESOURCES-
    # MIB::hrStorageTable is NOT implemented on any Cisco IOS/IOS-XE device tested (0 PDUs on
    # an access switch, the core switch, and the router), so this reads CISCO-FLASH-MIB
    # instead (see the "cisco_flash" snmp_exporter module and the "snmp_flash" prometheus.yml
    # job). Confirmed empirically that declaring one snmp_exporter metric PER COLUMN against
    # this table decodes nothing (0 PDUs every time); one raw catch-all metric walking the
    # whole partition entry decodes every row correctly, with the real column number and
    # partition index recovered as labels instead. Column 10 is the partition name (an OCTET
    # STRING, hex-encoded on the wire -- decoded below); columns 13/14 are the 64-bit-safe
    # size/free-space pair in bytes. Columns 4/5 carry the same figures but are the legacy
    # 32-bit pair and wrap to 4294967295 on any partition over 4GB -- confirmed live on the
    # core switch's own disk0:/bootflash: partitions, which is why 13/14 are used here.
    def _flash_rows(column: str) -> Dict[Tuple[str, str], str]:
        return {(r["labels"].get("instance"), r["labels"].get("ciscoFlashPartitionIndex")):
                r["labels"].get("ciscoFlashPartitionRaw", "")
                for r in _one(f'ciscoFlashPartitionRaw{{ciscoFlashPartitionColumn="{column}"}}')}

    def _hex_to_text(raw: str) -> str:
        if raw.startswith("0x"):
            try:
                return bytes.fromhex(raw[2:]).decode("ascii", errors="replace").strip()
            except ValueError:
                return raw
        return raw

    flash_names = _flash_rows("10")
    flash_sizes = _flash_rows("13")
    flash_frees = _flash_rows("14")
    # Fallback for older platforms that don't implement the 64-bit pair at all (confirmed
    # live: the 2951 ISR router only walks up to column 12, no 13/14) -- 4/5 carry the same
    # figures and are exact below the 4GB wrap point, so they're a safe stand-in UNLESS the
    # raw value IS the wrap sentinel itself (2**32-1), which means the true size is unknown,
    # not 4294967295 bytes.
    flash_sizes_32 = _flash_rows("4")
    flash_frees_32 = _flash_rows("5")
    _WRAP32 = str(2**32 - 1)

    def _flash_value(primary: dict, fallback: dict, key) -> Optional[float]:
        raw = primary.get(key)
        if raw:
            return float(raw)
        raw = fallback.get(key)
        if raw and raw != _WRAP32:
            return float(raw)
        return None

    flash_partitions = []
    for key in sorted(set(flash_names) | set(flash_sizes) | set(flash_frees)
                       | set(flash_sizes_32) | set(flash_frees_32)):
        instance, part_idx = key
        size = _flash_value(flash_sizes, flash_sizes_32, key)
        free = _flash_value(flash_frees, flash_frees_32, key)
        used_pct = round((size - free) / size * 100, 1) if size and free is not None else None
        flash_partitions.append({
            "device": instance,
            "index": part_idx,
            "name": _hex_to_text(flash_names.get(key, "")) or f"partition {part_idx}",
            "size_bytes": size,
            "free_bytes": free,
            "size_gb": round(size / 1024**3, 2) if size else None,
            "free_gb": round(free / 1024**3, 2) if free is not None else None,
            "used_pct": used_pct,
        })
    # Same 85%/gr.DISK_IMMINENT_PCT warn/critical split the systems report's own disk_high()
    # uses for near-full/full storage -- a partition with a size but no readable free-space
    # value (used_pct is None) is left out rather than treated as 0% used.
    flash_low = [p for p in flash_partitions if p["used_pct"] is not None and p["used_pct"] >= 85]
    flash_critical = [p for p in flash_partitions
                      if p["used_pct"] is not None and p["used_pct"] >= gr.DISK_IMMINENT_PCT]

    # ---- MAC / ARP table size (BRIDGE-MIB / IP-MIB) --------------------------------------
    # Entry counts only — the platform's hardware MAX per table is a datasheet figure, not
    # an SNMP one, so % used is deliberately not computed (see the catalogue entry).
    mac_count = len(_one("dot1dTpFdbPort"))
    arp_count = len(_one("ipNetToMediaIfIndex"))

    # ---- Wireless access points (CISCO-LWAPP-AP-MIB, cLApTable) --------------------------
    # 2026-09-29, on request: "Also include the Access points" for hre-wlc-02/byo-wlc-01. See
    # the "cisco_ap_name" snmp_exporter module's own comment for why this is a name list/
    # count only, not a real per-AP index -- cLApTable's true index (a 6-byte MAC address)
    # can't be parsed by this bare numeric-OID config, but every AP's own NAME is unique, so
    # Prometheus still returns one distinct series per AP despite the shared decode-artifact
    # `apIndex` label.
    ap_names_by_device: Dict[str, list] = {}
    for r in _one("cLApRaw"):
        inst = r["labels"].get("instance")
        name = _hex_to_text(r["labels"].get("cLApRaw", ""))
        if inst and name:
            ap_names_by_device.setdefault(inst, []).append(name)
    for _names in ap_names_by_device.values():
        _names.sort()
    # Every WLC actually reachable this run (via `devices`, the same ifOperStatus-derived
    # reachability signal used estate-wide), regardless of whether it returned any AP rows --
    # NOT just ap_names_by_device's own keys, which would silently omit a WLC that answered
    # SNMP but currently has ZERO APs joined (every one down at once). _update_ap_baseline()
    # needs this distinction to tell "this WLC wasn't checked -- unknown" apart from "this WLC
    # was checked and had nothing," the same way an unreachable device is already left alone
    # rather than treated as a wave of interface-down regressions.
    _wlc_targets = {d["target"] for d in DEVICES if d.get("kind") == "WLC"}
    wlc_targets_checked = {t for t in devices if t in _wlc_targets}

    # How long a 32-bit octet counter survives at the fastest rate actually observed here.
    # Computed, never hardcoded: the peak moves with the traffic, and a stale constant on a
    # page whose whole point is "this number is under-reported" would be its own small lie.
    #   2^32 bytes = 4.295 GB. seconds-to-wrap = 4.295e9 / bytes-per-second.
    peak_bps = max((max(i["in_bps"] or 0, i["out_bps"] or 0) for i in interfaces), default=0)
    wrap_seconds = (2 ** 32) / (peak_bps / 8) if peak_bps else None

    catalogue = measure_catalogue(q, wanted, report_kind)
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
        # Distinct from up_count (2026-09-23) -- up AND CDP-identified as an AP/uplink/
        # neighbour link, see `monitored`'s own comment above. This is what "Interfaces
        # monitored" and every per-interface finding actually count against now.
        "monitored_count": len(monitored),
        "monitored_interfaces": monitored,
        # {(device, if_index), ...} CDP currently identifies as an AP/uplink/neighbour link,
        # UNIONED with any manually monitored port (see MANUAL_MONITORED_INTERFACES) -- used
        # by _update_interface_baseline() to (re)confirm MonitoredInterface.is_scoped; see
        # that function's own comment on why regression detection reads the STORED sticky
        # flag, not this run's own set, once a port has actually gone down.
        "cdp_scoped_keys": _monitored_keys,
        # {(device, if_index), ...} manually monitored ports whose down_is_fault is False --
        # see MANUAL_MONITORED_INTERFACES' own comment. Passed to
        # _update_interface_baseline() so it never raises interface_down_regression for one
        # of these, and to build_report()'s Interface Detail so its Status column explains
        # WHY a down reading here is expected rather than painting it red.
        "manual_exempt_keys": _manual_exempt_keys,
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
        "count_total": len(catalogue),
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
        "cpu_by_device": cpu_by_device,
        "mem_by_device": mem_by_device,
        "uptime_by_device": uptime_by_device,
        "temp_by_device": temp_by_device,
        "psu_failed": psu_failed,
        "psu_total": psu_total,
        # psu_rows (2026-09-22, for a real PSU/Fan table per device in build_report) -- every
        # component's own current state, not just the failed ones psu_failed already narrows
        # to. Kept as its own key rather than asking a caller to re-derive it from psu_failed/
        # psu_total, which can't reconstruct the healthy rows.
        "psu_rows": psu_rows,
        "ospf_rows": ospf_rows,
        "ospf_down": ospf_down,
        "ospf_total": ospf_total,
        "cdp_neighbors": cdp_neighbors,
        "flash_partitions": flash_partitions,
        "flash_low": flash_low,
        "flash_critical": flash_critical,
        "mac_count": mac_count,
        "arp_count": arp_count,
        "ap_names_by_device": ap_names_by_device,
        "wlc_targets_checked": wlc_targets_checked,
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
    # ---------------------------------------------------------------------------------
    # Switches & Routers Report estate (2026-09-22) -- 39 SNMPv3 devices onboarded via the
    # RBZ_v3 auth profile (see reports.snmp_admin), confirmed reachable and genuinely Cisco
    # by direct probing of every one of them before this list was written (38 Catalyst
    # 9200/9300-Lite/2960X switches -- including the core switch, folded in here 2026-09-22
    # once RBZ_v3 was confirmed live against it too -- one 2951 ISR router, one C9800-CL WLC
    # on IOS-XE). "report": "switches_routers_report" is the ONLY SNMP report family left --
    # the old standalone "Network Report" (network_dashboard/network_report/network_generate,
    # core-switch alone under RBZ_v2) was retired the same day this list grew to cover the
    # rest of the estate; see git history for that removal if the old shape is ever needed
    # for reference. 3 more devices probed at the same time (RBZ_MSASA 10.0.0.148, DRS-FTD-01
    # 10.0.0.132, HRE-FTD-01 10.0.0.131) are deliberately NOT listed here: all three timed out
    # under RBZ_v3 (no response at all, not a bad reading) -- pending the network team fixing
    # on-device SNMPv3 config/ACLs. 9 further devices have no IP yet and are excluded the same
    # way. Neither group gets a stub entry: an entry with no live target would misreport as
    # "never scraped" instead of "not yet targeted", which is a different, more alarming claim
    # than the truth.
    # 3 core switches (2026-09-24, on request: "still see one core switch there are supposed
    # to be 3" -- confirmed live via RBZ_v3: HQ 10.100.210.253 (this app's original, "Core
    # Switch"), DR 10.100.210.251 (sysName RBZ-DR-CORE-SW-9300.rbz.co.zw), BYO 10.200.210.252
    # (sysName RBZ-BYO-CORE-SW-9300) -- all three real Catalyst 9300 L3 switches. `role: "core"`
    # is what is_access_switch()/core_switches_device_keys() actually key off (2026-09-24,
    # replacing the old single hardcoded `key != "core-switch"` check, which could only ever
    # recognise ONE core switch) -- tag any FUTURE core switch here, not a code change there.
    {"key": "core-switch", "name": "Core Switch (HQ)", "kind": "Switch", "role": "core",
     "target": "10.100.210.253", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "core-switch-dr", "name": "RBZ-DR-CORE-SW-9300.rbz.co.zw", "kind": "Switch", "role": "core",
     "target": "10.100.210.251", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "core-switch-byo", "name": "RBZ-BYO-CORE-SW-9300", "kind": "Switch", "role": "core",
     "target": "10.200.210.252", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "csw1-m5", "name": "CSW1-M5.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.88", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "hre-dr-swift-router", "name": "hre-dr-swift-router.rbz.co.zw", "kind": "Router",
     "target": "10.0.0.145", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "hre-tor-m03", "name": "HRE-TOR-M03.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.206", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "hre-wlc-02", "name": "hre-wlc-02", "kind": "WLC",
     "target": "10.0.0.142", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    # BYO-WLC-01 (2026-09-29) -- the Bulawayo site's own wireless controller, a second
    # C9800-CL alongside hre-wlc-02 above. Confirmed live via RBZ_v3 (sysName "BYO-WLC-01");
    # was already known to this app as an ICMP-only blackbox_ping_network target ("BYO
    # Controller") but never SNMP-onboarded until now, on request: "Also include the Access
    # points per... byo-wlc-01 10.200.246.12".
    {"key": "byo-wlc-01", "name": "BYO-WLC-01", "kind": "WLC",
     "target": "10.200.246.12", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    # 4 Dell EMC OS10 access switches (2026-09-29, on request: "Also add these access
    # switches") -- HCI/DR cluster Top-of-Rack and Storage Spaces Direct switches, all
    # confirmed live via RBZ_v3. NOT Cisco: standard IF-MIB (interface up/down/traffic) works
    # normally, but every Cisco-proprietary reading this report otherwise shows -- CPU/
    # memory/temperature/PSU/storage (CISCO-PROCESS-MIB/CISCO-MEMORY-POOL-MIB/ENTITY-SENSOR-
    # MIB via this platform's own OIDs/CISCO-ENTITY-FRU-CONTROL-MIB/CISCO-FLASH-MIB) and CDP-
    # based interface scoping (CISCO-CDP-MIB -- Dell doesn't speak CDP at all) -- will come
    # back genuinely absent for these four, not broken. See CATALOGUE's own state-measured
    # design for why that shows as "missing" rather than a fake zero, and MANUAL_MONITORED_
    # INTERFACES for how to hand-scope a specific port on a non-CDP device if one matters
    # enough to track despite the gap. "drs-s2dsw-01" given twice in the request for the pair
    # at 10.0.0.119/10.0.0.120 was a duplicate name -- confirmed live via sysName that
    # 10.0.0.120 is actually drs-s2dsw-02.
    {"key": "hre-hci-tor1", "name": "HRE-HCI-TOR1", "kind": "Switch",
     "target": "10.100.246.18", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "hre-hci-tor2", "name": "HRE-HCI-TOR2", "kind": "Switch",
     "target": "10.100.246.19", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "drs-s2dsw-01", "name": "drs-s2dsw-01", "kind": "Switch",
     "target": "10.0.0.119", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "drs-s2dsw-02", "name": "drs-s2dsw-02", "kind": "Switch",
     "target": "10.0.0.120", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "level2-swift-sw2", "name": "Level2_Swift_Sw2.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.52", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-level1-sw1", "name": "RBZ-BYO-LEVEL1-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.2.6", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-level2-sw1", "name": "RBZ-BYO-LEVEL2-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.2.5", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-upperbase-sw1", "name": "RBZ-BYO-UPPERBASE-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.2.17", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level18-sw1", "name": "RBZ-HRE-LEVEL18-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.18", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level20-sw1", "name": "RBZ-HRE-LEVEL20-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.20", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level3-sw1", "name": "RBZ-HRE-LEVEL3-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.3", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level9-sw1", "name": "RBZ-HRE-LEVEL9-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.9", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-pabxroom-sw1", "name": "RBZ-HRE-PABXROOM-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.30", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "hre-tor-m01", "name": "HRE-TOR-M01.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.204", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-groundfl-sw1", "name": "RBZ-BYO-GROUNDFL-SW1", "kind": "Switch",
     "target": "10.0.2.1", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-groundfl-sw3", "name": "RBZ-BYO-GROUNDFL-SW3", "kind": "Switch",
     "target": "10.0.2.19", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level10-sw1", "name": "RBZ-HRE-LEVEL10-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.10", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level11-sw1", "name": "RBZ-HRE-LEVEL11-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.11", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level12-sw1", "name": "RBZ-HRE-LEVEL12-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.12", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level13-sw1", "name": "RBZ-HRE-LEVEL13-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.13", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level14-sw1", "name": "RBZ-HRE-LEVEL14-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.14", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level15-sw1", "name": "RBZ-HRE-LEVEL15-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.15", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level16-sw1", "name": "RBZ-HRE-LEVEL16-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.16", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level17-sw1", "name": "RBZ-HRE-LEVEL17-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.17", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level19-sw1", "name": "RBZ-HRE-LEVEL19-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.19", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level21-sw1", "name": "RBZ-HRE-LEVEL21-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.21", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level22-sw1", "name": "RBZ-HRE-LEVEL22-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.22", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level2-sw1", "name": "RBZ-HRE-LEVEL2-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.2", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level3-sw2", "name": "RBZ-HRE-LEVEL3-SW2.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.53", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level8-sw1", "name": "RBZ-HRE-LEVEL8-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.8", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-pabxroom-sw2", "name": "RBZ-HRE-PABXROOM-SW2.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.35", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "csw2-m5", "name": "CSW2-M5.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.86", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "level3-switch-03", "name": "Level3_switch_03.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.95", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-groundfl-sw2", "name": "RBZ-BYO-GROUNDFL-SW2.rbz.co.zw", "kind": "Switch",
     "target": "10.0.2.7", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level-1-rtl-sw2", "name": "RBZ-HRE-LEVEL-1-RTL-SW2.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.37", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-level9-sw2", "name": "RBZ-HRE-LEVEL9-SW2.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.85", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-swift-hq-sw1", "name": "RBZ-HRE-SWIFT-HQ-SW1.rbz.co.zw", "kind": "Switch",
     "target": "10.0.0.60", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "swift-dr-switch", "name": "swift-dr-switch", "kind": "Switch",
     "target": "10.0.0.147", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    # 5 routers (2026-09-29, on request: "add these routers to the router report"). 3
    # confirmed live Cisco IOS/IOS-XE routers via RBZ_v3 -- normal "switches_routers_report"
    # membership, same as every other SNMP device above (they count toward the alert poller
    # and the Executive Dashboard's combined Network tile, same as any switch/WLC).
    {"key": "router-dr-prim01", "name": "ROUTER-DR-PRIM01.rbz.co.zw", "kind": "Router",
     "target": "10.0.0.146", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-hre-wan", "name": "RBZ-HRE-WAN.rbz.co.zw", "kind": "Router",
     "target": "10.100.210.252", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    {"key": "rbz-byo-wan", "name": "RBZ-BYO-WAN.rbz.co.zw", "kind": "Router",
     "target": "10.200.210.253", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "switches_routers_report"},
    # Mikrotik BYO and Msasa Liquid -- NOT answering SNMP at all right now (confirmed
    # 2026-09-29: tried both RBZ_v3 and the older RBZ_v2/v2c community against each, no
    # response from either -- a genuine reachability gap, not a wrong-auth mismatch like the
    # Sophos firewall below). Still added on request ("add these routers to the router
    # report"), but deliberately given a DIFFERENT "report" value so switches_routers_
    # device_keys() -- the alert poller and the Executive Dashboard's combined Network domain
    # tile -- never see them: they would otherwise report a permanent false "unreachable" for
    # something that was never really monitorable to begin with. "snmp_unconfigured": True
    # (2026-09-29, on request: "can we have unconfigured instead of unreachable to avoid
    # conflating with actual errors") is what _device_flags() reads to soften its own
    # reachability wording/band for a device in this known state -- see that function's own
    # comment. They still show, honestly, inside the Routers Report's own picker/report,
    # since routers_device_keys() filters on kind alone. Remove the marker (and switch
    # "report" to "switches_routers_report") once SNMP genuinely works on either one.
    {"key": "mikrotik-byo", "name": "Mikrotik BYO", "kind": "Router",
     "target": "10.0.2.100", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "routers_report_pending_snmp", "snmp_unconfigured": True},
    {"key": "msasa-liquid", "name": "Msasa Liquid", "kind": "Router",
     "target": "10.0.0.148", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "routers_report_pending_snmp", "snmp_unconfigured": True},
    # Firewall Report estate (2026-09-29, on request: "add these firewalls to a new firewall
    # report which is part of the network reports group... firewalls not yet on snmp but just
    # add them for now however they must not be a false negative on the management
    # dashboards"). None of the four answer SNMP yet -- confirmed 2026-09-29: the Sophos
    # responds but rejects RBZ_v3's own credentials ("incoming packet is not authentic,
    # discarding" -- it needs its own SNMP user/community, a credentials gap rather than a
    # reachability one); the Cisco FMC and both FTDs are completely silent. `kind: "Firewall"`
    # (a new kind, distinct from "Switch"/"Router"/"WLC") is what keeps every one of these out
    # of switches_routers_device_keys() (see that function's own kind filter) -- so none of
    # them can ever contribute a false "unreachable" to the alert poller or the Executive
    # Dashboard's Network tile. "snmp_unconfigured": True, same marker as the two routers
    # above, softens this report's own wording/band for them too -- see _device_flags' own
    # comment. "report" is set to "firewalls_report" for the same documentary reason the two
    # routers above get their own value, even though kind alone already excludes them here.
    {"key": "sophos-fw", "name": "Sophos Firewall", "kind": "Firewall",
     "target": "10.100.247.193", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "firewalls_report", "snmp_unconfigured": True},
    {"key": "cisco-fmc", "name": "Cisco FMC", "kind": "Firewall",
     "target": "10.0.0.130", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "firewalls_report", "snmp_unconfigured": True},
    {"key": "hq-ftd", "name": "HQ FTD", "kind": "Firewall",
     "target": "10.0.0.131", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "firewalls_report", "snmp_unconfigured": True},
    {"key": "dr-ftd", "name": "DR FTD", "kind": "Firewall",
     "target": "10.0.0.132", "system": "RBZ Network", "module": "if_mib_v3",
     "report": "firewalls_report", "snmp_unconfigured": True},
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
        "cluster": True,                 # see CLUSTER_DEVICE_KEYS' own comment below
    },
    # Disaster Recovery Cluster (2026-09-16) -- a second, independent HCI/S2D cluster, same
    # shape as HCI Cluster above (4 windows_exporter nodes, its own prometheus.yml job), added
    # once _hci_node_metrics/_hci_cluster_volumes/_infra_overview/build_infrastructure_report
    # were generalized to loop over every `cluster: True` device instead of assuming exactly
    # one. windows_hci_csv_volume_size_bytes (the real S2D CSV metrics) is present on all
    # nodes, confirmed live.
    #
    # CPU: originally special-cased to the standard counter cluster-wide on request ("this
    # cluster has all collectors for windows exporter across all nodes it does not use
    # workaround script metrics"). Confirmed live 2026-09-17 that this was premature and only
    # a partial rollout -- node1 (.111) and node2 (.112) now publish windows_hci_cpu_usage_
    # percent (the same workaround gauge HCI Cluster uses, here via Get-ClusterPerf), reading
    # well above the standard counter on both (node1: 9.6% gauge vs 3.8% standard; node2: 11.0%
    # vs 2.7% at the same instant), while node3/node4 (.113/.114) still don't. No per-device
    # override needed any more -- _hci_node_metrics() now checks per NODE, not per cluster:
    # whichever instance publishes the gauge uses it, any instance without one falls back to
    # the standard counter. See _hci_node_metrics' own comment for the merge.
    {
        "key": "dr-cluster",
        "name": "Disaster Recovery Cluster",
        "kind": "windows",
        "target": "10.100.246.111:9182",
        "system": "Disaster Recovery Cluster",
        "job": "dr_cluster",
        "report": "network_report",
        "cluster": True,
    },
    # Bulawayo Cluster (2026-09-17) -- a THIRD independent HCI/S2D cluster, at the Bulawayo
    # site (10.200.246.x, the same site-subnet convention BYO-AD-DC-01 already uses at
    # 10.200.200.x -- see that device's own comment), 2 nodes rather than 4. node2
    # (10.200.246.3, byo-vdihost-02) was live and reachable all along but had never actually
    # been added to the bulawayo_cluster Prometheus job -- fixed 2026-09-29, on request ("one
    # of the nodes in the byo cluster is missing from our reports"). Both nodes' hostnames are
    # now confirmed (byo-vdihost-01/02) and prometheus.yml's own `display` label reflects them
    # (the old bare-IP placeholder this comment used to describe is gone). This DEVICES entry
    # itself only ever needed to exist ONCE, job-scoped, regardless of node count:
    # _hci_node_metrics/_hci_cluster_volumes/_infra_overview/build_infrastructure_report all
    # loop over every `cluster: True` device and query by JOB, not by node count -- adding
    # node2 needed a prometheus.yml change only, zero code here.
    {
        "key": "bulawayo-cluster",
        "name": "Bulawayo Cluster",
        "kind": "windows",
        "target": "10.200.246.2:9182",
        "system": "Bulawayo Cluster",
        "job": "bulawayo_cluster",
        "report": "network_report",
        "cluster": True,
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
    # Standalone Servers (2026-09-17, on request: "added 3 standalone servers to be grouped
    # under Standalone server group in cluster health report") -- 10.100.249.240/.252/.253,
    # previously tracked as Linux "Oracle Hosts" (node_exporter, port 9100, a completely
    # separate/unrelated job) -- confirmed live these three now run windows_exporter on 9182
    # instead (the old node_exporter is gone on all three), i.e. repurposed to Windows. Not
    # `cluster: True` (three independent standalone boxes, not one clustered resource) --
    # picked up by build_infrastructure_report's own new "Standalone Servers" loop (grouped by
    # this shared `system` label), not the cluster-specific one.
    #
    # Real hostnames confirmed live via nbtstat (no reverse DNS configured for these three):
    # DRS-RTGS7DBH-01 / HRE-RTGS7DBH-01 / HRE-RTGS7DBH-02 -- `name`/`display` updated from
    # bare-IP to these on request ("replace all ip mentions with hostnames"). The naming
    # itself (RTGS7DBH = RTGS DB Host, HRE/DRS = Harare/DR site) suggests these are RTGS
    # database hosts specifically, not generic standalone boxes -- flagged to the admin, group
    # label ("Standalone Servers") deliberately left as-is for now pending their own call.
    {
        "key": "standalone-1",
        "name": "DRS-RTGS7DBH-01",
        "kind": "windows",
        "target": "10.100.249.240:9182",
        "system": "Standalone Servers",
        "job": "standalone_servers",
        "report": "network_report",
    },
    {
        "key": "standalone-2",
        "name": "HRE-RTGS7DBH-01",
        "kind": "windows",
        "target": "10.100.249.252:9182",
        "system": "Standalone Servers",
        "job": "standalone_servers",
        "report": "network_report",
    },
    {
        "key": "standalone-3",
        "name": "HRE-RTGS7DBH-02",
        "kind": "windows",
        "target": "10.100.249.253:9182",
        "system": "Standalone Servers",
        "job": "standalone_servers",
        "report": "network_report",
    },
    # Child Domain Controllers (2026-09-09) -- these two are additional DCs, added under the
    # existing "Child Domain Controllers" placeholder tier (see build_infrastructure_report's
    # own tier loop, reserved for exactly this since before either of these two existed) rather
    # than a separate third tier -- the admin's own call, for naming consistency with "Root
    # Domain Controllers" (2026-09-09: "rename The Domain Controllers to Child Domain
    # Controllers so its a bit more consistent with the root ones").
    {
        "key": "dc-203",
        "name": "RBZHQ-DC-203",
        "kind": "windows",
        "target": "10.100.249.203:9182",
        "system": "Child Domain Controllers",
        "job": "domain_controllers",   # prometheus.yml must scrape this target under this job
        "report": "network_report",
    },
    # RBZHQ-DC-204 -- Device Guard on this host blocks windows_exporter outright (code-signing
    # policy could not be found/disabled to allow it), so unlike every other windows-kind
    # device here, 204 has NO `up{instance=...}` of its own at all -- there is nothing to scrape
    # directly. Worked around with a scheduled ps1 script running on 204 itself every ~3
    # minutes, writing a textfile-collector .prom file that lands on 203's OWN textfile-
    # collector input directory instead -- so 204's readings are physically scraped as part of
    # 203's scrape, arriving under 203's own `instance` label. `metric_prefix` is how they're
    # told apart from 203's own genuine windows_exporter readings on that same instance --
    # `rbz_hq_cdc_02_` (matching the script's own hostname-derived naming), CONFIRMED LIVE
    # 2026-09-09 against real Prometheus data ("we could not install the exporter... but we do
    # have all its metrics" -- the script was already deployed and had its own naming by the
    # time this was checked; an earlier `dc204_`/textfile-mtime guess written before that check
    # has been corrected here to match). Real metric names confirmed present at that check:
    #
    #   rbz_hq_cdc_02_wmi_workaround_last_run_timestamp_seconds   gauge, unix seconds -- NOT
    #                                                               trusted for freshness, see
    #                                                               "freshness_file" below
    #   rbz_hq_cdc_02_wmi_workaround_cpu_load_percent              gauge, 0-100
    #   rbz_hq_cdc_02_wmi_workaround_memory_used_percent           gauge, 0-100 (pre-computed)
    #   rbz_hq_cdc_02_windows_logical_disk_free_bytes{volume="C:"} gauge, raw bytes
    #   rbz_hq_cdc_02_windows_logical_disk_size_bytes{volume="C:"} gauge, raw bytes
    #
    #   (also present but not yet wired into this report: AD replication last_result/
    #   consecutive_failures per partition/partner, Defender status, pending-reboot,
    #   eventlog-errors-last-hour, TCP connection counts, uptime -- a genuinely richer set than
    #   CPU/RAM/disk alone; worth a follow-up if the admin wants those surfaced as flags too.)
    {
        "key": "dc-204",
        "name": "RBZHQ-DC-204",
        "kind": "windows",
        "target": "10.100.249.204:relay",   # synthetic -- not a real queryable instance, see above
        "relay_instance": "10.100.249.203:9182",
        "relay_job": "domain_controllers",
        "metric_prefix": "rbz_hq_cdc_02_",
        # 2026-09-09, corrected the SAME day it was wired up: the script's own self-reported
        # `wmi_workaround_last_run_timestamp_seconds` was originally trusted as the freshness
        # signal (a script's own "when did I last finish" claim looked like the most authoritative
        # thing available) -- caught live as WRONG ("this shouldn't be correct... 2.0h" while the
        # server was confirmed fine): script_duration_seconds/uptime_seconds/process_count were
        # ALL still advancing on a healthy ~3-minute cadence the whole time, and the .prom FILE's
        # own OS-level mtime (windows_textfile_mtime_seconds) was consistently only ~3 minutes
        # old -- the script genuinely runs and rewrites the file every cycle; only the ONE
        # last_run_timestamp_seconds VALUE it computes/writes had gotten stuck. Freshness now
        # comes from the FILE's own mtime instead -- a signal windows_exporter computes itself
        # from the OS (stat() on the file), which cannot inherit a bug in the script's own
        # internal timestamp arithmetic the way trusting the script's self-report can.
        "freshness_file": "rbz-hq-cdc-02_wmi_metrics.prom",
        # 10x the ~3-minute publish cadence (the admin's own instruction: "greater than 3
        # minutes... say 30 minutes") -- deliberately generous so a couple of missed runs (a
        # slow WMI call, a brief network blip to 203's share) never misreports this device as
        # down; see _relay_windows_metrics for the other safeguards against a false negative.
        "stale_after_seconds": 1800,
        # A SECOND, fully independent reachability signal (2026-09-09, on request: "treat 204
        # like an anomaly... we need different mechanisms for checking whether it's reachable...
        # the server currently is up and running" -- the metrics-freshness check alone had just
        # flagged it fully "unreachable" purely because its OWN scheduled ps1 script had stalled
        # for a few hours, while the box itself was confirmed alive the whole time). ICMP-probed
        # via blackbox_exporter (prometheus.yml's own blackbox_ping_network job, the same
        # mechanism already used for switches/routers/firewalls/WLCs), independent of the ps1
        # script and of 203 entirely -- a ping failure here can only mean the BOX itself is
        # unreachable, never "the script didn't run." See _relay_windows_metrics for how this
        # is combined with metrics-freshness into a genuine three-state read (down / stale-but-
        # confirmed-up / healthy) instead of one collapsed reachable/unreachable boolean.
        "ping_target": "10.100.249.204",
        "ping_job": "blackbox_ping_network",
        "system": "Child Domain Controllers",
        "job": "domain_controllers",
        "report": "network_report",
    },
    # BYO-AD-DC-01 (2026-09-10) -- a THIRD Child Domain Controller, at the Bulawayo site
    # (10.200.200.x, not the HQ 10.100.249.x range every other DC here lives in) -- already
    # known to this report as a replication PARTNER of 203/204 (see network.py's own
    # _ad_replication_rows) before now being monitored directly. Unlike RBZHQ-DC-204, this one
    # needs NO relay/workaround at all: confirmed live 2026-09-10 that it runs a full,
    # unrestricted windows_exporter (cpu/logical_disk/memory/service/ad collectors all present,
    # same as RBZHQ-DC-203/206/207) plus the same wmi_workaround_* textfile publishing every
    # other DC-tier host has -- so it flows through the existing generic "normal" (non-relay)
    # windows-kind path in _windows_metrics/_ad_service_states/_ad_replication_states
    # unchanged, same as RBZHQ-DC-203 itself. All 7 _AD_SERVICES confirmed running, and its own
    # windows_ad_replication_* series (not a relay-prefixed copy) confirmed present.
    {
        "key": "dc-byo",
        "name": "BYO-AD-DC-01",
        "kind": "windows",
        "target": "10.200.200.8:9182",
        "system": "Child Domain Controllers",
        "job": "domain_controllers",
        "report": "network_report",
    },
    # AD Sync & Authentication (2026-09-10) -- two more AD-identity servers, not domain
    # controllers themselves: RBZ-HQ-ADS-01 runs Azure AD Connect Sync, RBZ-ADAPT-01 runs the
    # Pass-Through Authentication agent. The admin's own call ("New tier under Active
    # Directory"): a third tier alongside Root/Child Domain Controllers, same nested-group
    # shape, rather than standalone top-level systems -- see build_infrastructure_report's own
    # ad_hosts filter and tier loop. Both confirmed reachable on windows_exporter:9182 the same
    # TLS+basic_auth way as the DCs (plain HTTP returned 400 -- a TLS-only listener, matching
    # that pattern) 2026-09-10; hostnames are reverse-DNS confirmed (corp.rbz.co.zw suffix
    # dropped, matching the RBZHQ-DC-203-style short-name convention already used elsewhere in
    # this list), not guessed -- no cs/os collector is enabled on either host (same
    # service+textfile-only collector set as the DCs), so there is no in-metrics hostname to
    # read directly. See _AD_SYNC_AUTH_SERVICES below for why each host's own service list is
    # looked up per-device rather than shared the way _AD_SERVICES is across every DC.
    {
        "key": "ad-sync",
        "name": "RBZ-HQ-ADS-01",
        "kind": "windows",
        "target": "10.100.249.206:9182",
        "system": "AD Sync & Authentication",
        "job": "ad_sync_auth",
        "report": "network_report",
    },
    {
        "key": "pta",
        "name": "RBZ-ADAPT-01",
        "kind": "windows",
        "target": "10.100.249.207:9182",
        "system": "AD Sync & Authentication",
        "job": "ad_sync_auth",
        "report": "network_report",
    },
]

# ---------------------------------------------------------------------------------------
#  Manually monitored interfaces -- ports CDP can never scope on its own (2026-09-24, on
#  request: "add span port in core switch... spanport is an interface that collects logs,
#  it says that its down but its not, [the way] by which it collects those logs make it
#  appear as if it is down... TwentyFiveGigE1/2/0/1 · LINK TO STELLAR CYBER SENSOR").
#
#  A SPAN/mirror destination port has no CDP neighbour at all -- the device plugged into it
#  (here, a Stellar Cyber network sensor) is a passive traffic receiver, not a switch/router/
#  AP running CDP, so _cdp_neighbor_kind() would never classify it and it would never become
#  part of the CDP-derived "monitored" scope (see collect()'s own comment on that). Its
#  ifOperStatus also reads unreliably "down" by the very nature of how it collects mirrored
#  traffic (confirmed by the network team, not guessed at here) -- so even if it COULD be
#  CDP-scoped, treating that "down" reading as a fault (the interface_down_regression flag
#  every other scoped port earns) would be a permanent false alarm on every single report.
#
#  Keyed by (DEVICES key, interface name as SNMP reports it via ifDescr/ifName) -- name, not
#  ifIndex, since that's what a human confirms and it survives an index renumber across a
#  reload; collect() resolves it to the live (target, ifIndex) pair every run. `down_is_fault`
#  False means: still list it in Interface Detail (scoped, like any monitored port), but never
#  raise interface_down_regression for it and never paint its down status red -- see
#  collect()'s own _manual_exempt_keys and build_report()'s Interface Detail status logic.
MANUAL_MONITORED_INTERFACES = {
    # HQ's ACTUAL Stellar Cyber Sensor link (corrected 2026-09-29, on request: "you were
    # right this is the correct port" -- replaces the earlier TwentyFiveGigE1/2/0/1 guess,
    # which was a real port on this chassis but not the right one). A redundant PAIR across
    # both supervisors/linecards (the "1/1/0/48"/"2/1/0/48" split matches this chassis' own
    # dual-supervisor addressing, the same "1/x" vs "2/x" pattern the old, wrong guess also
    # happened to follow), both confirmed live and both currently down -- same down-by-design
    # SPAN/mirror behaviour as before, so both are exempt.
    ("core-switch", "TenGigabitEthernet1/1/0/48"): {
        "label": "Link to Stellar Cyber Sensor (Supervisor 1)",
        "down_is_fault": False,
    },
    ("core-switch", "TenGigabitEthernet2/1/0/48"): {
        "label": "Link to Stellar Cyber Sensor (Supervisor 2)",
        "down_is_fault": False,
    },
    # 2026-09-29, on request: "MONITOR THESE INTERFACES IN CORE SWITCHES" -- BYO and DR's own
    # Stellar Cyber Sensor connections, added alongside HQ's above. Confirmed live first (the
    # literal BYO port given, "TwentyFiveGigE1/0/24", didn't exist on that chassis -- real
    # port confirmed as TwentyFiveGigE1/0/23 instead; re-confirmed again 2026-09-29 when the
    # same "1/0/24" was given a second time -- still doesn't exist on BYO, 1/0/23 stands).
    #
    # BYO's is a MANAGEMENT port for the sensor, not a SPAN/mirror destination like HQ's --
    # a management interface negotiates a normal link the way any other port does, so
    # down_is_fault stays True (the default) here: an actual down reading on this one IS a
    # real fault, unlike a SPAN port's inherent "always reads down" behaviour.
    ("core-switch-byo", "TwentyFiveGigE1/0/23"): {
        "label": "Management port for Stellar Cyber Sensor",
    },
    # DR's is confirmed as the SAME kind of connection as HQ's (on request: "same span-port
    # exception") -- exempted from down_is_fault the same way.
    ("core-switch-dr", "TwentyFiveGigE1/0/24"): {
        "label": "Link to Stellar Cyber Sensor",
        "down_is_fault": False,
    },
}

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

    # A RELAY device (2026-09-09: RBZHQ-DC-204, Device Guard blocks its own windows_exporter
    # outright) has no `up{instance=...}` of its own to check at all -- its whole CPU/RAM/disk/
    # reachability path is inferred differently, in _relay_windows_metrics below. Split it out
    # here so the rest of this function's plain per-instance queries are untouched by it.
    normal = [d for d in wanted if not d.get("relay_instance")]
    relays = [d for d in wanted if d.get("relay_instance")]

    up: Dict[str, float] = {}
    for job in {d["job"] for d in normal} | {d["relay_job"] for d in relays}:
        for r in q(f'up{{job="{job}"}}'):
            up[r["labels"].get("instance", "")] = r["value"]

    # wmi_workaround_cpu_load_percent, NOT windows_cpu_time_total's rate() (2026-09-08, on
    # request, after confirming live on both Root DCs: the perflib-based idle-time counter
    # reads wildly wrong here (.200: 40.2% counter vs 1.0% workaround gauge; .201: 18.7% vs
    # 0.0%) -- the same perflib breakage HCI's own nodes have, just not yet noticed on these
    # hosts because their textfile collector only started publishing today. RAM and disk are
    # NOT switched: wmi_workaround_memory_used_percent/disk_free_bytes/disk_size_bytes agree
    # with the standard windows_memory_*/windows_logical_disk_* readings within rounding on
    # both hosts, confirming perflib's breakage here is CPU-rate-specific (a byte-count gauge
    # was never exposed to whatever perflib counter class is broken), not a wholesale reason to
    # distrust every collector on these hosts. HELP text (via /api/v1/metadata) confirms this is
    # a genuinely different measurement from HCI's own windows_hci_cpu_usage_percent ("via
    # Health Service Get-ClusterPerf", cluster-specific, no equivalent for a standalone DC) --
    # this one is "CPU load percent via WMI (perflib workaround)", the generic non-cluster
    # equivalent, which is why Root DCs need this metric instead of that one.
    # Per-INSTANCE fallback (2026-09-17, on request: "how come we have no readings for cpu in
    # stand alone servers" -- confirmed live: the 3 new Standalone Servers/RTGS DB hosts don't
    # publish wmi_workaround_cpu_load_percent at all, and this function had no fallback for a
    # host without it, unlike _hci_node_metrics' own per-node gauge/standard merge). Every
    # instance still PREFERS the workaround gauge where published (Root DCs' own standard
    # counter is confirmed broken there, see the comment above), but an instance without it
    # now falls back to the plain standard counter instead of reading no data forever --
    # confirmed live on these 3 hosts the standard counter reads a normal, plausible value
    # (0.2-0.3%), so nothing here suggests THEIR counter is broken the way Root DCs' is.
    workaround_cpu = {r["labels"]["instance"]: r["value"]
                      for r in q("wmi_workaround_cpu_load_percent")
                      if r["labels"].get("instance")}
    # Same per-core/aggregate-series split and negative-reading guard as _hci_node_metrics'
    # own "standard" path -- see that function's own comment for why both are needed.
    std_per_core = {r["labels"]["instance"]: r["value"]
                    for r in q(f'100 - (avg by (instance) (rate(windows_cpu_time_total'
                              f'{{mode="idle", core!=""}}[{RATE_WINDOW}])) * 100)')
                    if r["labels"].get("instance")}
    std_aggregate = {r["labels"]["instance"]: r["value"]
                     for r in q(f'100 - (avg by (instance) (rate(windows_cpu_time_total'
                               f'{{mode="idle", core=""}}[{RATE_WINDOW}])) * 100)')
                     if r["labels"].get("instance")}
    standard_cpu = {**std_aggregate, **std_per_core}
    standard_cpu = {inst: v for inst, v in standard_cpu.items() if v >= 0}
    cpu = {**standard_cpu, **workaround_cpu}
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
    for d in normal:
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
    if relays:
        out.update(_relay_windows_metrics(relays, q, up))
    return out


def _relay_windows_metrics(relays: list, q, up: Dict[str, float]) -> Dict[str, dict]:
    """known/reachable/cpu/mem/disk for a device with NO windows_exporter of its own at all
    (2026-09-09: RBZHQ-DC-204, blocked outright by a Device Guard code-signing policy that
    could not be found or disabled) -- worked around with a scheduled ps1 script that writes a
    textfile-collector .prom file onto a DIFFERENT, healthy host's own windows_exporter (its
    own `relay_instance`), with every metric given this device's own `metric_prefix`
    (`rbz_hq_cdc_02_`, matching the script's own hostname-derived naming, confirmed live
    2026-09-09) so it can never collide with the relay host's own genuine readings on that same
    instance. Corrected 2026-09-09 from an earlier, purely guessed convention (`dc204_` /
    `windows_textfile_mtime_seconds{file="dc204_metrics.prom"}`) written before the ps1 script
    had actually been deployed -- it was already live with its own, richer naming by the time
    this was checked against real data ("we could not install the exporter... but we do have
    all its metrics").

    Reachability can't be `up{instance=...}==1` here -- there is no such series for a device
    that is never itself scraped -- so it's inferred from FRESHNESS instead, using the
    `.prom` FILE's own OS-level mtime (`windows_textfile_mtime_seconds{file=freshness_file}`,
    something windows_exporter computes itself via stat(), not the script). CORRECTED
    2026-09-09, the same day this first shipped, after a report read "has not reported in 2.0h"
    while the admin insisted the server was fine ("this shouldn't be correct"): the ORIGINAL
    version trusted the script's own self-reported `{prefix}wmi_workaround_last_run_timestamp_
    seconds` instead, reasoning a script's own "when did I last finish" claim looked more
    authoritative than a bare file-touch time -- but live data proved that backwards. Checked
    against `script_duration_seconds`/`uptime_seconds`/`process_count` (all climbing steadily on
    a healthy ~3-minute cadence throughout) and the file's own mtime (consistently ~3 minutes
    old) at the exact moment `last_run_timestamp_seconds` claimed a 2-hour-old run: the script
    genuinely runs and rewrites the file every cycle -- only the ONE `last_run_timestamp_
    seconds` VALUE it computes and writes had gotten stuck, a bug INSIDE the script's own logic
    that a "trust the script's self-report" design inherits by construction. The file's mtime,
    computed by windows_exporter itself from the OS, cannot inherit that same class of bug.
    Three deliberate safeguards against a FALSE NEGATIVE (2026-09-09, on request: "you may add
    other safeguards so we can avoid a false negative") --

      1. Staleness is computed with Prometheus's OWN clock -- `time() - max_over_time(...)`
         evaluated INSIDE the PromQL expression itself, the query returning the age in seconds
         directly. (An earlier version of this function computed `now - mtime` in PYTHON using
         time.time() despite this same docstring already claiming otherwise -- a real
         discrepancy caught and fixed the same day: this app server's own wall clock is now
         never part of the comparison, so drift between it and the Prometheus server can never
         manufacture a false "stale" reading.)
      2. `max_over_time(...[5m])` rides out ONE single missed Prometheus scrape of the relay
         host (a transient network blip, a slow scrape) without the metric appearing to vanish
         entirely for this one report render.
      3. `stale_after_seconds` (per-device, DEVICES' own dc-204 entry: 1800s) is a deliberately
         generous 10x the documented ~3-minute publish cadence -- the admin's own instruction
         ("greater than 3 minutes... say 30 minutes") -- so a couple of missed runs (a slow WMI
         call, a brief share hiccup) never flips this to "unreachable" on its own.

    `known` distinguishes "this metric has never been seen reporting at all" (script not yet
    deployed, wrong prefix, or the relay host itself has been down for a while) from "was seen,
    has since gone stale" -- the same known/reachable split every other device in this module
    already uses, so a not-yet-configured device never gets rendered as a confirmed-down one.

    `host_reachable` (2026-09-09, on request: "treat 204 like an anomaly... we need different
    mechanisms for checking whether it's reachable... the server currently is up and running")
    is a SECOND, fully independent signal: an ICMP probe (`ping_target`/`ping_job`, blackbox_
    exporter, the same mechanism switches/routers/firewalls already use here) straight against
    the device's own IP -- independent of both the ps1 script AND of the relay host (203)
    entirely. This exists because metrics-freshness ALONE had just flagged 204 fully
    "unreachable" purely because its own scheduled ps1 script had stalled for hours, while the
    box itself stayed pingable the whole time -- conflating "the monitoring script stopped
    running" with "the server is down" is exactly the false-negative risk this splits apart.
    `host_reachable` is None (not False) when no `ping_target` is configured for this device, or
    Prometheus has no probe data for it yet -- "no independent signal available" is a different,
    weaker claim than "confirmed unreachable," and _windows_device_flags treats it that way
    (falls back to the single-signal red verdict, not a false amber "confirmed fine").

    `reachable` itself is UNCHANGED by `host_reachable` -- it still means "do the CPU/RAM/disk
    numbers above reflect the device's CURRENT state," which only metrics freshness can answer
    (a fresh ping says nothing about whether last night's CPU reading is still true). What
    changes is _windows_device_flags' own SEVERITY when `reachable` is False: red ("possibly a
    real outage") when `host_reachable` is False or unknown, amber ("server's up, its own
    monitoring has stalled") when `host_reachable` is True despite stale metrics -- see that
    function's own relay branch for the exact three-way split.

    Returns {target: {"known":, "reachable":, "cpu_pct":, "mem_pct":, "disks": [...],
             "relay_instance":, "relay_reachable":, "stale_seconds":, "host_reachable":}} --
    the extra keys are ignored by every caller that only knows the plain windows-device shape,
    and used by _windows_device_flags to phrase a precise, relay-aware reason and severity."""
    ages: Dict[Tuple[str, str], float] = {}   # (instance, freshness_file) -> seconds since mtime
    for d in relays:
        inst, fname = d["relay_instance"], d["freshness_file"]
        for r in q(f'time() - max_over_time('
                  f'windows_textfile_mtime_seconds{{instance="{inst}", file="{fname}"}}[5m])'):
            if r["labels"].get("instance") == inst:
                ages[(inst, fname)] = r["value"]

    ping: Dict[str, float] = {}   # ping_target -> probe_success (1.0/0.0)
    ping_targets = {d["ping_target"] for d in relays if d.get("ping_target")}
    if ping_targets:
        ping_jobs = {d["ping_job"] for d in relays if d.get("ping_target")}
        # NOT re.escape() -- see _ad_service_states' own comment: PromQL label-matcher strings
        # consume a backslash as a STRING escape before RE2 ever sees the regex, so `\.` (what
        # re.escape gives a dotted IP) comes back "unknown escape sequence"/HTTP 400 (confirmed
        # live 2026-09-09, the exact same mistake that comment already warns against). A bare
        # `.` in the regex just means "any character," harmless for these fixed, internally-
        # configured IP values.
        targets_re = "|".join(ping_targets)
        for job in ping_jobs:
            for r in q(f'probe_success{{job="{job}", instance=~"{targets_re}"}}'):
                inst = r["labels"].get("instance")
                if inst:
                    ping[inst] = r["value"]

    out: Dict[str, dict] = {}
    for d in relays:
        t, inst, prefix = d["target"], d["relay_instance"], d["metric_prefix"]
        age = ages.get((inst, d["freshness_file"]))
        known = age is not None
        relay_reachable = up.get(inst) == 1.0
        reachable = bool(known and relay_reachable
                         and age <= d.get("stale_after_seconds", 1800))
        ping_target = d.get("ping_target")
        host_reachable = (ping.get(ping_target) == 1.0) if ping_target in ping else None

        cpu_val = next((r["value"] for r in q(f"{prefix}wmi_workaround_cpu_load_percent")
                        if r["labels"].get("instance") == inst), None)
        # Already a pre-computed percentage from the script itself -- used directly rather than
        # re-deriving from free/total (the script's own MB-denominated free/total pair would
        # work identically as a ratio, but the ready-made percent needs no unit-matching at all).
        mem_val = next((r["value"] for r in q(f"{prefix}wmi_workaround_memory_used_percent")
                        if r["labels"].get("instance") == inst), None)
        disk_used = {r["labels"].get("volume"): r["value"] for r in
                    q(f"100*(1-{prefix}windows_logical_disk_free_bytes{{{_WIN_VOL}}}/"
                      f"{prefix}windows_logical_disk_size_bytes{{{_WIN_VOL}}})")
                    if r["labels"].get("instance") == inst}
        disk_free = {r["labels"].get("volume"): r["value"] for r in
                    q(f"{prefix}windows_logical_disk_free_bytes{{{_WIN_VOL}}}/1024/1024/1024")
                    if r["labels"].get("instance") == inst}
        disk_size = {r["labels"].get("volume"): r["value"] for r in
                    q(f"{prefix}windows_logical_disk_size_bytes{{{_WIN_VOL}}}/1024/1024/1024")
                    if r["labels"].get("instance") == inst}
        disks = [{"volume": vol, "used": u, "free": disk_free.get(vol), "size": disk_size.get(vol)}
                for vol, u in disk_used.items()]

        out[t] = {
            "known": known, "reachable": reachable,
            "cpu_pct": cpu_val, "mem_pct": mem_val, "disks": disks,
            "relay_instance": inst, "relay_reachable": relay_reachable, "stale_seconds": age,
            "host_reachable": host_reachable,
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


def _hci_node_metrics(job: str = "hci_cluster") -> Dict[str, dict]:
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
    for r in q(f'up{{job="{job}"}}'):
        inst = r["labels"].get("instance")
        if not inst:
            continue
        up[inst] = r["value"]
        display[inst] = r["labels"].get("display", inst)

    # Per-INSTANCE, not per-cluster (2026-09-17: was a per-cluster cpu_source switch on this
    # function until confirmed live that Disaster Recovery Cluster is a partial rollout, not
    # an all-or-nothing split -- node1/node2 (.111/.112) now publish windows_hci_cpu_usage_
    # percent while node3/node4 (.113/.114) still don't). So every node that publishes the
    # gauge uses it, and every node that doesn't falls back to the standard counter below --
    # whichever a given instance actually has, checked at merge time, not decided in advance
    # per device/cluster.
    #
    # windows_hci_cpu_usage_percent: NOT windows_cpu_time_total's rate() (2026-09-08, on
    # request, after confirming live: the idle-time counter reads garbage on these nodes --
    # 40.96% and even NEGATIVE values (-1.66%, -2.01%) on real nodes at the same instant this
    # gauge read 23.03% -- a wmi_workaround_metrics.prom textfile collector (HCI Cluster) or
    # Get-ClusterPerf (Disaster Recovery Cluster, confirmed live 2026-09-17) publishes CPU
    # usage directly, sidestepping whatever breaks the standard counter in this clustered/
    # virtualized context. A gauge, so read as-is, no rate() -- unlike windows_cpu_time_total,
    # this already IS the usage percentage. Preferred wherever present.
    gauge = {r["labels"]["instance"]: r["value"]
            for r in q("windows_hci_cpu_usage_percent")
            if r["labels"].get("instance")}
    # windows_cpu_time_total publishes in TWO shapes per instance on this cluster, confirmed
    # live (2026-09-16, tracking down a node reading -23% CPU): 80 individual per-core series
    # (core="0,0", core="0,1", ...) AND a separate aggregate series with an EMPTY core=""
    # label (a WMI "_Total" pseudo-instance). Averaging across both shapes together, as a bare
    # `mode="idle"` selector does, mixes two different measurements of the same thing, which is
    # never correct even when (as tested) the numeric effect is usually small (the 80 per-core
    # series heavily outnumber the one aggregate series). The negative reading itself turned
    # out to be a separate, genuine counter-reset rate() artifact on a node that publishes ONLY
    # the aggregate series (no per-core breakdown at all) -- re-querying minutes later, it had
    # already resolved to a normal positive value. Prefer the per-core average (core!="") where
    # a node publishes it; fall back to the aggregate (core="") only for a node like that one,
    # which has nothing else.
    #
    # The per-core breakdown itself turned out to be INTERMITTENT, not just absent for one node
    # (2026-09-16, re-checking the same instance minutes apart: 80 per-core series one query,
    # zero the next) -- so the aggregate-series fallback above keeps getting exercised for a
    # node that normally has per-core data too, precisely when that aggregate series is ALSO
    # the one glitching negative. A negative CPU% is physically impossible regardless of which
    # series produced it, so it's dropped here rather than shown -- "no reliable reading this
    # cycle" (None, the same convention every other gap in this function already uses), not a
    # fabricated number. Only used as a fallback for an instance with no gauge reading at all.
    per_core = {r["labels"]["instance"]: r["value"]
               for r in q(f'100 - (avg by (instance) (rate(windows_cpu_time_total'
                         f'{{job="{job}", mode="idle", core!=""}}[{RATE_WINDOW}])) * 100)')
               if r["labels"].get("instance")}
    aggregate = {r["labels"]["instance"]: r["value"]
                for r in q(f'100 - (avg by (instance) (rate(windows_cpu_time_total'
                          f'{{job="{job}", mode="idle", core=""}}[{RATE_WINDOW}])) * 100)')
                if r["labels"].get("instance")}
    standard = {**aggregate, **per_core}   # per_core wins wherever both exist
    standard = {inst: v for inst, v in standard.items() if v >= 0}
    cpu = {**standard, **gauge}   # gauge wins wherever an instance publishes it
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


_TIB = 1024 ** 4   # 1099511627776 -- TiB, not decimal TB, matching windows_exporter's own
                    # binary-byte convention everywhere else in this module (GB conversions
                    # above all divide by 1024, not 1000).


def _hci_cluster_volumes(job: str = "hci_cluster") -> list[dict]:
    """One row per real Cluster Shared Volume (2026-09-14) -- the THIRD attempt at this same
    table, corrected twice the same day:
      1st: windows_hci_physicaldisk_capacity_total_bytes/_used_bytes -- wrong metric, the raw
           PHYSICAL DISK POOL (includes resiliency/parity overhead), not what admins asked for.
      2nd: windows_hci_volume_size_total_bytes/_available_bytes -- closer (a real volume-level
           figure), but still only ONE aggregate row for what is actually several distinct
           CSVs, hiding which specific volume is under pressure.
      3rd (this one): windows_hci_csv_volume_size_bytes/_size_remaining_bytes/_used_percent,
           keyed by the `volume` label (e.g. "HRE-HCI-VOL-01") -- one row per ACTUAL volume,
           confirmed live: 4 distinct volumes, distinct sizes, distinct usage.

    Queried by JOB, not by a specific instance (on request: "they are scraped from one HCI node
    but apply cluster-wide") -- whichever node in THIS cluster's job currently answers speaks
    for that whole cluster, the same reasoning _windows_cluster_metrics' own mscluster queries
    already use. The job filter itself was added 2026-09-16, when a second cluster (Disaster
    Recovery Cluster) started publishing the same CSV volume metrics -- an unscoped query would
    have silently merged both clusters' volumes into one list with no way to tell them apart.

    Rows enumerated from windows_hci_csv_volume_size_bytes' own `volume` label values (on
    request), sorted by volume name ascending. used_percent is read directly from its own
    metric, not derived from size/remaining (they're independent readings; using the metric
    that's actually FOR this is more honest than a derived approximation), rounded to the
    nearest integer per the requested display format. `band` (green <85% / amber 85-90% / red
    >=90%, matching chip_colors' own bands -- on request, 2026-09-14: "thresholds not applied
    to cluster storage" after chip_colors moved to this same 85/90 split but this table's own
    separate band computation was missed) is decided here, not in the renderer -- see
    ClusterVolumeRow's own docstring for why that split is used throughout this report.

    Returns [] when the metric isn't published by anything reachable right now, same "don't
    fabricate a row from data that isn't there" rule every other HCI table in this module
    follows.

    Excludes "ClusterPerformanceHistory" (2026-09-17, confirmed live on both clusters: ~16GB,
    ~26% used) -- Failover Clustering's own hidden performance-history database, auto-created
    on every S2D/HCI cluster, not a data volume anyone provisioned. Its real size is 3+ orders
    of magnitude below the actual data volumes sitting next to it in this table, which at this
    table's 1-decimal TB rounding reads as a confusing all-"0.0 TB" row -- not broken data, just
    never a capacity-planning target, so it doesn't belong in an admin-facing storage table."""
    _EXCLUDED_VOLUMES = {"ClusterPerformanceHistory"}
    prom, _ = _prometheus()

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                   # noqa: BLE001
            return []

    size_by_vol = {r["labels"]["volume"]: r["value"]
                  for r in q(f'windows_hci_csv_volume_size_bytes{{job="{job}"}}')
                  if r["labels"].get("volume")}
    remaining_by_vol = {r["labels"]["volume"]: r["value"]
                       for r in q(f'windows_hci_csv_volume_size_remaining_bytes{{job="{job}"}}')
                       if r["labels"].get("volume")}
    used_pct_by_vol = {r["labels"]["volume"]: r["value"]
                      for r in q(f'windows_hci_csv_volume_used_percent{{job="{job}"}}')
                      if r["labels"].get("volume")}

    rows = []
    for vol in sorted(size_by_vol):
        if vol in _EXCLUDED_VOLUMES:
            continue
        if vol not in remaining_by_vol or vol not in used_pct_by_vol:
            continue
        total_tb = size_by_vol[vol] / _TIB
        remaining_tb = remaining_by_vol[vol] / _TIB
        used_pct = round(used_pct_by_vol[vol])
        band = "red" if used_pct >= 90 else "amber" if used_pct >= 85 else "green"
        rows.append({
            "volume": vol, "total_tb": total_tb, "remaining_tb": remaining_tb,
            "used_tb": max(0.0, total_tb - remaining_tb), "used_pct": used_pct, "band": band,
        })
    return rows


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

    # windows_mscluster_node_state/resource_state come from windows_exporter's own `mscluster`
    # collector -- confirmed estate-wide (2026-09-29, on request: "how come there is no
    # cluster resources dont we have this metric") that this collector is NOT enabled on any
    # cluster node (HCI/DR/Bulawayo all show the identical windows_exporter_collector_success
    # set, missing "mscluster") -- so these two queries return nothing anywhere, today. The
    # wmi_workaround_* textfile script ALREADY publishes the same WMI-sourced data under its
    # own metric names (wmi_workaround_cluster_node_state/cluster_resource_state, confirmed
    # live on every HCI/DR/Bulawayo node1 -- same 0=up/2=online/3=offline/4=failed numeric
    # convention as the standard collector, since both ultimately read the same MSCluster WMI
    # classes) -- read as a per-instance fallback here, the SAME "workaround wins where
    # published, standard covers the rest" precedence _windows_metrics' own CPU merge already
    # established. wmi_workaround_cluster_resource_state carries no `group` label (unlike the
    # standard collector's own resource_state), so a workaround-sourced failed/offline
    # resource's node can't be attributed via group_owner below and buckets under "Unknown" --
    # a known, honest gap (see _by_node's own fallback), not silently hidden.
    def _node_rows(rows):
        by_target: Dict[str, list] = {}
        for r in rows:
            inst = r["labels"].get("instance")
            if not inst:
                continue
            state = int(r["value"])
            by_target.setdefault(inst, []).append(
                (r["labels"].get("node", "?"), _CLUSTER_NODE_STATE.get(state, f"state {state}"), state == 0))
        return by_target

    def _resource_rows(rows):
        by_target: Dict[str, dict] = {}
        for r in rows:
            inst = r["labels"].get("instance")
            if not inst:
                continue
            state = int(r["value"])
            c = by_target.setdefault(inst, {"online": 0, "offline": 0, "failed": 0, "other": 0,
                                            "offline_names": [], "failed_names": []})
            name = r["labels"].get("resource") or r["labels"].get("name", "?")
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
        return by_target

    nodes_by_target = {**_node_rows(q("windows_mscluster_node_state")),
                       **_node_rows(q("wmi_workaround_cluster_node_state"))}
    res_by_target = {**_resource_rows(q("windows_mscluster_resource_state")),
                     **_resource_rows(q("wmi_workaround_cluster_resource_state"))}

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
                          nodes: Optional[Dict[str, dict]] = None,
                          svc_list: Optional[list] = None,
                          svc_states: Optional[Dict[str, dict]] = None) -> list:
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

    `svc_list`/`svc_states` (2026-10-06, see _service_list_for_device's own comment for why
    this exists) -- `svc_list` is this device's own applicable (key, display_name) pairs from
    _AD_SERVICES/_AD_SYNC_AUTH_SERVICES/_HCI_SERVICES/_STANDALONE_SERVER_SERVICES, `svc_states`
    is the FULL {target: {service_key: running_bool}} dict capture_snapshot already queried
    (unsliced -- same shape _ad_service_states()/etc. already return, no reshaping needed) so
    this function can look up either `dev["target"]` directly (single device) or each node's
    own target in turn (nodes given) without the caller having to pre-split it. A service
    absent from its own state dict entirely (key missing, not False) means "unknown/not
    installed on this host" -- same as the xlsx's own Services table already treats it -- and
    is silently skipped, never flagged as down.

    (2026-09-08: CPU was briefly suppressed here for Infrastructure Admin's own report --
    "kindly ignore the cpu metric from the infrastructure reports metric is broken" -- restored
    same day once the underlying reading was fixed: "restore cpu issue has been resolved".)
    """
    from .services import FlagVM

    # A RELAY device (2026-09-09: RBZHQ-DC-204) has no `up{instance=...}` of its own -- "has
    # never been scraped"/"is not answering" would be misleading (nothing was ever scraped
    # FROM it directly), so it gets its own, more accurate wording naming the relay host and,
    # when known, exactly how stale its last-published metrics are. See _relay_windows_metrics
    # for what "known"/"reachable"/"stale_seconds"/"relay_reachable" mean here.
    if m.get("relay_instance"):
        relay_name = next((d["name"] for d in DEVICES if d["target"] == m["relay_instance"]),
                          m["relay_instance"])
        if not m.get("known"):
            return [FlagVM("win_unscraped",
                           f"{dev['name']} has never published metrics via {relay_name}",
                           "red", "unreachable")]
        if not m.get("reachable"):
            age_txt = _fmt_duration(m.get("stale_seconds"))
            host_reachable = m.get("host_reachable")
            # 2026-09-09, on request: "treat 204 like an anomaly... the server currently is up
            # and running" -- an independent ICMP probe (host_reachable, see DEVICES' own
            # ping_target/_relay_windows_metrics) can CONFIRM the box itself is alive even while
            # its own metrics-collection script has stalled. Originally downgraded to amber as a
            # materially less severe case than a genuine outage; band="red" again (2026-10-01,
            # on request: "component unreachable is always imminent severity... yes, always
            # Imminent, remove the amber downgrade entirely") -- category="unreachable" is now a
            # blanket "we don't trust this component's own data right now" signal, not a
            # confidence-graded one; see alert_catalog._tier()'s own category exception for how
            # this becomes Imminent. host_reachable is None (no ping configured/no data yet)
            # falls through to the SAME red, single-signal verdict either way, so this branch
            # no longer actually differs in severity from the one below it -- kept separate
            # only because the WORDING genuinely differs (names the relay/script specifically).
            if host_reachable is True:
                cause = (f"its metrics can't currently be relayed via {relay_name}, which is "
                        f"itself unreachable" if not m.get("relay_reachable") else
                        f"its own metrics-collection script has not reported in {age_txt} via "
                        f"{relay_name} -- check the scheduled task on {dev['name']} itself")
                return [FlagVM(
                    "win_stale_but_pinging",
                    f"{dev['name']} is reachable (ping OK), but {cause}, not the server's "
                    f"availability", "red", "unreachable")]
            reason = (f"{relay_name} is itself unreachable" if not m.get("relay_reachable")
                      else f"no fresh metrics in {age_txt}")
            if host_reachable is False:
                reason = f"not answering ping, {reason}"
            return [FlagVM("win_down",
                           f"{dev['name']} has not reported fresh metrics via {relay_name} "
                           f"({reason})", "red", "unreachable")]
    elif not m.get("known"):
        return [FlagVM("win_unscraped", f"{dev['name']} has never been scraped by Prometheus",
                       "red", "unreachable")]
    elif not m.get("reachable"):
        return [FlagVM("win_down", f"{dev['name']} is not answering", "red", "unreachable")]
    flags = []
    if nodes:
        for target, n in sorted(nodes.items(), key=lambda kv: kv[1].get("display", kv[0])):
            label = n.get("display", target)
            if not n.get("reachable"):
                flags.append(FlagVM(f"node_down:{target}", f"{label} is not answering",
                                    "red", "unreachable"))
                continue
            # THREE tiers, three DIFFERENT category names per metric, not one name spanning
            # two severities (2026-10-01: "do not name them the exact same thing across
            # severities") -- amber=base/Warning, red<IMMINENT_PCT="high_*"/Critical,
            # red>=IMMINENT_PCT="very_high_*"/Imminent. See each *_IMMINENT_PCT constant's
            # own comment in generate_report.py.
            cpu = n.get("cpu_pct")
            if cpu is not None and cpu >= 80:
                if cpu >= gr.CPU_IMMINENT_PCT:
                    flags.append(FlagVM(f"very_high_cpu:{target}", f"{label} · CPU at {cpu:.0f}%",
                                        "red", "very_high_cpu"))
                elif cpu >= 90:
                    flags.append(FlagVM(f"high_cpu:{target}", f"{label} · CPU at {cpu:.0f}%",
                                        "red", "high_cpu"))
                else:
                    flags.append(FlagVM(f"node_cpu:{target}", f"{label} · CPU at {cpu:.0f}%",
                                        "amber", "cpu"))
            mem = n.get("mem_pct")
            if mem is not None and mem >= 80:
                if mem >= gr.RAM_IMMINENT_PCT:
                    flags.append(FlagVM(f"very_high_ram:{target}", f"{label} · Memory at {mem:.0f}% in use",
                                        "red", "very_high_ram"))
                elif mem >= 90:
                    flags.append(FlagVM(f"high_ram:{target}", f"{label} · Memory at {mem:.0f}% in use",
                                        "red", "high_ram"))
                else:
                    flags.append(FlagVM(f"node_mem:{target}", f"{label} · Memory at {mem:.0f}% in use",
                                        "amber", "ram"))
            for disk in n.get("disks", []):
                used = disk.get("used")
                if used is not None and used >= 80:
                    if used >= gr.DISK_IMMINENT_PCT:
                        flags.append(FlagVM(f"very_high_disk:{target}:{disk['volume']}",
                                            f"{label} · {disk['volume']} at {used:.0f}% used",
                                            "red", "very_high_disk"))
                    elif used >= 90:
                        flags.append(FlagVM(f"high_disk:{target}:{disk['volume']}",
                                            f"{label} · {disk['volume']} at {used:.0f}% used",
                                            "red", "high_disk"))
                    else:
                        flags.append(FlagVM(f"node_disk:{target}:{disk['volume']}",
                                            f"{label} · {disk['volume']} at {used:.0f}% used",
                                            "amber", "disk"))
            net = n.get("net") or {}
            err = net.get("err_in", 0) + net.get("err_out", 0)
            # category="degraded", NOT "unreachable" (fixed 2026-09-29, on request: "an
            # unreachable occurs IFF when we have lost comunication with the device / host...
            # you cant say heavy discards are an unreachable") -- a NIC error/discard count is
            # a reading taken FROM a node we successfully reached, the opposite situation from
            # send_report/generate_report.py's own canonical `Flag(f"unreachable:{c.label}",
            # ..., "unreachable")` (a component that could not be reached at all). Also fixes a
            # real behavioural bug: alerting.py's IMMINENT-reminder escalation triggers on
            # `category in ("unreachable", "disk")`, so a red node_net_err was incorrectly
            # getting persistent lost-communication-grade reminder urgency. Originally filed
            # under category="service" (there was no better bucket yet); moved to "degraded"
            # (2026-10-01, on request: "reserve service down for actual services that are
            # down") once that dedicated "reachable but impaired" category existed -- a NIC
            # error count was never a named service going down either way, see
            # AlertGroup.CATEGORY_CHOICES' own comment for the full category split.
            if err >= _NODE_ERR_RED:
                flags.append(FlagVM(f"node_net_err:{target}",
                                    f"{label} · {err:.0f} network error(s) in the last {RATE_WINDOW}",
                                    "red", "degraded"))
            disc = net.get("disc_in", 0) + net.get("disc_out", 0)
            if disc >= _NODE_DISC_RED:
                # band="note", not "amber" (2026-09-21, on request, after a screenshot showing
                # this still reading as a "4 warning" badge on the interactive review screen --
                # "cluster report generator still views the discards as warnings") -- the xlsx
                # side of this (the NODE NETWORK DISCARDS banner, _infra_notes' own tally) was
                # already fixed to treat this as a note, not a warning, but that fix worked by
                # excluding the flag by KEY, leaving its band untouched -- so every OTHER
                # consumer of a plain SystemVM (this review screen's own "N warning" chip and
                # per-row colour, any dashboard tile that counts flags by band) never got the
                # memo, since none of them go through _infra_notes at all. Fixing the band at
                # the SOURCE instead of chasing every individual display is what actually makes
                # this a note everywhere at once: SystemVM.red/.amber both check band by exact
                # string match ("red"/"amber"), so "note" falls out of both automatically, no
                # per-consumer special-casing needed. category="potentially_degrading", NOT
                # "unreachable"/"service" for the same reason err above was moved (not a
                # reachability finding, not a named service) -- and NOT "degraded" either
                # (2026-10-01, on request: "some of these discards are too severe to lump all
                # together") since this one is always band="note", the lightest of the three
                # severity-split categories under AlertGroup.CATEGORY_CHOICES' own comment.
                flags.append(FlagVM(f"node_net_disc:{target}",
                                    f"{label} · {disc:.0f} discard(s) in the last {RATE_WINDOW}",
                                    "note", "potentially_degrading"))
            lat = n.get("latency") or {}
            worst_ms = max((v for v in (lat.get("read_ms"), lat.get("write_ms")) if v is not None), default=None)
            if worst_ms is not None and worst_ms >= _NODE_LATENCY_AMBER_MS:
                flags.append(FlagVM(f"node_latency:{target}",
                                    f"{label} · disk latency {worst_ms:.1f}ms",
                                    "red" if worst_ms >= _NODE_LATENCY_RED_MS else "amber", "disk"))
    else:
        # Three tiers, three different category names per metric -- see the cluster-node
        # loop's own identical comment above.
        cpu = m.get("cpu_pct")
        if cpu is not None and cpu >= 80:
            if cpu >= gr.CPU_IMMINENT_PCT:
                flags.append(FlagVM("very_high_cpu", f"CPU at {cpu:.0f}% (5-minute average)",
                                    "red", "very_high_cpu"))
            elif cpu >= 90:
                flags.append(FlagVM("high_cpu", f"CPU at {cpu:.0f}% (5-minute average)",
                                    "red", "high_cpu"))
            else:
                flags.append(FlagVM("cpu_high", f"CPU at {cpu:.0f}% (5-minute average)",
                                    "amber", "cpu"))
        mem = m.get("mem_pct")
        if mem is not None and mem >= 80:
            if mem >= gr.RAM_IMMINENT_PCT:
                flags.append(FlagVM("very_high_ram", f"Memory at {mem:.0f}% in use",
                                    "red", "very_high_ram"))
            elif mem >= 90:
                flags.append(FlagVM("high_ram", f"Memory at {mem:.0f}% in use",
                                    "red", "high_ram"))
            else:
                flags.append(FlagVM("mem_high", f"Memory at {mem:.0f}% in use",
                                    "amber", "ram"))
        for disk in m.get("disks", []):
            used = disk.get("used")
            if used is not None and used >= 80:
                if used >= gr.DISK_IMMINENT_PCT:
                    flags.append(FlagVM(f"very_high_disk:{disk['volume']}",
                                        f"{disk['volume']} at {used:.0f}% used",
                                        "red", "very_high_disk"))
                elif used >= 90:
                    flags.append(FlagVM(f"high_disk:{disk['volume']}",
                                        f"{disk['volume']} at {used:.0f}% used",
                                        "red", "high_disk"))
                else:
                    flags.append(FlagVM(f"disk_high:{disk['volume']}",
                                        f"{disk['volume']} at {used:.0f}% used",
                                        "amber", "disk"))
    if cluster:
        for name, state_text, up in cluster.get("nodes", []):
            if not up:
                flags.append(FlagVM(f"cluster_node_down:{name}",
                                    f"Cluster node {name} is {state_text}", "red", "unreachable"))
        for name, _group in cluster.get("resources", {}).get("failed_names", []):
            flags.append(FlagVM(f"cluster_resource_failed:{name}",
                                f"Cluster resource '{name}' is in a Failed state", "red", "service"))
    # Named-service checks (2026-10-06, see _service_list_for_device's own comment) -- same
    # category="service"/band="red" vocabulary generate_report.py's own System Admin service
    # checks already use (Flag(f"service:{group}:{name}", f"{name} DOWN", "red", "service")),
    # so this reads identically everywhere a "service" category finding already shows up
    # (_exception_detail's word-match, the Needs Attention Now matrix, real AlertGroup
    # notifications) rather than a second, differently-shaped signal. Per-node when `nodes` is
    # given (an HCI cluster's own services genuinely belong to one node, not the cluster
    # device as a whole), same single-target lookup otherwise (an AD DC/AD Sync host/
    # standalone server).
    if svc_list and svc_states:
        if nodes:
            for target, n in sorted(nodes.items(), key=lambda kv: kv[1].get("display", kv[0])):
                label = n.get("display", target)
                state = svc_states.get(target, {})
                for key, name in svc_list:
                    if state.get(key) is False:
                        flags.append(FlagVM(f"service:{key}:{target}",
                                            f"{label} · {name} DOWN", "red", "service"))
        else:
            state = svc_states.get(dev["target"], {})
            for key, name in svc_list:
                if state.get(key) is False:
                    flags.append(FlagVM(f"service:{key}", f"{name} DOWN", "red", "service"))
    return flags


def ad_device_label(dev: dict) -> str:
    """A neutral, non-identifying label for an Active Directory device -- no hostname
    (2026-09-11, on request: "hide hostnames from the picker, we need a neutral way of
    referencing this devices... this is the exact same pattern we have for systems" -- the
    System Admin picker shows a business system name, e.g. "RTGS", never a raw hostname).

    Domain controllers get "Root Domain Controller N" / "Child Domain Controller N",
    numbered within their own tier by DEVICES' own declared order -- the tier prefix is
    required, not cosmetic: "Domain Controller 1" alone repeats once per tier (root's #1 and
    child's #1 would read as the same device in the picker), which is the bug this labeling
    was fixing (2026-09-11 follow-up). build_infrastructure_report's own per-host section
    titles use the same N within a tier but also show the real hostname alongside it, so they
    don't suffer the same collision and are left as-is.

    AD Sync & Authentication's two hosts are different ROLES, not peer DC instances (same
    reasoning as that report's own title split -- "AD Sync and PTA are two DIFFERENT roles,
    not peer instances of the same role"), so they get their own functional name instead of a
    number."""
    if dev["system"] == "AD Sync & Authentication":
        return {"ad-sync": "AD Sync Server", "pta": "PTA Server"}.get(dev["key"], dev["key"])
    # Matched by `key`, not the dict itself: callers (device_inventory()) pass a COPY of the
    # DEVICES entry with extra reachability fields merged in, which is never `==` to the
    # plain entry still sitting in DEVICES -- list.index() would raise ValueError on it.
    tier_keys = [d["key"] for d in DEVICES if d.get("system") == dev["system"]]
    tier_prefix = "Root" if dev["system"] == "Root Domain Controllers" else "Child"
    return f"{tier_prefix} Domain Controller {tier_keys.index(dev['key']) + 1}"


_AD_SEVERITY_RANK = {"red": 2, "amber": 1}


def hosts_from_ad_snapshot(systems, wm: dict) -> Dict[str, List[dict]]:
    """{sysvm.name: [host]} for the Active Directory / Infrastructure Admin report review
    screens -- connect.hosts_from_snapshot's own twin (2026-09-11, on request: "there should
    be a button that shows both ip and hostname for whichever device has issues, this is the
    exact same pattern we have for systems"), adapted for THIS module's own Snapshot shape:
    a System Admin `System` can own several host `Component`s, but a network.py SystemVM
    already IS one physical/virtual host -- so this builds exactly one connect host per
    system, keyed by DEVICES' own `target`, rather than walking a `.components` list that
    doesn't exist here.

    Unlike the picker (device_inventory/ad_device_label), the REPORT review screen already
    shows the real hostname everywhere (every card's own title) -- so the connect chip's own
    label is the real name too, matching System Admin's own Connect chips (which show a real
    host label like "DB"/"App", not a neutralised one). Neutrality is a picker-only concern.
    """
    from . import connect

    by_name = {d["name"]: d for d in DEVICES}
    up = {t: m.get("reachable", False) for t, m in (wm or {}).items()}
    out: Dict[str, List[dict]] = {}
    for s in systems:
        dev = by_name.get(s.name)
        if not dev:
            continue
        out[s.name] = [connect.build_host(s.name, s.name, dev["target"], up, "windows")]
    return out


def attach_ad_severity(hosts_by_system: Dict[str, List[dict]], system_vms) -> None:
    """Colour each AD/Infra connect chip by the worst flag on its own SystemVM.

    Simpler than connect.attach_flag_severity's own per-COMPONENT matching (which matches a
    flag to one of SEVERAL hosts via the colon-delimited label segment of its key, e.g.
    "disk:DB:E:") -- AD/Infra's own flags (see _windows_device_flags) use plain, uncolonned
    keys like "win_down"/"cpu_high" and there is only ever ONE host per system in this shape,
    so every flag on a SystemVM belongs to its own single chip; no key-parsing needed."""
    for svm in system_vms:
        hosts = hosts_by_system.get(svm.name) or []
        if not hosts:
            continue
        h = hosts[0]
        h["severity"] = None
        h["issues"] = []
        for f in getattr(svm, "flags", []):
            h["issues"].append(f.text)
            if _AD_SEVERITY_RANK.get(f.band, 0) > _AD_SEVERITY_RANK.get(h["severity"], 0):
                h["severity"] = f.band


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
            # host_reachable (2026-09-09, on request: "the whole chain of screens... still
            # reflecting that one server is down") -- carried through so the picker can tell a
            # relay device confirmed alive via ping (RBZHQ-DC-204's own amber state) apart from
            # a device with no independent signal at all, the same distinction the report's own
            # tables/flags already make (see _windows_reading_trusted).
            out.append(dict(d, reachable=m["reachable"], known=m["known"],
                            host_reachable=m.get("host_reachable"),
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
def _update_interface_baseline(interfaces: list, scoped_keys: set,
                               exempt_from_regression: Optional[set] = None, now=None) -> set:
    """Upserts MonitoredInterface for every interface this collect() call just observed, and
    returns {(device, if_index), ...} for interfaces that are baseline-monitored (have been
    seen up before), SCOPED (see below), but are DOWN right now -- a genuine regression, not
    just "currently down" (see MonitoredInterface's own docstring for the "seen up once ->
    monitored for good" rule). Consumed by _device_flags() to turn a regression into a real
    red finding.

    `scoped_keys` -- {(device, if_index), ...} CDP currently identifies as an AP/uplink/
    neighbour link (2026-09-23, on request: "we only want to monitor these interfaces not all
    of them"), UNIONED with any manually monitored port (see MANUAL_MONITORED_INTERFACES,
    2026-09-24). Sets MonitoredInterface.is_scoped=True (sticky, never unset -- see its own
    field comment) the first time a port appears here; a port's own CDP entry disappearing
    once it actually goes down is expected, not a reason to stop flagging it, so `regressed`
    is filtered by the STORED is_scoped flag, not by membership in this run's own
    `scoped_keys` (which would have already lost the very port that just failed).

    `exempt_from_regression` (2026-09-24) -- {(device, if_index), ...} that must NEVER count
    as a regression regardless of is_scoped/currently_up, e.g. a SPAN/mirror destination port
    whose ifOperStatus reads unreliably "down" by design (see MANUAL_MONITORED_INTERFACES'
    own comment) -- there is no fault to detect there, so raising one every single run would
    be a permanent false alarm, not a real finding.

    A manually scoped, EXEMPT port that has NEVER been seen up (the SPAN-port case above --
    its true state cannot read as "up" the normal way) still gets its own MonitoredInterface
    row created here, scoped, the first time it's observed -- otherwise it would never appear
    in Interface Detail at all, silently contradicting "add span port" (see the `elif
    newly_scoped and key in exempt_from_regression:` branch below). A NON-exempt manually
    scoped port that's never been up is deliberately left untouched instead, same as a plain
    unscoped port -- exactly the rule a CDP-scoped port already gets for free (a CDP neighbour
    only exists while its link is actually up, so it can never reach this function still
    "never seen up"); a port meant to be monitored NORMALLY needs a real "seen up" moment
    before a later "down" can mean anything.

    A device/port collect() did not observe this run (e.g. the device was unreachable, so it
    contributed no interface rows at all) is left untouched here -- absence means "we don't
    know", not "it went down", which is exactly why an unreachable device already gets its own
    snmp_down/snmp_unscraped flag instead of a wave of false interface-down regressions.
    """
    from django.utils import timezone

    from .models import MonitoredInterface

    now = now or timezone.now()
    exempt_from_regression = exempt_from_regression or set()
    rows = [i for i in interfaces if i.get("device") and i.get("index") is not None]
    if not rows:
        return set()

    devices = {i["device"] for i in rows}
    existing = {(m.device, m.if_index): m
               for m in MonitoredInterface.objects.filter(device__in=devices)}

    to_create, to_update, regressed = [], [], set()
    for i in rows:
        key = (i["device"], str(i["index"]))
        row = existing.get(key)
        newly_scoped = key in scoped_keys
        if i["up"]:
            if row is None:
                to_create.append(MonitoredInterface(
                    device=i["device"], if_index=str(i["index"]), if_name=i["name"],
                    first_seen_up_at=now, last_seen_up_at=now, last_checked_at=now,
                    currently_up=True, is_scoped=newly_scoped))
            else:
                row.currently_up = True
                row.last_seen_up_at = now
                row.last_checked_at = now
                row.if_name = i["name"]
                if newly_scoped and not row.is_scoped:
                    row.is_scoped = True
                to_update.append(row)
        elif row is not None:
            if newly_scoped and not row.is_scoped:
                row.is_scoped = True
            if row.is_scoped and key not in exempt_from_regression:
                regressed.add(key)
            row.currently_up = False
            row.last_checked_at = now
            to_update.append(row)
        elif newly_scoped and key in exempt_from_regression:
            # A manually scoped port with no existing row, observed down (see the docstring's
            # SPAN-port paragraph) -- create it scoped so it appears in Interface Detail, but
            # never as a regression: there is no PRIOR "up" baseline for it to regress from.
            #
            # Gated on `key in exempt_from_regression` (fixed 2026-09-29, confirmed live: a
            # NON-exempt manually monitored port -- BYO's own Stellar Cyber Sensor management
            # port, currently down with no prior "up" observation -- would otherwise get
            # is_scoped=True here and then read as a "down -- regression" on its very next
            # run, despite never having regressed FROM anything. Only the exempt (down-is-
            # expected) case has any use for scoping a port that's never been up; a port
            # meant to be monitored NORMALLY still needs a real "seen up" moment before
            # "down" can mean anything -- exactly the same rule a CDP-scoped port already
            # gets for free (CDP only ever sees a neighbour while its link is up).
            to_create.append(MonitoredInterface(
                device=i["device"], if_index=str(i["index"]), if_name=i["name"],
                first_seen_up_at=now, last_seen_up_at=now, last_checked_at=now,
                currently_up=False, is_scoped=True))

    if to_create:
        MonitoredInterface.objects.bulk_create(to_create)
    if to_update:
        MonitoredInterface.objects.bulk_update(
            to_update, ["currently_up", "last_seen_up_at", "last_checked_at", "if_name", "is_scoped"])
    return regressed


def _update_ap_baseline(ap_names_by_device: dict, wlc_targets_checked: set, now=None) -> set:
    """Upserts MonitoredAccessPoint for every AP this collect() call saw joined to a WLC, and
    returns {(device, ap_name), ...} for APs that WERE seen joined before but are NOT in this
    run's ap_names_by_device for a WLC we actually checked -- a genuine "gone down /
    disconnected", not just "never known". See MonitoredAccessPoint's own docstring (2026-09-
    29, on request: "we need to monitor all access points connected to these wireless
    contreollers whether they are connected ore have gone down").

    `wlc_targets_checked` -- see collect()'s own comment on why this must be the real
    reachable-WLC set, not just ap_names_by_device's own keys: a WLC that answered SNMP but
    currently has ZERO APs joined would otherwise never get checked against its own history
    at all, silently missing an "every AP on this controller just dropped" event.

    A WLC collect() did not observe this run (unreachable, so it's absent from
    `wlc_targets_checked`) is left untouched here -- same "absence means we don't know, not
    that it went down" rule _update_interface_baseline() already follows for the same reason.
    """
    from django.utils import timezone

    from .models import MonitoredAccessPoint

    now = now or timezone.now()
    if not wlc_targets_checked:
        return set()

    existing = {(m.device, m.ap_name): m
               for m in MonitoredAccessPoint.objects.filter(device__in=wlc_targets_checked)}

    seen_this_run = {(device, name) for device, names in ap_names_by_device.items()
                     for name in names if device in wlc_targets_checked}

    to_create, to_update, regressed = [], [], set()
    for key in seen_this_run:
        device, name = key
        row = existing.get(key)
        if row is None:
            to_create.append(MonitoredAccessPoint(
                device=device, ap_name=name,
                first_seen_at=now, last_seen_at=now, last_checked_at=now, currently_up=True))
        else:
            row.currently_up = True
            row.last_seen_at = now
            row.last_checked_at = now
            to_update.append(row)

    # An existing row for a WLC we DID check this run, whose AP was NOT among what we saw --
    # gone. `existing` is already scoped to wlc_targets_checked via the queryset filter above,
    # so every key here belongs to a WLC that was genuinely reachable this run.
    for key, row in existing.items():
        if key in seen_this_run:
            continue
        if row.currently_up:
            regressed.add(key)
        row.currently_up = False
        row.last_checked_at = now
        to_update.append(row)

    if to_create:
        MonitoredAccessPoint.objects.bulk_create(to_create)
    if to_update:
        MonitoredAccessPoint.objects.bulk_update(
            to_update, ["currently_up", "last_seen_at", "last_checked_at"])
    return regressed


def _device_flags(dev: dict, data: dict) -> list:
    """The flagged items for one device, worst first.

    `band` is "red" (immediate) or "amber" (watch), matching the systems report exactly so
    the counts, chips and colours all behave without special-casing.
    """
    from .services import FlagVM

    flags = []

    # A device known in advance to have no working SNMP yet (2026-09-29, on request: "can we
    # have unconfigured instead of unreachable to avoid conflating with actual errors" --
    # DEVICES' own "snmp_unconfigured": True marker, see the Firewall Report's/Mikrotik's/
    # Msasa Liquid's own DEVICES comment) used to read amber "not yet configured" here instead
    # of red "unreachable"/"not answering" -- a device nobody has credentialed for SNMP yet
    # never had a baseline to lose, so this was deliberately softer than a real fault. Now red
    # again (2026-10-01, on request: "component unreachable belongs only to imminent severity
    # remove it from [warning]") -- category="unreachable" is a blanket "no data is coming
    # back from this component" signal across the whole app now, not a confidence-graded one;
    # the wording still names the real cause ("not yet configured") so an admin reading it
    # still knows this is a known rollout gap, not a surprise outage, even though the severity
    # no longer distinguishes the two. The ~50-device SNMPv3 rollout (see
    # project_network_device_rollout) will persistently remind on every one of these until
    # each is configured -- a real, accepted consequence of this choice, not an oversight.
    if dev.get("snmp_unconfigured"):
        if not dev.get("known"):
            flags.append(FlagVM("snmp_unconfigured", f"{dev['name']} is not yet configured for SNMP monitoring",
                                "red", "unreachable"))
        elif not dev.get("reachable"):
            flags.append(FlagVM("snmp_unconfigured",
                                f"{dev['name']} is not yet configured for SNMP monitoring — no reply yet",
                                "red", "unreachable"))
    elif not dev.get("known"):
        flags.append(FlagVM("snmp_unscraped", f"{dev['name']} has never been scraped by Prometheus",
                            "red", "unreachable"))
    elif not dev.get("reachable"):
        flags.append(FlagVM("snmp_down", f"{dev['name']} is not answering SNMP", "red", "unreachable"))

    # A down port is NOT flagged just for being down (2026-09-22, on request: "don't manage/
    # monitor all interfaces — only interfaces currently up... admin-disabled ports aren't a
    # finding") -- an admin-disabled port (an unused wall jack, a spare uplink) is a decision,
    # not a fault, and no reliable signal short of ifAdminStatus tells the two apart here (see
    # the retired links_failed/links_shut/links_down flags this replaced -- ifAdminStatus is
    # confirmed absent from this vendor's SNMP module, not just unread).
    #
    # A port that HAS been seen up before, though, and is down NOW, is a real regression
    # (2026-09-23, on request: "take a snapshot of all currently on interfaces and monitor
    # them... if any of these at any given point goes down now it's a problem"). The baseline
    # that distinguishes the two -- MonitoredInterface, updated by _update_interface_baseline()
    # every time collect() runs for this estate -- is looked up here, not re-derived: this is
    # the one place that baseline turns into a finding, so the report, the banners, and the
    # occurrence log it feeds the alert poller all agree on what counts as a regression.
    dev_regressed = [idx for (tgt, idx) in (data.get("interface_regressions") or set())
                     if tgt == dev["target"]]
    if dev_regressed:
        name_by_idx = {str(i["index"]): i["name"] for i in data.get("interfaces", [])
                       if i["device"] == dev["target"]}
        names = sorted(name_by_idx.get(idx, idx) for idx in dev_regressed)
        flags.append(FlagVM(
            "interface_down_regression",
            f"{len(dev_regressed)} interface(s) that were previously up are now down — "
            + ", ".join(names[:6]) + ("…" if len(names) > 6 else ""),
            "red", "degraded"))

    # Same regression idea as interface_down_regression just above, for wireless access
    # points on a WLC (2026-09-29, on request: "we need to monitor all access points
    # connected to these wireless contreollers whether they are connected ore have gone
    # down") -- MonitoredAccessPoint/_update_ap_baseline() is the AP-table equivalent of
    # MonitoredInterface/_update_interface_baseline(): an AP that WAS joined and has since
    # disappeared from CISCO-LWAPP-AP-MIB is a real disconnection, not "never known". NOT
    # category="unreachable" -- one AP going offline is a reading taken FROM a WLC we
    # successfully reached, not "we lost communication with the device" (see network.py's
    # own 2026-09-29 fix on temp_high/psu_fan_failed/node_net_err for the exact same
    # reasoning); category="degraded" matches every other reachable-but-impaired finding
    # here (moved off "service" 2026-10-01 -- a disconnected AP/interface is not a NAMED
    # service going down, see AlertGroup.CATEGORY_CHOICES' own comment).
    dev_ap_down = sorted(name for (tgt, name) in (data.get("ap_regressions") or set())
                         if tgt == dev["target"])
    if dev_ap_down:
        flags.append(FlagVM(
            "ap_down_regression",
            f"{len(dev_ap_down)} access point(s) that were previously joined are now "
            f"disconnected — " + ", ".join(dev_ap_down[:6]) + ("…" if len(dev_ap_down) > 6 else ""),
            "red", "degraded"))

    # The counter-width problem is a defect in the MEASUREMENT, and belongs on the report as
    # one — an admin reading these numbers has to know they are a floor. category=
    # "untracked_metrics", NOT "untracked" (2026-10-01, on request: "how does this error fit
    # under backups untracked category" -> "make it untracked metrics instead") -- "untracked"
    # originally meant exactly one thing, generate_report.py's own "no backup check on any
    # host" Flag; this is a measurement-coverage defect, nothing to do with backups, and had
    # been silently caught by any blanket "untracked" (no-backups) silence that shared its
    # category purely by coincidence -- see AlertGroup.CATEGORY_CHOICES' own comment.
    if data.get("wrap_seconds") and not data.get("counters_are_64bit"):
        flags.append(FlagVM(
            "counter_width",
            f"Throughput is under-reported: the 32-bit octet counters wrap about every "
            f"{data['wrap_seconds']}s at the current peak of {data['peak_bps_text']}. "
            f"Poll ifHCInOctets/ifHCOutOctets to fix it.",
            "amber", "untracked_metrics"))

    # ---- hardware, once the vendor module is scraped -------------------------------
    # Per-device dicts (cpu_by_device/mem_by_device/temp_by_device/uptime_by_device), keyed
    # by dev["target"] -- NOT the old estate-wide cpu_pct/mem_pct/temp_max/uptime_days
    # scalars, which are one number across every device collect() was asked about. Reading
    # those scalars here was correct only by accident while there was exactly one device in
    # scope; see collect()'s own comment on why (2026-09-22 fix).
    dev_cpu = data.get("cpu_by_device", {}).get(dev["target"])
    if dev_cpu is not None and dev_cpu >= 80:
        # Three tiers, three different category names -- see the cluster-node loop's own
        # identical comment earlier in this file.
        if dev_cpu >= gr.CPU_IMMINENT_PCT:
            flags.append(FlagVM("very_high_cpu", f"CPU at {dev_cpu:.0f}% (5-minute average)",
                                "red", "very_high_cpu"))
        elif dev_cpu >= 90:
            flags.append(FlagVM("high_cpu", f"CPU at {dev_cpu:.0f}% (5-minute average)",
                                "red", "high_cpu"))
        else:
            flags.append(FlagVM("cpu_high", f"CPU at {dev_cpu:.0f}% (5-minute average)",
                                "amber", "cpu"))
    dev_mem = data.get("mem_by_device", {}).get(dev["target"])
    if dev_mem is not None and dev_mem >= 80:
        if dev_mem >= gr.RAM_IMMINENT_PCT:
            flags.append(FlagVM("very_high_ram", f"Memory at {dev_mem:.0f}% in use",
                                "red", "very_high_ram"))
        elif dev_mem >= 90:
            flags.append(FlagVM("high_ram", f"Memory at {dev_mem:.0f}% in use",
                                "red", "high_ram"))
        else:
            flags.append(FlagVM("mem_high", f"Memory at {dev_mem:.0f}% in use",
                                "amber", "ram"))
    # category="degraded"/"degrading" below (PSU/uptime), NOT "unreachable" (fixed 2026-09-29,
    # on request: "an unreachable occurs IFF when we have lost comunication with the device /
    # host... you cant say heavy discards are an unreachable"). send_report/generate_report.py's
    # own Flag() construction -- the original, authoritative reference this whole vocabulary
    # comes from -- uses "unreachable" for exactly one thing: `Flag(f"unreachable:{c.label}",
    # f"{c.label} · unreachable", "red", "unreachable")`, a component that could not be
    # reached AT ALL. PSU/uptime are readings taken FROM a device we successfully reached --
    # the opposite situation -- so the "reachable but impaired" bucket OSPF/interface-error/
    # saturation findings below already use is the correct fit. This ALSO fixed a real
    # behavioural bug, not just a label, when it first moved off "unreachable": alerting.py's
    # own IMMINENT-reminder escalation triggers on `category in ("unreachable", "disk")` --
    # these were incorrectly getting persistent "unreachable"-grade reminder urgency for a PSU
    # fault or a recent reboot, neither of which is a lost-communication event.
    #
    # temp_high gets its OWN category, "temperature" (2026-10-01, on request: "create a new
    # issue type called temperature" -- a real Core Switch reading was found still showing as
    # "unreachable", traced to a genuinely orphaned IssueOccurrence row from before that
    # switch's rename, see 0068_temperature_category_and_orphan_cleanup). It briefly rode the
    # "degraded"/"degrading" severity-split (band varying live, >=75C red else amber) before
    # collapsing to a single always-red band (same date, on request: "temperature is always
    # only critical") -- a hot sensor at 60C is already worth a real Critical finding, not a
    # graduated amber-then-red escalation; the 60C threshold itself is unchanged, only the
    # two-stage severity grading is gone.
    dev_temp = data.get("temp_by_device", {}).get(dev["target"])
    if dev_temp is not None and dev_temp >= 60:
        flags.append(FlagVM("temp_high", f"Hottest sensor reading {dev_temp:.0f}°C",
                            "red", "temperature"))
    dev_uptime = data.get("uptime_by_device", {}).get(dev["target"])
    if dev_uptime is not None and dev_uptime < 1:
        # A switch that has just rebooted is the single most useful thing on this page: it
        # explains every other anomaly on it.
        flags.append(FlagVM("recent_reboot",
                            f"Device restarted {dev_uptime * 24:.0f} hours ago",
                            "red", "degraded"))
    psu_failed = [r for r in data.get("psu_failed", [])
                 if r["labels"].get("instance") == dev["target"]]
    if psu_failed:
        flags.append(FlagVM(
            "psu_fan_failed",
            f"{len(psu_failed)} of {data.get('psu_total', 0)} power/fan component(s) not in "
            f"a normal operating state",
            "red", "degraded"))
    ospf_down = [r for r in data.get("ospf_down", [])
                if r["labels"].get("instance") == dev["target"]]
    if ospf_down:
        flags.append(FlagVM(
            "ospf_adjacency_lost",
            f"{len(ospf_down)} of {data.get('ospf_total', 0)} OSPF neighbour(s) not Full "
            f"(stuck below the 2-Way/Full states)",
            "red", "degraded"))
    # Same 85%/gr.DISK_IMMINENT_PCT split as the flash_low/flash_critical tiles below and the
    # systems report's own disk_high() -- a storage partition running out is a real outage
    # risk (a switch that cannot write its own crashinfo/config), not just a space nag.
    # category="very_high_disk" here (2026-10-01, not "disk" any more -- this WAS the
    # original precedent the generalized 95% split borrowed from, see that category's own
    # comment in models.py), always Imminent -- flash_critical is already scoped to
    # >=DISK_IMMINENT_PCT at its own collect()-time definition, so every row reaching here is
    # already in the severe range.
    dev_flash_critical = [p for p in data.get("flash_critical", []) if p["device"] == dev["target"]]
    if dev_flash_critical:
        worst = max(dev_flash_critical, key=lambda p: p["used_pct"])
        flags.append(FlagVM(
            "flash_storage_critical",
            f"{len(dev_flash_critical)} storage partition(s) at or above {gr.DISK_IMMINENT_PCT}% used — worst "
            f"{worst['name']} at {worst['used_pct']:.0f}%",
            "red", "very_high_disk"))
    else:
        # Excludes anything already >=95% -- that's the critical branch above, not counted
        # twice (same non-overlapping pattern err_only/discard_heavy/disc_light use above).
        dev_flash_watch = [p for p in data.get("flash_low", []) if p["device"] == dev["target"]
                          and p not in dev_flash_critical]
        if dev_flash_watch:
            worst = max(dev_flash_watch, key=lambda p: p["used_pct"])
            flags.append(FlagVM(
                "flash_storage_low",
                f"{len(dev_flash_watch)} storage partition(s) at or above 85% used — worst "
                f"{worst['name']} at {worst['used_pct']:.0f}%",
                "amber", "disk"))
    # ---- interface health, once the counters are collected --------------------------
    # category="degraded"/"degrading" throughout this block (moved off "service" 2026-10-01,
    # on request: "reserve service down for actual services that are down" -- none of these
    # are a named service/process, they're link-layer signals from a device we successfully
    # reached), then split further by severity the same day ("some of these discards are too
    # severe to lump all together") -- each flag_key here has a FIXED band at its own call
    # site, so "degraded" (red ones) vs "degrading" (amber ones) is just naming each one by
    # its own already-fixed severity, not a live recomputation; see
    # AlertGroup.CATEGORY_CHOICES' own comment for the full category split.
    # >=95% is not "worth watching" — it is where real links start dropping packets.
    sat_critical = [i for i in data.get("saturated_critical", []) if i["device"] == dev["target"]]
    if sat_critical:
        worst = max(sat_critical, key=lambda i: i["util_pct"])
        flags.append(FlagVM(
            "links_saturated_critical",
            f"{len(sat_critical)} interface(s) at or above 95% of capacity — worst {worst['name']} "
            f"at {worst['util_pct']:.0f}% of {_fmt_bps(worst['speed_bps'])} — packets are likely "
            f"being dropped now",
            "red", "degraded"))
    sat = [i for i in data.get("saturated", []) if i["device"] == dev["target"]
          and i not in data.get("saturated_critical", [])]
    if sat:
        worst = max(sat, key=lambda i: i["util_pct"])
        flags.append(FlagVM(
            "links_saturated",
            f"{len(sat)} interface(s) at or above 80% of capacity — worst {worst['name']} "
            f"at {worst['util_pct']:.0f}% of {_fmt_bps(worst['speed_bps'])}",
            "amber", "degrading"))
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
            "red", "degraded"))
    discard_heavy = [i for i in data.get("discard_heavy", []) if i["device"] == dev["target"]]
    if discard_heavy:
        total = sum(i["errors"].get("in_disc", 0) + i["errors"].get("out_disc", 0) for i in discard_heavy)
        flags.append(FlagVM(
            "iface_discards_heavy",
            f"{total:.0f} discard(s) across {len(discard_heavy)} interface(s) in the last "
            f"{RATE_WINDOW} — congestion or a QoS policy actively dropping traffic",
            "red", "degraded"))
    disc_light = [i for i in data.get("disc_light", []) if i["device"] == dev["target"]]
    if disc_light:
        total = sum(sum(i["errors"].values()) for i in disc_light)
        flags.append(FlagVM(
            "iface_discards",
            f"{total:.0f} discard(s) across {len(disc_light)} interface(s) in the last "
            f"{RATE_WINDOW} — often a QoS policy dropping excess traffic on purpose, worth "
            f"confirming rather than assuming a fault",
            "amber", "degrading"))

    # category="untracked_metrics" (2026-10-01, on request: "how does this error fit under
    # backups untracked category" -> "make it untracked metrics instead") -- this is an SNMP
    # data-coverage gap ("we asked for 19 metrics, N aren't collected"), not a backup finding;
    # see counter_width above/AlertGroup.CATEGORY_CHOICES' own comment for the full history.
    catalogue = data.get("catalogue", CATALOGUE)
    missing = [m["name"] for m in catalogue if m["state"] == "missing"]
    if missing:
        flags.append(FlagVM(
            "metrics_missing",
            f"{len(missing)} of {len(catalogue)} requested metrics are not collected: "
            + ", ".join(missing[:4]) + ("…" if len(missing) > 4 else ""),
            "amber", "untracked_metrics"))
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
        # No dashboard tile for cluster/volume storage here (2026-09-14, on request: removed,
        # not replaced with a tile) -- the real figures are now the per-volume "Cluster
        # Storage Volumes" table in the Infrastructure Report (see build_infrastructure_
        # report's own HCI section, fed by _hci_cluster_volumes). A single glance/immediate
        # tile can't represent several independent CSVs without collapsing exactly the
        # per-volume detail that table exists to show, and this screen is tiles-only by
        # design (see this function's own module docstring) -- so this dashboard simply
        # doesn't attempt a cluster storage figure any more, rather than showing another
        # placeholder aggregate.
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
            # "Unreachable components" (2026-10-03, on request: "can we rename all not
            # responding or component down to be Unreachable components just to standardise
            # things" -- was "Not responding"; see services.py's own identically-named System
            # Admin tile and network._infra_overview's own former "Components down" for the
            # other two labels this same rename covers. Every reader keyed off the OLD label
            # text (views._management_dashboard_context's own exceptions/standing-rows block,
            # the AD+Cluster Health mailing merge) was updated in the same pass -- see each
            # one's own comment at its own call site).
            {"label": "Unreachable components", "value": f"{len(unreachable)} | {dev_total}",
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


def _switches_routers_overview(data: dict, devices: list) -> dict:
    """The Switches & Routers Report's own dashboard tiles -- a separate function from
    _network_overview (which stays exactly as it is, unchanged, for the long-standing Network
    Report tile) for the same reason _infra_overview is its own function: a genuinely
    different device set deserves tiles computed over THAT set, not a shared function
    branching on estate. Unlike _infra_overview, though, the underlying DATA shape here is
    identical to _network_overview's own (both read collect()'s SNMP-shaped dict) -- PSU/
    OSPF/optics/saturation/errors/discards tiles below are lifted near-verbatim from
    _network_overview, since data["psu_failed"]/["ospf_down"]/etc. already come back scoped
    to exactly `devices` (collect() was called with only=switches_routers_device_keys()).

    CPU/Memory/Temperature are the one place this deliberately does NOT mirror
    _network_overview: that function's cpu_pct/mem_pct are a single scalar across whatever
    collect() was asked about, correct only because the Network Report's own SNMP estate is
    exactly one device. Here, with 38 devices, the per-device dicts collect() now also
    returns (cpu_by_device/mem_by_device/temp_by_device -- see collect()'s own 2026-09-22
    comment) are used instead, so "N devices over threshold" is a real per-device count.
    """
    unreachable = [d for d in devices if d.get("known") and not d.get("reachable")]
    unscraped = [d for d in devices if not d.get("known")]
    dev_total = len(devices)
    iface_total = data["iface_count"]
    # Every interface-shaped tile below reads "N | monitored_total", not "N | iface_total"
    # (2026-09-23, on request: "we only want to monitor these interfaces not all of them...
    # uplink, accesspoint, links going to other switches" -- narrower than the previous
    # up-only scope from 2026-09-22, kept as the earlier step in the same direction). collect()
    # itself now only populates saturated/err_only/discard_heavy/disc_light from `monitored`
    # interfaces (see its own comment) -- up AND CDP-identified as an AP/uplink/neighbour
    # link -- so this is just using the matching denominator: a port that's up but has no
    # CDP-identified purpose was never a candidate for any of these findings in the first
    # place, and counting it in the total would make a fully healthy monitored-interface
    # estate read as though some fraction of it were unaccounted for.
    monitored_total = data.get("monitored_count", 0)
    # data["catalogue"] (not the bare global CATALOGUE) -- collect() already filtered it by
    # report_kind (2026-09-24), so a report that drops entries via skip_for (e.g. Core
    # Switches dropping BGP/Active connections/Connected devices) doesn't still count them
    # toward "N metrics not collected" here.
    catalogue = data.get("catalogue", CATALOGUE)
    missing = sum(1 for m in catalogue if m["state"] == "missing")
    psu_failed, psu_total = len(data.get("psu_failed", [])), data.get("psu_total", 0)
    ospf_down_n, ospf_total = len(data.get("ospf_down", [])), data.get("ospf_total", 0)
    flash_total = len(data.get("flash_partitions", []))
    flash_critical_n = len(data.get("flash_critical", []))
    # Non-overlapping with flash_critical_n -- same pattern _device_flags' own
    # flash_storage_low/flash_storage_critical split uses.
    flash_watch_n = len(data.get("flash_low", [])) - flash_critical_n
    sat_n = len(data.get("saturated", []))
    sat_critical_n = len(data.get("saturated_critical", []))
    err_only_n = len(data.get("err_only", []))
    discard_heavy_n = len(data.get("discard_heavy", []))
    disc_light_n = len(data.get("disc_light", []))
    bad = lambda n: "good" if not n else "bad"
    warn = lambda n: "good" if not n else "warn"

    targets = [d["target"] for d in devices]
    cpu_by_device = data.get("cpu_by_device") or {}
    mem_by_device = data.get("mem_by_device") or {}
    temp_by_device = data.get("temp_by_device") or {}
    cpu_vals = [cpu_by_device[t] for t in targets if t in cpu_by_device]
    mem_vals = [mem_by_device[t] for t in targets if t in mem_by_device]
    temp_vals = [temp_by_device[t] for t in targets if t in temp_by_device]
    cpu_over = sum(1 for v in cpu_vals if v >= 80)
    mem_over = sum(1 for v in mem_vals if v >= 80)
    temp_over = sum(1 for v in temp_vals if v >= 60)
    cpu_state = "bad" if any(v >= 90 for v in cpu_vals) else warn(cpu_over)
    mem_state = "bad" if any(v >= 90 for v in mem_vals) else warn(mem_over)
    temp_state = "bad" if any(v >= 75 for v in temp_vals) else warn(temp_over)

    # Interfaces that were previously up (baseline-monitored) and are down right now -- a
    # genuine regression, not just "currently down" (see _update_interface_baseline's own
    # docstring and _device_flags' matching comment). monitored_total + regressed_n is this
    # run's own view of "everything the baseline currently knows to be monitored" --
    # currently-monitored plus currently-down-but-monitored, so the denominator reads as a
    # real total, not a guess.
    regressed_n = len(data.get("interface_regressions") or set())

    fully_dark = dev_total > 0 and (len(unreachable) + len(unscraped)) >= dev_total
    if fully_dark:
        accuracy = {"label": "Throughput accuracy", "value": "No data",
                   "sub": "every device unreachable — see above", "state": "info"}
    else:
        accuracy = {
            "label": "Throughput accuracy",
            "value": "Accurate" if data.get("counters_are_64bit") else "Understated",
            "sub": ("64-bit counters" if data.get("counters_are_64bit")
                    else "32-bit counters — wrap and lose data on a fast link"),
            "state": "info" if data.get("counters_are_64bit") else "warn",
        }

    return {
        "glance": [
            {"label": "Devices", "value": dev_total, "state": "info"},
            {"label": "Interfaces monitored", "value": f"{monitored_total} | {iface_total}",
             "sub": "monitored | total", "state": "info"},
            # ↓ IN / ↑ OUT (2026-09-22, on request: a clear visual distinction between
            # inbound and outbound wherever the two appear together) -- the direction arrows
            # are the marker; tile_band's own panel rendering keeps them in two separate
            # sub-columns rather than one combined string, so they read as two numbers, not one.
            {"label": "Throughput", "value": f"{data['total_in_text']} | {data['total_out_text']}",
             "sub": "↓ IN | ↑ OUT", "state": "info"},
            {"label": "MAC / ARP entries",
             "value": f"{data.get('mac_count', 0)} | {data.get('arp_count', 0)}",
             "sub": "entry count, not % of capacity", "state": "info"},
        ],
        "immediate": [
            # "Unreachable components" (2026-10-03, see _network_overview's own identical
            # rename comment just above in this file for the full history/reasoning -- was
            # "Not responding" here).
            {"label": "Unreachable components", "value": f"{len(unreachable)} | {dev_total}",
             "sub": "devices | total", "state": bad(len(unreachable))},
            {"label": "Never monitored", "value": f"{len(unscraped)} | {dev_total}",
             "sub": "devices | total", "state": bad(len(unscraped))},
            {"label": "PSU / fan failed", "value": f"{psu_failed} | {psu_total}",
             "sub": "failed | total", "state": bad(psu_failed)},
            {"label": "OSPF adjacencies lost", "value": f"{ospf_down_n} | {ospf_total}",
             "sub": "down | total", "state": bad(ospf_down_n)},
            {"label": "Interfaces down (were up)",
             "value": f"{regressed_n} | {monitored_total + regressed_n}",
             "sub": "regressed | monitored total", "state": bad(regressed_n)},
            {"label": "Interfaces with errors", "value": f"{err_only_n} | {monitored_total}",
             "sub": "true errors | monitored", "state": bad(err_only_n)},
            {"label": "Storage critical", "value": f"{flash_critical_n} | {flash_total}",
             "sub": "partitions ≥95% used | total", "state": bad(flash_critical_n)},
        ],
        "watch": [
            {"label": "High CPU", "value": f"{cpu_over} | {dev_total}",
             "sub": "devices | total", "state": cpu_state},
            {"label": "Storage low", "value": f"{flash_watch_n} | {flash_total}",
             "sub": "partitions ≥85% used | total", "state": warn(flash_watch_n)},
            {"label": "High Memory", "value": f"{mem_over} | {dev_total}",
             "sub": "devices | total", "state": mem_state},
            {"label": "High Temperature", "value": f"{temp_over} | {dev_total}",
             "sub": "devices | total", "state": temp_state},
            {"label": "At capacity", "value": f"{sat_n} | {monitored_total}",
             "sub": "monitored ≥80% | monitored total",
             "state": "bad" if sat_critical_n else warn(sat_n)},
            {"label": "Heavy discards", "value": f"{discard_heavy_n} | {monitored_total}",
             "sub": "monitored | monitored total", "state": bad(discard_heavy_n)},
            {"label": "Some discards", "value": f"{disc_light_n} | {monitored_total}",
             "sub": "monitored | monitored total", "state": warn(disc_light_n)},
            {"label": "Metrics not collected", "value": f"{missing} | {len(catalogue)}",
             "sub": "metrics | total requested", "state": warn(missing)},
            accuracy,
        ],
        "banners": [],
    }


def _infra_overview(wm: Dict[str, dict], win_devices: list, wc: Dict[str, dict],
                    hci_nodes: Dict[str, dict], svc_counts: Tuple[int, int] = (0, 0)) -> dict:
    """Infrastructure Admin's OWN dashboard tiles -- deliberately a separate function from
    _network_overview (which stays exactly as it is, switch-oriented, Network Admin's own
    screen) rather than one function branching on estate: the two estates share almost no
    data shape (PSU/OSPF/optics/discards mean nothing here, and this needs per-host CPU/RAM/
    Disk in a way the switch-first function never tracks). Mirrors
    build_infrastructure_report's own needs_attention/watch_list tile set EXACTLY -- same
    labels' meaning, same thresholds, same formulas -- so the web review screen the admin
    signs off on and the xlsx they download never disagree about what counts as a problem.
    See that function's own comments for why each threshold is what it is; changes there
    should come here too.

    ONE deliberate exception to "mirrors exactly": `svc_counts` (2026-10-06, see
    _service_list_for_device's own comment for the full story) feeds a new "Services down"
    tile below that has NO counterpart in build_infrastructure_report's own needs_attention
    list -- that panel is hard-capped at 4 tiles by its own xlsx column-merge math (confirmed:
    "a 5th tile in needs_attention's narrower span doesn't fit... raises a merge-range error",
    see CLUSTER RESOURCES FAILED's own comment on why IT had to go in watch_list instead for
    the identical reason). Reworking that layout is a real, separate xlsx-rendering change, not
    a one-line addition -- left for its own pass rather than risking the production report
    document here. The dashboard tile is real (same `_ad_service_states()`/etc. queries the
    xlsx's own Services table already runs, read a second time, never guessed), it just has no
    xlsx-side twin yet.

    HCI Cluster is excluded from the flat per-device pass below and re-added via hci_nodes
    instead (same substitution build_infrastructure_report's own group-building does): its
    wm entry is one flat reading for a single target, not the real per-node breakdown, so
    counting both would double-count the cluster and undercount its actual node failures.
    """
    svc_down, svc_total = svc_counts
    all_cpu_ram: List[Tuple[float, float]] = []
    all_disks: List[float] = []
    components_total = components_down = 0
    for dev in win_devices:
        if dev.get("cluster"):
            continue
        m = wm.get(dev["target"], {"known": False, "reachable": False})
        components_total += 1
        # _windows_reading_trusted, NOT a bare m.get("reachable") (2026-09-09, on request: "the
        # whole chain of screens... still reflecting that one server is down" -- this tile used
        # to count RBZHQ-DC-204 as fully down purely from stale metrics-freshness, even once
        # its own ping-confirmed-alive amber state had already been fixed everywhere else).
        if not _windows_reading_trusted(m):
            components_down += 1
        else:
            if m.get("cpu_pct") is not None or m.get("mem_pct") is not None:
                all_cpu_ram.append((m.get("cpu_pct") or 0.0, m.get("mem_pct") or 0.0))
            for d in m.get("disks", []) or []:
                if d.get("used") is not None:
                    all_disks.append(d["used"])

    cluster_devices_here = [d for d in win_devices if d.get("cluster")]
    cluster_nodes = len(hci_nodes)
    cluster_nodes_down = sum(1 for n in hci_nodes.values() if not n.get("reachable"))
    if hci_nodes or cluster_devices_here:
        components_total += cluster_nodes if cluster_nodes else len(cluster_devices_here)
        components_down += cluster_nodes_down
    for n in hci_nodes.values():
        if not n.get("reachable"):
            continue
        if n.get("cpu_pct") is not None or n.get("mem_pct") is not None:
            all_cpu_ram.append((n.get("cpu_pct") or 0.0, n.get("mem_pct") or 0.0))
        for d in n.get("disks", []) or []:
            if d.get("used") is not None:
                all_disks.append(d["used"])

    cres = {"online": 0, "offline": 0, "failed": 0, "other": 0}
    for w in wc.values():
        res = w.get("resources") or {}
        for k in cres:
            cres[k] += res.get(k, 0)

    storage_critical = sum(1 for u in all_disks if u >= 95)
    mem_critical = sum(1 for _, r in all_cpu_ram if r >= 95)
    mem_amber = sum(1 for _, r in all_cpu_ram if 80 <= r < 95)
    cpu_amber = sum(1 for c, _ in all_cpu_ram if c >= 80)
    cpu_red = sum(1 for c, _ in all_cpu_ram if c >= 90)

    def _tone(n):
        return "bad" if n else "good"

    def _watch_tone(n, red_n):
        return "bad" if red_n else ("warn" if n else "good")

    import datetime
    now = datetime.datetime.now()

    return {
        # Cluster-only inventory readings (2026-09-16, on request: "remove the first 2 tiles in
        # the at a glance section of this report and just leave cluster count cluster nodes
        # etc." -- Devices/Components dropped). Same formulas as the xlsx's own AT A GLANCE
        # band (devices_total/cluster_count/cluster_resources_total in
        # build_infrastructure_report) for the readings that remain -- informational, never a
        # state color, so "info" throughout like _network_overview's own glance tiles use for
        # the equivalent readings there.
        "glance": [
            {"label": "Cluster count", "value": len(cluster_devices_here), "state": "info"},
            {"label": "Cluster nodes", "value": cluster_nodes, "state": "info"},
            {"label": "Cluster resources", "value": sum(cres.values()), "state": "info"},
            {"label": "Last checked", "value": now.strftime("%H:%M"), "state": "info"},
        ],
        "immediate": [
            # "Unreachable components" (2026-10-03, see _network_overview's own identical
            # rename comment for the full history -- was "Components down" here). Two real
            # consumers string-match this label by name and were updated in the same pass:
            # views._management_dashboard_context's own extract-and-exclude logic for the
            # AD+Cluster Health mailing merge, and generate_active_directory_report's own twin
            # copy of that same logic.
            {"label": "Unreachable components", "value": f"{components_down} | {components_total}",
             "sub": "down | total", "state": _tone(components_down)},
            {"label": "Nodes down", "value": f"{cluster_nodes_down} | {cluster_nodes}",
             "sub": "down | total", "state": _tone(cluster_nodes_down)},
            # Real, not fabricated (2026-10-06) -- same _ad_service_states()/
            # _ad_sync_auth_service_states()/_hci_service_states()/
            # _standalone_server_service_states() queries the xlsx's own per-DC Services table
            # already runs, summed by capture_snapshot once per capture and passed in as
            # svc_counts -- see this function's own docstring for why this tile has no xlsx-side
            # twin yet. Matches System Admin's OWN "Services down" tile exactly: same label,
            # same "down | total" sub-split, same _tone() bad-if-any-down rule.
            #
            # cres["failed"]/sum(cres.values()) folded in too (2026-10-06, on request: "are
            # cluster resources services also considered" -- confirmed they weren't: a failed
            # Hyper-V cluster RESOURCE, the VM/role a cluster manages, is a conceptually
            # different thing from the 4 named OS-level _HCI_SERVICES above, but it's already a
            # real category="service" flag (cluster_resource_failed, see
            # _windows_device_flags' own cluster branch) -- just one that, before this, had no
            # way to show up anywhere on Pretty's own matrix/Domain Health, since "Cluster
            # resources failed" (its own separate tile just below, UNCHANGED, still shown on
            # its own too) isn't one of the 4 fixed Needs Attention Now row labels. Folding its
            # same real numbers into THIS tile's total is the same "one real count feeds more
            # than one tile" pattern Nodes Down's own cluster_nodes_down already uses above
            # (also rolled into Unreachable components' own total, not just its own tile) --
            # not a double-counting bug, the same real finding legitimately belongs under both
            # a specific label and a broader rollup.
            {"label": "Services down", "value": f"{svc_down + cres['failed']} | {svc_total + sum(cres.values())}",
             "sub": "down | total", "state": _tone(svc_down + cres["failed"])},
            # "Storage critical" is now the ONE storage tile Infrastructure has, anywhere
            # (2026-09-18, on request: "storage capacity and storage critical are the same
            # metric... combine every occurrence and remove this redundancy", confirmed after
            # a first pass only hid the duplicate on the exec dashboards: "infrastructure
            # still views these as separate"). The watch-tier "Storage at capacity" tile that
            # used to sit alongside this (>=85%, storage_amber + storage_critical -- i.e.
            # ALWAYS including whatever's already counted here, unlike High memory's own
            # amber-only, non-overlapping watch tile) is gone outright, not just re-scoped to
            # exclude the overlap -- every caller that read "Storage at capacity" by name
            # (the xlsx AT A GLANCE band, the AD+Cluster Health mailing template's own "High
            # disk usage" merge) now reads "Storage critical" instead. The now-unused
            # storage_amber (85-94% count) was dropped from this function entirely, not kept
            # around -- nothing here reads it any more.
            {"label": "Storage critical", "value": f"{storage_critical} | {len(all_disks)}",
             "sub": "disks >=95% | total", "state": _tone(storage_critical)},
            {"label": "Memory critical", "value": f"{mem_critical} | {len(all_cpu_ram)}",
             "sub": "nodes >=95% | total", "state": _tone(mem_critical)},
        ],
        "watch": [
            {"label": "High CPU", "value": f"{cpu_amber + cpu_red} | {len(all_cpu_ram)}",
             "sub": "nodes | total", "state": _watch_tone(cpu_amber + cpu_red, cpu_red)},
            {"label": "High memory", "value": f"{mem_amber} | {len(all_cpu_ram)}",
             "sub": "nodes | total", "state": _watch_tone(mem_amber, 0)},
            # Offline deliberately not tracked -- see _CLUSTER_RESOURCE_STATE's own comment
            # (mostly powered-off test/UAT/DR VMs, informational not a fault). Same reasoning
            # as the xlsx's own CLUSTER RESOURCES FAILED tile, kept in sync with it here.
            {"label": "Cluster resources failed", "value": f"{cres['failed']} | {sum(cres.values())}",
             "sub": "resources | total", "state": _tone(cres["failed"])},
        ],
        "banners": [],
    }


def capture_snapshot(token: str, only: Optional[set] = None, infra: bool = False, *,
                     mode: Optional[str] = None, report_kind: Optional[str] = None):
    """A Snapshot of the selected network devices, interchangeable with the systems one.

    SNMP devices (the switch) go through collect()'s machinery, which is SNMP-shaped
    throughout (interfaces, OSPF, optics, PSU) and does not apply to a windows_exporter
    device — those (kind="windows", e.g. HCI Cluster) are gathered separately by
    _windows_metrics()/_windows_device_flags() and merged into the same systems list, so the
    report reads as one estate regardless of which mechanism actually measured each row.

    `mode` picks which dashboard-tile function runs: `"network"` (default) is
    _network_overview's own switch-oriented set (the long-standing Network Report tile),
    `"infra"` is _infra_overview's (Infrastructure Admin's own windows-exporter estate),
    `"switches_routers"` is _switches_routers_overview's (2026-09-22, the new Switches &
    Routers Report -- correct per-device CPU/RAM/temperature over its own 38-device SNMP
    estate, where _network_overview's single-scalar reading would be wrong -- see that
    function's own docstring). `infra=True` is kept as a back-compat alias for `mode="infra"`
    (every existing call site still passes the bool) -- new call sites should pass `mode=`.

    `report_kind` (2026-09-24) -- passed straight through to collect() so a report picker can
    drop CATALOGUE entries that don't apply to it (e.g. "core_switches" dropping BGP/Active
    connections/Connected devices -- see CATALOGUE's own skip_for comment). None (the
    default) keeps every existing call site's full catalogue unchanged.

    Raises NetworkUnavailable when Prometheus cannot be reached, mirroring
    services.capture_snapshot raising PrometheusUnavailable — the view handles them the same.
    """
    if mode is None:
        mode = "infra" if infra else "network"
    import datetime

    from .services import Snapshot, SystemVM, mute_reason_notes_for_system

    data = collect(only=only, report_kind=report_kind)
    # Interface baseline (2026-09-23) -- updated on EVERY switches_routers capture (the alert
    # poller's own cycle and any admin viewing the live report alike, see
    # _update_interface_baseline's own docstring), before _device_flags() runs below so a
    # freshly-detected regression is already visible on the SAME capture that found it. Other
    # modes never touch MonitoredInterface -- it is specific to this estate's own interfaces.
    data["interface_regressions"] = (
        _update_interface_baseline(data.get("interfaces", []), data.get("cdp_scoped_keys", set()),
                                   data.get("manual_exempt_keys", set()))
        if mode == "switches_routers" else set())
    # AP baseline (2026-09-29) -- same cadence/reasoning as the interface baseline just above,
    # see _update_ap_baseline's own docstring.
    data["ap_regressions"] = (
        _update_ap_baseline(data.get("ap_names_by_device", {}), data.get("wlc_targets_checked", set()))
        if mode == "switches_routers" else set())
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
        # notes= wired in (2026-10-08, on request: "check carefully and ensure" muted alerts
        # get an automated comment -- confirmed live this never existed for ANY network device:
        # mute_reason_notes_for_system (System Admin/Infra's own automated-comment pipeline,
        # reusing alerting._active_silences()/_silenced() verbatim) was only ever wired into
        # services.capture_snapshot, never into THIS module's own capture_snapshot, so a muted
        # discard/saturation/OSPF/temperature finding on a switch or router showed no "Muted
        # until..." explanation anywhere -- SystemVM.notes defaulted to [] on every network
        # device, silently, since the field itself already existed and just was never passed.
        flags = _device_flags(live, data)
        svms.append(SystemVM(name=dev["name"],
                             hosts=len([i for i in data["interfaces"] if i["device"] == dev["target"]]),
                             flags=flags,
                             notes=mute_reason_notes_for_system(dev["name"], flags)))

    win_devices = [d for d in DEVICES if d.get("kind") == "windows" and (only is None or d["key"] in only)]
    win_keys = {d["key"] for d in win_devices}
    wm = _windows_metrics(win_keys) if win_devices else {}
    wc = _windows_cluster_metrics(win_keys) if win_devices else {}
    # job-scoped (not per-DEVICES-target), so each one naturally covers all of ITS OWN nodes --
    # queried once per `cluster: True` device actually in scope (2026-09-16: generalized from a
    # single hardcoded hci-cluster check to loop over every such device, when Disaster Recovery
    # Cluster became a second one). Kept BOTH per-cluster dicts (for each cluster's own
    # SystemVM.hosts count and its own xlsx section -- see build_infrastructure_report) and a
    # merged dict/list across all clusters (for _infra_overview/_network_overview's own
    # aggregate tile counts, which never needed to know which cluster a node belongs to).
    cluster_devices = [d for d in win_devices if d.get("cluster")]
    hci_nodes_by_key = {d["key"]: _hci_node_metrics(d.get("job", "hci_cluster"))
                       for d in cluster_devices}
    hci_volumes_by_key = {d["key"]: _hci_cluster_volumes(d.get("job", "hci_cluster")) for d in cluster_devices}
    hci_nodes = {inst: n for nodes in hci_nodes_by_key.values() for inst, n in nodes.items()}
    hci_volumes = [v for vols in hci_volumes_by_key.values() for v in vols]
    # Named-service state, batched ONCE per group rather than per device (2026-10-06, see
    # _service_list_for_device's own comment) -- the exact same real queries
    # build_infrastructure_report's own Services table already runs, read a second time here
    # rather than recomputed differently, so the aggregate tile/flags below can never disagree
    # with the xlsx's own per-DC table. `win_devices` is already scoped to ONE report kind at
    # this point (infra_device_keys()/ad_device_keys(), via `only`), so these groups are never
    # mixed within a single capture_snapshot call -- whichever of the four is actually present
    # here is the only one that runs a real query.
    ad_hosts = [d for d in win_devices
               if d.get("system") in AD_SYSTEMS and d.get("system") != "AD Sync & Authentication"]
    ad_sync_auth_hosts = [d for d in win_devices if d.get("system") == "AD Sync & Authentication"]
    standalone_hosts = [d for d in win_devices if d.get("system") == "Standalone Servers"]
    svc_states: Dict[str, dict] = {}
    if ad_hosts:
        svc_states.update(_ad_service_states(
            [d["target"] for d in ad_hosts if not d.get("relay_instance")],
            relay_devices=[d for d in ad_hosts if d.get("relay_instance")]))
    if ad_sync_auth_hosts:
        svc_states.update(_ad_sync_auth_service_states(ad_sync_auth_hosts))
    if cluster_devices:
        svc_states.update(_hci_service_states(list(hci_nodes.keys())))
    if standalone_hosts:
        svc_states.update(_standalone_server_service_states([d["target"] for d in standalone_hosts]))
    svc_down = svc_total = 0
    for dev in win_devices:
        svc_list = _service_list_for_device(dev)
        if not svc_list:
            continue
        targets_here = (list(hci_nodes_by_key.get(dev["key"], {}).keys())
                        if dev.get("cluster") else [dev["target"]])
        for target in targets_here:
            state = svc_states.get(target, {})
            for key, _name in svc_list:
                running = state.get(key)
                if running is not None:
                    svc_total += 1
                    if not running:
                        svc_down += 1
    for dev in win_devices:
        m = wm.get(dev["target"], {"known": False, "reachable": False})
        nodes = hci_nodes_by_key.get(dev["key"]) if dev.get("cluster") else None
        # notes= wired in (2026-10-08) -- same gap/fix as the switch/router loop above, for the
        # Windows-kind devices this function ALSO builds SystemVMs for (domain controllers,
        # HCI clusters, etc.).
        win_flags = _windows_device_flags(dev, m, wc.get(dev["target"]), nodes,
                                          svc_list=_service_list_for_device(dev), svc_states=svc_states)
        svms.append(SystemVM(
            name=dev["name"], hosts=(len(nodes) if nodes else 1),
            flags=win_flags, notes=mute_reason_notes_for_system(dev["name"], win_flags)))

    if mode == "infra":
        overview = _infra_overview(wm, win_devices, wc, hci_nodes, (svc_down, svc_total))
    elif mode == "switches_routers":
        overview = _switches_routers_overview(data, list(inv.values()))
    else:
        overview = _network_overview(data, list(inv.values()), win_metrics=list(wm.values()),
                                     win_cluster=list(wc.values()), hci_nodes=hci_nodes)
    snap = Snapshot(
        token=token,
        captured_at=datetime.datetime.now(),
        prom_url=data["prom_url"],
        systems=svms,
        overview=overview,
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
    snap._hci_volumes = hci_volumes
    snap._hci_nodes_by_key = hci_nodes_by_key
    snap._hci_volumes_by_key = hci_volumes_by_key
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


def switches_routers_report_filename(theme: str = "dark", when=None) -> str:
    """Same family as network_report_filename just above, its own name (not "Infrastructure
    Report") since this is a genuinely separate report/estate -- see DEVICES' own comment on
    the 38-device block for why the two are kept apart. Kept for the alert poller's own use
    of the combined estate (see switches_routers_device_keys' own comment) -- no report
    picker generates this filename any more, see the four below."""
    import datetime
    when = when or datetime.datetime.now()
    return f"Switches & Routers Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def core_switches_report_filename(theme: str = "dark", when=None) -> str:
    import datetime
    when = when or datetime.datetime.now()
    return f"Core Switches Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def routers_report_filename(theme: str = "dark", when=None) -> str:
    import datetime
    when = when or datetime.datetime.now()
    return f"Routers Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def wireless_controller_report_filename(theme: str = "dark", when=None) -> str:
    import datetime
    when = when or datetime.datetime.now()
    return f"Wireless Controller Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def access_switches_report_filename(theme: str = "dark", when=None) -> str:
    import datetime
    when = when or datetime.datetime.now()
    return f"Access Switches Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def firewalls_report_filename(theme: str = "dark", when=None) -> str:
    import datetime
    when = when or datetime.datetime.now()
    return f"Firewall Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


def build_report(snapshot, *, theme: str = "dark", author: str,
                 annotations: dict, summary_comment: str,
                 title: str = "Infrastructure Report") -> bytes:
    """Render the network report as .xlsx, in the SAME theme as the systems report.

    Written directly rather than through gr.build_report_bytes: that builder reads the
    engine's Store — node_exporter disks, windows services, certificates — none of which a
    switch has, and feeding it a fabricated Store to borrow the layout would mean inventing
    the very fields this report exists to say are missing.

    The COLOURS, though, are not reinvented. They come from gr.PALETTES via gr.palette(), the
    same swap the systems build uses, so "dark" and "light" mean exactly one thing in this app
    and an adjustment to either palette reaches both reports without being copied across.

    `title` (2026-09-22, for switches_routers_generate) -- this builder used to hardcode
    "Infrastructure Report" as both the sheet title and the printed header, which was already
    a bit of a misnomer for the core-switch-only Network Report (kept, unchanged, as the
    default so that existing caller is unaffected) and would be flatly wrong for the new
    Switches & Routers Report, which is not Infrastructure Admin's estate at all -- see
    DEVICES' own comment on the 38-device block.
    """
    import io

    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation

    if theme not in gr.PALETTES:
        theme = "dark"

    with gr.palette(theme):
        T = gr.Theme

        # Times New Roman (2026-09-22, on request: "look exactly in terms of formatting to
        # the other reports... times new roman font") -- the System Admin Report's own
        # gr.Theme.font() and the Cluster Health/AD Report's own FONT_NAME already both use
        # it; this builder was the one report in the app still defaulting to openpyxl's bare
        # Calibri, the actual source of the visual mismatch (colours already came from this
        # same gr.Theme/gr.palette() the other two reports use -- see this function's own
        # docstring). F() stands in for every bare Font(...) call in this function (all 26 of
        # them, mechanically renamed) rather than repeating name="Times New Roman" at each
        # call site.
        def F(**kw):
            kw.setdefault("name", "Times New Roman")
            return Font(**kw)

        # openpyxl wants RRGGBB; the engine stores its colours as 00RRGGBB
        rgb = lambda c: str(c)[-6:]
        BG, CARD, HDR = rgb(T.BG), rgb(T.CARD), rgb(T.HDR)
        BORDER, INK, GREY = rgb(T.BORDER), rgb(T.WHITE), rgb(T.GREY)
        CYAN, SUB = rgb(T.CYAN), rgb(T.SUB)
        CHIP = {k: (rgb(v[0]), rgb(v[1])) for k, v in T.CHIP.items()}
        # "good"/"bad"/"warn" aliased onto green/red/amber (2026-09-23 fix, confirmed live:
        # "no normal warning and red coloring on panels and panel text"). _switches_routers_
        # overview()'s own bad()/warn() lambdas (and cpu_state/mem_state/temp_state alongside
        # them) return "good"/"bad"/"warn" -- CHIP's real keys are "green"/"amber"/"red"/
        # "critical", so every tile state PALETTE.get(state, PALETTE["info"]) looked up was
        # silently missing and falling back to the neutral info tint, regardless of whether
        # the tile was actually a real finding. Every AT A GLANCE/NEEDS IMMEDIATE ATTENTION/
        # NEEDS ATTENTION tile on this report has been rendering in the same blue "info"
        # colour since the tile-band system was introduced, never red or amber.
        PALETTE = dict(CHIP, info=(rgb(T.INFO[0]), rgb(T.INFO[1])),
                      good=CHIP["green"], bad=CHIP["red"], warn=CHIP["amber"])

        edge = Side(style="thin", color=BORDER)
        box = Border(left=edge, right=edge, top=edge, bottom=edge)
        page = PatternFill("solid", fgColor=BG)
        card = PatternFill("solid", fgColor=CARD)
        head = PatternFill("solid", fgColor=HDR)

        wb = Workbook()
        ws = wb.active
        ws.title = title[:31]   # openpyxl sheet-title limit
        ws.sheet_view.showGridLines = False
        ws.sheet_properties.tabColor = CYAN
        # REVERTED to the original widths (2026-09-23) -- two narrowing passes earlier the
        # same day ("way too much horizontal space... shift tables closer to the LHS edge",
        # then "narrow lhs gap by another 45 percent") shrank B-H by ~65% total, on the
        # assumption these columns were pure gap before the first lane. They are not: B-H is
        # ALSO the AT A GLANCE/banner dashboard's own content columns (FIRST..DASH_RIGHT).
        # Narrowing them first broke two things at once, confirmed from screenshots: the crest
        # image drifted into the title text (fixed separately -- see the title/subtitle block
        # below, which now starts at column C, not B, so the logo's own column B no longer
        # needs to double as text space), and dashboard tile labels ("PSU / FAN FAILED" etc)
        # overflowed into neighbouring tiles once DASH_RIGHT was widened to compensate for the
        # lost width by borrowing lane-system columns -- which include narrow, deliberately-3-
        # wide GAP columns (K/N/Q/...) meant only for the per-device lane rows. That second
        # problem is what's actually fixed now: _split_cols (above) divides by real column
        # WIDTH, not raw column count, so a tile group can never land on nothing but a narrow
        # gap column -- safe to widen DASH_RIGHT again (see its own comment) instead of
        # reverting it, and safe to keep these columns narrow, restoring the LHS-gap request.
        for col, width in zip("BCDEFGH", (12, 6, 22, 4, 12, 2, 3)):
            ws.column_dimensions[col].width = width

        FIRST, LAST = 2, 7

        # ---- side-by-side table lanes (2026-09-22) -----------------------------------------
        # The System Admin Report (Services | Memory·CPU | Disk | Backups | Clock | Notes) and
        # Cluster Health/AD Report (Services | CPU·RAM | Disk | Cluster Storage/Replication/
        # NTP | Notes -- see infrastructure_report.py's own column-plan docstring) both lay
        # several tables out SIDE BY SIDE at fixed columns on the SAME rows, not stacked one
        # below another -- that's the actual visual signature "multiple tables per device"
        # means here, not just "more than one table exists". table_at() (below) is this
        # report's own equivalent: a fixed column LANE per table type, all starting at the
        # same row for a given device, each independent of how tall its neighbours are (the
        # Interfaces lane can run to 300+ rows while Hardware Health next to it is 4 rows --
        # exactly how Disk sits next to the much shorter Memory·CPU table in the System Admin
        # Report). Ends at column AA (27) -- the same shared right edge RIGHT_EDGE uses in
        # infrastructure_report.py, not a coincidence: both reports' widest lane lands there.
        # Every lane sits behind a fixed, EVEN 1-column gap (width 3, narrow) -- locked in
        # 2026-09-23, on request: "fix and lock in [the lane] table spacing". Every lane below
        # is positioned as COL_N-1's own right edge + 1 gap column, not a standalone literal,
        # so shrinking or widening any one lane can never silently widen its own trailing gap.
        HW_COL, HW_W = 9, 2          # I:J   Hardware health (Metric, Value)
        OSPF_COL, OSPF_W = HW_COL + HW_W + 1, 2      # L:M   OSPF neighbours (Neighbour, State)
        PSU_COL, PSU_W = OSPF_COL + OSPF_W + 1, 2    # O:P   Power / fan (Component, Status)
        # Interface Totals (Metric, Value) -- 2026-09-22, replaces the old full per-port
        # Interfaces (Port, Status, In, Out, Errors, Discards) table, which listed EVERY port
        # including admin-down ones. Scoped to MONITORED interfaces now (2026-09-23: up AND
        # CDP-identified as an access point, uplink, or neighbour link -- see collect()'s own
        # `monitored` comment, narrower than the up-only scope this started as); the full
        # breakdown of every interface, monitored or not, is still on its own "Interface
        # Detail" sheet.
        IFACE_COL, IFACE_W = PSU_COL + PSU_W + 1, 2  # R:S
        # Optics retired entirely (2026-09-23, on request: "leave out optic details entirely")
        # -- the Optics Totals lane, the "Optics Detail" sheet, and every optics-derived flag/
        # tile/banner are gone, not just hidden; see collect()'s own removal of the optical
        # Tx/Rx block for the data-layer half of this.
        #
        # Storage (Partition, Size GB, Free GB, Used %) -- 2026-09-23, on request: "need to
        # add storage table for all switches" (every device, unlike the access-only CDP lane
        # below) -- see collect()'s own flash_partitions (CISCO-FLASH-MIB; HOST-RESOURCES-MIB
        # is not implemented on any device tested). A device's own partition count is small
        # (3-6, confirmed live) so the full per-partition breakdown fits directly in the lane
        # -- no separate "Storage Detail" sheet needed, unlike Interfaces/CDP.
        STORAGE_COL, STORAGE_W = IFACE_COL + IFACE_W + 1, 4  # U:X
        #
        # Important links (Interface, Status) -- 2026-09-29, on request: "add these particular
        # interfaces to the main report somehow its just 3 these ones are important". The
        # manually monitored interfaces (see MANUAL_MONITORED_INTERFACES) were only visible on
        # the 'Interface Detail' tab until now, same as every other monitored port -- but these
        # specific 3 (the Stellar Cyber Sensor links on HQ/DR/BYO) are important enough to want
        # on the main sheet directly, without a click-through. Rendered ONLY for a device that
        # actually has one or more manual entries (dev_manual, computed alongside dev_flash
        # below) -- most devices have none and skip this lane entirely, same as Storage/CDP.
        MANUAL_COL, MANUAL_W = STORAGE_COL + STORAGE_W + 1, 3  # Z:AB (Link, Interface, Status
                                                               # -- Interface added 2026-09-29,
                                                               # on request: "we dont know
                                                               # which interfaces these are")
        #
        # AP / Uplink port totals (Metric, Value) -- 2026-09-23, on request: "specific
        # monitoring on access switches not core switches... for access switches we want to
        # monitor only accesspoint ports... then we also need to monitor uplink ports". Sourced
        # from CDP neighbour discovery (see collect()'s own cdp_neighbors -- a new "cisco_cdp"
        # SNMP module/job, confirmed live: a neighbour's reported platform string identifies an
        # access point (Catalyst 9100-series, "C91xx"/"AIR-AP") or another switch/router (an
        # uplink) far more reliably than guessing "usually port 47/48"). Only rendered for
        # ACCESS switches (kind=="Switch" and not the one core-switch device) -- see
        # is_access_switch(); the core switch and routers/WLC skip this lane entirely, same
        # gating table_at's own `if dev_psu:` etc. already use for data that doesn't apply to
        # every device.
        CDP_COL, CDP_W = MANUAL_COL + MANUAL_W + 1, 2  # AD:AE
        # Notes -- moved here (2026-09-23, on request: "move notes section to be the last
        # section on the rhs") to become the OUTERMOST lane, matching generate_report.py's own
        # Notes panel exactly ("the outermost thing should be notes"): same row as every other
        # lane, not a separate narrow section stacked below them. metric spans the first 3
        # columns (wide -- flag text runs to full sentences), then Fix needed?, then Resolved.
        NOTES_COL, NOTES_W = CDP_COL + CDP_W + 1, 5  # AG:AK
        PAINT_LAST = NOTES_COL + NOTES_W + 3   # margin past Notes' own right edge, same
                                                # "+3 past the report's own right edge" golden
                                                # rule infrastructure_report.py's MAX_COL uses
        for col, width in zip(
            ("I", "J", "K", "L", "M", "N", "O", "P", "Q",
             "R", "S", "T", "U", "V", "W", "X", "Y",
             "Z", "AA", "AB", "AC",
             "AD", "AE", "AF",
             "AG", "AH", "AI", "AJ", "AK"),
            (16, 12, 3, 16, 10, 3, 28, 10, 3,
             16, 12, 3, 18, 10, 10, 10, 3,
             22, 24, 14, 3,
             16, 12, 3,
             34, 15, 62, 12, 12)):
            ws.column_dimensions[col].width = width

        def table_at(row0, col0, ncols, title, headers, rows):
            """table()'s own twin, written at an explicit (row0, col0) instead of the shared
            cursor `r`, so several tables can sit side by side on ONE starting row -- see the
            lane comment above. Returns the row immediately past its own last line, so the
            caller can take max() across every lane actually used on this device and continue
            from there. Every row is painted/bordered out to col0+ncols only (not PAINT_LAST)
            -- the gap columns between lanes are painted separately by the caller's own
            paint(row, PAINT_LAST) pass over the whole row span first."""
            y = row0
            last = col0 + ncols
            ws.cell(y, col0, title.upper()).font = F(bold=True, size=10, color=INK)
            for c in range(col0, last):
                ws.cell(y, c).fill = head
                ws.cell(y, c).border = box
            y += 1
            cols = list(range(col0, col0 + len(headers)))
            for h, c in zip(headers, cols):
                cell = ws.cell(y, c, h)
                cell.font = F(bold=True, size=9, color=SUB)
                cell.fill = head
                cell.border = box
            y += 1
            for row_vals in rows:
                for c in range(col0, last):
                    ws.cell(y, c).fill = card
                    ws.cell(y, c).border = box
                for (text, chip_band), c in zip(row_vals, cols):
                    cell = ws.cell(y, c, text)
                    if chip_band:
                        fg, bgc = CHIP[chip_band]
                        cell.font = F(bold=True, size=10, color=fg)
                        cell.fill = PatternFill("solid", fgColor=bgc)
                    else:
                        cell.font = F(size=10, color=INK)
                y += 1
            return y

        def paint(row, last=LAST):
            """Fill the row with the page colour.

            The canvas is painted rather than left to Excel's default white: on the dark
            theme an unpainted sheet frames the report in white and the whole thing reads as
            broken. The systems report paints for the same reason.

            `last` defaults to the narrow header/KPI-band/Findings width (LAST=7) -- unchanged
            for every existing caller. Rows carrying the wide side-by-side device tables pass
            PAINT_LAST instead, so the gap columns between lanes (and past the widest lane)
            still read as the same dark canvas rather than raw white Excel between tables.
            """
            for c in range(1, last + 1):
                ws.cell(row, c).fill = page

        # ---- header: the same crest-then-title block the systems report opens with -------
        # The logo floats over the grid rather than sitting in a cell, exactly as it does
        # there; a missing or unreadable file is not worth failing a report over, so it is
        # skipped with a note and the header renders without it.
        cfg = gr.load_config()
        for row in range(1, 9):
            paint(row, PAINT_LAST)
        try:
            from openpyxl.drawing.image import Image as XLImage
            from openpyxl.drawing.spreadsheet_drawing import AnchorMarker, OneCellAnchor
            from openpyxl.drawing.xdr import XDRPositiveSize2D
            img = XLImage(cfg.logo)
            # colOff nudged 10px left of the shared cfg value (2026-09-23, on request: "the
            # logo also snapped out of place... move it about 10 pixels to the left") -- a
            # LOCAL adjustment (9525 EMU/px at 96 DPI), not a change to cfg.logo_from_coloff
            # itself, since that value is shared with generate_report.py/infrastructure_
            # report.py's own headers and neither of those has this problem. Column B here has
            # gone through several width changes of its own this session (see its own comment
            # above the B-H width block); the logo's fixed-EMU offset into it never moved, but
            # how much of column B is actually left for it to sit in without crossing into
            # column C -- where the title now starts -- keeps changing as B's width does.
            logo_coloff = max(0, cfg.logo_from_coloff - 9525 * 10)
            img.anchor = OneCellAnchor(
                _from=AnchorMarker(col=cfg.logo_from_col, colOff=logo_coloff,
                                   row=cfg.logo_from_row, rowOff=cfg.logo_from_rowoff),
                ext=XDRPositiveSize2D(cx=cfg.logo_cx, cy=cfg.logo_cy))
            ws.add_image(img)
        except Exception as exc:                      # missing/unreadable logo -> carry on
            import sys as _sys
            print(f"[!] logo not embedded ({exc})", file=_sys.stderr)
        for row, ht in {1: 6, 2: 18, 3: 26, 4: 15, 5: 20, 6: 34, 7: 18}.items():
            ws.row_dimensions[row].height = ht
        # column A is the crest gutter, and the logo itself (anchored INSIDE column B, see
        # cfg.logo_from_col/coloff above) visually occupies column B too -- so the title block
        # starts at C, not B (2026-09-23 fix, confirmed live: "look at how the logo image is
        # sitting w[i]te on the report name" -- the crest was drawn directly over "SWITCHES &
        # ROUTERS REPORT"'s own "WIT"). generate_report.py's own title starts at column 3 for
        # exactly this reason ("self._merge(3, 3, 12, ...)"); infrastructure_report.py's does
        # too ("sh.put(1, 3, data.report_title, ...)") -- this header's own text block had
        # never actually matched either, despite the row-5 text/button comment below already
        # (correctly) describing the reference's "cols 3-8" convention.
        ws.column_dimensions["A"].width = 9

        # Byte-identical to before for the default title (the existing Network Report caller
        # never passes `title`) -- only a caller passing a different `title` (e.g. Switches &
        # Routers Report) gets a different subtitle, see build_report's own docstring.
        dash_subtitle = ("Infrastructure Analyses Dashboard" if title == "Infrastructure Report"
                         else f"{title} — Analyses Dashboard")
        ws.cell(3, 3, title.upper()).font = F(bold=True, size=22, color=INK)
        ws.cell(4, 3, snapshot.captured_at.strftime(
            f"snapshot generated %d %b %Y  ·  %H:%M      •      {dash_subtitle}")).font = F(color=SUB, size=9)
        ws.merge_cells(start_row=5, start_column=3, end_row=5, end_column=8)
        ws.cell(5, 3, "Static snapshot.   For LIVE, auto-refreshing monitoring, click  →").font = F(
            color=GREY, size=9)
        # Text and button live in SEPARATE merged column ranges (not adjacent single cells) so
        # a long row-5 text value can never visually run into the button -- the same structure
        # generate_report.py (cols 3-8 text / 9-13 button) and infrastructure_report.py (cols
        # 3-8 / 9-14) both use. No hyperlink target is wired here, on the same precedent
        # infrastructure_report.py's own header already set: unlike generate_report.py's
        # self.cfg.grafana (a real, configured URL), no live Switches & Routers dashboard URL
        # exists to link to, and inventing one would be fabrication this module doesn't do.
        dash_name = (title[: -len(" Report")] if title.endswith(" Report") else title).upper()
        ws.merge_cells(start_row=5, start_column=HW_COL, end_row=5, end_column=HW_COL + 4)
        btn = ws.cell(5, HW_COL, f"▸  OPEN LIVE {dash_name} DASHBOARD")
        btn.font = F(bold=True, size=12, color=CYAN)
        ws.cell(7, 3, f"By  {author}").font = F(color=SUB, size=9)
        r = 9

        # ---- grouped-column KPI tiles (2026-09-22, rescaled 2026-09-23) ---------------------
        # Matches the System Admin/Cluster Health Report's own "AT A GLANCE" card row and
        # "NEEDS IMMEDIATE ATTENTION"/"NEEDS ATTENTION" paired panel bands (see
        # generate_report.py's own card()/panel()/caption()/band()) -- including their WIDTH,
        # not just their shape. First set to DASH_RIGHT = HW_COL, matching
        # infrastructure_report.py's own DASH_LEFT=2/DASH_RIGHT=9; widened here to the CDP
        # lane's own right edge once B-H (this dashboard's own left portion) went narrow for
        # the LHS-gap request and needed the width made up elsewhere. An earlier attempt at
        # exactly this (borrowing columns J-S) broke tile labels -- confirmed from screenshots
        # -- because J-S includes narrow (width 3) GAP columns the lane system uses between
        # HW/OSPF/PSU/etc on per-device rows, and _split_cols back then divided by raw column
        # COUNT, so a tile group could land on nothing but one of those. _split_cols (above)
        # now divides by actual column WIDTH instead, so widening DASH_RIGHT through the same
        # uneven columns is safe -- a narrow gap column just gets absorbed into whichever
        # neighbouring tile's own boundary search prefers it, never stands alone.
        DASH_RIGHT = CDP_COL + CDP_W - 1

        def caption(row, text):
            paint(row, PAINT_LAST)
            ws.merge_cells(start_row=row, start_column=FIRST, end_row=row, end_column=DASH_RIGHT)
            ws.cell(row, FIRST, "  " + text).font = F(bold=True, size=8, color=SUB)
            ws.row_dimensions[row].height = 14

        def _split_cols(n, first, last):
            """Divide [first, last] into n contiguous groups by actual COLUMN WIDTH, not raw
            column count (2026-09-23 fix, confirmed live: DASH_RIGHT's own span mixes wide
            content columns with narrow (width 3) gap columns borrowed from the lane system --
            the previous count-based split could hand an entire tile group nothing but a
            narrow gap column, starving it of real width and overflowing its label into the
            next tile).

            Each internal boundary is the column whose CUMULATIVE width comes closest to that
            boundary's ideal proportional share of the total (searched over every position
            that still leaves at least one column for every remaining group) -- not a greedy
            left-to-right walk. A greedy walk was tried first and still starves a group: if
            that group's own first column happens to be a narrow gap column, the walk's own
            "leave enough columns for what's left" cap can trip before a SECOND column is ever
            considered, handing the group nothing but that one narrow column regardless of how
            far short of its target that leaves it. Searching every valid boundary and picking
            the closest avoids that -- a narrow column ends up absorbed into whichever
            neighbouring group's boundary search prefers it, never forced to stand alone.
            """
            from openpyxl.utils import get_column_letter

            n = max(n, 1)
            idxs = list(range(first, last + 1))
            widths = [ws.column_dimensions[get_column_letter(c)].width or 8.43 for c in idxs]
            cum = [0.0]
            for w in widths:
                cum.append(cum[-1] + w)
            total = cum[-1]
            target = total / n

            groups, start = [], 0
            for g in range(1, n):
                goal = target * g
                lo = start + 1
                hi = len(widths) - (n - g)   # must leave >= (n - g) columns for what's left
                best_i, best_diff = lo, abs(cum[lo] - goal)
                for i in range(lo, hi + 1):
                    diff = abs(cum[i] - goal)
                    if diff < best_diff:
                        best_diff, best_i = diff, i
                groups.append((idxs[start], idxs[best_i - 1]))
                start = best_i
            groups.append((idxs[start], idxs[-1]))
            return groups

        def stat_card(rtop, c1, c2, label, value, state):
            # Always 3 rows tall, matching stat_panel's own height -- a band can now mix
            # single-value cards with 2-sub-column panels (e.g. AAT A GLANCE's "Devices" card
            # beside its "Interfaces"/"Throughput" panels), and Excel row height is whole-row,
            # so a shorter card would either clip its neighbour's height or leave an unpainted
            # gap below it. The value merges across the bottom TWO rows instead, bottom-heavy
            # the same way generate_report.py's own card(vrow=...) bottom-aligns a short card
            # next to a taller panel in the same band.
            accent, tint = PALETTE.get(state, PALETTE["info"])
            fill = PatternFill("solid", fgColor=tint)
            bar = Border(left=Side(style="thick", color=accent))
            ws.merge_cells(start_row=rtop, start_column=c1, end_row=rtop, end_column=c2)
            lc = ws.cell(rtop, c1, label)
            lc.font = F(bold=True, size=8, color=SUB)
            lc.alignment = Alignment(horizontal="center")
            ws.merge_cells(start_row=rtop + 1, start_column=c1, end_row=rtop + 2, end_column=c2)
            vc = ws.cell(rtop + 1, c1, value)
            vc.font = F(bold=True, size=18, color=accent)
            vc.alignment = Alignment(horizontal="center", vertical="center")
            for rr in (rtop, rtop + 1, rtop + 2):
                for c in range(c1, c2 + 1):
                    ws.cell(rr, c).fill = fill
            for rr in (rtop, rtop + 1, rtop + 2):
                ws.cell(rr, c1).border = bar
            ws.row_dimensions[rtop + 2].height = 26

        def stat_panel(rtop, c1, c2, title, subA, valA, subB, valB, state):
            accent, tint = PALETTE.get(state, PALETTE["info"])
            fill = PatternFill("solid", fgColor=tint)
            bar = Border(left=Side(style="thick", color=accent))
            div = Border(left=Side(style="thin", color=SUB))
            ws.merge_cells(start_row=rtop, start_column=c1, end_row=rtop, end_column=c2)
            tc = ws.cell(rtop, c1, title)
            tc.font = F(bold=True, size=8, color=SUB)
            tc.alignment = Alignment(horizontal="center")
            mid = c1 + (c2 - c1 + 1) // 2
            mid = min(max(mid, c1 + 1), c2) if c2 > c1 else c1
            for (a, b), (sub, val) in (((c1, max(mid - 1, c1)), (subA, valA)), ((mid, c2), (subB, valB))):
                ws.merge_cells(start_row=rtop + 1, start_column=a, end_row=rtop + 1, end_column=b)
                sc = ws.cell(rtop + 1, a, sub)
                sc.font = F(bold=True, size=8, color=SUB)
                sc.alignment = Alignment(horizontal="center")
                ws.merge_cells(start_row=rtop + 2, start_column=a, end_row=rtop + 2, end_column=b)
                vc = ws.cell(rtop + 2, a, val)
                vc.font = F(bold=True, size=16, color=accent)
                vc.alignment = Alignment(horizontal="center")
            for rr in (rtop, rtop + 1, rtop + 2):
                for c in range(c1, c2 + 1):
                    ws.cell(rr, c).fill = fill
            if c2 > c1:
                ws.cell(rtop + 1, mid).border = div
                ws.cell(rtop + 2, mid).border = div
            for rr in (rtop, rtop + 1, rtop + 2):
                ws.cell(rr, c1).border = bar
            ws.row_dimensions[rtop + 2].height = 26

        # A panel needs at least 2 columns for its sub-column divider to mean anything -- capped
        # at 4/row for readability regardless of how wide DASH_RIGHT is (width-aware _split_cols
        # means more tiles COULD fit without starving any one of them, but a wider tile still
        # reads better than a merely possible one). A band with more tiles than that wraps onto
        # additional 3-row groups under the SAME caption, rather than squeezing narrower.
        MAX_TILES_PER_ROW = 4

        def tile_band(cap_row, title, tiles):
            """A tile renders as a `panel` (2 sub-columns, e.g. "3 | 39") when its value
            carries a " | " pair, and a plain `card` (one big number) otherwise -- auto-
            detected per TILE, not fixed per band, so a band can mix the two (e.g. AT A
            GLANCE's single-value "Devices" card beside its "Interfaces"/"Throughput" panels).
            """
            nonlocal r
            if not tiles:
                r = cap_row
                return
            caption(cap_row, title)
            trow = cap_row + 1
            for start in range(0, len(tiles), MAX_TILES_PER_ROW):
                chunk = tiles[start:start + MAX_TILES_PER_ROW]
                for rr in range(trow, trow + 3):
                    paint(rr, PAINT_LAST)
                for (c1, c2), item in zip(_split_cols(len(chunk), FIRST, DASH_RIGHT), chunk):
                    state = item.get("state", "info")
                    value = str(item["value"])
                    if " | " in value:
                        subs = (item.get("sub") or " | ").split(" | ")
                        vals = value.split(" | ")
                        subA = subs[0].upper() if subs else ""
                        subB = subs[1].upper() if len(subs) > 1 else ""
                        valA = vals[0] if vals else ""
                        valB = vals[1] if len(vals) > 1 else ""
                        stat_panel(trow, c1, c2, item["label"].upper(), subA, valA, subB, valB, state)
                    else:
                        stat_card(trow, c1, c2, item["label"].upper(), value, state)
                trow += 3
            r = trow
            paint(r, PAINT_LAST)
            r += 1

        def banner_line(row, text, font, tint, accent):
            paint(row, PAINT_LAST)
            ws.merge_cells(start_row=row, start_column=FIRST, end_row=row, end_column=DASH_RIGHT)
            cell = ws.cell(row, FIRST, "  " + text)
            cell.font = font
            cell.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            cell.border = Border(left=Side(style="thick", color=accent))
            fill = PatternFill("solid", fgColor=tint)
            for c in range(FIRST, DASH_RIGHT + 1):
                ws.cell(row, c).fill = fill
            # Narrower merge now (FIRST..DASH_RIGHT, not FIRST..PAINT_LAST-1) wraps sooner --
            # roughly half the old merge's total column width, so `per` is halved to match
            # (erring generous: a row a little taller than strictly needed is harmless, a row
            # too short clips text).
            per = 75
            ws.row_dimensions[row].height = max(1, (len(text) + per - 1) // per) * 14 + 6

        def render_banner_summary(top, header, band_, count, anchor_row):
            """A banner is now a 2-row SUMMARY -- the header line, then a single clickable
            link line -- not the full per-device listing (2026-09-23, on request: "some
            banners are way too large... should just summarise finding, introduce a button or
            link on each banner that navigates to another sheet that has a breakdown of
            everything"). The full per-device detail this banner used to list inline now lives
            on the "Findings Detail" sheet, at `anchor_row` -- build_findings_detail_sheet()
            builds that sheet FIRST and hands back exactly where each finding's own section
            starts, so this link jumps straight to it, not just the top of the sheet.
            """
            accent, tint = CHIP["red" if band_ == "red" else "amber"]
            banner_line(top, header, F(bold=True, size=10, color=accent), tint, accent)
            link_row = top + 1
            paint(link_row, PAINT_LAST)
            ws.merge_cells(start_row=link_row, start_column=FIRST, end_row=link_row, end_column=DASH_RIGHT)
            link = ws.cell(link_row, FIRST, f"  ▸  View all {count} — 'Findings Detail' sheet")
            link.font = F(bold=True, size=9, color=CYAN, underline="single")
            link.alignment = Alignment(horizontal="left", vertical="center")
            link.hyperlink = f"#'Findings Detail'!A{anchor_row}"
            link.border = Border(left=Side(style="thick", color=accent))
            fill = PatternFill("solid", fgColor=tint)
            for c in range(FIRST, DASH_RIGHT + 1):
                ws.cell(link_row, c).fill = fill
            return link_row

        def pct_band(v):
            # Always green/amber/red for a KNOWN reading, never uncoloured (2026-09-23 fix,
            # on request: "variable metrics are either green amber or red... look at all
            # other reports... use this exact same design" -- a healthy 9% CPU reading used
            # to render in the same plain ink colour as a purely descriptive count like
            # "Up: 74 interfaces", giving no visual signal that it had even been judged.
            # `None` is reserved for "not measured" (v is None), never "measured and fine".
            return None if v is None else ("red" if v >= cfg.chip_red else
                                           "amber" if v >= cfg.chip_amber else "green")

        def table(title, headers, rows, last=None):
            """A real, multi-column data table -- header row + data rows -- for the detail
            that used to render as a banner (see _network_overview's docstring): who/what,
            not a passive summary. Same visual language the tile bands (`band`) and the
            per-device Findings table below already use: HDR-filled title/header, CARD-filled
            data rows, thin borders throughout. `rows` is a list of rows, each a list of
            (text, chip_band_or_None) pairs, one per header -- chip_band colours that cell
            the same red/amber/green a percentage chip gets anywhere else in this app.

            `last` defaults to LAST (the narrow HCI/DR table width, every existing caller's
            behaviour unchanged) -- a caller sitting in the WIDE part of the sheet (e.g.
            Summary Notes, between the full-width tile bands and the full-width per-device
            blocks) passes PAINT_LAST instead, so the gap columns past its own content still
            get the same dark canvas paint() gives every other wide row, not raw white Excel.
            """
            nonlocal r
            last = last or LAST
            paint(r, last)
            ws.cell(r, FIRST, title.upper()).font = F(bold=True, size=10, color=INK)
            for c in range(FIRST, LAST):
                ws.cell(r, c).fill = head
                ws.cell(r, c).border = box
            r += 1
            paint(r, last)
            cols = list(range(FIRST, FIRST + len(headers)))
            for h, c in zip(headers, cols):
                cell = ws.cell(r, c, h)
                cell.font = F(bold=True, size=9, color=SUB)
                cell.fill = head
                cell.border = box
            for c in range(FIRST + len(headers), LAST):
                ws.cell(r, c).fill = head
                ws.cell(r, c).border = box
            r += 1
            for row_vals in rows:
                paint(r, last)
                for c in range(FIRST, LAST):
                    ws.cell(r, c).fill = card
                    ws.cell(r, c).border = box
                for (text, chip_band), c in zip(row_vals, cols):
                    cell = ws.cell(r, c, text)
                    if chip_band:
                        fg, bg = CHIP[chip_band]
                        cell.font = F(bold=True, size=10, color=fg)
                        cell.fill = PatternFill("solid", fgColor=bg)
                    else:
                        cell.font = F(size=10, color=INK)
                r += 1
            paint(r, last)
            r += 1

        def render_notes_lane(row0, sysvm):
            """Notes as the OUTERMOST lane on a device's row (2026-09-23, on request: "move
            notes section to be the last section on the rhs") -- Flagged metric / Fix needed?
            / Resolved table, THEN a Comment box, THEN a "By {author}" line, at NOTES_COL,
            same row0 every other lane uses, not a separate narrow section stacked below them
            (matches generate_report.py's own Notes panel: "the outermost thing should be
            notes"). `Resolved` is formula-derived from `Fix needed?`: no fix needed ->
            resolved; fix needed -> still open; blank until the admin picks. Produces EXACTLY
            the row count notes_h (computed by the caller, before row_max) predicts -- keep
            the two in sync if this ever changes.
            """
            ann = annotations.get(sysvm.name, {})
            ann_flags = ann.get("flags", {})
            mcol = NOTES_COL + 2
            fix_col, res_col = NOTES_COL + 3, NOTES_COL + 4
            y = row0
            if sysvm.flags:
                ws.merge_cells(start_row=y, start_column=NOTES_COL, end_row=y, end_column=mcol)
                h = ws.cell(y, NOTES_COL, "  Flagged metric")
                h.font = F(bold=True, size=8, color=SUB)
                for col, label in ((fix_col, "Fix needed?"), (res_col, "Resolved")):
                    hc = ws.cell(y, col, label)
                    hc.font = F(bold=True, size=8, color=SUB)
                    hc.alignment = Alignment(horizontal="center", wrap_text=True)
                for col in range(NOTES_COL, res_col + 1):
                    ws.cell(y, col).fill = head
                    ws.cell(y, col).border = box
                y += 1
                dv = DataValidation(type="list", formula1='"Yes,No"', allow_blank=True)
                ws.add_data_validation(dv)
                fix_letter = get_column_letter(fix_col)
                for flag in sysvm.flags:
                    fg = CHIP["red" if flag.band == "red" else "amber"][0]
                    ws.merge_cells(start_row=y, start_column=NOTES_COL, end_row=y, end_column=mcol)
                    d = ws.cell(y, NOTES_COL, "  " + flag.text)
                    d.font = F(color=fg, size=9)
                    d.alignment = Alignment(wrap_text=True, vertical="top")
                    for col in range(NOTES_COL, mcol + 1):
                        ws.cell(y, col).fill = card
                        ws.cell(y, col).border = box
                    answer = ann_flags.get(flag.key)
                    fix = ws.cell(y, fix_col, answer if answer in ("Yes", "No") else "")
                    fix.font = F(size=9, color=INK)
                    fix.fill = card
                    fix.border = box
                    fix.alignment = Alignment(horizontal="center")
                    dv.add(fix)
                    res = ws.cell(y, res_col,
                                 f'=IF({fix_letter}{y}="No","Yes",IF({fix_letter}{y}="Yes","No",""))')
                    res.font = F(size=9, color=INK)
                    res.fill = card
                    res.border = box
                    res.alignment = Alignment(horizontal="center")
                    y += 1
            else:
                ws.merge_cells(start_row=y, start_column=NOTES_COL, end_row=y, end_column=res_col)
                ws.cell(y, NOTES_COL, "  No critical or warning metrics this run.").font = F(
                    color=SUB, size=9)
                for col in range(NOTES_COL, res_col + 1):
                    ws.cell(y, col).fill = card
                    ws.cell(y, col).border = box
                y += 1

            ws.cell(y, NOTES_COL, "  Comment").font = F(bold=True, size=8, color=SUB)
            for col in range(NOTES_COL, res_col + 1):
                ws.cell(y, col).fill = card
            y += 1
            comment_text = (ann.get("comment") or "").strip()
            if not comment_text and not sysvm.flags:
                comment_text = "No issues identified."
            ws.merge_cells(start_row=y, start_column=NOTES_COL, end_row=y, end_column=res_col)
            cm = ws.cell(y, NOTES_COL, comment_text)
            cm.font = F(color=INK, size=9)
            cm.alignment = Alignment(wrap_text=True, vertical="top")
            for col in range(NOTES_COL, res_col + 1):
                ws.cell(y, col).fill = card
                ws.cell(y, col).border = box
            y += 1

            by = ws.cell(y, NOTES_COL, f"By  {author}")
            by.font = F(color=SUB, size=8)
            by.alignment = Alignment(horizontal="right")
            for col in range(NOTES_COL, res_col + 1):
                ws.cell(y, col).fill = card
            y += 1
            return y

        ov = snapshot.overview or {}
        # "N interfaces" describes the switch; a windows_exporter device (e.g. HCI Cluster)
        # has no interface count in this report's sense, so it gets the same "host(s)"
        # wording reports/form.html already uses for it on the live screen.
        win_names = {d["name"] for d in DEVICES if d.get("kind") == "windows"}
        # Per-cluster, not the merged snapshot._hci_nodes (2026-09-16, generalized: a second
        # cluster device must get its OWN node table here, not have both clusters' nodes
        # combined under whichever cluster row renders first).
        cluster_key_by_name = {d["name"]: d["key"] for d in DEVICES if d.get("cluster")}
        cluster_target_by_name = {d["name"]: d["target"] for d in DEVICES if d.get("cluster")}
        hci_nodes_by_key = getattr(snapshot, "_hci_nodes_by_key", None) or {}
        wc = getattr(snapshot, "_wc", None) or {}
        # target_by_name/data (2026-09-22, for the per-device switch/router/WLC tables below)
        # -- snapshot._store is the SAME collect() output capture_snapshot already built for
        # this exact run, never a fresh query.
        target_by_name = {d["name"]: d["target"] for d in DEVICES if d.get("kind") != "windows"}
        dev_by_name = {d["name"]: d for d in DEVICES if d.get("kind") != "windows"}
        data = getattr(snapshot, "_store", None) or {}

        # Computed early (2026-09-23), NOT where the Interface Detail sheet itself is actually
        # built (way below, after the per-device loop) -- the per-device loop's own "Interface
        # totals" pointer needs to know each device's own first row THERE before it writes its
        # own link, and both this and the sheet-building code below share the exact same sort
        # (by device name, then interface index), so the row numbers agree without the sheet
        # having to exist yet.
        #
        # Interface Detail lists SCOPED interfaces only (2026-09-24, on request: "the
        # interface breakdown still shows interfaces not monitored kindly remove these...
        # the admins are adament they dont want to see these interfaces save for the few they
        # specifically chose") -- MonitoredInterface.is_scoped is the same sticky "ever
        # CDP-identified as an AP/uplink/neighbour link" flag _device_flags' own
        # flash_storage_critical/interface_down_regression flags already trust (see that
        # model's own docstring): True for a port currently up AND CDP-scoped, and STAYS True
        # once a port is down too, so a genuine regression (a monitored port that just failed)
        # still shows here -- only a port NEVER chosen is excluded, not one that is chosen but
        # currently down. A per-device "not monitored" count for what's excluded is added at
        # the end of the sheet itself, below the main table, so the exclusion isn't silently
        # forgotten even though the ports themselves are gone from view.
        from .models import MonitoredInterface as _MonitoredInterface
        _interface_scoped_keys = set(_MonitoredInterface.objects.filter(
            device__in=target_by_name.values(), is_scoped=True).values_list("device", "if_index"))
        # Manually monitored interfaces, grouped by TARGET rather than DEVICES key (2026-09-29,
        # for the new "Important links" lane below) -- MANUAL_MONITORED_INTERFACES is keyed by
        # (DEVICES key, interface name), same resolution collect() itself already does.
        _target_by_dev_key = {d["key"]: d["target"] for d in DEVICES}
        _manual_by_target: Dict[str, list] = {}
        for (_dev_key, _if_name), _cfg in MANUAL_MONITORED_INTERFACES.items():
            _t = _target_by_dev_key.get(_dev_key)
            if _t:
                _manual_by_target.setdefault(_t, []).append((_if_name, _cfg))

        name_by_target_early = {t: n for n, t in target_by_name.items()}
        _det_rows_sorted = sorted(
            ((name_by_target_early[i["device"]], int(i["index"] or 0))
             for i in data.get("interfaces", [])
             if i["device"] in name_by_target_early
             and (i["device"], str(i["index"])) in _interface_scoped_keys),
            key=lambda pair: pair)
        det_first_row_by_device: Dict[str, int] = {}
        for _idx, (_dname, _ifidx) in enumerate(_det_rows_sorted):
            det_first_row_by_device.setdefault(_dname, 6 + _idx)

        # Same trick for the CDP Neighbors Detail sheet (2026-09-23) -- computed early so the
        # per-device "AP / Uplink ports" lane's own pointer link can name a row before that
        # sheet itself is actually built, sharing the exact same sort (device, then local
        # port) the sheet-building code below uses.
        _cdp_rows_sorted = sorted(
            ((name_by_target_early[n["instance"]], n["local_port"])
             for n in data.get("cdp_neighbors", []) if n["instance"] in name_by_target_early),
            key=lambda pair: pair)
        cdp_first_row_by_device: Dict[str, int] = {}
        for _idx, (_dname, _lport) in enumerate(_cdp_rows_sorted):
            cdp_first_row_by_device.setdefault(_dname, 6 + _idx)

        # Access point status, read fresh from MonitoredAccessPoint (2026-09-29, on request:
        # "we need to monitor all access points connected to these wireless contreollers
        # whether they are connected ore have gone down") -- NOT just data["ap_names_by_
        # device"] (this run's own live cLApRaw walk, currently-joined APs only): a
        # disconnected AP has already dropped out of that walk by design (see
        # MonitoredAccessPoint's own docstring), so reading the STICKY baseline table instead
        # is what lets a gone-down AP still show up here at all, the same "read the baseline,
        # not just this run's own live view" choice Interface Detail's own
        # _interface_scoped_keys already makes for ports. capture_snapshot() already ran
        # _update_ap_baseline() before build_report() was ever called, so this table is
        # already current for this exact run.
        from .models import MonitoredAccessPoint

        _wlc_targets_all = {d["target"] for d in DEVICES if d.get("kind") == "WLC"}
        ap_status_by_target: Dict[str, list] = {}
        for _row in MonitoredAccessPoint.objects.filter(device__in=_wlc_targets_all):
            ap_status_by_target.setdefault(_row.device, []).append(
                (_row.ap_name, _row.currently_up))
        for _lst in ap_status_by_target.values():
            _lst.sort()

        # Same trick again for the Access Points Detail sheet -- computed early so the per-WLC
        # "Access Points" lane's own pointer link can name a row before that sheet itself is
        # actually built, sharing the exact same sort (device, then AP name) the sheet-building
        # code below uses.
        _ap_rows_sorted = sorted(
            ((name_by_target_early[_t], _name)
             for _t, _statuses in ap_status_by_target.items()
             if _t in name_by_target_early for _name, _ in _statuses),
            key=lambda pair: pair)
        ap_first_row_by_device: Dict[str, int] = {}
        for _idx, (_dname, _name) in enumerate(_ap_rows_sorted):
            ap_first_row_by_device.setdefault(_dname, 6 + _idx)

        # ---- Summary Notes (2026-09-22, repositioned 2026-09-23) ---------------------------
        # Matches generate_report.py's own RHS "Summary Notes" panel exactly: it sits BESIDE
        # the AT A GLANCE cards, its own title row level with row 9 (where the cards start),
        # not stacked below the whole dashboard+banners block ("topmost summary section top
        # edge must align with top edge of dashboard section"). Rendered here, before the
        # dashboard/banners below, using its OWN row cursor at the exact row the dashboard is
        # about to start from -- NOTES_COL sits far to the right of DASH_RIGHT (see both their
        # own comments), so the two never collide column-wise even while sharing rows.
        # `notes_col_bottom` is reconciled against the dashboard+banners' own bottom (`r`)
        # further down, the same "take whichever side ran taller" pattern generate_report.py's
        # own content_bottom/notes_bottom max() uses -- one comment further down explains why.
        #
        # One row per DISTINCT comment, grouped so several devices sharing the exact same note
        # (most commonly "no issues") don't repeat it once per device. Sourced from the SAME
        # annotations dict each device's own Comment box below reads, and the same flags list
        # feeding the Findings table -- never a second, independently-worded summary.
        note_groups: List[Tuple[str, List[str]]] = []
        note_seen: Dict[str, int] = {}
        for sysvm in snapshot.systems:
            if sysvm.name not in target_by_name:
                continue
            ann = annotations.get(sysvm.name, {})
            text = (ann.get("comment") or "").strip()
            if not text:
                nc_ = sum(1 for f in sysvm.flags if f.band == "red")
                nw_ = sum(1 for f in sysvm.flags if f.band == "amber")
                text = "No issues identified." if not (nc_ or nw_) else f"{nc_} critical · {nw_} warning finding(s)."
            if text in note_seen:
                note_groups[note_seen[text]][1].append(sysvm.name)
            else:
                note_seen[text] = len(note_groups)
                note_groups.append((text, [sysvm.name]))

        # RHS-aligned, not the narrow header width (house rule: "the notes sections... even
        # the main notes section that consolidates all comments... must all be aligned to the
        # rhs edge of the report, regardless of whatever horizontal gap is created between the
        # note section and closest neighbour table" -- notes sections are explicitly NOT
        # tables for the "every gap must be equal" spacing rule; only their own right edge is
        # fixed, to the same NOTES_COL..NOTES_COL+NOTES_W-1 span the per-device Notes lane
        # uses, so every notes-shaped thing in this report shares one right edge). Matches
        # generate_report.py's own placement too: the admin's freeform remark sits ABOVE its
        # own Summary Notes table, same RHS columns as the table itself.
        notes_right = NOTES_COL + NOTES_W - 1
        nr = r   # Summary Notes' OWN cursor -- starts level with the dashboard, below
        if summary_comment:
            paint(nr, PAINT_LAST)
            ws.merge_cells(start_row=nr, start_column=NOTES_COL, end_row=nr, end_column=notes_right)
            sc = ws.cell(nr, NOTES_COL, summary_comment)
            sc.font = F(color=INK, size=9)
            sc.alignment = Alignment(wrap_text=True, vertical="top")
            nr += 1
        if note_groups:
            num_col = NOTES_COL
            dev_c1, dev_c2 = NOTES_COL + 1, NOTES_COL + 2
            cmt_c1, cmt_c2 = NOTES_COL + 3, notes_right
            paint(nr, PAINT_LAST)
            ws.merge_cells(start_row=nr, start_column=num_col, end_row=nr, end_column=notes_right)
            ws.cell(nr, num_col, "SUMMARY NOTES").font = F(bold=True, size=10, color=INK)
            for c in range(num_col, notes_right + 1):
                ws.cell(nr, c).fill = head
                ws.cell(nr, c).border = box
            nr += 1
            paint(nr, PAINT_LAST)
            hdr_cells = ((num_col, num_col, "#", "center"), (dev_c1, dev_c2, "Devices", "left"),
                        (cmt_c1, cmt_c2, "Comment", "left"))
            for c1, c2, label, al in hdr_cells:
                if c2 > c1:
                    ws.merge_cells(start_row=nr, start_column=c1, end_row=nr, end_column=c2)
                hc = ws.cell(nr, c1, label)
                hc.font = F(bold=True, size=9, color=SUB)
                hc.alignment = Alignment(horizontal=al)
                for c in range(c1, c2 + 1):
                    ws.cell(nr, c).fill = head
                    ws.cell(nr, c).border = box
            nr += 1
            for i, (text, names) in enumerate(note_groups):
                paint(nr, PAINT_LAST)
                ncell = ws.cell(nr, num_col, str(i + 1))
                ncell.font = F(size=10, color=INK)
                ncell.alignment = Alignment(horizontal="center")
                ws.merge_cells(start_row=nr, start_column=dev_c1, end_row=nr, end_column=dev_c2)
                dv = ws.cell(nr, dev_c1, ", ".join(names))
                dv.font = F(size=9, color=INK)
                dv.alignment = Alignment(wrap_text=True, vertical="top")
                ws.merge_cells(start_row=nr, start_column=cmt_c1, end_row=nr, end_column=cmt_c2)
                cv = ws.cell(nr, cmt_c1, text)
                cv.font = F(size=9, color=INK)
                cv.alignment = Alignment(wrap_text=True, vertical="top")
                for c in range(num_col, notes_right + 1):
                    ws.cell(nr, c).fill = card
                    ws.cell(nr, c).border = box
                nr += 1
            paint(nr, PAINT_LAST)
            nr += 1
        notes_col_bottom = nr

        tile_band(r, "AT A GLANCE  ·  inventory & readings", ov.get("glance", []))
        tile_band(r, "NEEDS IMMEDIATE ATTENTION", ov.get("immediate", []))
        tile_band(r, "NEEDS ATTENTION", ov.get("watch", []))

        # ---- named CRITICAL/WARNING banners (2026-09-22) -----------------------------------
        # Matches generate_report.py's own render_banner() -- a worded callout for findings
        # that need who/what, not just a count, grouped by the SAME flag key _device_flags()
        # already assigns (never a second, independently-computed judgement -- the tile bands
        # above, these banners, and each device's own Findings table below all read the exact
        # same flags list). Red-band flags become CRITICAL, amber-band become WARNING -- this
        # report's own existing two-tier vocabulary, not the systems report's 3-tier
        # imminent/critical/warning one (nothing here is scoped narrowly enough to need a
        # third level). Rendered most-affected first within each level.
        _BANNER_META = {
            "snmp_unscraped": ("NOT RESPONDING", "device(s) have never been scraped by Prometheus"),
            "snmp_down": ("NOT RESPONDING", "device(s) are not answering SNMP"),
            # links_failed/links_shut/links_down retired (2026-09-22): a port down for no known
            # reason is no longer flagged on its own -- see interface_down_regression below,
            # which flags the one shape of "down" this report DOES treat as a fault: a
            # regression from the baseline MonitoredInterface tracks (2026-09-23).
            "interface_down_regression": ("INTERFACES DOWN (WERE UP)",
                                          "device(s) have an interface that was previously up "
                                          "and is now down"),
            "counter_width": ("THROUGHPUT UNDER-REPORTED",
                              "device(s) are on 32-bit counters, which wrap and understate throughput"),
            "cpu_high": ("HIGH CPU", "device(s) are running hot on CPU"),
            "mem_high": ("HIGH MEMORY", "device(s) are running hot on memory"),
            "temp_high": ("HIGH TEMPERATURE", "device(s) are reporting elevated sensor temperatures"),
            "recent_reboot": ("RECENT REBOOT",
                              "device(s) restarted recently — likely explains other anomalies on it"),
            "psu_fan_failed": ("POWER / FAN FAILED",
                               "device(s) have a power or fan component not in a normal state"),
            "ospf_adjacency_lost": ("OSPF ADJACENCY LOST",
                                    "device(s) have an OSPF neighbour stuck below Full"),
            "links_saturated_critical": ("LINKS AT CAPACITY",
                                        "device(s) have a link at or above 95% of capacity"),
            "links_saturated": ("LINKS APPROACHING CAPACITY",
                                "device(s) have a link at or above 80% of capacity"),
            "iface_errors": ("INTERFACE ERRORS",
                             "device(s) are logging interface errors — almost always a physical fault"),
            "iface_discards_heavy": ("HEAVY INTERFACE DISCARDS",
                                     "device(s) are dropping significant traffic"),
            "iface_discards": ("INTERFACE DISCARDS",
                               "device(s) are dropping some traffic (often a QoS policy)"),
            "metrics_missing": ("METRICS NOT COLLECTED", "device(s) are missing some requested metrics"),
        }
        by_key: Dict[Tuple[str, str], list] = {}
        for sysvm in snapshot.systems:
            if sysvm.name not in target_by_name:
                continue
            for flag in sysvm.flags:
                by_key.setdefault((flag.key, flag.band), []).append((sysvm.name, flag.text))
        banner_specs = sorted(by_key.items(), key=lambda kv: (0 if kv[0][1] == "red" else 1, -len(kv[1])))

        def build_findings_detail_sheet(specs):
            """One consolidated sheet holding every banner's full per-device breakdown -- the
            detail that used to render inline in each main-sheet banner (2026-09-23, on
            request: "some banners are way too large... should just summarise finding,
            introduce a button or link on each banner that navigates to another sheet that has
            a breakdown of everything"). Built BEFORE the main sheet's own short banners below,
            so each one's link can jump straight to its own section here (the returned anchor
            row), not just the top of the sheet. Empty when `specs` is (every device clean) --
            still created, so a stale "Findings Detail" tab from a WORSE previous run's own
            xlsx is never confused with this one having nothing to report.
            """
            fd = wb.create_sheet("Findings Detail")
            fd.sheet_view.showGridLines = False
            fd.sheet_properties.tabColor = CYAN
            FD_LAST = 9
            for col, width in zip("ABCDEFGHI", (4, 26, 62, 4, 4, 4, 4, 4, 4)):
                fd.column_dimensions[col].width = width

            def fd_paint(row, last=FD_LAST):
                for c in range(1, last + 1):
                    fd.cell(row, c).fill = page

            fd_paint(1)
            fd.row_dimensions[1].height = 6
            fd_paint(2)
            fd.cell(2, 2, "FINDINGS DETAIL").font = F(bold=True, size=18, color=INK)
            fd_paint(3)
            back = fd.cell(3, 2, f"← Back to {ws.title}")
            back.font = F(bold=True, size=10, color=CYAN, underline="single")
            back.hyperlink = f"#'{ws.title}'!A1"
            fd_paint(4)
            fd.cell(4, 2, "Full per-device breakdown behind every CRITICAL/WARNING banner on "
                         "the main report — each banner there links straight to its own "
                         "section below.").font = F(color=SUB, size=9)
            fd.row_dimensions[4].height = 20
            fd_paint(5)
            fd.row_dimensions[5].height = 8

            anchors = {}
            rr = 6
            if not specs:
                fd_paint(rr)
                fd.cell(rr, 2, "No CRITICAL or WARNING findings this run.").font = F(
                    color=CHIP["green"][0], size=10)
                rr += 1
            for (key, band_), rows in specs:
                topic, cond = _BANNER_META.get(key, (key.replace("_", " ").upper(), "device(s) flagged"))
                level = "CRITICAL" if band_ == "red" else "WARNING"
                header = f"{level}  —  {topic}  —  {len(rows)} {cond}"
                anchors[(key, band_)] = rr
                accent, tint = CHIP["red" if band_ == "red" else "amber"]
                fill = PatternFill("solid", fgColor=tint)
                fd_paint(rr)
                fd.merge_cells(start_row=rr, start_column=2, end_row=rr, end_column=FD_LAST - 1)
                hcell = fd.cell(rr, 2, "  " + header)
                hcell.font = F(bold=True, size=11, color=accent)
                hcell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
                hcell.border = Border(left=Side(style="thick", color=accent))
                for c in range(2, FD_LAST):
                    fd.cell(rr, c).fill = fill
                rr += 1
                fd_paint(rr)
                for c, h in zip((2, 3), ("Device", "Detail")):
                    hc = fd.cell(rr, c, h)
                    hc.font = F(bold=True, size=9, color=SUB)
                    hc.fill = head
                    hc.border = box
                for c in range(4, FD_LAST):
                    fd.cell(rr, c).fill = head
                    fd.cell(rr, c).border = box
                rr += 1
                for device, detail in sorted(rows):
                    fd_paint(rr)
                    dc = fd.cell(rr, 2, device)
                    dc.font = F(bold=True, size=9, color=INK)
                    dc.border = box
                    dtc = fd.cell(rr, 3, detail)
                    dtc.font = F(size=9, color=INK)
                    dtc.alignment = Alignment(wrap_text=True, vertical="top")
                    dtc.border = box
                    for c in range(4, FD_LAST):
                        fd.cell(rr, c).fill = card
                        fd.cell(rr, c).border = box
                    fd.row_dimensions[rr].height = max(15, 14 * (1 + len(detail) // 90))
                    rr += 1
                fd_paint(rr)
                rr += 1   # gap between sections
            for _ in range(4):
                fd_paint(rr)
                rr += 1
            return anchors

        findings_anchor = build_findings_detail_sheet(banner_specs)
        if banner_specs:
            for (key, band_), rows in banner_specs:
                topic, cond = _BANNER_META.get(key, (key.replace("_", " ").upper(), "device(s) flagged"))
                level = "CRITICAL" if band_ == "red" else "WARNING"
                header = f"{level}  —  {topic}  —  {len(rows)} {cond}"
                anchor_row = findings_anchor[(key, band_)]
                r = render_banner_summary(r, header, band_, len(rows), anchor_row) + 1
            paint(r, PAINT_LAST)
            r += 1

        # Reconcile the two independent cursors -- the dashboard/banners' own `r` and Summary
        # Notes' own `nr`, run side by side since Summary Notes' top edge above (on request:
        # "topmost summary section top edge must align with top edge of dashboard section")
        # -- whichever ran taller governs where the per-device rows below start, the same
        # "take the max of both sides' own bottoms" pattern generate_report.py's own
        # content_bottom/notes_bottom use for the exact same left-tiles/right-notes shape.
        r = max(r, notes_col_bottom)

        for sysvm in snapshot.systems:
            nc = sum(1 for f in sysvm.flags if f.band == "red")
            nw = sum(1 for f in sysvm.flags if f.band == "amber")
            count_word = (f"{sysvm.hosts} host{'s' if sysvm.hosts != 1 else ''}" if sysvm.name in win_names
                         else f"{sysvm.hosts} interface{'s' if sysvm.hosts != 1 else ''}")
            segs = [f"{nc} critical", f"{nw} warning", count_word]
            red_c, amber_c, green_c = CHIP["red"][0], CHIP["amber"][0], CHIP["green"][0]
            summary_color = red_c if nc else (amber_c if nw else green_c)
            paint(r, PAINT_LAST)
            for c in range(FIRST, PAINT_LAST):
                ws.cell(r, c).fill = card
            ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=LAST - 1)
            ws.cell(r, FIRST, f"▌  {sysvm.name}").font = F(bold=True, size=13, color=CYAN)
            # Right edge is NOTES_COL+NOTES_W-1 -- Notes' OWN right edge, not PAINT_LAST-1 (2026-
            # 09-23 fix, on request: "the rhs edge of the section banner (switch name/title)
            # should align with the rhs edge of the notes section" -- PAINT_LAST-1 sits 3
            # columns past Notes' own content, inside the plain painted margin, so the badge
            # used to overrun where Notes itself actually ends.
            notes_right_edge = NOTES_COL + NOTES_W - 1
            ws.merge_cells(start_row=r, start_column=HW_COL, end_row=r, end_column=notes_right_edge)
            sm = ws.cell(r, HW_COL, "  ·  ".join(segs))
            sm.font = F(color=summary_color, size=10)
            sm.alignment = Alignment(horizontal="right")
            r += 1

            # HCI Cluster gets real tables here -- Nodes/Drives/Network/Cluster Resources --
            # the detail that used to render as banners on the web screen (see
            # _network_overview's docstring: that screen is tiles-only now, capturing admin
            # sign-off on flagged anomalies, not a second report). Sourced from the exact
            # snapshot the admin reviewed (snapshot._hci_nodes/_wc), not a fresh query, so
            # the xlsx can never disagree with what was on screen. Only rendered for the
            # device that actually has this data -- the switch's own card is untouched.
            hci_nodes = hci_nodes_by_key.get(cluster_key_by_name.get(sysvm.name), {})
            if sysvm.name in cluster_key_by_name and hci_nodes:
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
                # (resource -> group -> owner) the old banners used, now a table. Scoped to
                # THIS cluster's own target (2026-09-16, generalized) -- `wc` is keyed by
                # device target across every cluster device, so an unscoped `wc.values()` would
                # have shown the SAME combined data under every cluster's row once there was
                # more than one.
                this_wc = wc.get(cluster_target_by_name.get(sysvm.name))
                wc_here = {cluster_target_by_name[sysvm.name]: this_wc} if this_wc else {}
                cnodes = [n for w in wc_here.values() for n in w.get("nodes", [])]
                cres = {"online": 0, "offline": 0, "failed": 0, "other": 0}
                offline_pairs, failed_pairs, group_owner = [], [], {}
                for w in wc_here.values():
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

            elif sysvm.name in target_by_name:
                # Switch/router/WLC devices get real tables here too (2026-09-22, "redesign...
                # to look exactly in terms of formatting to the other reports... using tables"
                # -- HCI/DR/Bulawayo above already did; the switch estate's own card used to
                # fall straight through to the generic Finding/Band/Detail list below with no
                # tables of its own at all). Laid out SIDE BY SIDE in fixed column lanes (see
                # table_at's own comment) -- "multiple tables per device" means matching the
                # System Admin/Cluster Health/AD reports' own multi-table-per-card layout, not
                # just having more than one table. Sourced from snapshot._store -- the SAME
                # collect() output the admin's own screen and the Findings table below already
                # read, never a fresh query.
                target = target_by_name[sysvm.name]
                ifaces = [i for i in data.get("interfaces", []) if i["device"] == target]
                dev_ospf = [row for row in data.get("ospf_rows", [])
                           if row["labels"].get("instance") == target]
                dev_psu = [row for row in data.get("psu_rows", []) if row["labels"].get("instance") == target]
                dev_flash = sorted((p for p in data.get("flash_partitions", []) if p["device"] == target),
                                   key=lambda p: p["name"])
                # Important links (2026-09-29, on request: "add these particular interfaces
                # to the main report somehow its just 3 these ones are important") -- the
                # manually monitored interfaces for THIS device (see MANUAL_MONITORED_
                # INTERFACES/_manual_by_target above), each paired with its live interface
                # reading (None if this run never saw it at all, e.g. the device was
                # unreachable) so the lane can show a real status rather than just a name.
                dev_manual = [(if_name, cfg, next((i for i in ifaces if i["name"] == if_name), None))
                             for if_name, cfg in _manual_by_target.get(target, [])]

                # dev_kind computed here (not just below, where it also feeds wlc_ap_names)
                # so hw_rows can already gate on it -- see that row's own comment.
                dev_kind = dev_by_name.get(sysvm.name, {}).get("kind")
                cpu = data.get("cpu_by_device", {}).get(target)
                mem = data.get("mem_by_device", {}).get(target)
                temp = data.get("temp_by_device", {}).get(target)
                uptime = data.get("uptime_by_device", {}).get(target)
                # Always green/amber/red for a KNOWN reading, never left plain (see pct_band's
                # own comment) -- Temperature/Uptime are hand-rolled bands, not pct_band, so
                # they need the same "green when healthy, not just uncoloured" fix applied
                # here directly.
                temp_band = (None if temp is None else
                            "red" if temp >= 75 else "amber" if temp >= 60 else "green")
                uptime_band = (None if uptime is None else
                              "red" if uptime < 1 else "green")
                hw_rows = [
                    [("CPU", None), (f"{cpu:.0f}%" if cpu is not None else "—", pct_band(cpu))],
                    [("Memory", None), (f"{mem:.0f}%" if mem is not None else "—", pct_band(mem))],
                    [("Uptime", None), (f"{uptime:.1f} days" if uptime is not None else "—", uptime_band)],
                ]
                # Temperature dropped entirely for a WLC (2026-09-29, on request: "all access
                # controllers are virtual, no need to check somethings we were checking for in
                # actuall devices") -- not just left as a dash: a virtual C9800-CL has no
                # physical sensor to ever report one, so the row itself is omitted rather than
                # showing "—" for something that was never going to have a reading, the same
                # "genuinely doesn't apply, not just uncollected" distinction CATALOGUE's own
                # skip_for makes for this same metric a few hundred lines up.
                if dev_kind != "WLC":
                    hw_rows.insert(2, [("Temperature", None),
                                      (f"{temp:.0f}°C" if temp is not None else "—", temp_band)])

                # AP / Uplink port totals sourced from CDP neighbour discovery -- computed
                # here, ABOVE Interface Totals, since 2026-09-23 the two are the same scope
                # (see below). "switch" and "router" neighbour kinds both count as an uplink
                # (either is the direction traffic goes UP toward, or a lateral link to
                # another switch -- see _cdp_neighbor_kind's own comment).
                dev_is_access = is_access_switch(dev_by_name.get(sysvm.name, {}))
                dev_cdp = [n for n in data.get("cdp_neighbors", []) if n["instance"] == target]
                # Wireless access points (2026-09-29, on request: "Also include the Access
                # points") -- WLC-only, and mutually exclusive with the "AP / Uplink ports"
                # CDP lane above (that's access-switch-only, see is_access_switch's own
                # comment) -- both safely reuse CDP_COL below since a device is never both.
                wlc_ap_status = (ap_status_by_target.get(target, [])
                                if dev_kind == "WLC" else [])
                ap_n = sum(1 for n in dev_cdp if n["kind"] == "ap")
                uplink_n = sum(1 for n in dev_cdp if n["kind"] in ("switch", "router"))
                _monitored_if_indexes = {n["if_index"] for n in dev_cdp
                                        if n["kind"] in ("ap", "switch", "router")}

                # Scoped to MONITORED interfaces (2026-09-23, on request: "we only want to
                # monitor these interfaces not all of them... uplink, accesspoint, links going
                # to other switches (neighboar links)") -- up AND CDP-identified as one of
                # those three, not every up port (the 2026-09-22 "up-only" scope this started
                # as). The full port-by-port breakdown (Device | Port | Status | In | Out |
                # Errors | Discards, every interface regardless of monitored status) is still
                # on its own "Interface Detail" sheet, built once at the end of this function.
                ifaces_monitored = [i for i in ifaces
                                    if i["up"] and str(i["index"]) in _monitored_if_indexes]
                iface_err_n = sum(1 for i in ifaces_monitored
                                  if (i["errors"].get("in_err", 0) + i["errors"].get("out_err", 0)) > 0)
                iface_disc_n = sum(1 for i in ifaces_monitored
                                   if (i["errors"].get("in_disc", 0) + i["errors"].get("out_disc", 0)) > 0)
                # "Monitored"/"Total monitored" stay uncoloured -- estate counts, not a
                # judgement (see this report's own "estate vs variable metric" distinction).
                # "With errors"/"With discards" ARE variable/threshold metrics, so -- same fix
                # as pct_band's own comment -- they're green, not plain, when genuinely 0.
                iface_totals_rows = [
                    [("Monitored", None), (str(len(ifaces_monitored)), None)],
                    [("With errors", None), (str(iface_err_n), "red" if iface_err_n else "green")],
                    [("With discards", None), (str(iface_disc_n), "amber" if iface_disc_n else "green")],
                    [("Total monitored", None), (str(len(ifaces_monitored)), None)],
                ]

                ospf_rows_t = [[
                    (row["labels"].get("ospfNbrIpAddr", "—"), None),
                    ({4: "2-Way", 8: "Full"}.get(int(row["value"]), f"state {int(row['value'])}"),
                     "green" if int(row["value"]) in (4, 8) else "red"),
                ] for row in sorted(dev_ospf, key=lambda row: row["labels"].get("ospfNbrIpAddr", ""))]

                psu_rows_t = [[
                    (row["labels"].get("entPhysicalName", "—"), None),
                    (row["labels"].get("cefcFRUPowerOperStatus", "—"),
                     "green" if row["labels"].get("cefcFRUPowerOperStatus") == "on" else "red"),
                ] for row in sorted(dev_psu, key=lambda row: row["labels"].get("entPhysicalName", ""))]
                # Used % is a VARIABLE metric (this report's own "estate vs variable metric"
                # distinction) -- always green/amber/red via pct_band, same as CPU/Memory
                # above, never left plain just because a partition happens to be healthy.
                storage_rows_t = [[
                    (p["name"], None),
                    (f"{p['size_gb']:.1f}" if p["size_gb"] is not None else "—", None),
                    (f"{p['free_gb']:.1f}" if p["free_gb"] is not None else "—", None),
                    (f"{p['used_pct']:.0f}%" if p["used_pct"] is not None else "—",
                     pct_band(p["used_pct"])),
                ] for p in dev_flash]
                cdp_totals_rows = [
                    [("AP ports", None), (str(ap_n), None)],
                    [("Uplink ports", None), (str(uplink_n), None)],
                    [("Other neighbours", None),
                     (str(sum(1 for n in dev_cdp if n["kind"] == "other")), None)],
                    [("Total CDP neighbours", None), (str(len(dev_cdp)), None)],
                ]

                # Notes' own row count, computed up front (2026-09-23, on request: "move notes
                # section to be the last section on the rhs") so it counts toward row_max like
                # every other lane -- render_notes_lane() below produces EXACTLY this many
                # rows, always (flagged-metric header + N flag rows, or one "no findings" row;
                # then Comment title; then the comment text; then the By line).
                notes_flagged_rows = (1 + len(sysvm.flags)) if sysvm.flags else 1
                notes_h = notes_flagged_rows + 3   # + Comment title + comment text + By line

                # Important links (Link, Interface, Status) -- 2026-09-29, see dev_manual's
                # own comment above. Shows the LABEL first (e.g. "Link to Stellar Cyber
                # Sensor") -- a reader skimming the main sheet cares what it's FOR before its
                # raw SNMP name -- but the raw interface string is now its OWN column too
                # ("we dont know which interfaces these are should we mabe add another
                # column to this table") rather than making the reader click through to
                # 'Interface Detail' just to see which physical port a label refers to,
                # especially now that HQ alone has two. "down — expected" (neutral, not red)
                # for an exempt port reading down by design (see MANUAL_MONITORED_INTERFACES'
                # own down_is_fault) -- a real fault still shows red like anything else.
                manual_rows_t = []
                for if_name, manual_cfg, iface in dev_manual:
                    # NOT `cfg` -- this whole function already has an OUTER `cfg` (the real
                    # gr.load_config() result pct_band()'s own closure reads for chip_red/
                    # chip_amber); reusing that name here silently shadowed it for the rest
                    # of this device's own iteration and crashed pct_band() on the very next
                    # CPU/Memory tile (confirmed live, 2026-09-29 -- AttributeError: 'dict'
                    # object has no attribute 'chip_red').
                    label = manual_cfg.get("label", if_name)
                    if iface is None:
                        status_text, status_band = "not observed", None
                    elif iface["up"]:
                        status_text, status_band = "up", "green"
                    elif not manual_cfg.get("down_is_fault", True):
                        status_text, status_band = "down — expected", None
                    else:
                        status_text, status_band = "down", "red"
                    manual_rows_t.append([(label, None), (if_name, None), (status_text, status_band)])

                # Every lane starts at the SAME row; each ends wherever its own row count
                # takes it (2 title/header rows + its data rows). Paint the full wide span
                # first, for every row any lane will occupy, so the gap columns between lanes
                # -- and any lane shorter than its tallest neighbour -- read as the same dark
                # canvas rather than raw white past where that lane's own table_at() call ends.
                # +1 on the interface lane for its own pointer line below its table.
                lane_heights = [2 + len(hw_rows), notes_h]
                if ospf_rows_t: lane_heights.append(2 + len(ospf_rows_t))
                if dev_psu:      lane_heights.append(2 + len(psu_rows_t))
                if ifaces:       lane_heights.append(2 + len(iface_totals_rows) + 1)
                if dev_flash:    lane_heights.append(2 + len(storage_rows_t))
                if dev_manual:   lane_heights.append(2 + len(manual_rows_t))
                if dev_is_access and dev_cdp:
                    lane_heights.append(2 + len(cdp_totals_rows) + 1)
                elif dev_kind == "WLC" and wlc_ap_status:
                    lane_heights.append(2 + 1 + 1)   # Access points row + pointer line
                row0 = r
                row_max = row0 + max(lane_heights)
                for wide_row in range(row0, row_max):
                    paint(wide_row, PAINT_LAST)

                table_at(row0, HW_COL, HW_W, "Hardware health", ("Metric", "Value"), hw_rows)
                if ospf_rows_t:
                    table_at(row0, OSPF_COL, OSPF_W, "OSPF neighbours", ("Neighbour", "State"), ospf_rows_t)
                if dev_psu:
                    table_at(row0, PSU_COL, PSU_W, "Power / fan", ("Component", "Status"), psu_rows_t)
                if ifaces:
                    end = table_at(row0, IFACE_COL, IFACE_W, "Interface totals",
                                   ("Metric", "Value"), iface_totals_rows)
                    ws.merge_cells(start_row=end, start_column=IFACE_COL, end_row=end,
                                  end_column=IFACE_COL + IFACE_W - 1)
                    # Real hyperlink (2026-09-23, was plain text), jumping straight to THIS
                    # device's own first row in Interface Detail, not just the top of the
                    # sheet -- det_first_row_by_device is computed early, before this loop,
                    # from the exact same sort the sheet itself is built with below. Falls
                    # back to the HEADER row (5, not row 6) when this device has no scoped
                    # interfaces at all (2026-09-24) -- landing on the column headers rather
                    # than silently on whichever OTHER device's data happens to occupy row 6.
                    ptr_row = det_first_row_by_device.get(sysvm.name, 5)
                    ptr_label = ("↳ full breakdown: 'Interface Detail' tab" if sysvm.name in det_first_row_by_device
                                else "↳ 'Interface Detail' tab (no monitored interfaces here)")
                    ptr = ws.cell(end, IFACE_COL, ptr_label)
                    ptr.font = F(size=8, color=CYAN, italic=True, underline="single")
                    ptr.hyperlink = f"#'Interface Detail'!A{ptr_row}"
                    for c in range(IFACE_COL, IFACE_COL + IFACE_W):
                        ws.cell(end, c).fill = card
                if dev_flash:
                    table_at(row0, STORAGE_COL, STORAGE_W, "Storage",
                            ("Partition", "Size GB", "Free GB", "Used %"), storage_rows_t)
                if dev_manual:
                    table_at(row0, MANUAL_COL, MANUAL_W, "Important links",
                            ("Link", "Interface", "Status"), manual_rows_t)
                if dev_is_access and dev_cdp:
                    cend = table_at(row0, CDP_COL, CDP_W, "AP / Uplink ports",
                                    ("Metric", "Value"), cdp_totals_rows)
                    ws.merge_cells(start_row=cend, start_column=CDP_COL, end_row=cend,
                                  end_column=CDP_COL + CDP_W - 1)
                    cptr_row = cdp_first_row_by_device.get(sysvm.name, 6)
                    cptr = ws.cell(cend, CDP_COL, "↳ full breakdown: 'CDP Neighbors' tab")
                    cptr.font = F(size=8, color=CYAN, italic=True, underline="single")
                    cptr.hyperlink = f"#'CDP Neighbors'!A{cptr_row}"
                    for c in range(CDP_COL, CDP_COL + CDP_W):
                        ws.cell(cend, c).fill = card
                elif dev_kind == "WLC" and wlc_ap_status:
                    _ap_online = sum(1 for _, up in wlc_ap_status if up)
                    _ap_total = len(wlc_ap_status)
                    aend = table_at(row0, CDP_COL, CDP_W, "Access points",
                                    ("Metric", "Value"),
                                    [[("Access points", None),
                                      (f"{_ap_online} | {_ap_total}",
                                       "red" if _ap_online < _ap_total else "green")]])
                    ws.merge_cells(start_row=aend, start_column=CDP_COL, end_row=aend,
                                  end_column=CDP_COL + CDP_W - 1)
                    aptr_row = ap_first_row_by_device.get(sysvm.name, 6)
                    aptr = ws.cell(aend, CDP_COL, "↳ full breakdown: 'Access Points' tab")
                    aptr.font = F(size=8, color=CYAN, italic=True, underline="single")
                    aptr.hyperlink = f"#'Access Points'!A{aptr_row}"
                    for c in range(CDP_COL, CDP_COL + CDP_W):
                        ws.cell(aend, c).fill = card
                render_notes_lane(row0, sysvm)
                # row_max itself is the one blank gap row after every lane, Notes included --
                # paint it explicitly rather than just skipping past it, or it reads as raw
                # white Excel before the next device's own row starts.
                paint(row_max, PAINT_LAST)
                r = row_max + 1
                continue

            # ---- Notes (fallback, narrow, stacked below): every switch/router/WLC device hit
            # `continue` above and never reaches this -- see render_notes_lane() instead, which
            # renders Notes as the outermost LANE on the same row (2026-09-23, on request:
            # "move notes section to be the last section on the rhs"). This narrow version
            # only still runs for a device that fell through the HCI/switch branches above
            # without matching either (not reachable via switches_routers_generate's own
            # capture_snapshot(mode="switches_routers"), which only ever selects switch/
            # router/WLC devices -- kept as a safety net, not dead code removed outright, in
            # case build_report() is ever called against a differently-scoped snapshot). Same
            # Flagged metric / Fix needed? / Resolved table, THEN a Comment box, THEN a
            # "By {author}" line -- matching generate_report.py's own _system_card() Notes
            # panel structure. `Resolved` is formula-derived from `Fix needed?`: no fix needed
            # -> resolved; fix needed -> still open; blank until the admin picks.
            mcol = FIRST + 2
            fix_col, res_col = FIRST + 3, FIRST + 4
            ann = annotations.get(sysvm.name, {})
            ann_flags = ann.get("flags", {})
            paint(r, PAINT_LAST)
            if sysvm.flags:
                ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=mcol)
                h = ws.cell(r, FIRST, "  Flagged metric")
                h.font = F(bold=True, size=8, color=SUB)
                for col, label in ((fix_col, "Fix needed?"), (res_col, "Resolved")):
                    hc = ws.cell(r, col, label)
                    hc.font = F(bold=True, size=8, color=SUB)
                    hc.alignment = Alignment(horizontal="center", wrap_text=True)
                for col in range(FIRST, res_col + 1):
                    ws.cell(r, col).fill = head
                    ws.cell(r, col).border = box
                r += 1
                dv = DataValidation(type="list", formula1='"Yes,No"', allow_blank=True)
                ws.add_data_validation(dv)
                fix_letter = get_column_letter(fix_col)
                for flag in sysvm.flags:
                    paint(r, PAINT_LAST)
                    fg = CHIP["red" if flag.band == "red" else "amber"][0]
                    ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=mcol)
                    d = ws.cell(r, FIRST, "  " + flag.text)
                    d.font = F(color=fg, size=9)
                    d.alignment = Alignment(wrap_text=True, vertical="top")
                    for col in range(FIRST, mcol + 1):
                        ws.cell(r, col).fill = card
                        ws.cell(r, col).border = box
                    answer = ann_flags.get(flag.key)
                    fix = ws.cell(r, fix_col, answer if answer in ("Yes", "No") else "")
                    fix.font = F(size=9, color=INK)
                    fix.fill = card
                    fix.border = box
                    fix.alignment = Alignment(horizontal="center")
                    dv.add(fix)
                    res = ws.cell(r, res_col,
                                 f'=IF({fix_letter}{r}="No","Yes",IF({fix_letter}{r}="Yes","No",""))')
                    res.font = F(size=9, color=INK)
                    res.fill = card
                    res.border = box
                    res.alignment = Alignment(horizontal="center")
                    r += 1
            else:
                ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=res_col)
                ws.cell(r, FIRST, "  No critical or warning metrics this run.").font = F(
                    color=SUB, size=9)
                for col in range(FIRST, res_col + 1):
                    ws.cell(r, col).fill = card
                    ws.cell(r, col).border = box
                r += 1

            paint(r, PAINT_LAST)
            ws.cell(r, FIRST, "  Comment").font = F(bold=True, size=8, color=SUB)
            for col in range(FIRST, res_col + 1):
                ws.cell(r, col).fill = card
            r += 1
            comment_text = (ann.get("comment") or "").strip()
            if not comment_text and not sysvm.flags:
                comment_text = "No issues identified."
            paint(r, PAINT_LAST)
            ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=res_col)
            cm = ws.cell(r, FIRST, comment_text)
            cm.font = F(color=INK, size=9)
            cm.alignment = Alignment(wrap_text=True, vertical="top")
            for col in range(FIRST, res_col + 1):
                ws.cell(r, col).fill = card
                ws.cell(r, col).border = box
            r += 1

            paint(r, PAINT_LAST)
            by = ws.cell(r, FIRST, f"By  {author}")
            by.font = F(color=SUB, size=8)
            by.alignment = Alignment(horizontal="right")
            for col in range(FIRST, res_col + 1):
                ws.cell(r, col).fill = card
            r += 1

            paint(r, PAINT_LAST)
            r += 1

        # ---- footer: 3-line chip-key / legend / cross-reference note (2026-09-22) -----------
        # Matches infrastructure_report.py's own FOOTER_LINES pattern exactly -- plain text
        # lines, no table -- with a reciprocal cross-reference note (that module's own footer
        # already points here; this points back). The switches/routers-specific SNMP caveats
        # below ("HOW TO READ THESE NUMBERS") are KEPT as an additional block, not replaced --
        # they document a real measurement limitation this report has and the reference
        # reports don't, so folding them into this 3-line legend would either bury them or
        # bloat every other report's footer with a caveat that doesn't apply to it.
        for line in (
            "chip key:  green under 80%   ·   amber 80-89%   ·   red 90% and over "
            "(temperature: amber 60-74°C, red 75°C and over)      |      device status "
            "UP / DOWN      |      live from SNMP",
            "▌ badge:  N critical = red-band findings requiring action now   ·   "
            "N warning = amber-band findings worth watching   ·   interfaces = ports "
            "collected on that device",
            "Servers, HCI/DR clusters and Active Directory hosts are tracked in the "
            "separate Infrastructure Report and Active Directory Report, not here.",
        ):
            paint(r)
            fc = ws.cell(r, FIRST, line)
            fc.font = F(color=SUB, size=8)
            fc.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=PAINT_LAST - 1)
            ws.row_dimensions[r].height = 20
            r += 1
        paint(r, PAINT_LAST)
        r += 1

        # The caveats belong IN the artifact. A spreadsheet outlives the screen it was made on,
        # and these numbers are wrong in a specific, knowable way its reader has to be told.
        paint(r, PAINT_LAST)
        ws.cell(r, FIRST, "HOW TO READ THESE NUMBERS").font = F(bold=True, size=10, color=INK)
        r += 1
        for line in (
            "Throughput is a FLOOR, not a measurement: only 32-bit octet counters are polled "
            "and every counter wrap loses traffic.",
            "No percentage utilisation appears anywhere - port speed (ifHighSpeed) is not "
            "collected, so there is no capacity to compare against.",
            "Interfaces are identified by index because ifDescr is not collected.",
            "This report's totals, banners and findings — and the 'Interface Detail' tab — "
            "are scoped to MONITORED interfaces only: an access point, an uplink, or a "
            "neighbour link (CDP-identified), whether currently up or down. A port never "
            "chosen this way is excluded everywhere, not just hidden — see 'Interface "
            "Detail's own 'Not monitored' count at the end of that tab for what's excluded, "
            "per device.",
        ):
            paint(r)
            cell = ws.cell(r, FIRST, "• " + line)
            cell.font = F(color=SUB, size=9)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            ws.merge_cells(start_row=r, start_column=FIRST, end_row=r, end_column=PAINT_LAST - 1)
            ws.row_dimensions[r].height = 26
            r += 1

        # a painted margin below the content, so the themed canvas does not stop mid-page
        for _ in range(8):
            paint(r, PAINT_LAST)
            r += 1

        # ---- Interface Detail: breakdown of every SCOPED interface (2026-09-22, revised
        # 2026-09-23, narrowed 2026-09-24) --------------------------------------------------
        # The main sheet's own per-device "Interface totals" lane is a summary, scoped to
        # MONITORED interfaces; this sheet used to list EVERY interface, up or down, monitored
        # or not -- reverted (2026-09-24, on request: "the interface breakdown still shows
        # interfaces not monitored kindly remove these... the admins are adament they dont
        # want to see these interfaces save for the few they specifically chose") to list only
        # SCOPED ones (MonitoredInterface.is_scoped -- see _interface_scoped_keys' own comment
        # above, computed early). A down port still gets a real Status here: "down —
        # regression" (red) when it is scoped but currently down -- the SAME fact that already
        # earned it a red finding on the main sheet. A port never chosen is excluded outright,
        # not shown as "not monitored" any more -- its EXISTENCE is still on record, as a
        # per-device count in the "Not monitored" block at the end of this sheet, so the
        # exclusion itself is never silently forgotten even though the port rows are gone. ONE
        # shared sheet with a Device column, not one tab per device -- 39 devices would mean 39
        # tabs, worse to scan and worse tooling fit than one sortable table here.
        name_by_target = {t: n for n, t in target_by_name.items()}
        det = wb.create_sheet("Interface Detail")
        det.sheet_view.showGridLines = False
        det.sheet_properties.tabColor = CYAN
        DET_LAST = 9   # A margin, B..H content (Device..Discards), I margin
        for col, width in zip("ABCDEFGHI", (4, 26, 20, 20, 16, 16, 10, 10, 4)):
            det.column_dimensions[col].width = width

        def det_paint(row, last=DET_LAST):
            for c in range(1, last + 1):
                det.cell(row, c).fill = page

        det_paint(1)
        det.row_dimensions[1].height = 6
        det_paint(2)
        det.cell(2, 2, "INTERFACE DETAIL").font = F(bold=True, size=18, color=INK)
        back = det.cell(2, 5, f"← Back to {ws.title}")
        back.font = F(bold=True, size=10, color=CYAN, underline="single")
        back.hyperlink = f"#'{ws.title}'!A1"
        det_paint(3)
        det.cell(3, 2, "Every MONITORED interface across the full estate — an access point, "
                      "an uplink, or a neighbour link, the same scope the main report's own "
                      "findings use — up or down (a scoped port that has gone down still "
                      "appears here as a regression). Ports never chosen as monitored are not "
                      "listed; see the 'Not monitored' count at the end of this sheet for "
                      "what's excluded per device.").font = F(color=SUB, size=9)
        det.row_dimensions[3].height = 26
        det_paint(4)
        det.row_dimensions[4].height = 8

        # Directional accents (2026-09-22, on request: "give inbound and outbound their own
        # distinct visual treatment... so the two aren't just two plain adjacent numbers") --
        # green for inbound, cyan for outbound: two hues this theme already carries that
        # neither collide with the red/amber "problem" vocabulary used for Errors/Discards in
        # the SAME rows, nor with each other. Arrow glyphs in the header text reinforce it for
        # anyone reading in black-and-white.
        in_accent, in_tint = CHIP["green"]
        out_accent = CYAN
        hdr_row = 5
        headers = ("Device", "Port", "Status", "↓ In", "↑ Out", "Errors", "Discards")
        det_paint(hdr_row)
        for c, h in zip(range(2, 2 + len(headers)), headers):
            cell = det.cell(hdr_row, c, h)
            cell.fill = head
            cell.border = box
            if h == "↓ In":
                cell.font = F(bold=True, size=9, color=in_accent)
            elif h == "↑ Out":
                cell.font = F(bold=True, size=9, color=out_accent)
            else:
                cell.font = F(bold=True, size=9, color=SUB)
        for c in range(2 + len(headers), DET_LAST + 1):
            det.cell(hdr_row, c).fill = head
            det.cell(hdr_row, c).border = box
        det.freeze_panes = det.cell(hdr_row + 1, 2).coordinate

        rows_out = []
        not_monitored_by_device: Dict[str, int] = {}
        for i in data.get("interfaces", []):
            dname = name_by_target.get(i["device"])
            if dname is None:
                continue
            if (i["device"], str(i["index"])) in _interface_scoped_keys:
                rows_out.append((dname, i))
            else:
                not_monitored_by_device[dname] = not_monitored_by_device.get(dname, 0) + 1
        rows_out.sort(key=lambda pair: (pair[0], int(pair[1]["index"] or 0)))

        _manual_exempt_keys = data.get("manual_exempt_keys", set())
        rr = hdr_row + 1
        for dname, i in rows_out:
            det_paint(rr)
            in_err = i["errors"].get("in_err", 0) + i["errors"].get("out_err", 0)
            disc = i["errors"].get("in_disc", 0) + i["errors"].get("out_disc", 0)
            # Every row here is scoped by construction (see the rows_out filter above), so a
            # down one is normally a genuine regression -- EXCEPT a manually monitored port
            # whose down_is_fault is False (2026-09-24, the SPAN/mirror destination case --
            # see MANUAL_MONITORED_INTERFACES' own comment): its "down" reading is expected
            # by design, not a fault, so it gets its own honest label instead of a red alarm.
            if i["up"]:
                status_text, status_band = "up", "green"
            elif (i["device"], str(i["index"])) in _manual_exempt_keys:
                status_text, status_band = "down — expected (SPAN destination)", None
            else:
                status_text, status_band = "down — regression", "red"
            cells = [
                (2, dname, None, INK), (3, i["name"], None, INK), (4, status_text, status_band, SUB),
                (5, i["in_text"], None, in_accent), (6, i["out_text"], None, out_accent),
                (7, f"{in_err:.0f}", "red" if in_err >= _NODE_ERR_RED else "green", INK),
                (8, f"{disc:.0f}", "amber" if disc >= _NODE_DISC_RED else "green", INK),
            ]
            for c, text, chip_band, plain_color in cells:
                cell = det.cell(rr, c, text)
                cell.border = box
                if chip_band:
                    fg, bgc = CHIP[chip_band]
                    cell.font = F(bold=True, size=9, color=fg)
                    cell.fill = PatternFill("solid", fgColor=bgc)
                else:
                    cell.font = F(size=9, color=plain_color or INK)
                    cell.fill = card
            det.cell(rr, DET_LAST).fill = card
            rr += 1

        if not rows_out:
            det_paint(rr)
            det.cell(rr, 2, "No interfaces reported across this estate.").font = F(
                color=SUB, size=9)
            rr += 1

        for _ in range(3):
            det_paint(rr)
            rr += 1

        # ---- Not monitored: what got excluded above, by count only -- never full port rows
        # (2026-09-24, on request: "just ad a note to lett us what isnt being monitores so we
        # wont forget but the admins are adament they dont want to see these interfaces"). A
        # port here was simply never CDP-identified as an access point, uplink, or neighbour
        # link -- the administratively-normal case (an unused wall jack, a downstream host
        # port), not a fault, so it earns a count, not a row of its own.
        det_paint(rr)
        det.cell(rr, 2, "NOT MONITORED").font = F(bold=True, size=10, color=INK)
        rr += 1
        total_not_monitored = sum(not_monitored_by_device.values())
        det_paint(rr)
        note = (f"{total_not_monitored} interface(s) across "
                f"{len(not_monitored_by_device)} device(s) are not monitored -- never "
                f"CDP-identified as an access point, uplink, or neighbour link -- and are "
                f"excluded from the list above." if total_not_monitored else
                "Every interface this estate reported is monitored -- nothing is excluded.")
        cell = det.cell(rr, 2, note)
        cell.font = F(color=SUB, size=9)
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        det.merge_cells(start_row=rr, start_column=2, end_row=rr, end_column=DET_LAST - 1)
        det.row_dimensions[rr].height = 26
        rr += 1
        if not_monitored_by_device:
            rr += 1
            det_paint(rr)
            for c, h in ((2, "Device"), (3, "Not monitored")):
                cell = det.cell(rr, c, h)
                cell.font = F(bold=True, size=9, color=SUB)
                cell.fill = head
                cell.border = box
            for c in range(4, DET_LAST + 1):
                det.cell(rr, c).fill = head
                det.cell(rr, c).border = box
            rr += 1
            for dname in sorted(not_monitored_by_device):
                det_paint(rr)
                nm_cell = det.cell(rr, 2, dname)
                nm_cell.font = F(size=9, color=INK)
                nm_cell.border = box
                cnt_cell = det.cell(rr, 3, not_monitored_by_device[dname])
                cnt_cell.font = F(size=9, color=INK)
                cnt_cell.border = box
                det.cell(rr, 2).fill = card
                det.cell(rr, 3).fill = card
                rr += 1

        for _ in range(6):
            det_paint(rr)
            rr += 1

        # ---- CDP Neighbors: full breakdown of everything CDP found plugged into this estate
        # (2026-09-23) -- same treatment as Interface Detail: the per-device "AP /
        # Uplink ports" lane above (access switches only) is a summary; this is the complete
        # list its own pointer link sends the reader to, covering EVERY device with CDP data
        # (not just access switches -- informative for the core switch and routers too, even
        # though they don't get their own summary lane). "Type" is derived from the
        # neighbour's own reported platform string (see _cdp_neighbor_kind's own comment) --
        # AP and Uplink are colour-flagged since those are what this report actually monitors
        # for; Phone/Other are informational only, never a finding.
        cdpsheet = wb.create_sheet("CDP Neighbors")
        cdpsheet.sheet_view.showGridLines = False
        cdpsheet.sheet_properties.tabColor = CYAN
        CDPS_LAST = 9
        for col, width in zip("ABCDEFGHI", (4, 26, 20, 26, 20, 26, 12, 4, 4)):
            cdpsheet.column_dimensions[col].width = width

        def cdps_paint(row, last=CDPS_LAST):
            for c in range(1, last + 1):
                cdpsheet.cell(row, c).fill = page

        cdps_paint(1)
        cdpsheet.row_dimensions[1].height = 6
        cdps_paint(2)
        cdpsheet.cell(2, 2, "CDP NEIGHBORS").font = F(bold=True, size=18, color=INK)
        cdpback = cdpsheet.cell(2, 5, f"← Back to {ws.title}")
        cdpback.font = F(bold=True, size=10, color=CYAN, underline="single")
        cdpback.hyperlink = f"#'{ws.title}'!A1"
        cdps_paint(3)
        cdpsheet.cell(3, 2, "Everything CDP discovered plugged into the Switches & Routers "
                            "estate. Type is read from the neighbour's OWN reported platform "
                            "string (an access point, another switch or router -- an uplink "
                            "-- or an unrecognised device such as a phone), never guessed from "
                            "a fixed port number. A device with nothing here either has no "
                            "CDP-speaking neighbour on any port, or CDP itself is off on it.").font = F(
            color=SUB, size=9)
        cdpsheet.row_dimensions[3].height = 30
        cdps_paint(4)
        cdpsheet.row_dimensions[4].height = 8

        cdps_headers = ("Device", "Local Port", "Neighbor", "Neighbor Port", "Platform", "Type")
        cdps_hdr_row = 5
        cdps_paint(cdps_hdr_row)
        for c, h in zip(range(2, 2 + len(cdps_headers)), cdps_headers):
            cell = cdpsheet.cell(cdps_hdr_row, c, h)
            cell.font = F(bold=True, size=9, color=SUB)
            cell.fill = head
            cell.border = box
        for c in range(2 + len(cdps_headers), CDPS_LAST + 1):
            cdpsheet.cell(cdps_hdr_row, c).fill = head
            cdpsheet.cell(cdps_hdr_row, c).border = box
        cdpsheet.freeze_panes = cdpsheet.cell(cdps_hdr_row + 1, 2).coordinate

        _CDPS_TYPE_LABEL = {"ap": "Access point", "switch": "Uplink (switch)",
                            "router": "Uplink (router)", "other": "Other"}
        _CDPS_TYPE_BAND = {"ap": "green", "switch": "amber", "router": "amber", "other": None}

        cdps_rows_out = []
        for n in data.get("cdp_neighbors", []):
            dname = name_by_target.get(n["instance"])
            if dname is None:
                continue
            cdps_rows_out.append((dname, n))
        cdps_rows_out.sort(key=lambda pair: (pair[0], pair[1]["local_port"]))

        crr = cdps_hdr_row + 1
        for dname, n in cdps_rows_out:
            cdps_paint(crr)
            type_text = _CDPS_TYPE_LABEL.get(n["kind"], "Other")
            type_band = _CDPS_TYPE_BAND.get(n["kind"])
            cells = [
                (2, dname, None), (3, n["local_port"], None), (4, n["device_id"] or "—", None),
                (5, n["device_port"] or "—", None), (6, n["platform"] or "—", None),
                (7, type_text, type_band),
            ]
            for c, text, chip_band in cells:
                cell = cdpsheet.cell(crr, c, text)
                cell.border = box
                if chip_band:
                    fg, bgc = CHIP[chip_band]
                    cell.font = F(bold=True, size=9, color=fg)
                    cell.fill = PatternFill("solid", fgColor=bgc)
                else:
                    cell.font = F(size=9, color=INK)
                    cell.fill = card
            for c in range(8, CDPS_LAST + 1):
                cdpsheet.cell(crr, c).fill = card
            crr += 1

        if not cdps_rows_out:
            cdps_paint(crr)
            cdpsheet.cell(crr, 2, "No CDP neighbours reported across this estate.").font = F(
                color=SUB, size=9)
            crr += 1

        for _ in range(6):
            cdps_paint(crr)
            crr += 1

        # ---- Access Points: full name list for every WLC (2026-09-29, on request: "Also
        # include the Access points") -- same treatment as Interface Detail/CDP Neighbors:
        # the per-WLC "Access points" lane above is a count only, this is the complete list
        # its own pointer link sends the reader to. One shared sheet across every WLC, not
        # one tab each -- same "worse to scan, worse tooling fit" reasoning Interface Detail's
        # own comment gives for not splitting per device.
        apsheet = wb.create_sheet("Access Points")
        apsheet.sheet_view.showGridLines = False
        apsheet.sheet_properties.tabColor = CYAN
        APS_LAST = 6
        for col, width in zip("ABCDEF", (4, 26, 34, 14, 4, 4)):
            apsheet.column_dimensions[col].width = width

        def aps_paint(row, last=APS_LAST):
            for c in range(1, last + 1):
                apsheet.cell(row, c).fill = page

        aps_paint(1)
        apsheet.row_dimensions[1].height = 6
        aps_paint(2)
        apsheet.cell(2, 2, "ACCESS POINTS").font = F(bold=True, size=18, color=INK)
        apback = apsheet.cell(2, 5, f"← Back to {ws.title}")
        apback.font = F(bold=True, size=10, color=CYAN, underline="single")
        apback.hyperlink = f"#'{ws.title}'!A1"
        aps_paint(3)
        apsheet.cell(3, 2, "Every access point ever seen joined to a wireless LAN controller "
                          "in this estate (CISCO-LWAPP-AP-MIB), by its own reported name. "
                          "Status is read from a sticky baseline, the same idea Interface "
                          "Detail's own Status column uses for switch ports: an AP that WAS "
                          "joined and has since dropped off the controller shows Down here, "
                          "not silently disappeared. A device with nothing here is not a "
                          "WLC, or has never had an AP join it.").font = F(color=SUB, size=9)
        apsheet.row_dimensions[3].height = 38
        aps_paint(4)
        apsheet.row_dimensions[4].height = 8

        aps_headers = ("Device", "Access point", "Status")
        aps_hdr_row = 5
        aps_paint(aps_hdr_row)
        for c, h in zip(range(2, 2 + len(aps_headers)), aps_headers):
            cell = apsheet.cell(aps_hdr_row, c, h)
            cell.font = F(bold=True, size=9, color=SUB)
            cell.fill = head
            cell.border = box
        for c in range(2 + len(aps_headers), APS_LAST + 1):
            apsheet.cell(aps_hdr_row, c).fill = head
            apsheet.cell(aps_hdr_row, c).border = box
        apsheet.freeze_panes = apsheet.cell(aps_hdr_row + 1, 2).coordinate

        aps_rows_out = []
        for _t, _statuses in ap_status_by_target.items():
            dname = name_by_target.get(_t)
            if dname is None:
                continue
            for _name, _up in _statuses:
                aps_rows_out.append((dname, _name, _up))
        aps_rows_out.sort(key=lambda row: (row[0], row[1]))

        arr = aps_hdr_row + 1
        for dname, apname, is_up in aps_rows_out:
            aps_paint(arr)
            status_text, status_band = ("up", "green") if is_up else ("down", "red")
            for c, text, chip_band in ((2, dname, None), (3, apname, None),
                                       (4, status_text, status_band)):
                cell = apsheet.cell(arr, c, text)
                cell.border = box
                if chip_band:
                    fg, bgc = CHIP[chip_band]
                    cell.font = F(bold=True, size=9, color=fg)
                    cell.fill = PatternFill("solid", fgColor=bgc)
                else:
                    cell.font = F(size=9, color=INK)
                    cell.fill = card
            for c in range(5, APS_LAST + 1):
                apsheet.cell(arr, c).fill = card
            arr += 1

        if not aps_rows_out:
            aps_paint(arr)
            apsheet.cell(arr, 2, "No access points reported across this estate.").font = F(
                color=SUB, size=9)
            arr += 1

        for _ in range(6):
            aps_paint(arr)
            arr += 1

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
    return f"Cluster Health Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


# `system` label values that make up the Active Directory estate -- Root/Child Domain
# Controllers and AD Sync & Authentication (2026-09-11: split out of the combined
# Infrastructure Admin Report into its own report, reachable from both Infrastructure Admin
# -- its real owner -- and Network Admin). One source of truth for both build_infrastructure_
# report's own `ad_hosts` filter below AND views.py's active_directory_form/_report device
# filters, so the two can never quietly drift apart on which systems count as "AD".
AD_SYSTEMS = {"Root Domain Controllers", "Child Domain Controllers", "AD Sync & Authentication"}


def infra_device_keys() -> set:
    """DEVICES keys for Infrastructure Admin's own estate (HCI Clusters, Standalone Servers)
    -- every windows-kind device EXCEPT the AD ones, the same filter infra_form's own picker
    already applies to device_inventory(). Built straight from DEVICES (no live Prometheus
    round trip), so it's cheap enough to call just to SCOPE a capture -- both views.py's
    exec-dashboard live capture and alerting.run_alert_cycle's own broadened poll (2026-09-18)
    share this one definition rather than each keeping their own copy to drift apart."""
    return {d["key"] for d in DEVICES
           if d.get("kind") == "windows" and d.get("system") not in AD_SYSTEMS}


def ad_device_keys() -> set:
    """DEVICES keys for Active Directory's own estate (Root/Child Domain Controllers, AD Sync
    & Authentication) -- active_directory_form's own picker filter, reused here. See
    infra_device_keys' own docstring on why this lives here, not in views.py or alerting.py."""
    return {d["key"] for d in DEVICES if d.get("system") in AD_SYSTEMS}


def switches_routers_device_keys() -> set:
    """DEVICES keys for the WHOLE SNMP switch/router/WLC estate, core switch included --
    39 devices. NOT a report picker's own scope any more (2026-09-23, on request: "report
    not split as requested" -- the single combined Switches & Routers Report picker was
    replaced by four narrower ones, see core_switches_device_keys/routers_device_keys/
    wireless_controller_device_keys/access_switches_device_keys just below). Kept, unchanged,
    for the alert poller and the Executive Dashboard's LiveEstateOverview (alerting.py's own
    "switches_routers" poller entry) -- those want ONE combined view of the whole estate
    regardless of which report screen an admin happens to be looking at, a different question
    than "which devices does this report picker show"."""
    return {d["key"] for d in DEVICES
           if d.get("kind") in ("Switch", "Router", "WLC")
           and d.get("report") == "switches_routers_report"}


def is_access_switch(dev: dict) -> bool:
    """True for every switch except a core one (2026-09-23, on request: "specific monitoring
    on access switches not core switches"; generalized 2026-09-24 from a single hardcoded
    `key != "core-switch"` check to DEVICES' own `role: "core"` tag, once a second and third
    core switch -- DR, BYO -- joined the original HQ one). Everything else with kind "Switch"
    is treated as access-tier. Routers and the WLC are neither: AP/uplink-port monitoring is a
    switch-port concept, so build_report()'s own CDP lane (see its comment) is gated on this,
    not just `kind == "Switch"` alone."""
    return dev.get("kind") == "Switch" and dev.get("role") != "core"


# ---------------------------------------------------------------------------------------
#  The four report-picker estates (2026-09-23, on request: "create a seperate core switches
#  report and a seperate routers report ... this current report rename it to Access
#  switches" -- then, on clarifying WLC placement: "the one without poe wireless
#  controller... put it in its own report called wireless controller"). Replaces the single
#  combined Switches & Routers Report picker (switches_routers_form/_report/_generate in
#  views.py) with four narrower ones, each reusing the SAME collect()/build_report() engine
#  (mode="switches_routers") -- only the device scope and the report's own title differ.
#  switches_routers_device_keys() above is untouched and still backs the alert poller's own
#  combined view; these four are picker-only.
# ---------------------------------------------------------------------------------------
def core_switches_device_keys() -> set:
    """DEVICES keys for the Core Switches Report -- today, three devices tagged `role: "core"`
    (HQ 10.100.210.253, DR 10.100.210.251, BYO 10.200.210.252; see DEVICES' own comment on
    them). Written as `not is_access_switch(d)` rather than a literal key match so another
    core switch, if one is ever added, only needs its own DEVICES entry -- not a change here
    too."""
    return {d["key"] for d in DEVICES if d.get("kind") == "Switch" and not is_access_switch(d)}


def routers_device_keys() -> set:
    """DEVICES keys for the Routers Report -- today, exactly one device
    (`hre-dr-swift-router`, the 2951 ISR)."""
    return {d["key"] for d in DEVICES if d.get("kind") == "Router"}


def wireless_controller_device_keys() -> set:
    """DEVICES keys for the Wireless Controller Report -- today, exactly one device
    (`hre-wlc-02`, a virtual C9800-CL with no PoE/PSU/fan of its own -- confirmed on request,
    2026-09-23: "the one without poe wireless controller", kept out of Access Switches rather
    than folded in, since it isn't a switch)."""
    return {d["key"] for d in DEVICES if d.get("kind") == "WLC"}


def access_switches_device_keys() -> set:
    """DEVICES keys for the Access Switches Report -- every switch except the core one (see
    is_access_switch's own comment); this is the renamed, narrowed successor to the old
    combined Switches & Routers Report picker."""
    return {d["key"] for d in DEVICES if is_access_switch(d)}


def firewall_device_keys() -> set:
    """DEVICES keys for the Firewall Report (2026-09-29, on request: "add these firewalls to
    a new firewall report which is part of the network reports group") -- today, four
    devices, none of which answer SNMP yet (see their own DEVICES comment). Filtered on kind
    alone, same idiom as the other three narrow pickers above -- `kind: "Firewall"` is what
    keeps these OUT of switches_routers_device_keys()'s combined estate (its own kind filter
    only matches "Switch"/"Router"/"WLC"), so they can never feed a false "unreachable" into
    the alert poller or the Executive Dashboard's Network tile, while still showing up here,
    honestly, for this report's own picker/generate flow."""
    return {d["key"] for d in DEVICES if d.get("kind") == "Firewall"}


# Cisco hardware platform prefixes CDP neighbours actually report on this estate (confirmed
# live, 2026-09-23 -- see the cisco_cdp SNMP module's own comment in snmp.yml). "ap" and
# "switch"/"router" prefixes never collide (Catalyst 9100-series ACCESS POINTS are C91xx;
# Catalyst 9200/9300/9400-series SWITCHES are C92xx/C93xx/C94xx -- a different hundreds
# digit, not a coincidence, Cisco's own model-number convention). Deliberately narrow and
# observed, not a speculative full vendor catalogue: an unrecognised platform string (a
# Yealink/Polycom phone, a Webex Touch10 panel, an unknown vendor) is left unclassified
# ("other") rather than guessed into either bucket.
_CDP_AP_PREFIXES = ("AIR-AP", "C91")
_CDP_SWITCH_PREFIXES = ("C92", "C93", "C94", "WS-C", "N30")
_CDP_ROUTER_PREFIXES = ("CISCO19", "CISCO29", "CISCO39", "ISR", "ASR")


def _cdp_neighbor_kind(platform: str) -> str:
    """'ap' / 'switch' / 'router' / 'other', from a CDP neighbour's own reported platform
    string. 'switch' and 'router' are both "uplink" candidates from an access switch's own
    point of view (either is the direction traffic goes UP toward, not a downstream host) --
    callers that only care about "is this an uplink" check `kind in ("switch", "router")`."""
    p = (platform or "").upper()
    if any(tok in p for tok in _CDP_AP_PREFIXES):
        return "ap"
    if any(tok in p for tok in _CDP_SWITCH_PREFIXES):
        return "switch"
    if any(tok in p for tok in _CDP_ROUTER_PREFIXES):
        return "router"
    return "other"


def active_directory_report_filename(theme: str = "dark", when=None) -> str:
    """Same family as infrastructure_report_filename just above -- its own report now, not a
    section of the combined Infrastructure Admin one, so it gets its own named file rather
    than downloading as another "Infrastructure Admin Report"."""
    import datetime
    when = when or datetime.datetime.now()
    return f"Active Directory Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


# ---- e-mail for this module's own Snapshot/SystemVM shape (Network/Infra/AD reports) ---------
#
# services.email_report (the System Admin report's own e-mail path) is built entirely on
# generate_report.py's Store/System dataclasses via mail_report.analyse()/render_html() --
# neither applies to a network.py Snapshot (SystemVM/FlagVM, windows-kind devices, the switch).
# Rather than adapting Store/System to fake that shape, this is its own small, self-contained
# renderer straight off SystemVM/FlagVM -- the same information views.py already turns into
# each screen's `report_content` dict, just as HTML/plain text instead of JSON.
#
# Confirmed live 2026-09-17: network_generate/infra_generate/active_directory_generate never
# actually sent e-mail at all -- none of the three read request.POST["action"], so clicking
# "Generate & email" on any of those three screens (the button renders unconditionally, same
# shared form.html as the System Admin report) silently downloaded the file instead and left
# the page's "Sending…" button stuck forever, since no navigation or JS ever ran to reset it.
# This is the actual send path all three were missing.
def _overview_tiles_html(overview: dict) -> str:
    """The same {label, value, sub, state} tiles _network_overview/_infra_overview hand the
    web screen's own AT A GLANCE / NEEDS IMMEDIATE ATTENTION / NEEDS ATTENTION bands -- now
    rendered by CALLING mail_report.py's own real tile functions (_kpi/_kpi_panel) directly,
    not a hand-maintained HTML copy of them (2026-10-07, on request: "modify the exact system
    admin report template panel [to] contain network data... that would make these emailing
    templates identical instead of trying to copy what is in the other template"). This is a
    READ-ONLY import -- mail_report.py itself is never edited (feedback_never_touch_system_
    admin_report.md) -- just its already-proven, already-proportioned tile markup reused with
    network data passed in instead of business-system data. Whatever _kpi/_kpi_panel look like
    in that file is exactly what these tiles look like too, permanently, with zero copy-drift
    risk ever again.

    Confirmed live (2026-10-07) which real shape each tier uses in mail_report.render_html
    itself: the glance tier calls plain _kpi(label, value, color) (one combined value, e.g.
    "61% | 39%"); the immediate/watch tiers call _kpi_panel(title, [(sublabel, val), ...],
    color) -- TWO separate labelled sub-columns, never one combined string. Network's own tile
    dicts store value as one combined "N | M" string with a separate "sub" line ("devices |
    total") describing it -- both get split back into the two (sublabel, value) pairs
    _kpi_panel expects when they match that shape; a tile whose value/sub don't fit a clean
    "X | Y" split (e.g. "Accurate" / "64-bit counters") falls back to plain _kpi() instead,
    same as mail_report.py's own glance tier already does for its own non-ratio tiles."""
    import re

    import mail_report as mr

    color_map = {"bad": mr.RED, "warn": mr.AMBER, "good": mr.GREEN, "info": mr.NAVY}
    ratio_re = re.compile(r"^\s*(\S+)\s*\|\s*(\S+)\s*$")
    sub_re = re.compile(r"^\s*([A-Za-z0-9 ]+?)\s*\|\s*([A-Za-z0-9 ]+?)\s*$")
    headers = {
        "glance": f'<div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:#000000;text-transform:uppercase;margin:10px 0 2px;">At a glance</div>',
        "immediate": f'<div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:{mr.RED};text-transform:uppercase;margin:10px 0 2px;">&#9679;&nbsp; Needs immediate attention</div>',
        "watch": f'<div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:{mr.AMBER};text-transform:uppercase;margin:10px 0 2px;">&#9679;&nbsp; Needs attention</div>',
    }
    parts = []
    for section in ("glance", "immediate", "watch"):
        tiles = overview.get(section) or []
        if not tiles:
            continue
        cells = []
        for t in tiles:
            color = color_map.get(t.get("state", "info"), mr.NAVY)
            label = str(t.get("label", ""))
            value = str(t.get("value", ""))
            sub = str(t.get("sub", ""))
            m_val = ratio_re.match(value)
            m_sub = sub_re.match(sub) if sub else None
            if m_val and m_sub:
                cols = [(m_sub.group(1).strip().title(), m_val.group(1)),
                       (m_sub.group(2).strip().title(), m_val.group(2))]
                cells.append(mr._kpi_panel(label, cols, color))
            else:
                cells.append(mr._kpi(label, value, color))
        rows = "".join(f'<tr>{"".join(cells[i:i + 4])}</tr>' for i in range(0, len(cells), 4))
        parts.append(headers[section] +
                     f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tbody>{rows}</tbody></table>')
    return "".join(parts)


def _flagged_systems_html(systems: list) -> str:
    """One row per flagged SystemVM (name + its FlagVM texts, red/amber/note colour-coded) --
    the same information every xlsx section header already shows ("N critical / N warning"),
    just listed instead of nested, since an e-mail body has no room for the xlsx's tree
    layout."""
    import html as _html

    from mail_report import AMBER, NAVY, RED
    BLACK = "#000000"   # black ink, never gray -- see _overview_tiles_html's own comment
    flagged = [s for s in systems if not s.healthy]
    if not flagged:
        return (f'<p style="color:{BLACK};font-size:13px;">'
               "No flagged items this run — everything in this report is healthy.</p>")
    # {"red": RED, "amber": AMBER}.get(f.band, AMBER) used to be the WHOLE rule -- anything
    # that wasn't literally "red" fell to amber, so a "note" band flag (e.g. a cluster node's
    # network discard count -- see network.py's own comment on why a discard is background
    # context, not a fault) rendered as a false warning here (2026-09-29, on request: "why
    # call it service now.....what is is is a note.....so you need to design a notebanner
    # that follows the designs for all banners....just different coloring") -- NAVY is a
    # distinct informational blue, the same role send_report/infrastructure_report.py's own
    # CHIP_NOTE_TXT and app.css's own .chip.note both fill for the identical reason: not a
    # finding, not "all clear" either.
    _band_color = {"red": RED, "amber": AMBER, "note": NAVY}
    rows = []
    for s in flagged:
        items = "".join(
            f'<li style="color:{_band_color.get(f.band, AMBER)};margin-bottom:2px;">{_html.escape(f.text)}</li>'
            for f in s.flags)
        rows.append(
            f'<tr><td style="padding:8px 0;border-bottom:1px solid #e5e8ec;">'
            f'<div style="font-weight:600;font-size:13px;color:{BLACK};">{_html.escape(s.name)}'
            f'<span style="color:{BLACK};font-weight:400;font-size:11px;"> — {s.red} critical, {s.amber} warning</span></div>'
            f'<ul style="margin:4px 0 0 18px;padding:0;font-size:12px;">{items}</ul></td></tr>')
    return f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tbody>{"".join(rows)}</tbody></table>'


def _windows_report_email_bodies(snapshot, title: str, author: str) -> Tuple[str, str]:
    """(html_body, text_body) for a network.py Snapshot -- see this section's own module-level
    comment for why this exists instead of reusing mail_report.render_html()."""
    import datetime

    from mail_report import RED, AMBER, GREEN, RED_T, AMBER_T, GREEN_T, CRITICAL, NAVY, GOLD
    BLACK = "#000000"   # black ink, never gray -- see _overview_tiles_html's own comment

    red = sum(s.red for s in snapshot.systems)
    amber = sum(s.amber for s in snapshot.systems)
    if red:
        banner_bg, banner_fg, headline = RED_T, CRITICAL, f"CRITICAL — {red} item(s) need immediate attention"
    elif amber:
        banner_bg, banner_fg, headline = AMBER_T, AMBER, f"WARNING — {amber} item(s) to keep an eye on"
    else:
        banner_bg, banner_fg, headline = GREEN_T, GREEN, "All monitored devices are healthy"

    prepared_by = f" &middot; prepared by {author}" if author else ""
    today = datetime.date.today().strftime("%d %B %Y")
    # Header/banner/footer now match mail_report.render_html's own canonical look verbatim
    # (NAVY/GOLD header, "Reserve Bank of Zimbabwe · live snapshot ·" branding line, bulleted
    # banner, muted footer bar) -- fixed 2026-10-07, on request: "networks reports emailing
    # template looks different from all others in formatting fix the formating". This function
    # is the ONE real source for every Networks Report family email (Core/Access Switches,
    # Routers, Wireless Controller, Firewalls, Cluster Health, Active Directory -- see its own
    # module comment / email_windows_report's 7 real callers in views.py) plus
    # email_network_reports_bundle's own header below reuses the identical values, so fixing
    # the look here (and there) covers every one of them in one pass, not per-report-type.
    #
    # Table-based responsive wrapper, not a `max-width` DIV (fixed 2026-10-05, on request: "the
    # network, infrastructure and digest emails squash to much trying to fit a smaller
    # screen...the whole layout should shrink and everything remain in place...look at how the
    # systems email scales down" -- a `max-width` div is exactly the CSS Outlook's Word engine
    # does not reliably honor, the same class of bug the Silenced Alerts Digest's own flex/grid
    # layout hit earlier this session. mail_report.render_html's own "systems email" never had
    # this problem because it was never built on a div at all: a real `<table width="640"
    # style="max-width:640px;width:100%">` -- BOTH the HTML width attribute (Outlook's own
    # fallback) and the CSS max-width/width:100% pair (what lets modern/mobile clients shrink
    # the whole card fluidly as ONE block, carrying every tile/row inside it down in the same
    # proportion instead of each one re-flowing independently) -- is what actually makes it
    # scale down cleanly; this now copies that exact, already-proven structure verbatim rather
    # than reinventing a second responsive technique.
    #
    # table-layout:fixed/overflow-wrap:anywhere was tried twice (2026-10-06, 2026-10-07) and
    # REMOVED for good 2026-10-07: a real screenshot showed it breaking words mid-letter
    # ("Accurate" -> "Accura"/"te") on a real phone -- individual cells reflowing/shrinking
    # independently, exactly what was asked to stop ("stop using gray use black ink"... "my
    # columns still scale down based on screen size i do not want this... scale it as a whole
    # not individual report elements... use system admin report scaling n[o] compromises").
    # table-layout:auto (the browser default, and mail_report.py's own CURRENT/reverted
    # behaviour, untouched per feedback_never_touch_system_admin_report.md) is what's used here
    # now, permanently -- the whole 660px card shrinks as ONE block (the width-attribute +
    # max-width:660px;width:100% wrapper below), and each tile sizes itself to its own content
    # instead of being forced into an equal fixed share that then has to break words to fit.
    # Known, accepted tradeoff (explicitly chosen over the word-breaking): on a row with many
    # long labels, auto-layout COULD in principle starve one column enough to push it off the
    # right edge -- not reintroduced defensively; fix it for real if it's ever seen live, don't
    # pre-emptively add back the thing that was just explicitly rejected.
    html_body = f"""\
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f3;font-family:'Times New Roman',Times,serif;">
<tr><td align="center" style="padding:24px 12px;">
<table width="660" cellpadding="0" cellspacing="0" style="max-width:660px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.12);">
  <tr><td style="background:{NAVY};padding:22px 24px;">
    <div style="font-size:20px;font-weight:700;color:{GOLD};letter-spacing:.5px;">{title}</div>
    <div style="font-size:12px;color:#aebfd1;margin-top:3px;">Reserve Bank of Zimbabwe &nbsp;&middot;&nbsp; live snapshot &nbsp;&middot;&nbsp; {today}{prepared_by}</div>
  </td></tr>
  <tr><td style="background:{banner_bg};border-bottom:1px solid #e6e8ec;padding:12px 24px;">
    <span style="color:{banner_fg};font-weight:700;font-size:14px;">&#9679; {headline}</span>
  </td></tr>
  <tr><td style="padding:16px 24px;border:1px solid #e5e8ec;border-top:none;">
    {_overview_tiles_html(snapshot.overview)}
    <div style="margin-top:16px;">
      {_flagged_systems_html(snapshot.systems)}
    </div>
    <p style="font-size:11px;color:{BLACK};margin-top:16px;">
      Full detail (per-node CPU/RAM/disk, services, storage volumes) is in the attached report.
    </p>
  </td></tr>
  <tr><td style="background:#f7f8fa;border-top:1px solid #e6e8ec;padding:14px 24px;">
    <div style="font-size:11px;color:{BLACK};line-height:1.6;">
      {title} &nbsp;&middot;&nbsp; Reserve Bank of Zimbabwe Monitoring Console
    </div>
  </td></tr>
</table>
</td></tr>
</table>"""

    lines = [title, today, ""]
    lines.append(headline)
    lines.append("")
    for s in snapshot.systems:
        if s.healthy:
            continue
        lines.append(f"{s.name} — {s.red} critical, {s.amber} warning")
        lines.extend(f"  - {f.text}" for f in s.flags)
    if red == 0 and amber == 0:
        lines.append("No flagged items this run — everything in this report is healthy.")
    lines.append("")
    lines.append("Full detail is in the attached report.")
    text_body = "\n".join(lines)
    return html_body, text_body


_DISK_FLAG_RE = re.compile(r"^(?:(.+?) · )?(\S+) at (\d+)% used$")


def critical_disk_items(snapshot, threshold: int = 95) -> list:
    """[(system, host, mount, used%), ...] for every disk-high FlagVM at/over `threshold` in
    this Snapshot -- the SAME (system, host, mount, used%) shape send_report/mail_report.py's
    own engine.disk_near_full returns, so mail_report.py's existing near-full banner template
    can render Cluster Health's own findings unchanged (2026-09-17, on request: "the report
    says there is critical storage usage... but no critical banner to tell us exactly whats
    going on[,] copy and reuse one of the banner templates from the system admin report's
    mailing template" -- see mail_report.py's own _cluster_storage_critical_block).

    A single, shared function rather than duplicated inline in each caller (the scheduled
    command AND its own test-fire twin both need this) -- exactly the "kept in step by hand"
    duplication that already drifted out of sync once this session (see
    generate_active_directory_report.py's own module docstring on _send_xlsx_report_test);
    this one lives in ONE place instead.

    Parses FlagVM.text back apart rather than reading raw disk %s directly: category="disk"
    flags are already computed once (by _windows_device_flags, the same code the interactive
    report/xlsx use) in two text shapes -- "{node label} · {volume} at {used}% used" for a
    cluster's own per-node disks, bare "{volume} at {used}% used" for a single-target device
    (no node label to prefix) -- re-deriving from Prometheus here would be a second, parallel
    computation that could disagree with the report's own numbers; reusing the flag text
    guarantees this banner can never show a different disk or % than the report itself does.
    Filters strictly at `threshold` (95 by default, matching _infra_overview's own "Storage
    critical" tile) -- NOT band=="red" (that fires at >=90%, a wider net that would list more
    disks than the tile it's meant to explain claims)."""
    by_name = {d["name"]: d for d in DEVICES}
    items = []
    for s in snapshot.systems:
        group_label = by_name.get(s.name, {}).get("system", s.name)
        for f in s.flags:
            if f.category != "disk":
                continue
            m = _DISK_FLAG_RE.match(f.text)
            if not m:
                continue
            node_label, mount, pct = m.group(1), m.group(2), int(m.group(3))
            if pct < threshold:
                continue
            items.append((group_label, node_label or s.name, mount, float(pct)))
    items.sort(key=lambda t: -t[3])
    return items


def email_windows_report(snapshot, data: bytes, *, recipients: List[str], author: str,
                         filename: str, title: str) -> str:
    """E-mail an already-built report for a network.py Snapshot (Network/Infrastructure/
    Active Directory) -- the send path those three screens never had, see this section's own
    module-level comment. Mirrors services.email_report's contract exactly (same "send first,
    only record on success" caller obligation, same exceptions): returns the subject on
    success, raises EmailNotConfigured / the underlying SMTP error on failure."""
    import datetime
    import os
    import pathlib
    import tempfile

    import mail_report as mr   # send_report/mail_report.py (on sys.path)

    from .services import EmailNotConfigured

    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        raise EmailNotConfigured("No SMTP host configured in send_report/config.ini ([smtp]).")
    if author:
        mailcfg["from_name"] = f"{author} · {title}"

    red = sum(s.red for s in snapshot.systems)
    amber = sum(s.amber for s in snapshot.systems)
    sev = f"{red} critical" if red else (f"{amber} warning(s)" if amber else "all healthy")
    subject = f"{title} — {datetime.date.today():%d %b %Y} — {sev}"
    if author:
        subject += f" — by {author}"

    html_body, text_body = _windows_report_email_bodies(snapshot, title, author)

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


def email_network_reports_bundle(reports: list, *, recipients: List[str], author: str,
                                 subject_prefix: str = "") -> str:
    """One e-mail, N xlsx attachments -- for reports whose own snapshots are too many to send
    as separate e-mails but too different in scope to merge into one Snapshot (2026-09-24, on
    request: "wire them in in reporting config to send to the same people... at around the
    same time" -- the Core Switches/Routers/Wireless Controller/Access Switches Report split,
    see generate_network_reports.py).

    `reports` -- [{"snapshot":, "data": bytes, "filename":, "title":}, ...], already built, in
    the order they should appear. Each section reuses _overview_tiles_html/
    _flagged_systems_html verbatim -- the SAME per-report rendering email_windows_report's own
    single-report body already uses -- concatenated under one shared header/banner, not a new
    rendering engine. Subject/banner severity is the WORST across every report here, same "one
    critical thing must never hide behind an all-healthy headline" rule
    generate_active_directory_report.py's own combined AD+Cluster Health severity uses.

    Mirrors email_windows_report's own contract: returns the subject on success, raises
    EmailNotConfigured / the underlying SMTP error on failure. A `reports` entry with no data
    (a failed capture -- see generate_network_reports.py's own per-report isolation) must be
    filtered out by the CALLER before this runs; this function assumes every entry it's given
    is a real, already-built report.

    `subject_prefix` -- see services.email_report's own docstring on why a test send's marker
    belongs in the subject, never in `author`.
    """
    import datetime
    import os
    import pathlib
    import tempfile

    import mail_report as mr   # send_report/mail_report.py (on sys.path)

    from .services import EmailNotConfigured

    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        raise EmailNotConfigured("No SMTP host configured in send_report/config.ini ([smtp]).")
    bundle_title = "Network Reports"
    if author:
        mailcfg["from_name"] = f"{author} · {bundle_title}"

    from mail_report import RED, AMBER, GREEN, RED_T, AMBER_T, GREEN_T, CRITICAL, NAVY, GOLD
    BLACK = "#000000"   # black ink, never gray -- see _overview_tiles_html's own comment

    red = sum(sum(s.red for s in r["snapshot"].systems) for r in reports)
    amber = sum(sum(s.amber for s in r["snapshot"].systems) for r in reports)
    if red:
        banner_bg, banner_fg, headline = (
            RED_T, CRITICAL, f"CRITICAL — {red} item(s) across the network estate need immediate attention")
    elif amber:
        banner_bg, banner_fg, headline = AMBER_T, AMBER, f"WARNING — {amber} item(s) to keep an eye on"
    else:
        banner_bg, banner_fg, headline = GREEN_T, GREEN, "All monitored network devices are healthy"

    sev = f"{red} critical" if red else (f"{amber} warning(s)" if amber else "all healthy")
    subject = f"{bundle_title} — {datetime.date.today():%d %b %Y} — {sev}"
    if author:
        subject += f" — by {author}"
    # subject_prefix (2026-09-24, for the "network_reports" test-fire branch of
    # views._send_xlsx_report_test) -- same "[SYNTHETIC TEST]" marker in the SUBJECT only,
    # never in `author`, matching services.email_report's own subject_prefix (see that
    # function's own docstring for why author must stay the real value).
    if subject_prefix:
        subject = f"{subject_prefix} {subject}"

    prepared_by = f" &middot; prepared by {author}" if author else ""
    today = datetime.date.today().strftime("%d %B %Y")

    sections, text_sections = [], []
    for r in reports:
        snap = r["snapshot"]
        sections.append(f"""
    <div style="margin-top:20px;padding-top:16px;border-top:1px solid #e5e8ec;">
      <div style="font-size:14px;font-weight:700;color:{NAVY};">{r['title']}</div>
      <div style="margin-top:8px;">{_overview_tiles_html(snap.overview)}</div>
      <div style="margin-top:12px;">{_flagged_systems_html(snap.systems)}</div>
    </div>""")
        text_sections.append(r["title"])
        text_sections.append("")
        for s in snap.systems:
            if s.healthy:
                continue
            text_sections.append(f"  {s.name} — {s.red} critical, {s.amber} warning")
            text_sections.extend(f"    - {f.text}" for f in s.flags)
        text_sections.append("")

    # Table-based responsive wrapper, not a `max-width` DIV -- see _windows_report_email_bodies'
    # own comment (2026-10-05, same request/fix, same copy of mail_report.render_html's own
    # already-proven structure) for the full reasoning. table-layout:fixed/overflow-wrap
    # removed for good 2026-10-07 -- see that same function's own comment (real screenshot of
    # mid-word breaking, "scale it as a whole not individual report elements").
    html_body = f"""\
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f3;font-family:'Times New Roman',Times,serif;">
<tr><td align="center" style="padding:24px 12px;">
<table width="660" cellpadding="0" cellspacing="0" style="max-width:660px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.12);">
  <tr><td style="background:{NAVY};padding:22px 24px;">
    <div style="font-size:20px;font-weight:700;color:{GOLD};letter-spacing:.5px;">{bundle_title}</div>
    <div style="font-size:12px;color:#aebfd1;margin-top:3px;">Reserve Bank of Zimbabwe &nbsp;&middot;&nbsp; live snapshot &nbsp;&middot;&nbsp; {today}{prepared_by}</div>
  </td></tr>
  <tr><td style="background:{banner_bg};border-bottom:1px solid #e6e8ec;padding:12px 24px;">
    <span style="color:{banner_fg};font-weight:700;font-size:14px;">&#9679; {headline}</span>
  </td></tr>
  <tr><td style="padding:16px 24px;border:1px solid #e5e8ec;border-top:none;">
    {"".join(sections)}
    <p style="font-size:11px;color:{BLACK};margin-top:16px;">
      Full detail (per-device CPU/RAM/temperature/interfaces/storage) is in each attached report.
    </p>
  </td></tr>
  <tr><td style="background:#f7f8fa;border-top:1px solid #e6e8ec;padding:14px 24px;">
    <div style="font-size:11px;color:{BLACK};line-height:1.6;">
      {bundle_title} &nbsp;&middot;&nbsp; Reserve Bank of Zimbabwe Monitoring Console
    </div>
  </td></tr>
</table>
</td></tr>
</table>"""

    text_body = "\n".join([bundle_title, today, "", headline, ""] + text_sections
                          + ["Full detail is in each attached report."])

    tmpdir = tempfile.mkdtemp(prefix="network_reports_")
    paths = []
    try:
        for r in reports:
            p = pathlib.Path(tmpdir) / r["filename"]
            p.write_bytes(r["data"])
            paths.append(p)
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, paths)
    finally:
        for p in paths:
            try:
                p.unlink()
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
    return subject


#: flag.text already carries its own label for these -- see _windows_device_flags: the "nodes"
#: branch (node_*) prefixes every text with the node's own display name, and win_down/
#: win_unscraped are written with the device's name baked in before any branching happens.
#: Every OTHER flag (cpu_high/mem_high/disk_high, cluster_node_down/cluster_resource_failed)
#: carries no name at all, so _infra_notes prefixes those with the device/group name itself.
_INFRA_LABELED_FLAG_PREFIXES = ("win_down", "win_unscraped", "win_stale_but_pinging", "node_")

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
    # node_net_disc: flags get their own dedicated banner now (build_infrastructure_report's
    # own "NODE NETWORK DISCARDS", added right before this) -- excluded from the per-device
    # Notes rows here so the same finding doesn't ALSO repeat there (2026-09-16, on request:
    # "remove these warnings and errors from notes boxes"), the same de-duplication precedent
    # node_down's own notes already followed for multi-node clusters.
    #
    # ALSO excluded from critical/warning below as of 2026-09-21 (on request: "make discards
    # from cluster report a note banner instead of a warning banner") -- that banner is now
    # severity "NOTE" (see build_infrastructure_report's own comment), and a note that still
    # silently counted toward this device's own warning tally/pill colour would still read as
    # a real warning everywhere else in the report, undoing the whole point of downgrading it.
    # Before this date it was deliberately STILL counted here even though hidden from Notes --
    # that was correct while the banner itself was a real WARNING; it stopped being correct
    # the moment the banner became informational.
    notable = [f for f in sysvm.flags if not f.key.startswith("node_net_disc:")]
    critical = sum(1 for f in notable if f.band == "red")
    warning = len(notable) - critical
    if not notable:
        return [ir.NoteRow(ir.SENTINEL_NOTE, comment=comment)], critical, warning
    rows = []
    last = len(notable) - 1
    for i, flag in enumerate(notable):
        text = (flag.text if flag.key.startswith(_INFRA_LABELED_FLAG_PREFIXES)
               else f"{sysvm.name} · {flag.text}")
        text = _infra_short_node(text)
        rows.append(ir.NoteRow(
            flagged_metric=text,
            fix_needed=flag_answers.get(flag.key, ""),
            comment=comment if i == last else "",
            band=flag.band,
        ))
    return rows, critical, warning


def _windows_reading_trusted(m: dict) -> bool:
    """Whether m's own CPU/RAM/disk numbers should be treated as usable RIGHT NOW: either
    genuinely reachable, or a RELAY device (2026-09-09: RBZHQ-DC-204) whose metrics-freshness
    check reads unreachable but whose independent ICMP probe confirms the box is genuinely up
    (`host_reachable`, see _relay_windows_metrics) -- its last-known numbers ARE real
    (Prometheus is still holding whatever `rbz_hq_cdc_02_*` values it last scraped from 203,
    just possibly some hours old), not a fabrication.

    CENTRALISED (2026-09-09, on request: "the whole chain of screens in infrastructure reports
    needs to be looked at, it's still reflecting that one server is down") so every screen that
    decides "does this device count as down" -- the device picker, the review screen's own AT A
    GLANCE tiles, and the final xlsx's own tables -- agrees on the SAME definition. Before this,
    only the xlsx's own table-building (_infra_cpu_ram_disks) and flag wording
    (_windows_device_flags) knew about `host_reachable` -- device_inventory() (the picker) and
    _infra_overview (the review screen's own tile counts) each had their own, older, `not m.get
    ("reachable")` check that still read 204 as fully down two screens upstream of where it had
    already been fixed."""
    return bool(m.get("reachable") or (m.get("relay_instance") and m.get("host_reachable")))


def _infra_cpu_ram_disks(m: dict, label: str):
    """One windows_exporter target's raw metrics (see _windows_metrics/_hci_node_metrics) ->
    (CpuRam-or-None, [DiskRow, ...]). None for CpuRam when the target has never been
    reachable -- there is no percentage to show, not a fabricated 0%. See
    _windows_reading_trusted for the one exception (a relay device confirmed alive via ping
    despite stale metrics) -- shown with a LAST-KNOWN caveat by build_infrastructure_report's
    own AD tier loop, "treat it like an anomaly" means surfacing more of what's actually known,
    not collapsing to the same blank table a genuinely-never-reported host gets."""
    import infrastructure_report as ir

    if not _windows_reading_trusted(m):
        return None, []
    cpu_ram = None
    if m.get("cpu_pct") is not None or m.get("mem_pct") is not None:
        mem_total = m.get("mem_total_gb")
        # `or 0.0` here was the bug (2026-09-14, confirmed live): coerced a genuinely missing
        # reading into a fabricated 0% the moment the OTHER of the pair was present (e.g. an
        # HCI node whose CPU textfile collector went silent while its standard memory reading
        # kept flowing) -- CpuRam.cpu_pct/ram_pct are each independently Optional now, and
        # write_cpu_ram prints "-" for None instead of a false zero.
        cpu_ram = ir.CpuRam(
            node=label, cpu_pct=m.get("cpu_pct"), ram_pct=m.get("mem_pct"),
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


def _ad_service_states(targets: list, relay_devices: Optional[list] = None) -> Dict[str, dict]:
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
    Pinning state="running" makes the value itself mean what running_bool claims.

    `relay_devices` (2026-09-09, on request: "services table is empty [for 204]... are we not
    getting any service metrics" -- confirmed live: we ARE, just never queried) covers a device
    like RBZHQ-DC-204 with no windows_exporter/windows_service_state of its own: its own
    `target` is a synthetic placeholder that can never match a real `instance` label, so it was
    silently degrading to "no services listed" every time. Its relay's OWN prefixed gauge
    (`{prefix}wmi_workaround_service_running{name=...}`, confirmed live to cover all seven
    _AD_SERVICES for RBZHQ-DC-204) is queried separately here and merged back into `out` keyed
    by the RELAY DEVICE's own (synthetic) target -- so the caller's existing `ad_svc_states.
    get(dev["target"], {})` lookup keeps working unchanged for both kinds of device. Unlike the
    real windows_service_state gauge, this one has no `state=` enumeration at all -- it's
    already a plain 1/0 running boolean, no `state="running"` filter needed."""
    prom, _ = _prometheus()
    # No re.escape() here: PromQL label-matcher strings consume a backslash as a STRING escape
    # before RE2 ever sees the regex, so `\.` (what re.escape gives a dotted IP) comes back as
    # "unknown escape sequence" -- confirmed live. `.` un-escaped just means "any character" in
    # the regex, harmless for these fixed, internally-configured name/IP:port values.
    names_re = "|".join(k for k, _ in _AD_SERVICES)
    by_lower = {k.lower(): k for k, _ in _AD_SERVICES}
    out: Dict[str, dict] = {t: {} for t in targets}

    if targets:
        targets_re = "|".join(targets)
        try:
            rows = prom.query(
                f'windows_service_state{{state="running", '
                f'name=~"(?i)^({names_re})$", instance=~"{targets_re}"}}')
        except Exception:                       # noqa: BLE001
            rows = []
        for r in rows:
            inst = r["labels"].get("instance")
            key = by_lower.get(r["labels"].get("name", "").lower())
            if inst in out and key:
                out[inst][key] = r["value"] >= 1

    for d in (relay_devices or []):
        t, inst, prefix = d["target"], d["relay_instance"], d["metric_prefix"]
        out.setdefault(t, {})
        try:
            rows = prom.query(
                f'{prefix}wmi_workaround_service_running{{'
                f'name=~"(?i)^({names_re})$", instance="{inst}"}}')
        except Exception:                       # noqa: BLE001
            rows = []
        for r in rows:
            key = by_lower.get(r["labels"].get("name", "").lower())
            if key:
                out[t][key] = r["value"] >= 1
    return out


# AD replication (2026-09-10, on request: "add a table in the Domain controllers level to show
# replication these metrics are already there") -- genuine Active Directory NTDS replication
# between domain controller partners, NOT Hyper-V Replica (the admin's own clarification: "not
# throughhyper v") -- windows_exporter's `ad` collector, confirmed live only on RBZHQ-DC-203
# (and, by relay, RBZHQ-DC-204 -- see _ad_replication_states' own relay_devices param below):
# 4 partitions x 3
# partners = 12 (partition, partner) series per metric on that host. Root Domain Controllers
# (200/201) do NOT expose this at all yet (confirmed live 2026-09-10 -- no windows_ad_
# replication_* series on either), so their own replication table is simply empty, same
# "nothing to show" handling used everywhere else in this report rather than a fabricated
# all-OK row.
# 'CN=NTDS Settings,CN=RBZ-HQ-CDC-02,CN=Servers,CN=Harare,CN=Sites,CN=Configuration,...' ->
# 'RBZ-HQ-CDC-02 (Harare)' -- the partner DN's own server CN + site CN, not the whole
# distinguishedName (unreadable at this table's own column width).
_REPL_PARTNER_RE = re.compile(r"CN=NTDS Settings,CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites")


def _replication_partner_label(dn: Optional[str]) -> str:
    m = _REPL_PARTNER_RE.search(dn or "")
    return f"{m.group(1)} ({m.group(2)})" if m else (dn or "unknown partner")


def _ad_replication_rows(prefix: str, instance: str, q) -> list:
    """[{"partner":, "failures":, "ok":, "last_success":}, ...] for one target, rolled up per
    PARTNER across every partition that partner replicates -- windows_exporter's `ad` collector
    reports one series per (partition, partner) pair, and partition-level detail has no
    admin-facing value a partner-level rollup doesn't already carry: a genuine replication
    problem with a partner shows up on every partition it carries, so collapsing to worst-case-
    per-partner keeps the table at a few readable rows per DC instead of a dozen. failures = MAX
    across that partner's partitions (a single stuck partition is still a real problem); ok =
    True only if every partition's last_result == 0 (AD replication result codes follow the
    Win32 error-code convention: 0 = success) AND failures == 0; last_success = the OLDEST (min)
    timestamp across partitions -- the most conservative reading, so a partially-stale partner
    is never hidden behind a fresher partition's own success time."""
    by_partner: Dict[str, dict] = {}
    fail_rows = q(f'{prefix}windows_ad_replication_consecutive_failures{{instance="{instance}"}}')
    result_rows = q(f'{prefix}windows_ad_replication_last_result{{instance="{instance}"}}')
    success_rows = q(f'{prefix}windows_ad_replication_last_success_timestamp_seconds{{instance="{instance}"}}')

    def bucket(partner: str) -> dict:
        return by_partner.setdefault(
            partner, {"failures": 0, "bad_result": False, "last_success": None})

    for r in fail_rows:
        d = bucket(_replication_partner_label(r["labels"].get("partner")))
        d["failures"] = max(d["failures"], int(r["value"]))
    for r in result_rows:
        d = bucket(_replication_partner_label(r["labels"].get("partner")))
        if r["value"] != 0:
            d["bad_result"] = True
    for r in success_rows:
        d = bucket(_replication_partner_label(r["labels"].get("partner")))
        v = r["value"]
        d["last_success"] = v if d["last_success"] is None else min(d["last_success"], v)

    return [{"partner": p, "failures": d["failures"],
             "ok": d["failures"] == 0 and not d["bad_result"],
             "last_success": d["last_success"]}
            for p, d in sorted(by_partner.items())]


def _ad_replication_states(devices: list, relay_devices: Optional[list] = None) -> Dict[str, list]:
    """{target: [row dicts from _ad_replication_rows]} for every DEVICES entry passed in.
    `relay_devices` (2026-09-10, same convention as _ad_service_states' own relay_devices
    param) covers RBZHQ-DC-204: no windows_exporter of its own, so its replication data is its
    relay's own prefixed series (`rbz_hq_cdc_02_windows_ad_replication_*` on RBZHQ-DC-203's own
    instance), queried separately and merged back keyed by the RELAY DEVICE's own (synthetic)
    target."""
    prom, _ = _prometheus()

    def q(expr):
        try:
            return prom.query(expr)
        except Exception:                       # noqa: BLE001
            return []

    out: Dict[str, list] = {}
    for d in devices:
        out[d["target"]] = _ad_replication_rows("", d["target"], q)
    for d in (relay_devices or []):
        out[d["target"]] = _ad_replication_rows(d["metric_prefix"], d["relay_instance"], q)
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

#: CpuRam.node label for the synthetic cluster-average row build_infrastructure_report adds
#: to the HCI parent group (2026-09-14, on request: "add average ram and cpu at the cluster
#: level infered from the individual nodes"). A shared constant, not a literal repeated at
#: both the append site and the all_cpu_ram exclusion filter -- this row is a DERIVED figure,
#: not one more node, so it must never count toward "how many NODES are over threshold" in
#: the HIGH CPU/MEMORY CRITICAL summary tiles (that would both double-count against the real
#: per-node rows already in all_cpu_ram, and could fire its own redundant banner entry).
_HCI_CLUSTER_AVERAGE_LABEL = "Cluster average"


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


# Standalone Servers' own service list (2026-09-17, on request: "can you pick services that may
# be important" -- NOT a guess: confirmed live on all 3 hosts (windows_service_state, state=
# "running") before picking anything, the same "never fabricate a check nobody asked for"
# discipline this module uses everywhere else, just satisfied by evidence instead of an
# admin naming them up front. Their "RTGS7DBH" hostnames suggested SQL Server, but no
# MSSQLSERVER/SQLSERVERAGENT service exists on any of the three -- confirmed absent, not
# assumed. What's actually running and role-defining on all three: vmms/vmcompute/HvHost (this
# is a Hyper-V HOST, same role HCI Cluster's own _HCI_SERVICES checks, minus ClusSvc -- these
# three are standalone, not clustered, and ClusSvc is confirmed NOT running on them) and
# StorageReplica (Windows' block-level replication feature) -- running on all three INCLUDING
# the DR-site host (DRS-RTGS7DBH-01), suggesting these three replicate storage with each other
# despite "RTGS7DBH" reading like a plain DB host name. Everything else running on these hosts
# (132 services on .252 alone) is generic OS/agent plumbing (BITS, EventLog, ManageEngine
# agents, ...) no different from what every other Windows host in this estate already omits.
_STANDALONE_SERVER_SERVICES = [
    ("vmms", "Hyper-V Virtual Machine Management"),
    ("vmcompute", "Hyper-V Host Compute Service"),
    ("HvHost", "Hyper-V Host Service"),
    ("StorageReplica", "Storage Replica"),
]


def _standalone_server_service_states(targets: list) -> Dict[str, dict]:
    """{target: {service_key: running_bool}} for _STANDALONE_SERVER_SERVICES -- same query
    shape (and same state="running" requirement) as _hci_service_states/_ad_service_states,
    see either's own docstring."""
    if not targets:
        return {}
    prom, _ = _prometheus()
    names_re = "|".join(k for k, _ in _STANDALONE_SERVER_SERVICES)
    targets_re = "|".join(targets)
    try:
        rows = prom.query(
            f'windows_service_state{{state="running", '
            f'name=~"(?i)^({names_re})$", instance=~"{targets_re}"}}')
    except Exception:                       # noqa: BLE001
        rows = []
    by_lower = {k.lower(): k for k, _ in _STANDALONE_SERVER_SERVICES}
    out: Dict[str, dict] = {t: {} for t in targets}
    for r in rows:
        inst = r["labels"].get("instance")
        key = by_lower.get(r["labels"].get("name", "").lower())
        if inst in out and key:
            out[inst][key] = r["value"] >= 1
    return out


# AD Sync & Authentication (2026-09-10) -- unlike _AD_SERVICES/_HCI_SERVICES (one shared
# service list queried across several SAME-role hosts), RBZ-HQ-ADS-01 (Azure AD Connect Sync)
# and RBZ-ADAPT-01 (Pass-Through Authentication agent) run genuinely different services, so
# this is keyed per DEVICES `key` instead of one list shared by the whole tier. Real service
# short names (windows_service_state's own `name` label) CONFIRMED LIVE 2026-09-10, queried
# right after both hosts started scraping -- deliberately NOT the DisplayName column the
# admin's own brief quoted (Get-Service's DisplayName != the short Name windows_exporter
# reports as `name`; e.g. "Microsoft Azure AD Sync" is really `ADSync`, "Microsoft Entra
# Connect Health Agent" is really `AzureADConnectHealthAgent`, "Windows Security Service" is
# really `SecurityHealthService`). "Windows Security Service" was initially left off (Manual
# start, judged as a generic Windows service rather than one of the named services to watch,
# same reasoning as _HCI_SERVICES' own SmbWitness/TieringEngineService case) -- corrected
# 2026-09-10 on explicit request, since the admin's own original brief did list it (Get-Service
# output showed it Running on both hosts) even though Manual start type doesn't guarantee it
# stays running the way Automatic does. `AzureADConnectAgentUpdater`/`vmictimesync` (also
# present on both, never named in the brief) remain excluded.
# `AzureADConnectAuthenticationAgent` is also present (and running) on RBZ-HQ-ADS-01 itself,
# not just RBZ-ADAPT-01 -- Azure AD Connect installs the PTA agent capability alongside Sync by
# default even when PTA isn't that box's own primary role, per the admin's own brief ("PTA
# 10.100.249.207") only that host's copy is the one being watched here.
_AD_SYNC_AUTH_SERVICES = {
    "ad-sync": [
        ("ADSync", "Azure AD Sync"),
        ("AzureADConnectHealthAgent", "Microsoft Entra Connect Health Agent"),
        ("SecurityHealthService", "Windows Security Service"),
    ],
    "pta": [
        ("AzureADConnectAuthenticationAgent", "Azure AD Connect Authentication Agent (PTA)"),
        ("SecurityHealthService", "Windows Security Service"),
    ],
}


def _ad_sync_auth_service_states(devices: list) -> Dict[str, dict]:
    """{target: {service_key: running_bool}} for _AD_SYNC_AUTH_SERVICES -- same state="running"
    requirement as _ad_service_states/_hci_service_states (see _ad_service_states' own
    docstring for why a bare max-by would silently report stopped services as running), but
    queried per-device since these two hosts don't share one service list the way DCs/HCI
    nodes do."""
    prom, _ = _prometheus()
    out: Dict[str, dict] = {}
    for d in devices:
        target = d["target"]
        svc_list = _AD_SYNC_AUTH_SERVICES.get(d["key"], [])
        out[target] = {}
        if not svc_list:
            continue
        names_re = "|".join(k for k, _ in svc_list)
        by_lower = {k.lower(): k for k, _ in svc_list}
        try:
            rows = prom.query(
                f'windows_service_state{{state="running", '
                f'name=~"(?i)^({names_re})$", instance="{target}"}}')
        except Exception:                       # noqa: BLE001
            rows = []
        for r in rows:
            key = by_lower.get(r["labels"].get("name", "").lower())
            if key:
                out[target][key] = r["value"] >= 1
    return out


def _service_list_for_device(dev: dict) -> list:
    """Which (service_key, display_name) pairs apply to this device's own real, already-
    confirmed service checks -- _AD_SERVICES/_AD_SYNC_AUTH_SERVICES/_HCI_SERVICES/
    _STANDALONE_SERVER_SERVICES above, whichever this device's own `system`/`cluster` field
    matches (same two fields infra_device_keys()/ad_device_keys() and
    build_infrastructure_report's own tier loop already branch on -- not a second,
    independently-derived classification). Empty for any windows device with no defined
    service list at all (there are none today, but a future windows_exporter addition with no
    curated service list should get no flags/tile contribution, not a guess).

    Added 2026-10-06, on request: "pretty sure infra structure has reports do contain services
    and have a services down alert associated with them...why not add these to the pretty
    dashboard as well" -- these four lists/queries already existed (confirmed live,
    2026-08-28/09-09/09-10/09-17, see each one's own comment) but fed ONLY the xlsx's own
    per-DC Services table (`ir.ServiceRow`, build_infrastructure_report's own tier loop) --
    never a flag, never an overview tile, never alerting. This is the shared classification
    both the new flag-emission in _windows_device_flags and the new "Services down" overview
    tile in _infra_overview use, so neither can drift from the other."""
    system = dev.get("system")
    if system == "AD Sync & Authentication":
        return _AD_SYNC_AUTH_SERVICES.get(dev["key"], [])
    if system in AD_SYSTEMS:
        return _AD_SERVICES
    if dev.get("cluster"):
        return _HCI_SERVICES
    if system == "Standalone Servers":
        return _STANDALONE_SERVER_SERVICES
    return []


# NTP / Time Sync Status (2026-09-11, on request), scoped to RBZHQ-ROOT-01 ONLY -- the
# forest's primary time source, not every domain controller. Confirmed live 2026-09-11: all
# four w32time metrics genuinely present on 10.100.249.200:9182 (root-dc-1's own target).
# Bands per the request's own explicit thresholds: stratum <=3 green / >3 amber / ==16
# (w32time's own "never synchronized" sentinel) red; sync age <=300s green / <=900s amber /
# >900s red.
_HARARE_OFFSET_SECONDS = 7200  # UTC+2 -- Africa/Harare observes no DST, so a fixed offset is
                               # exact, not an approximation (2026-09-11, on request:
                               # "wmi_workaround_w32tm_last_sync_timestamp_seconds is UTC --
                               # display as UTC+2").


def _ntp_sync_row(target: str, dc_name: str) -> Optional[dict]:
    """One row's worth of raw values for `target`'s own w32time state, or None if either
    metric is missing (a host with no w32time textfile publishing yet, rather than a
    fabricated all-clear row -- same "nothing to show" discipline as everywhere else in this
    report). Returns a plain dict, not an ir.NtpSyncRow -- the caller (build_infrastructure_
    report) does that conversion, same split _ad_replication_rows already uses.

    Sync age is computed LIVE as `time() - last_sync_timestamp` in the PromQL query itself
    (2026-09-11, on request), not read from the script's own separately-published
    wmi_workaround_w32tm_seconds_since_last_sync gauge -- confirmed live the two disagree
    significantly (the pre-computed gauge read a small, stale value while the live
    subtraction showed ~2h), so the script's own gauge isn't refreshed often enough to trust
    for "how stale is this right now"; time() is evaluated at THIS query, so it can't lag the
    same way."""
    import datetime

    prom, _ = _prometheus()

    def q1(expr):
        try:
            rows = prom.query(expr)
        except Exception:                       # noqa: BLE001
            return None
        return rows[0] if rows else None

    stratum_row = q1(f'wmi_workaround_w32tm_stratum{{instance="{target}"}}')
    source_row = q1(f'wmi_workaround_w32tm_source_info{{instance="{target}"}}')
    last_sync_row = q1(f'wmi_workaround_w32tm_last_sync_timestamp_seconds{{instance="{target}"}}')
    age_row = q1(f'time() - wmi_workaround_w32tm_last_sync_timestamp_seconds{{instance="{target}"}}')
    if not (stratum_row and source_row and last_sync_row and age_row):
        return None

    stratum = int(stratum_row["value"])
    stratum_band = "red" if stratum == 16 else ("amber" if stratum > 3 else "green")
    age_seconds = age_row["value"]
    hours, minutes = divmod(int(age_seconds) // 60, 60)
    last_sync_utc2 = datetime.datetime.fromtimestamp(
        last_sync_row["value"] + _HARARE_OFFSET_SECONDS, tz=datetime.timezone.utc)
    return {
        "dc": dc_name,
        "stratum": stratum,
        "stratum_band": stratum_band,
        "source": source_row["labels"].get("source") or "—",
        "last_sync": last_sync_utc2.strftime("%d %b %Y, %H:%M:%S"),
        "sync_age": f"{hours}h {minutes}m",
        "sync_age_band": "red" if age_seconds > 900 else ("amber" if age_seconds > 300 else "green"),
    }


def build_infrastructure_report(snapshot, *, theme: str = "dark", author: str,
                                annotations: dict, summary_comment: str,
                                report_title: str = "CLUSTER HEALTH REPORT") -> bytes:
    """Map the annotated Snapshot into a ReportData tree and render it via
    infrastructure_report.build_report(). See this section's module docstring above.

    `report_title` (2026-09-11): the Active Directory Report shares this exact renderer
    (build_infrastructure_report is already correctly scoped by whatever `only=` subset the
    caller's own capture_snapshot used) rather than needing a second one -- only the masthead
    text and sheet-tab name need to say something different, so this is the one thing the
    caller can override rather than duplicating the whole function. Defaults to the original
    literal so infra_generate's own existing call site is unaffected."""
    import infrastructure_report as ir

    wm = getattr(snapshot, "_wm", None) or {}
    wc = getattr(snapshot, "_wc", None) or {}
    by_name = {d["name"]: d for d in DEVICES}
    # DEVICES' own declared order (root-dc-1 before root-dc-2) -- the intentional ordering
    # this report should follow within a tier, independent of whatever order snapshot.systems
    # itself arrived in. views.infra_report sorts snapshot.systems alphabetically by name for
    # the picker/review screen's own reasons, but "RBZ-HQ-ROOT-02" alphabetically precedes
    # "RBZHQ-ROOT-01" (a hyphen sorts before a letter), which silently reversed the two DCs
    # here (2026-09-08, on request: "start with the first root... now its vice versed"). Keying
    # on DEVICES' own position sidesteps that naming-inconsistency trap entirely, rather than
    # relying on the two names happening to sort in the intended order.
    device_order = {d["name"]: i for i, d in enumerate(DEVICES)}

    groups = []
    # Three real levels: "Active Directory" (all DCs combined) > "Root Domain Controllers" /
    # "Child Domain Controllers" (one DEVICES `system` value each) > each DC's own section,
    # titled "Domain Controller N (Hostname)" -- the SAME shape HCI Cluster Host uses for its
    # own nodes ("HCI Cluster Node N (Hostname)"), applied here 2026-09-09 on request ("Is it
    # Possible to say Domain Controller 1 (Hostname) to match the naming convention established
    # in HCL CLuster Host"). Numbered PER TIER, restarting at 1 in each (the admin's own choice:
    # "take option 2" -- Root's own two get "Domain Controller 1/2", Child's own two ALSO get
    # "Domain Controller 1/2", the tier heading directly above each is what distinguishes Root
    # from Child, exactly how "HCI Cluster Node N" never repeats "HCI Cluster" in the child
    # title since the parent section already says that). Genuine nested DeviceGroups at indent
    # 0/1/2, not a label-only divider -- see infrastructure_report.py's COL_WIDTHS for the gap-
    # column equations that make indent 2 actually fit (Disk's own column is fixed while
    # Services/CPU-RAM shift per indent, so a 3rd level needs its own reserved gap column).
    ad_hosts = [s for s in snapshot.systems
               if by_name.get(s.name, {}).get("system") in AD_SYSTEMS]
    if ad_hosts:
        ad_children = []
        ad_critical = ad_warning = 0
        dc_hosts = [s for s in ad_hosts if by_name[s.name]["system"] != "AD Sync & Authentication"]
        # A relay device (RBZHQ-DC-204)'s own service state is queried separately, from its
        # relay's OWN prefixed metric -- see _ad_service_states' own relay_devices docstring
        # (2026-09-09, on request: "services table is empty... are we not getting any service
        # metrics" -- we ARE, this just wasn't querying for them yet). Scoped to dc_hosts only
        # (2026-09-10) -- RBZ-HQ-ADS-01/RBZ-ADAPT-01 run entirely different services than
        # _AD_SERVICES names, see _ad_sync_auth_service_states below for their own query.
        ad_svc_states = _ad_service_states(
            [by_name[s.name]["target"] for s in dc_hosts if not by_name[s.name].get("relay_instance")],
            relay_devices=[by_name[s.name] for s in dc_hosts if by_name[s.name].get("relay_instance")])
        # AD replication (2026-09-10) -- same relay split as ad_svc_states just above, same
        # reason (RBZHQ-DC-204 has no windows_exporter of its own to query directly).
        ad_repl_states = _ad_replication_states(
            [by_name[s.name] for s in dc_hosts if not by_name[s.name].get("relay_instance")],
            relay_devices=[by_name[s.name] for s in dc_hosts if by_name[s.name].get("relay_instance")])
        ad_sync_auth_states = _ad_sync_auth_service_states(
            [by_name[s.name] for s in ad_hosts if by_name[s.name]["system"] == "AD Sync & Authentication"])
        # RBZHQ-DC-203/204 (2026-09-09) live under "Child Domain Controllers" -- the admin's own
        # call, for naming consistency with "Root Domain Controllers" ("rename The Domain
        # Controllers to Child Domain Controllers so its a bit more consistent with the root
        # ones"), reusing this tier value rather than a separate third one -- it had been an
        # empty placeholder (reserved for exactly this) until now. "AD Sync & Authentication"
        # (2026-09-10) is a genuine third tier, not reusing either -- the admin's own call ("New
        # tier under Active Directory") for these two non-DC AD-identity servers.
        for tier_label, tier_system in (("Root Domain Controllers", "Root Domain Controllers"),
                                        ("Child Domain Controllers", "Child Domain Controllers"),
                                        ("AD Sync & Authentication", "AD Sync & Authentication")):
            tier_hosts = sorted(
                (s for s in ad_hosts if by_name[s.name]["system"] == tier_system),
                key=lambda s: device_order.get(s.name, 0))
            if not tier_hosts:
                continue
            # Each DC gets its OWN section (child), not one Services/CPU-RAM/Disk table
            # combining both -- a shared table only ever distinguished rows by suffixing the
            # hostname onto every service name. The tier's own tables are deliberately left
            # empty, same as the Active Directory parent above it -- unlike HCI (one cluster,
            # a rollup genuinely describes the shared resource), each DC is entirely its own
            # independent host; a rolled-up copy at the tier level said nothing an admin
            # couldn't already read on that DC's own section one level down. Each DC's own
            # comment/flag answers land on ITS OWN section (annotations are already keyed per
            # host, sysvm.name) instead of being merged into one shared list.
            tier_children = []
            tier_critical = tier_warning = 0
            is_ad_sync_auth_tier = tier_system == "AD Sync & Authentication"
            for dc_num, sysvm in enumerate(tier_hosts, start=1):
                dev = by_name[sysvm.name]
                m = wm.get(dev["target"], {"known": False, "reachable": False})
                cr, dk = _infra_cpu_ram_disks(m, sysvm.name)
                if is_ad_sync_auth_tier:
                    svc_list = _AD_SYNC_AUTH_SERVICES.get(dev["key"], [])
                    svc_state = ad_sync_auth_states.get(dev["target"], {})
                else:
                    svc_list = _AD_SERVICES
                    svc_state = ad_svc_states.get(dev["target"], {})
                host_services = [ir.ServiceRow(display_name, "RUNNING" if running else "DOWN")
                                 for key, display_name in svc_list
                                 for running in [svc_state.get(key)]
                                 if running is not None]
                # AD replication (2026-09-10) -- DC tiers only, never AD Sync & Authentication
                # (neither RBZ-HQ-ADS-01 nor RBZ-ADAPT-01 is a domain controller, so there is no
                # NTDS replication state to show for either).
                repl_rows = []
                if not is_ad_sync_auth_tier:
                    now = time.time()
                    for r in ad_repl_states.get(dev["target"], []):
                        last_success = (f"{_fmt_duration(now - r['last_success'])} ago"
                                        if r["last_success"] is not None else "never")
                        repl_rows.append(ir.ReplicationRow(
                            partner=r["partner"], status="OK" if r["ok"] else "FAILED",
                            last_success=last_success, failures=r["failures"]))
                ann = annotations.get(sysvm.name, {})
                rows, c, w = _infra_notes(sysvm, ann.get("comment", ""), ann.get("flags", {}))
                if cr is None and m.get("reachable"):
                    # Reachable, but with no CPU/RAM/Disk data at all -- these hosts expose
                    # that via windows_exporter's textfile collector, not the live collectors
                    # this app queries elsewhere (see DEVICES' own root-dc-1/2 comment), and
                    # nothing has been published there yet (collector_success=0, confirmed
                    # live). Without this note, the host has no CPU/RAM table row to appear in
                    # (cpu_ram/disks both end up empty for it) and no flag either (it's not
                    # down), so it would otherwise vanish from the report with nothing
                    # anywhere naming it -- indistinguishable from "not included at all".
                    # Prepended ahead of whatever _infra_notes produced so the admin's own
                    # comment (if any) is kept, not overwritten. The `service` collector IS
                    # live for these hosts though (unlike textfile) -- see the Services table
                    # below, not another blank gap.
                    rows = [ir.NoteRow(f"Reachable, but CPU/RAM/Disk have not been published "
                                       f"yet (expected via the textfile collector); service "
                                       f"status below is live.")] + rows
                elif cr is not None and not m.get("reachable") and m.get("host_reachable"):
                    # A relay device shown DESPITE stale metrics (2026-09-09, see
                    # _infra_cpu_ram_disks' own comment) -- flags the table itself as last-
                    # known, not live, so it never reads as a fresher reading than it is.
                    rows = [ir.NoteRow(
                        f"CPU/RAM/Disk below are the LAST KNOWN reading, "
                        f"{_fmt_duration(m.get('stale_seconds'))} old -- {sysvm.name} is "
                        f"confirmed reachable via ping, but its own metrics-collection script "
                        f"has not reported since then.")] + rows
                tier_critical += c
                tier_warning += w
                # Section title only -- every ROW beneath it (CPU/RAM, disk, notes, flags,
                # services) still uses the bare sysvm.name, unchanged, the same "full label on
                # the title, bare hostname on every row underneath" split HCI Cluster Node
                # already uses (see _infra_short_node's own comment for why repeating the
                # wrapper on every row under an already-titled section is redundant).
                # AD Sync and PTA are two DIFFERENT roles, not peer instances of the same role
                # the way Root/Child DCs are -- "Domain Controller 1/2" numbering only makes
                # sense for interchangeable peers, so this tier's own hosts title on their bare
                # hostname instead (still unique, still matches the row labels beneath it).
                title = sysvm.name if is_ad_sync_auth_tier else f"Domain Controller {dc_num} ({sysvm.name})"
                tier_children.append(ir.DeviceGroup(
                    title=title, services=host_services, replication=repl_rows,
                    cpu_ram=[cr] if cr else [], disks=dk, notes=rows, critical=c, warning=w,
                    count=1, count_label="host", signed_by=author))
            ad_critical += tier_critical
            ad_warning += tier_warning
            ad_children.append(ir.DeviceGroup(
                title=tier_label, notes=[], children=tier_children,
                critical=tier_critical, warning=tier_warning,
                count=len(tier_hosts), count_label="host" if len(tier_hosts) == 1 else "hosts",
                signed_by=author))
        # NTP / Time Sync Status (2026-09-11: "move the table to the highest point under
        # active directory" -- previously nested three levels deep in RBZHQ-ROOT-01's own
        # per-host card; it now sits directly on the Active Directory group itself, one
        # forest-wide fact rather than something that belongs to one host's own section.
        # Still scoped to RBZHQ-ROOT-01 only -- rendered only when that specific host is
        # actually part of this report run, same as before.
        ntp_rows = []
        root1 = next((s for s in ad_hosts if by_name[s.name]["key"] == "root-dc-1"), None)
        if root1 is not None:
            ntp_raw = _ntp_sync_row(by_name[root1.name]["target"], root1.name)
            if ntp_raw:
                ntp_rows.append(ir.NtpSyncRow(**ntp_raw))
        # The tier level still carries no tables of its own -- with 3 real levels, an
        # aggregate at EVERY level (Active Directory, tier, AND host) was one rollup too
        # many; each DC's own section is still where the CPU/RAM/disk/services/replication
        # data lives. Active Directory itself is the one exception now: NTP is a top-level
        # fact, not a per-host or per-tier one, so it (and the sentinel Notes panel that
        # comes with any table on this report) live here instead.
        groups.append(ir.DeviceGroup(
            title="Active Directory", children=ad_children,
            critical=ad_critical, warning=ad_warning,
            count=len(ad_hosts), count_label="devices", signed_by=author,
            ntp_sync=ntp_rows,
            notes=[ir.NoteRow(ir.SENTINEL_NOTE)] if ntp_rows else []))

    # Every `cluster: True` device gets its own section, not just HCI Cluster (2026-09-16,
    # generalized when Disaster Recovery Cluster became a second one). Each cluster's own
    # hci_nodes/hci_volumes come from snapshot._hci_nodes_by_key/_hci_volumes_by_key -- the
    # PER-CLUSTER dicts capture_snapshot keeps precisely so two clusters' nodes/volumes are
    # never merged together here the way _infra_overview's own aggregate tallies deliberately
    # do merge them (see that function's own comment on why that's fine for a tile count but
    # would be wrong for a device's own node list/CSV table).
    cluster_sysvms = [s for s in snapshot.systems if by_name.get(s.name, {}).get("cluster")]
    for hci_sysvm in cluster_sysvms:
        cluster_dev = by_name[hci_sysvm.name]
        cluster_key = cluster_dev["key"]
        cluster_title = cluster_dev["name"]
        hci_nodes = snapshot._hci_nodes_by_key.get(cluster_key, {})
        hci_volumes = snapshot._hci_volumes_by_key.get(cluster_key, [])
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
        # mscluster WMI call for THIS cluster's own representative target -- scoped per-cluster
        # (2026-09-16) rather than grabbing whatever `wc` happened to have first, which was only
        # ever correct while there was exactly one cluster to find.
        wc_target = cluster_dev["target"]
        wc_data = wc.get(wc_target)
        members = (wc_data or {}).get("nodes") or []
        if members:
            queried_via = hci_nodes.get(wc_target, {}).get("display", wc_target)
            parts = ", ".join(f"{name} ({state.upper()})"
                              for name, state, _up in sorted(members))
            notes = [ir.NoteRow(f"Cluster's own view of node membership (queried via "
                                f"{_infra_short_node(queried_via)}): {parts}.")] + notes
        node_order = sorted(hci_nodes.items(), key=lambda kv: kv[1].get("display", kv[0]))
        # The parent "HCI Cluster Host" row carries ONLY facts that belong to the host/cluster
        # itself -- notes, critical/warning, count -- never a rolled-up copy of what each
        # child node's OWN section already shows (on request, 2026-09-04: "the parent node...
        # is currently displaying information that is already shown in its child nodes...
        # each child node should display only its own data"). Per-node CPU/RAM/disk/services
        # go on the parent ONLY when there is exactly one node and therefore no child section
        # for them to live in instead -- otherwise every node gets its own child DeviceGroup
        # below and the parent stays a pure container.
        multi_node = len(node_order) > 1
        if multi_node:
            # _infra_notes already turned hci_sysvm's own "node_down:..." flags into a
            # "{label} is not answering" NoteRow above -- exactly the fact each unreachable
            # node's own child section repeats below via child_notes. Drop it from the
            # parent's copy so it shows in exactly one place, the same duplication already
            # fixed for CPU/RAM/disk/services.
            down_texts = {f"{_infra_short_node(n.get('display', target))} is not answering"
                         for target, n in node_order if not n.get("reachable")}
            notes = [nr for nr in notes if nr.flagged_metric not in down_texts]
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
            # A node not yet reporting (see _hci_node_metrics) has nothing in
            # hci_svc_states[target] at all -- an empty services list, not a table full of
            # "unknown", same as its own empty cpu_ram/disks above.
            node_services = [ir.ServiceRow(display_name, "RUNNING" if running else "DOWN")
                             for key, display_name in _HCI_SERVICES
                             for running in [hci_svc_states.get(target, {}).get(key)]
                             if running is not None]
            if multi_node:
                child_notes = ([ir.NoteRow(ir.SENTINEL_NOTE)] if n.get("reachable")
                               else [ir.NoteRow(f"{label} is not answering", band="red")])
                children.append(ir.DeviceGroup(
                    title=full_label, services=node_services, cpu_ram=[cr] if cr else [], disks=dk,
                    notes=child_notes, critical=0 if n.get("reachable") else 1, count=1,
                    count_label="node", signed_by=author))
            else:
                # Only node -- no child section exists, so its data has to live on the
                # parent, the same as it always did before this device ever had siblings.
                if cr:
                    cpu_ram.append(cr)
                disks += dk
                parent_services += node_services
        # Cluster-wide average CPU/RAM across reporting nodes, on the PARENT row (2026-09-14,
        # on request: "add average ram and cpu at the cluster level infered from the
        # individual nodes") -- multi-node only: the single-node case already puts that one
        # node's own reading on the parent (see the `else` branch above), where "average of
        # one" would be a redundant restatement, not new information. Reachable nodes only,
        # and cpu_pct/mem_pct are each averaged independently over whichever nodes actually
        # have THAT one reading -- a node reporting RAM but not CPU (a real gap, see
        # _hci_node_metrics' own docstring) still legitimately contributes to the RAM average
        # rather than an all-or-nothing per-node filter dropping it from both. Tagged with
        # _HCI_CLUSTER_AVERAGE_LABEL so all_cpu_ram's own summary-tile counts below can
        # exclude it -- a derived average is not one more node to flag as "over threshold".
        if multi_node:
            def _avg_reachable(key):
                vals = [n.get(key) for _, n in node_order
                        if n.get("reachable") and n.get(key) is not None]
                return sum(vals) / len(vals) if vals else None
            avg_cpu, avg_ram = _avg_reachable("cpu_pct"), _avg_reachable("mem_pct")
            if avg_cpu is not None or avg_ram is not None:
                cpu_ram.append(ir.CpuRam(node=_HCI_CLUSTER_AVERAGE_LABEL,
                                         cpu_pct=avg_cpu, ram_pct=avg_ram))
        # Cluster Storage Volumes on the PARENT row (2026-09-14): queried cluster-wide, not
        # per node (see _hci_cluster_volumes' own docstring -- the metric is scraped from
        # whichever node answers but describes the whole cluster's CSVs), so it belongs once
        # on the cluster's own row, not repeated per node. Omitted entirely when nothing
        # publishes it, same "don't fabricate a row from data that isn't there" rule this
        # group used to justify not showing a storage table at all before these metrics
        # existed.
        cluster_volumes = [ir.ClusterVolumeRow(**v) for v in hci_volumes]
        groups.append(ir.DeviceGroup(
            # Renamed from "HCI Cluster Host" (2026-09-14, on request) -- "Host" read as one
            # more physical box among the Node children below it; the parent row is the
            # CLUSTER itself, which is what its own Cluster Storage Volumes table (the
            # cluster's shared CSVs, not a per-host figure) makes explicit now anyway.
            # cluster_title (2026-09-16): each cluster device's own DEVICES["name"] ("HCI
            # Cluster", "Disaster Recovery Cluster", ...) now that there's more than one.
            title=cluster_title, services=parent_services, cpu_ram=cpu_ram, disks=disks,
            cluster_volumes=cluster_volumes,
            notes=notes, children=children,
            critical=critical, warning=warning, count=max(1, len(node_order)),
            count_label="node" if len(node_order) == 1 else "nodes", signed_by=author))

    # Standalone Servers (2026-09-17, on request: "added 3 standalone servers to be grouped
    # under Standalone server group") -- any windows-kind device that's neither AD-tiered nor
    # `cluster: True` was already being counted into the summary tiles below (components_total
    # already has a generic `else` branch for exactly this), but never actually got a section
    # of its own to appear in -- this loop is that missing section. Grouped by each device's
    # own DEVICES `system` label, the same convention the AD tiers and every cluster already
    # use, so a future second standalone group (a different `system` value) falls into its own
    # section automatically rather than needing new code each time.
    #
    # Services (2026-09-17, on request: "can you pick services that may be important" -- see
    # _STANDALONE_SERVER_SERVICES' own comment for what was actually confirmed running before
    # picking these, not guessed) -- shared across the whole group the same way _HCI_SERVICES
    # is shared across every HCI Cluster node, since all three standalone servers here were
    # confirmed running the identical set.
    standalone_hosts = [s for s in snapshot.systems
                        if by_name.get(s.name, {}).get("kind") == "windows"
                        and by_name[s.name].get("system") not in AD_SYSTEMS
                        and not by_name[s.name].get("cluster")]
    standalone_svc_states = _standalone_server_service_states(
        [by_name[s.name]["target"] for s in standalone_hosts])
    standalone_by_system: Dict[str, list] = {}
    for s in standalone_hosts:
        standalone_by_system.setdefault(by_name[s.name]["system"], []).append(s)
    for sys_label, hosts in standalone_by_system.items():
        hosts = sorted(hosts, key=lambda s: device_order.get(s.name, 0))
        children = []
        group_critical = group_warning = 0
        for sysvm in hosts:
            dev = by_name[sysvm.name]
            m = wm.get(dev["target"], {"known": False, "reachable": False})
            cr, dk = _infra_cpu_ram_disks(m, sysvm.name)
            svc_state = standalone_svc_states.get(dev["target"], {})
            host_services = [ir.ServiceRow(display_name, "RUNNING" if running else "DOWN")
                             for key, display_name in _STANDALONE_SERVER_SERVICES
                             for running in [svc_state.get(key)]
                             if running is not None]
            ann = annotations.get(sysvm.name, {})
            rows, c, w = _infra_notes(sysvm, ann.get("comment", ""), ann.get("flags", {}))
            group_critical += c
            group_warning += w
            children.append(ir.DeviceGroup(
                title=sysvm.name, services=host_services, cpu_ram=[cr] if cr else [], disks=dk,
                notes=rows, critical=c, warning=w, count=1, count_label="host", signed_by=author))
        groups.append(ir.DeviceGroup(
            title=sys_label, children=children,
            critical=group_critical, warning=group_warning,
            count=len(hosts), count_label="device" if len(hosts) == 1 else "devices",
            signed_by=author))

    devices_total = len(snapshot.systems)
    all_disks = [d for g in groups for d in (g.disks + [dd for c in g.children for dd in c.disks])]
    # Excludes the synthetic HCI cluster-average row (_HCI_CLUSTER_AVERAGE_LABEL) -- a derived
    # figure, not one more node, so it must never count toward "how many NODES are over
    # threshold" in the STORAGE/HIGH CPU/MEMORY CRITICAL summary tiles below (every real
    # node's own reading is already in here via its own child group).
    all_cpu_ram = [c for g in groups for c in (g.cpu_ram + [cc for ch in g.children for cc in ch.cpu_ram])
                  if c.node != _HCI_CLUSTER_AVERAGE_LABEL]
    # snapshot._hci_nodes (MERGED across every cluster), not the `hci_nodes` local the loop
    # above left pointing at whichever cluster it last iterated (2026-09-16, generalized from a
    # single-cluster assumption) -- this tally is the estate-wide "how many cluster nodes total,
    # how many down", same as _infra_overview's own equivalent merge.
    cluster_nodes = len(snapshot._hci_nodes)
    cluster_nodes_down = sum(1 for n in snapshot._hci_nodes.values() if not n.get("reachable"))
    cres = {"online": 0, "offline": 0, "failed": 0, "other": 0}
    for w in wc.values():
        res = w.get("resources") or {}
        for k in cres:
            cres[k] += res.get(k, 0)

    # Components are counted at the finest tracked granularity: a device with sub-nodes (any
    # `cluster: True` device) contributes one component PER NODE, not one for the whole device
    # -- everything else (Root DCs, ...) is a single component. "Devices down"/"components
    # down" differ the same way: a cluster device counts as one down device even when several
    # of its nodes are down, which understates the real down-count, so the tile below is
    # measured in components (each cluster's own node-down count, not a 0/1 per device) rather
    # than devices. Each cluster contributes ITS OWN node count here (via
    # _hci_nodes_by_key), not the merged estate-wide total above -- two clusters must each be
    # counted by their own node count, not have the combined total double-attributed to both.
    cluster_keys_by_name = {s.name: by_name[s.name]["key"] for s in cluster_sysvms}
    components_total = 0
    components_down = 0
    for s in snapshot.systems:
        if s.name in cluster_keys_by_name:
            this_nodes = snapshot._hci_nodes_by_key.get(cluster_keys_by_name[s.name], {})
            components_total += len(this_nodes) if this_nodes else 1
            components_down += sum(1 for n in this_nodes.values() if not n.get("reachable"))
        else:
            components_total += 1
            if any(f.key.startswith(("win_down", "win_unscraped")) for f in s.flags):
                components_down += 1

    def _tone(count):
        return "red" if count else "green"

    def _watch_tone(count, red_count):
        return "red" if red_count else ("amber" if count else "green")

    storage_critical = sum(1 for d in all_disks if d.used_pct >= 95)
    # `c.ram_pct is not None and ...` (2026-09-14): cpu_pct/ram_pct can each now be genuinely
    # None (a host reporting one but not the other -- see CpuRam's own docstring), so a bare
    # `>=` here would raise TypeError the moment that host is in scope, not just render wrong.
    mem_critical = sum(1 for c in all_cpu_ram if c.ram_pct is not None and c.ram_pct >= 95)
    cpu_amber = sum(1 for c in all_cpu_ram if c.cpu_pct is not None and c.cpu_pct >= 80)
    cpu_red = sum(1 for c in all_cpu_ram if c.cpu_pct is not None and c.cpu_pct >= 90)
    mem_amber = sum(1 for c in all_cpu_ram if c.ram_pct is not None and 80 <= c.ram_pct < 95)

    # "STORAGE AT CAPACITY >=85%" (used to sit in watch_list below, storage_amber +
    # storage_critical -- ALWAYS including whatever STORAGE CRITICAL above already counts) is
    # gone (2026-09-18, on request: "storage capacity and storage critical are the same
    # metric... combine every occurrence and remove this redundancy", confirmed after a first
    # pass only touched the exec dashboards: "infrastructure still views these as separate").
    # STORAGE CRITICAL alone is this report's one storage tile now, matching every other
    # caller of the same underlying idea (see network._infra_overview's own comment).
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
            # Relay devices (2026-09-09: RBZHQ-DC-204) phrase their own reason differently --
            # see _windows_device_flags' own relay branch for exactly what these two shapes are.
            elif " has never published metrics via " in text:
                lbl, _, tail = text.partition(" has never published metrics via ")
                detail = f"never published via {tail}"
            elif " has not reported fresh metrics via " in text:
                lbl, _, tail = text.partition(" has not reported fresh metrics via ")
                detail = tail
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
                         for c in all_cpu_ram if c.ram_pct is not None and c.ram_pct >= 95]
    if mem_critical_rows:
        banners.append(ir.Banner(
            "CRITICAL", "MEMORY CRITICAL",
            f"{len(mem_critical_rows)} node(s) at/over 95% RAM",
            rows=mem_critical_rows,
            note="Memory this high risks paging/swapping and service instability -- "
                 "investigate the top consumer or add memory."))

    cpu_hot_rows = [ir.BannerRow(c.node, f"CPU {c.cpu_pct:.0f}%")
                   for c in all_cpu_ram if c.cpu_pct is not None and c.cpu_pct >= 80]
    if cpu_hot_rows:
        banners.append(ir.Banner(
            "WARNING", "HIGH CPU",
            f"{len(cpu_hot_rows)} node(s) at/over 80% CPU",
            rows=cpu_hot_rows,
            note="Sustained high CPU degrades response times before it causes an outage -- "
                 "watch for a runaway process or plan capacity."))

    mem_warn_rows = [ir.BannerRow(c.node, f"RAM {c.ram_pct:.0f}%")
                     for c in all_cpu_ram if c.ram_pct is not None and 80 <= c.ram_pct < 95]
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

    # NODE NETWORK DISCARDS (2026-09-16, on request: "warnings like those discards have a
    # banner designed for them check system admin report" -- DR Cluster nodes' own
    # node_net_disc flags, live since that cluster's own onboarding, had never had a banner
    # here, unlike every other flagged category above). No SummaryMetric tile alongside it --
    # `banners` is its own field on ReportData, independent of needs_attention/watch_list,
    # which are ALREADY at the hard 4-tile-per-panel maximum DASH_LEFT:DASH_RIGHT's fixed
    # 8-column span allows (see infrastructure_report.py's own DASH_RIGHT comment: deliberately
    # matched to the System Admin Report's own dashboard band width, confirmed a 5th tile
    # raises a real merge-range error) -- a banner needs no matching tile to exist, only a
    # named detail list, exactly like every banner above already provides one.
    #
    # Downgraded WARNING -> NOTE (2026-09-21, on request: "make discards from cluster report a
    # note banner instead of a warning banner") -- this banner's own text has always said a
    # discard "is usually buffer/queue pressure, not a wire fault", i.e. background context,
    # not a finding -- the WARNING severity/tone never actually matched what the banner itself
    # was telling the reader. See _infra_notes' own comment for the matching change to how
    # node_net_disc flags count toward a device's severity tally -- a note must not silently
    # keep counting as a real warning there either, or nothing about "it's just a note" is true.
    disc_warn_rows = []
    for s in snapshot.systems:
        for f in s.flags:
            if not f.key.startswith("node_net_disc:"):
                continue
            lbl, _, detail = f.text.partition(" · ")
            disc_warn_rows.append(ir.BannerRow(_infra_short_node(lbl) if detail else s.name,
                                               detail or f.text))
    if disc_warn_rows:
        banners.append(ir.Banner(
            "NOTE", "NODE NETWORK DISCARDS",
            f"{len(disc_warn_rows)} node(s) dropping packets",
            rows=disc_warn_rows,
            note="A discarded packet is usually buffer/queue pressure, not a wire fault -- "
                 "watch for it worsening or pairing with real network errors."))

    import datetime
    now = datetime.datetime.now()
    data = ir.ReportData(
        generated_at=now.strftime("%d %b %Y  ·  %H:%M"),
        nodes_total=devices_total,
        cluster_count=len(cluster_sysvms),
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
        report_title=report_title,
        summary_signed_by=author,
        components_total=components_total,
    )

    import io
    buf = io.BytesIO()
    ir.build_report(data, buf)
    return buf.getvalue()

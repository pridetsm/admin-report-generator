"""The single canonical list of every metric this app captures into the long-term archive
(`prometheus_snapshot_db`, formerly `MetricSample` in `admin_report` -- see
PROMETHEUS-RETENTION-PLAN.md) -- built from a full audit of every PromQL call site in
network.py, generate_report.py, metric_history.py, system_alerts.py, folders.py, and
connect.py (2026-09-30). Extends network.py's own CATALOGUE philosophy ("every requested
metric appears, and every one carries its state") app-wide: what gets archived is derived from
what the app actually queries, not a hand-picked guess.

DESIGN RULE, never violate it: every entry must be AGGREGATE/COUNT-shaped (one row per
INSTANCE, or one row for the whole estate), never per-port/per-interface/per-object raw. The
existing archive table's own index already costs more than its data at only 316,940 rows
(narrow, 5-series scope) -- a per-port entry would multiply row count by device x port count
and make that far worse. "N interfaces erroring on this switch" is an entry; "this one port's
raw octet counter" is not.

Each entry:
  key                 archive metric_key PREFIX (e.g. "psu_failed" -> "psu_failed:<instance>")
  kind                "global"  -- one bulk query returns EVERY instance's reading via its own
                                    `instance` label (mirrors capture_now()'s existing ram/cpu/
                                    disk shape: one HTTP round trip, not N)
                      "scalar"  -- one number for the whole estate, no instance split (swift,
                                    cob)
  bulk_promql         the combined query capture_now()/backfill() actually run
  live_query_template "global" entries only -- the SAME reading, filtered to ONE instance, for
                       reports.historical_query.series()'s "recent" half of a stitched range
                       (fixes plan review finding #2: a metric_key alone cannot be turned back
                       into a live query without this). Takes one `{instance}` placeholder.
  mount_label          disk-shaped entries only -- (linux_label, windows_label) pair, since
                       Linux/Windows series name their mount-point label differently
  source_ref           file:function this was derived from -- keeps the registry auditable
                       against the code it's supposed to mirror
  used_by              which report/feature this metric backs, for anyone wondering "can I
                       delete this"

Extending this list: append an entry, nothing else needs editing -- capture_now()/backfill()
loop over REGISTRY uniformly. See "NOT YET REGISTERED" at the bottom for the next candidates
identified in the 2026-09-30 audit but deliberately left for a follow-up pass rather than
rushed in here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import generate_report as gr


@dataclass(frozen=True)
class MetricRegistryEntry:
    key: str
    kind: str                                   # "global" | "scalar"
    bulk_promql: str
    live_query_template: Optional[str] = None
    mount_label: Optional[tuple] = None
    target_label: bool = False                  # folder-shaped entries only -- one
                                                 # folder_exporter instance monitors MULTIPLE
                                                 # folders, each its own `target` label
                                                 # (confirmed live: folder_files carries both
                                                 # instance AND target) -- instance alone is
                                                 # not a unique key here, same reasoning as
                                                 # mount_label for disk.
    extra_label: Optional[str] = None           # generic version of mount_label/target_label
                                                 # for anything else needing a third key
                                                 # segment under a DIFFERENT label name (e.g.
                                                 # HCI CSV volumes: one instance can have
                                                 # multiple `volume`-labelled series) -- add a
                                                 # bespoke bool+dedicated handling (like the
                                                 # two above) only if a label needs its OWN
                                                 # multi-source lookup the way disk's mount
                                                 # does (mountpoint OR volume); a single plain
                                                 # label name belongs here instead.
    floor_zero: bool = False                    # scalar entries only -- e.g. swift's raw
                                                 # counter can read a transient negative reset
    source_ref: str = ""
    used_by: str = ""


REGISTRY: list[MetricRegistryEntry] = [
    # ---- the original 5 (2026-09-18), unchanged in spirit -- migrated from metric_history.
    #      _global_expressions()/SCALAR_METRICS verbatim, now with live_query_template added
    #      (needed for stitching, not previously required since everything went through the
    #      archive only). ------------------------------------------------------------------
    MetricRegistryEntry(
        key="ram", kind="global",
        bulk_promql=(
            "100*(1-node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes) or "
            "100*(1-windows_memory_physical_free_bytes/windows_memory_physical_total_bytes)"),
        live_query_template=(
            '100*(1-node_memory_MemAvailable_bytes{{instance="{instance}"}}/'
            'node_memory_MemTotal_bytes{{instance="{instance}"}}) or '
            '100*(1-windows_memory_physical_free_bytes{{instance="{instance}"}}/'
            'windows_memory_physical_total_bytes{{instance="{instance}"}})'),
        source_ref="metric_history.py:_global_expressions",
        used_by="Hourly Activity chart (RAM)"),
    MetricRegistryEntry(
        key="cpu", kind="global",
        bulk_promql=(
            '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) or '
            '100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)'),
        live_query_template=(
            '100 - (avg by (instance) (rate(node_cpu_seconds_total{{mode="idle",instance="{instance}"}}[5m])) * 100) or '
            '100 - (avg by (instance) (rate(windows_cpu_time_total{{mode="idle",instance="{instance}"}}[5m])) * 100)'),
        source_ref="metric_history.py:_global_expressions",
        used_by="Hourly Activity chart (CPU)"),
    MetricRegistryEntry(
        key="disk", kind="global",
        bulk_promql=(
            f"100*(1-node_filesystem_avail_bytes{{{gr._FS}}}/node_filesystem_size_bytes{{{gr._FS}}}) or "
            f"100*(1-windows_logical_disk_free_bytes{{{gr._VOL}}}/windows_logical_disk_size_bytes{{{gr._VOL}}})"),
        # Plain-string concatenation, deliberately NOT an f-string: gr._FS/_VOL get spliced in
        # now, but the {{instance}} placeholder must survive untouched for a LATER .format()
        # call in historical_query.py -- an f-string here would consume that escaping itself
        # and leave a single-braced {instance} that .format() then can't parse (it sits inside
        # a larger {...} block with other content, which trips format()'s field-name parser).
        # Every other entry below uses the same {{...}} convention for the same reason.
        live_query_template=(
            '100*(1-node_filesystem_avail_bytes{{instance="{instance}",' + gr._FS + '}}/'
            'node_filesystem_size_bytes{{instance="{instance}",' + gr._FS + '}}) or '
            '100*(1-windows_logical_disk_free_bytes{{instance="{instance}",' + gr._VOL + '}}/'
            'windows_logical_disk_size_bytes{{instance="{instance}",' + gr._VOL + '}})'),
        mount_label=("mountpoint", "volume"),
        source_ref="metric_history.py:_global_expressions",
        used_by="Hourly Activity chart (Disk)"),
    MetricRegistryEntry(
        key="swift", kind="scalar",
        bulk_promql="swift_transactions_total",
        floor_zero=True,
        source_ref="metric_history.py:SCALAR_METRICS",
        used_by="SWIFT transaction chart"),
    MetricRegistryEntry(
        key="cob", kind="scalar",
        bulk_promql="cob_time",
        source_ref="metric_history.py:SCALAR_METRICS",
        used_by="COB duration chart"),

    # ---- new, from the 2026-09-30 audit -- all aggregate/count-shaped, per the design rule
    #      above. Each is a real gap this app's own reports already surface as a live flag
    #      but had zero history behind before now. -----------------------------------------
    MetricRegistryEntry(
        key="psu_failed", kind="global",
        bulk_promql='count by (instance) (cefcFRUPowerOperStatus{cefcFRUPowerOperStatus!="on"} == 1)',
        live_query_template=(
            'count by (instance) (cefcFRUPowerOperStatus{{cefcFRUPowerOperStatus!="on",'
            'instance="{instance}"}} == 1)'),
        source_ref="network.py:collect (PSU/fan status)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (PSU/fan tile)"),
    MetricRegistryEntry(
        key="ospf_down", kind="global",
        bulk_promql='count by (instance) (ospfNbrState != 4 and ospfNbrState != 8)',
        live_query_template=(
            'count by (instance) (ospfNbrState{{instance="{instance}"}} != 4 and '
            'ospfNbrState{{instance="{instance}"}} != 8)'),
        source_ref="network.py:collect (OSPF adjacency)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (OSPF tile)"),
    MetricRegistryEntry(
        # count by (instance) (X > 0), NOT clamp_min(X, 1) -- clamp_min raises the FLOOR, so a
        # healthy interface's genuine 0 would ALSO become 1 and get counted as "erroring".
        # Confirmed live 2026-09-30: the clamp_min version returned a count matching each
        # device's total interface count, not its erroring one -- caught before this shipped.
        key="iface_errors", kind="global",
        bulk_promql=(
            "count by (instance) ("
            "sum by (instance, ifIndex) (increase(ifInErrors[1h]) + increase(ifOutErrors[1h]) + "
            "increase(ifInDiscards[1h]) + increase(ifOutDiscards[1h])) > 0)"),
        live_query_template=(
            "count by (instance) ("
            'sum by (instance, ifIndex) (increase(ifInErrors{{instance="{instance}"}}[1h]) + '
            'increase(ifOutErrors{{instance="{instance}"}}[1h]) + '
            'increase(ifInDiscards{{instance="{instance}"}}[1h]) + '
            'increase(ifOutDiscards{{instance="{instance}"}}[1h])) > 0)'),
        source_ref="network.py:collect (interface errors/discards)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (errors/discards tile)"),
    MetricRegistryEntry(
        key="backup_check_ok", kind="global",
        bulk_promql="backup_check_success",
        live_query_template='backup_check_success{{instance="{instance}"}}',
        source_ref="generate_report.py:capture_backups",
        used_by="System Health Report backup status, NO BACKUP flag history"),

    # ---- added 2026-09-30, on request: "anything on uptime folder monitoring etc" -- both
    #      were found in the original audit but left out; added properly once asked, not left
    #      as a silent scoping call. ------------------------------------------------------
    MetricRegistryEntry(
        # sysUpTime is SNMPv2-MIB TimeTicks (hundredths of a second) -- converted to days
        # in the PromQL itself, matching how network.py's own collect() reads it
        # (uptime_days = value / 100 / 86400), so the archived number is already meaningful
        # without the reader needing to know the raw unit.
        key="uptime", kind="global",
        bulk_promql="sysUpTime / 100 / 86400",
        live_query_template='sysUpTime{{instance="{instance}"}} / 100 / 86400',
        source_ref="network.py:collect (switch/router uptime)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (uptime tile)"),
    MetricRegistryEntry(
        # One representative folder-monitoring metric (current queue depth), not all 13 raw
        # sub-metrics folders.py's own dashboard reads (folder_exists/up/size_bytes/oldest_
        # file_timestamp/etc.) -- those are a mix of byte counts, timestamps and histogram
        # buckets with no single common "value", and capturing all 13 per folder would
        # multiply row count for something the Folder Watch screen already dashboards live.
        # folder_files alone gives a genuine, chartable "was the queue backing up" trend --
        # if a specific other folder metric turns out to matter for history later, it's one
        # more entry away, same as everything else in this registry.
        key="folder_queue_depth", kind="global", target_label=True,
        bulk_promql='folder_files',
        live_query_template='folder_files{{instance="{instance}",target="{target}"}}',
        source_ref="folders.py:_QUERY (folder_files)",
        used_by="Folder Watch dashboard, backup/interface queue depth trend"),

    # ---- added 2026-09-30, on request: "scan all reports... ensure every metric they query
    #      is preserved" -- systematic pass over network.py's Cisco-SNMP-specific readings
    #      (distinct from the existing ram/cpu/disk entries, which cover Linux/Windows HOSTS
    #      via node_exporter/windows_exporter -- switches read through entirely different
    #      Cisco MIBs), the Infra Report's HCI-specific storage/network readings, and the
    #      System Health Report's reachability/web-link/SSL/backup-count readings. Each
    #      verified live against Prometheus before being added (see this session's own
    #      iface_errors clamp_min bug -- multi-row-per-instance metrics silently collide/drop
    #      data under a bare per-instance key unless aggregated first, confirmed here for both
    #      switch CPU (multiple cpmCPUTotalIndex rows) and switch memory (multiple
    #      ciscoMemoryPoolName rows) before committing either to the registry). ---------------
    MetricRegistryEntry(
        key="switch_cpu", kind="global",
        bulk_promql="max by (instance) (cpmCPUTotal5minRev)",
        live_query_template='max by (instance) (cpmCPUTotal5minRev{{instance="{instance}"}})',
        source_ref="network.py:collect (switch CPU, CISCO-PROCESS-MIB)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (CPU tile)"),
    MetricRegistryEntry(
        # "Processor" pool specifically, not every pool on the device (matches the single
        # number collect()'s own mem_used reading shows) -- confirmed live 2026-09-30 this
        # pool name is present and populated on every SNMP device checked.
        key="switch_mem_used", kind="global",
        bulk_promql='max by (instance) (ciscoMemoryPoolUsed{ciscoMemoryPoolName="Processor"})',
        live_query_template=(
            'max by (instance) (ciscoMemoryPoolUsed{{ciscoMemoryPoolName="Processor",'
            'instance="{instance}"}})'),
        source_ref="network.py:collect (switch memory, CISCO-MEMORY-POOL-MIB)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (memory tile)"),
    MetricRegistryEntry(
        # entSensorType="8" (celsius) filtered to a plausible 0-200 range, MAX across however
        # many sensors a device has -- exactly matches collect()'s own temp_max computation.
        key="switch_temp", kind="global",
        bulk_promql='max by (instance) (entSensorValue{entSensorType="8"} > 0 < 200)',
        live_query_template=(
            'max by (instance) (entSensorValue{{entSensorType="8",instance="{instance}"}} '
            '> 0 < 200)'),
        source_ref="network.py:collect (temperature sensors, ENTITY-SENSOR-MIB)",
        used_by="Core/Access Switches, Routers, Wireless Controller Reports (temperature tile)"),
    MetricRegistryEntry(
        # HCI Cluster Shared Volumes -- one instance can own multiple named volumes, hence
        # extra_label rather than a bare per-instance key (same reasoning as disk's mount).
        key="hci_csv_used_pct", kind="global", extra_label="volume",
        bulk_promql="windows_hci_csv_volume_used_percent",
        live_query_template=(
            'windows_hci_csv_volume_used_percent{{instance="{instance}",volume="{target}"}}'),
        source_ref="network.py:_hci_cluster_volumes",
        used_by="Cluster Health Report (HCI CSV storage tile)"),
    MetricRegistryEntry(
        key="hci_net_errors", kind="global",
        bulk_promql=(
            "count by (instance) (sum by (instance, nic) ("
            "increase(windows_net_packets_received_errors_total[1h]) + "
            "increase(windows_net_packets_outbound_errors_total[1h]) + "
            "increase(windows_net_packets_received_discarded_total[1h]) + "
            "increase(windows_net_packets_outbound_discarded_total[1h])) > 0)"),
        live_query_template=(
            "count by (instance) (sum by (instance, nic) ("
            'increase(windows_net_packets_received_errors_total{{instance="{instance}"}}[1h]) + '
            'increase(windows_net_packets_outbound_errors_total{{instance="{instance}"}}[1h]) + '
            'increase(windows_net_packets_received_discarded_total{{instance="{instance}"}}[1h]) + '
            'increase(windows_net_packets_outbound_discarded_total{{instance="{instance}"}}[1h])) > 0)'),
        source_ref="network.py:_hci_node_metrics (network errors/discards)",
        used_by="Cluster Health Report (HCI network errors tile)"),
    MetricRegistryEntry(
        key="backup_file_count", kind="global",
        bulk_promql="backup_file_count",
        live_query_template='backup_file_count{{instance="{instance}"}}',
        source_ref="generate_report.py:capture_backups",
        used_by="System Health Report backup status (fresh-file count, alongside backup_check_ok)"),
    MetricRegistryEntry(
        # One series per FRESH file (filename in the `file` label, value = the file's own mtime
        # unix seconds) -- extra_label (not target_label, which hardcodes the live-query label
        # name to "target") since the real label here is "file", same reasoning as
        # hci_csv_used_pct's own "volume" just above. Added 2026-10-06 for the Backup History
        # Report: backup_check_ok/backup_file_count (just above) were already archived but only
        # ever recorded the CHECK's own verdict/count, never which file or when -- this is what
        # lets that report show a real filename+timestamp per day, going forward from whenever
        # this entry first starts capturing (no retroactive history exists before that; see
        # generate_report.py's own capture_backups() docstring for why the "day" label itself
        # ("today"/"yesterday") is query-time-relative and not stored here).
        key="backup_file", kind="global", extra_label="file",
        bulk_promql="last_over_time((backup_file)[6h:1m])",   # same _stable() wrapping
                                                               # capture_backups() itself uses
                                                               # for this exact series (one
                                                               # missed scrape must not drop a
                                                               # file that's still genuinely
                                                               # fresh) -- backup_check_ok/
                                                               # backup_file_count above predate
                                                               # this convention and are left as
                                                               # they are, not retrofitted here.
        live_query_template='backup_file{{instance="{instance}",file="{target}"}}',
        source_ref="generate_report.py:capture_backups",
        used_by="Backup History Report (per-file name + timestamp archive)"),
    MetricRegistryEntry(
        # Estate-wide scalars, not per-instance -- a web link/SSL cert isn't owned by one
        # "instance" the way a host metric is (see assign_link's own system-attribution logic,
        # which is a DIFFERENT question from archival scope).
        key="web_link_down_count", kind="scalar",
        bulk_promql="count(probe_success == 0)",
        source_ref="generate_report.py:capture_links",
        used_by="System Health Report Web Links & SSL section"),
    MetricRegistryEntry(
        key="ssl_expiry_min_days", kind="scalar",
        bulk_promql="min((probe_ssl_earliest_cert_expiry - time()) / 86400)",
        source_ref="generate_report.py:capture_links",
        used_by="System Health Report Web Links & SSL section (earliest expiry, estate-wide)"),
]

#: Found in the 2026-09-30 full-report audit, deliberately NOT registered, with the specific
#: architectural reason each one doesn't fit this registry's "one static PromQL aggregate per
#: entry" shape -- these need a different mechanism, not a missed line item:
#:   - Service-state checks (generate_report.py SERVICE_CHECKS' ~34 win_service()/18 systemd()
#:     rows; network.py's four _*_SERVICES name-list templates for AD/HCI/Standalone/AD-Sync-
#:     Auth) -- "how many of THIS instance's OWN expected services are down" needs the Python-
#:     side expected-service-list context each caller already has (SERVICE_CHECKS/_AD_SERVICES/
#:     etc.), not a single instance-agnostic PromQL aggregate -- a bare windows_service_state
#:     count can't tell "service X isn't installed here" from "service X is down here" without
#:     that list. Needs a registry entry KIND this module doesn't have yet (a Python-computed
#:     value, not a raw PromQL query) -- a real follow-up, not a gap to paper over.
#:   - Flash/storage partitions (CISCO-FLASH-MIB) -- 5 separate column queries (name/size64/
#:     free64/size32/free32) that need combining into one used% per partition, and a device can
#:     have multiple partitions (another extra_label case) -- doable, not done in this pass.
#:   - BGP peer state -- confirmed live 2026-09-30: bgpPeerState returns ZERO rows anywhere in
#:     this estate (not "all healthy", genuinely no BGP peers configured/monitored at all) --
#:     nothing to register.
#:   - AD replication failure counts / NTP sync staleness (network.py's own per-DC templates) --
#:     same "needs the Python-side DC list" shape as the service-state checks above.
#:   - Host clock drift (generate_report.py capture_host_times) -- low priority, no report tile
#:     currently surfaces a clock-drift TREND, only a point-in-time check.
#:   - Bare `up`/reachability -- deliberately skipped: `up` means different things across many
#:     different job types (blackbox_http vs windows_exporter vs snmp vs postgres_exporter...),
#:     and this registry's simple `key:instance` archival scheme has no job dimension to keep
#:     those apart -- a real collision risk if the same instance string is ever scraped by two
#:     jobs, confirmed NOT worth the ambiguity given every other entry here already goes silent
#:     (no row that hour) for a genuinely-down instance, which is itself a usable signal.

#: NOT YET REGISTERED (2026-09-30 audit found these; deliberately left for a follow-up pass,
#: not rushed into the core set -- see this module's own docstring on why extensibility beats
#: a one-shot exhaustive migration):
#:   - Windows service-state checks (AD DC/HCI/Standalone/AD-Sync-Auth's four `_*_SERVICES`
#:     name lists in network.py, and generate_report.py's ~34 win_service()/18 systemd() rows
#:     in SERVICE_CHECKS) -- these currently return which services ARE running, not a ready-
#:     made "N down" count; turning that into a clean aggregate needs the expected-count
#:     context each caller already has in Python, not just a PromQL rewrite.
#:   - AD replication failure counts (network.py:_ad_replication_rows).
#:   - NTP sync staleness (network.py:_ntp_sync_row).
#:   - Web link probe success/SSL-expiry (generate_report.py:capture_links) -- estate-wide,
#:     genuinely useful, but a different shape again (per-URL, not per-instance).
#:   - Folder queue depths (folders.py) -- already has its own dashboard; low priority for a
#:     long-term archive since queue depth right now is rarely interesting hours later.

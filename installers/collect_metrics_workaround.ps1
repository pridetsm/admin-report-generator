# Perflib workaround LITE: collects only metrics NOT covered by windows_exporter's
# native collectors. Designed for servers running the FULL collector list
# (cpu, memory, logical_disk, physical_disk, net, os, service, system, tcp, textfile).
#
# Sections removed vs full script (already covered by native collectors):
#   - wmi_workaround_cpu_load_percent / windows_cpu_time_total  (cpu collector)
#   - wmi_workaround_memory_* / windows_memory_*                (memory collector)
#   - wmi_workaround_disk_* / windows_logical_disk_*            (logical_disk collector)
#   - wmi_workaround_service_running                            (service collector)
#   - wmi_workaround_tcp_connections_*                          (tcp collector)
#   - wmi_workaround_netadapter_up                              (net collector)

$ScriptStart = Get-Date

$TextfileDir = "C:\Program Files\windows_exporter\conf\textfile_inputs"
$OutFile     = "$TextfileDir\wmi_workaround_metrics.prom"
$TmpFile     = "$OutFile.tmp"

if (-not (Test-Path $TextfileDir)) {
    New-Item -ItemType Directory -Force -Path $TextfileDir | Out-Null
}

$lines = @()

# Helper: Prometheus text format requires backslashes AND quotes to be escaped in label
# values and HELP text. Backslashes must be escaped first, or escaping quotes afterward
# would double-escape the backslashes just added. A raw \ (e.g. in a path, a DOMAIN\user
# name, or "LocalMachine\My" in a HELP string) breaks the parser with "invalid escape
# sequence" and fails the WHOLE file, not just that line.
function Escape-PromText {
    param([string]$Text)
    return ($Text -replace '\\', '\\\\') -replace '"', '\"'
}

# --- HCI Cluster Health Service metrics (Get-ClusterPerf, S2D nodes only) ---
# On Storage Spaces Direct / HCI cluster nodes, Windows runs a Health Service that
# continuously collects real performance data (CPU, memory, network, storage) into its
# own database (the ClusterPerformanceHistory volume) - completely independent of the
# broken perflib/PDH counter subsystem. This is the SAME data Windows Admin Center's own
# HCI dashboard visualizes, and it is explicitly documented as scripting-friendly. Where
# available, this is a far better source than the WMI-approximation/kernel-API sections
# below - use it for CPU and memory in preference to those, and add the extra series
# (network bandwidth, storage capacity/IOPS/latency/throughput) it uniquely provides.
# Skips quietly on non-cluster hosts (e.g. the RBZ-HQ-ROOT domain controllers).
$hciPerfAvailable = $false
try {
    $nodeName = $env:computername
    $perfSamples = Get-ClusterNode -Name $nodeName -ErrorAction Stop | Get-ClusterPerf -ErrorAction Stop
    if ($perfSamples) {
        $hciPerfAvailable = $true

        # Get-ClusterPerf returns one CimInstance per metric series, where .MetricId is
        # the series name (e.g. "ClusterNode.Cpu.Usage") and .Records is an array of
        # timestamped samples, each with its own .TimeStamp and .Value. Build a lookup of
        # the LATEST record's value per series - this does NOT match the flat
        # Series/Value/Time columns shown by the default table display, which is
        # formatted output, not the actual object shape.
        #
        # IMPORTANT: .MetricId is NOT the plain series name alone - it includes a
        # trailing instance qualifier, e.g. "ClusterNode.Cpu.Usage,ClusterNode=HOSTNAME"
        # or "Volume.IOPS.Total,Volume=SomeVolumeName". Strip everything from the first
        # comma onward to get the plain series name used for lookups below.
        $perfLookup = @{}
        foreach ($sample in $perfSamples) {
            if ($sample.Records -and $sample.Records.Count -gt 0) {
                $latestRecord = $sample.Records | Sort-Object TimeStamp | Select-Object -Last 1
                $plainSeriesName = ($sample.MetricId -split ',')[0]
                $perfLookup[$plainSeriesName] = $latestRecord.Value
            }
        }

        function Add-HciGauge {
            param([string]$SeriesName, [string]$MetricName, [string]$Help)
            if ($perfLookup.ContainsKey($SeriesName)) {
                $val = $perfLookup[$SeriesName]
                $script:lines += "# HELP $MetricName $Help"
                $script:lines += "# TYPE $MetricName gauge"
                $script:lines += "$MetricName $val"
            }
        }

        Add-HciGauge "ClusterNode.Cpu.Usage" "windows_hci_cpu_usage_percent" "Node CPU usage percent via Health Service Get-ClusterPerf (perflib-independent)"
        Add-HciGauge "ClusterNode.Cpu.Usage.Guest" "windows_hci_cpu_usage_guest_percent" "Node CPU usage percent attributable to VM guests via Get-ClusterPerf"
        Add-HciGauge "ClusterNode.Cpu.Usage.Host" "windows_hci_cpu_usage_host_percent" "Node CPU usage percent attributable to the host itself via Get-ClusterPerf"

        Add-HciGauge "ClusterNode.Memory.Total" "windows_hci_memory_total_bytes" "Node total memory via Get-ClusterPerf"
        Add-HciGauge "ClusterNode.Memory.Available" "windows_hci_memory_available_bytes" "Node available memory via Get-ClusterPerf"
        Add-HciGauge "ClusterNode.Memory.Usage" "windows_hci_memory_usage_bytes" "Node memory in use via Get-ClusterPerf"
        Add-HciGauge "ClusterNode.Memory.Usage.Guest" "windows_hci_memory_usage_guest_bytes" "Node memory in use by VM guests via Get-ClusterPerf"
        Add-HciGauge "ClusterNode.Memory.Usage.Host" "windows_hci_memory_usage_host_bytes" "Node memory in use by the host itself via Get-ClusterPerf"

        Add-HciGauge "NetAdapter.Bandwidth.Inbound" "windows_hci_netadapter_bandwidth_inbound_bps" "Node inbound network bandwidth via Get-ClusterPerf"
        Add-HciGauge "NetAdapter.Bandwidth.Outbound" "windows_hci_netadapter_bandwidth_outbound_bps" "Node outbound network bandwidth via Get-ClusterPerf"
        Add-HciGauge "NetAdapter.Bandwidth.Total" "windows_hci_netadapter_bandwidth_total_bps" "Node total network bandwidth via Get-ClusterPerf"
        Add-HciGauge "NetAdapter.Bandwidth.RDMA.Total" "windows_hci_netadapter_bandwidth_rdma_total_bps" "Node total RDMA network bandwidth via Get-ClusterPerf"

        Add-HciGauge "PhysicalDisk.Capacity.Size.Total" "windows_hci_physicaldisk_capacity_total_bytes" "Node physical disk total capacity via Get-ClusterPerf"
        Add-HciGauge "PhysicalDisk.Capacity.Size.Used" "windows_hci_physicaldisk_capacity_used_bytes" "Node physical disk used capacity via Get-ClusterPerf"

        Add-HciGauge "VM.Memory.Maximum" "windows_hci_vm_memory_maximum_bytes" "Maximum memory assignable to VMs on this node via Get-ClusterPerf"

        Add-HciGauge "Volume.IOPS.Read" "windows_hci_volume_iops_read" "Cluster volume read IOPS via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.IOPS.Write" "windows_hci_volume_iops_write" "Cluster volume write IOPS via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.IOPS.Total" "windows_hci_volume_iops_total" "Cluster volume total IOPS via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.Latency.Read" "windows_hci_volume_latency_read_seconds" "Cluster volume read latency via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.Latency.Write" "windows_hci_volume_latency_write_seconds" "Cluster volume write latency via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.Latency.Average" "windows_hci_volume_latency_average_seconds" "Cluster volume average latency via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.Throughput.Read" "windows_hci_volume_throughput_read_bps" "Cluster volume read throughput via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.Throughput.Write" "windows_hci_volume_throughput_write_bps" "Cluster volume write throughput via Get-ClusterPerf (cluster-wide, not per-node)"
        Add-HciGauge "Volume.Throughput.Total" "windows_hci_volume_throughput_total_bps" "Cluster volume total throughput via Get-ClusterPerf (cluster-wide, not per-node)"

        # Volume.Size.* series are only available at cluster scope (MetricId qualifier is
        # ",Cluster=NAME" not ",ClusterNode=NAME") so they never appear in the per-node
        # Get-ClusterNode | Get-ClusterPerf query above. Query the cluster object directly
        # for these and build a separate lookup - all other series stay in $perfLookup.
        try {
            $clusterSamples = Get-Cluster -ErrorAction Stop | Get-ClusterPerf -ErrorAction Stop
            $clusterLookup = @{}
            foreach ($sample in $clusterSamples) {
                if ($sample.Records -and $sample.Records.Count -gt 0) {
                    $latestRecord = $sample.Records | Sort-Object TimeStamp | Select-Object -Last 1
                    $plainName = ($sample.MetricId -split ',')[0]
                    $clusterLookup[$plainName] = $latestRecord.Value
                }
            }
            if ($clusterLookup.ContainsKey("Volume.Size.Total")) {
                $lines += "# HELP windows_hci_volume_size_total_bytes Cluster total CSV/S2D volume capacity via Get-ClusterPerf (cluster-wide)"
                $lines += "# TYPE windows_hci_volume_size_total_bytes gauge"
                $lines += "windows_hci_volume_size_total_bytes $($clusterLookup['Volume.Size.Total'])"
            }
            if ($clusterLookup.ContainsKey("Volume.Size.Available")) {
                $lines += "# HELP windows_hci_volume_size_available_bytes Cluster available CSV/S2D volume capacity via Get-ClusterPerf (cluster-wide)"
                $lines += "# TYPE windows_hci_volume_size_available_bytes gauge"
                $lines += "windows_hci_volume_size_available_bytes $($clusterLookup['Volume.Size.Available'])"
            }
        } catch {
            $lines += "# cluster-wide volume size collection failed: $($_.Exception.Message)"
        }

        # --- Per CSV volume breakdown (Get-Volume, CSVFS only) ---
        # Get-ClusterPerf only exposes cluster-wide volume aggregates, not per-volume
        # breakdown. Get-Volume gives the per-volume figures matching what WAC shows in
        # its storage volumes table (FriendlyName/FileSystemLabel, Size, SizeRemaining).
        try {
            $csvVolumes = Get-Volume -ErrorAction Stop | Where-Object {
                ($_.FileSystemType -eq "CSVFS" -or $_.FileSystem -like "*CSVFS*") -or
                ($_.FileSystemLabel -eq "ClusterPerformanceHistory")
            }
            if ($csvVolumes) {
                $csvSizeLines      = @()
                $csvRemainingLines = @()
                $csvUsedPctLines   = @()

                foreach ($vol in $csvVolumes) {
                    $volName = Escape-PromText ($vol.FileSystemLabel.Trim())
                    if (-not $volName) { $volName = Escape-PromText ($vol.FriendlyName.Trim()) }
                    if (-not $volName) { continue }

                    $csvSizeLines      += "windows_hci_csv_volume_size_bytes{volume=`"$volName`"} $($vol.Size)"
                    $csvRemainingLines += "windows_hci_csv_volume_size_remaining_bytes{volume=`"$volName`"} $($vol.SizeRemaining)"

                    if ($vol.Size -gt 0) {
                        $usedPct = (($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100
                        $csvUsedPctLines += "windows_hci_csv_volume_used_percent{volume=`"$volName`"} $usedPct"
                    }
                }

                if ($csvSizeLines.Count -gt 0) {
                    $lines += "# HELP windows_hci_csv_volume_size_bytes Total size of each CSV volume in bytes via Get-Volume"
                    $lines += "# TYPE windows_hci_csv_volume_size_bytes gauge"
                    $lines += $csvSizeLines

                    $lines += "# HELP windows_hci_csv_volume_size_remaining_bytes Remaining space per CSV volume in bytes via Get-Volume"
                    $lines += "# TYPE windows_hci_csv_volume_size_remaining_bytes gauge"
                    $lines += $csvRemainingLines

                    $lines += "# HELP windows_hci_csv_volume_used_percent Percentage of CSV volume space used via Get-Volume"
                    $lines += "# TYPE windows_hci_csv_volume_used_percent gauge"
                    $lines += $csvUsedPctLines
                }
            }
        } catch {
            $lines += "# csv volume collection failed: $($_.Exception.Message)"
        }
    }
} catch {
    # Not a cluster node, FailoverClusters module unavailable, or Health Service not
    # running - skip quietly, this is expected on the non-HCI RBZ-HQ-ROOT domain
    # controllers and any other non-clustered host.
    $lines += "# HCI Get-ClusterPerf collection skipped: not a cluster node or Health Service unavailable ($($_.Exception.Message))"
}

# --- Failover Cluster metrics (root\MSCluster WMI namespace, not perflib) ---
# Only produces output if this server is an active cluster node; fails silently otherwise.
try {
    $clusterState = Get-CimInstance -Namespace root\MSCluster -ClassName MSCluster_Cluster -ErrorAction Stop
    $clusterName = Escape-PromText $clusterState.Name
    $lines += "# HELP wmi_workaround_cluster_up Whether this node can query the cluster via WMI (1=yes)"
    $lines += "# TYPE wmi_workaround_cluster_up gauge"
    $lines += "wmi_workaround_cluster_up{cluster=`"$clusterName`"} 1"

    $lines += "# HELP wmi_workaround_cluster_node_state Cluster node state (0=Up, 1=Down, 2=Paused, 3=Joining) via MSCluster_Node"
    $lines += "# TYPE wmi_workaround_cluster_node_state gauge"
    Get-CimInstance -Namespace root\MSCluster -ClassName MSCluster_Node -ErrorAction Stop | ForEach-Object {
        $nodeName = Escape-PromText $_.Name
        $lines += "wmi_workaround_cluster_node_state{node=`"$nodeName`"} $($_.State)"
    }

    $lines += "# HELP wmi_workaround_cluster_resource_state Cluster resource state (0=Inherited, 2=Online, 3=Offline, 4=Failed, etc) via MSCluster_Resource"
    $lines += "# TYPE wmi_workaround_cluster_resource_state gauge"
    Get-CimInstance -Namespace root\MSCluster -ClassName MSCluster_Resource -ErrorAction Stop | ForEach-Object {
        $resName = Escape-PromText $_.Name
        $resType = Escape-PromText $_.Type
        $lines += "wmi_workaround_cluster_resource_state{resource=`"$resName`",type=`"$resType`"} $($_.State)"
    }

    $lines += "# HELP wmi_workaround_cluster_resourcegroup_state Cluster resource group (role) state via MSCluster_ResourceGroup"
    $lines += "# TYPE wmi_workaround_cluster_resourcegroup_state gauge"
    Get-CimInstance -Namespace root\MSCluster -ClassName MSCluster_ResourceGroup -ErrorAction Stop | ForEach-Object {
        $grpName = Escape-PromText $_.Name
        $lines += "wmi_workaround_cluster_resourcegroup_state{group=`"$grpName`"} $($_.State)"
    }
} catch {
    # Not a cluster node, or clustering WMI namespace unavailable - skip quietly, this is expected on non-cluster hosts.
    $lines += "# cluster collection skipped: not a cluster node or MSCluster namespace unavailable ($($_.Exception.Message))"
}

# --- Hyper-V VM state (Get-VM, root\virtualization\v2 WMI namespace, not perflib) ---
# Only produces output if Hyper-V role is installed and the Hyper-V PowerShell module is
# present; fails silently otherwise, same pattern as the cluster section above.
try {
    $lines += "# HELP windows_hyperv_vm_state VM state via Get-VM (0=Other,1=Running,2=Off,3=Stopping,4=Saved,5=Paused,6=Starting,7=Reset,8=Saving,9=Pausing,10=Resuming)"
    $lines += "# TYPE windows_hyperv_vm_state gauge"
    Get-VM -ErrorAction Stop | ForEach-Object {
        $vmName = Escape-PromText $_.Name
        $stateNum = switch ($_.State) {
            'Running'  { 1 }
            'Off'      { 2 }
            'Stopping' { 3 }
            'Saved'    { 4 }
            'Paused'   { 5 }
            'Starting' { 6 }
            'Reset'    { 7 }
            'Saving'   { 8 }
            'Pausing'  { 9 }
            'Resuming' { 10 }
            default    { 0 }
        }
        $lines += "windows_hyperv_vm_state{vm=`"$vmName`"} $stateNum"
    }

    $lines += "# HELP windows_hyperv_vm_uptime_seconds VM uptime in seconds via Get-VM"
    $lines += "# TYPE windows_hyperv_vm_uptime_seconds gauge"
    Get-VM -ErrorAction Stop | ForEach-Object {
        $vmName = Escape-PromText $_.Name
        $uptimeSec = $_.Uptime.TotalSeconds
        $lines += "windows_hyperv_vm_uptime_seconds{vm=`"$vmName`"} $uptimeSec"
    }

    $lines += "# HELP windows_hyperv_vm_memory_assigned_bytes Memory currently assigned to VM in bytes via Get-VM"
    $lines += "# TYPE windows_hyperv_vm_memory_assigned_bytes gauge"
    Get-VM -ErrorAction Stop | ForEach-Object {
        $vmName = Escape-PromText $_.Name
        $lines += "windows_hyperv_vm_memory_assigned_bytes{vm=`"$vmName`"} $($_.MemoryAssigned)"
    }
} catch {
    # Hyper-V role/module not present, or no permission - skip quietly, expected on non-Hyper-V hosts.
    $lines += "# hyperv vm collection skipped: Hyper-V not present or inaccessible ($($_.Exception.Message))"
}

# --- Hyper-V Replica health (Get-VMReplication, same WMI namespace as above, not perflib) ---
# Only produces output on hosts with Hyper-V Replica configured; fails silently otherwise.
try {
    $lines += "# HELP windows_hyperv_replication_health Replication health via Get-VMReplication (0=Normal,1=Warning,2=Critical)"
    $lines += "# TYPE windows_hyperv_replication_health gauge"
    Get-VMReplication -ErrorAction Stop | ForEach-Object {
        $vmName = Escape-PromText $_.Name
        $healthNum = switch ($_.Health) {
            'Normal'   { 0 }
            'Warning'  { 1 }
            'Critical' { 2 }
            default    { 2 }
        }
        $lines += "windows_hyperv_replication_health{vm=`"$vmName`"} $healthNum"
    }

    $lines += "# HELP windows_hyperv_replication_last_sync_timestamp_seconds Unix timestamp of last successful replication via Get-VMReplication"
    $lines += "# TYPE windows_hyperv_replication_last_sync_timestamp_seconds gauge"
    Get-VMReplication -ErrorAction Stop | ForEach-Object {
        $vmName = Escape-PromText $_.Name
        if ($_.LastReplicationTime) {
            $lastSyncUnix = [int](($_.LastReplicationTime.ToUniversalTime() - [datetime]"1970-01-01T00:00:00Z").TotalSeconds)
        } else {
            $lastSyncUnix = 0
        }
        $lines += "windows_hyperv_replication_last_sync_timestamp_seconds{vm=`"$vmName`"} $lastSyncUnix"
    }
} catch {
    # Hyper-V Replica not configured, or cmdlet unavailable - skip quietly, expected on most hosts.
    $lines += "# hyperv replication collection skipped: not configured or inaccessible ($($_.Exception.Message))"
}

# --- Active Directory DS replication health (domain controllers only) ---
# This is separate from Hyper-V Replica above - AD DS replication is directory data
# syncing between domain controllers, not VM disaster-recovery replication.
#
# Uses Get-ADReplicationPartnerMetadata (ActiveDirectory module) rather than repadmin -
# repadmin's /replsummary does not support /csv on all Windows Server versions (confirmed:
# "This (null) command does not support Comma Separated Values (/csv) output mode" on this
# environment), and its plain-text table isn't reliably parseable. The PowerShell cmdlet
# returns real structured objects instead - same underlying data, no text/CSV parsing at
# all. Only produces output on domain controllers; skips quietly elsewhere (e.g. the
# HRE-HCIHOST cluster nodes, which are not DCs).
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $replMeta = Get-ADReplicationPartnerMetadata -Target $env:computername -Partition * -ErrorAction Stop

    if ($replMeta) {
        $lines += "# HELP windows_ad_replication_last_result Last replication result code per partner via Get-ADReplicationPartnerMetadata (0=success, non-zero=error code)"
        $lines += "# TYPE windows_ad_replication_last_result gauge"
        foreach ($r in $replMeta) {
            $partner = Escape-PromText $r.Partner
            $partition = Escape-PromText $r.Partition
            $lines += "windows_ad_replication_last_result{partner=`"$partner`",partition=`"$partition`"} $($r.LastReplicationResult)"
        }

        $lines += "# HELP windows_ad_replication_consecutive_failures Consecutive replication failures per partner via Get-ADReplicationPartnerMetadata"
        $lines += "# TYPE windows_ad_replication_consecutive_failures gauge"
        foreach ($r in $replMeta) {
            $partner = Escape-PromText $r.Partner
            $partition = Escape-PromText $r.Partition
            $lines += "windows_ad_replication_consecutive_failures{partner=`"$partner`",partition=`"$partition`"} $($r.ConsecutiveReplicationFailures)"
        }

        $lines += "# HELP windows_ad_replication_last_success_timestamp_seconds Unix timestamp of last successful replication per partner via Get-ADReplicationPartnerMetadata"
        $lines += "# TYPE windows_ad_replication_last_success_timestamp_seconds gauge"
        foreach ($r in $replMeta) {
            $partner = Escape-PromText $r.Partner
            $partition = Escape-PromText $r.Partition
            if ($r.LastReplicationSuccess) {
                $successUnix = [int](($r.LastReplicationSuccess.ToUniversalTime() - [datetime]"1970-01-01T00:00:00Z").TotalSeconds)
            } else {
                $successUnix = 0
            }
            $lines += "windows_ad_replication_last_success_timestamp_seconds{partner=`"$partner`",partition=`"$partition`"} $successUnix"
        }
    } else {
        $lines += "# ad replication collection skipped: Get-ADReplicationPartnerMetadata returned no data"
    }
} catch {
    # Not a domain controller, ActiveDirectory module unavailable, or no replication
    # partners configured - skip quietly, expected on non-DC hosts like the
    # HRE-HCIHOST cluster nodes.
    $lines += "# ad replication collection skipped: not a domain controller or ActiveDirectory module unavailable ($($_.Exception.Message))"
}

# --- Uptime / last boot time (direct WMI property) ---
try {
    $os2 = Get-CimInstance Win32_OperatingSystem
    $bootTime = $os2.LastBootUpTime
    if ($bootTime -and $bootTime -ne "-" -and $bootTime -ne "") {
        $uptimeSeconds = ((Get-Date) - $bootTime).TotalSeconds
        $lines += "# HELP wmi_workaround_uptime_seconds Seconds since last boot via WMI LastBootUpTime"
        $lines += "# TYPE wmi_workaround_uptime_seconds gauge"
        $lines += "wmi_workaround_uptime_seconds $uptimeSeconds"
    } else {
        $lines += "# uptime collection skipped: LastBootUpTime returned invalid value '$bootTime'"
    }
} catch {
    $lines += "# uptime collection failed: $($_.Exception.Message)"
}

# --- Certificate expiry (local machine cert store, not perflib) ---
try {
    # NOTE: "LocalMachine\My" is deliberately NOT written into this HELP text with a raw
    # backslash - that alone previously broke the whole file's parsing (invalid escape
    # sequence '\M'). HELP/TYPE comment text is subject to the same escaping rules as
    # label values in the Prometheus text format.
    $lines += "# HELP wmi_workaround_cert_expiry_seconds Certificate expiry as unix timestamp via LocalMachine cert store"
    $lines += "# TYPE wmi_workaround_cert_expiry_seconds gauge"
    Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | ForEach-Object {
        $thumb = Escape-PromText $_.Thumbprint
        $subj = Escape-PromText $_.Subject
        # Culture-invariant Unix-seconds conversion: -UFormat %s is locale-sensitive on
        # some PowerShell versions and can emit a fractional value using the culture's
        # decimal separator (e.g. "1735689600,25" on non-US locales), which is not a
        # valid Prometheus sample value. DateTimeOffset.ToUnixTimeSeconds() is invariant.
        $expiryUnix = [int](($_.NotAfter.ToUniversalTime() - [datetime]"1970-01-01T00:00:00Z").TotalSeconds)
        $lines += "wmi_workaround_cert_expiry_seconds{thumbprint=`"$thumb`",subject=`"$subj`"} $expiryUnix"
    }
} catch {
    $lines += "# certificate collection failed: $($_.Exception.Message)"
}

# --- Pending reboot flag (registry checks, not perflib) ---
try {
    $pendingReboot = 0
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $pendingReboot = 1 }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $pendingReboot = 1 }
    $pfro = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($pfro) { $pendingReboot = 1 }
    $lines += "# HELP wmi_workaround_pending_reboot Whether a reboot is pending (1=yes, 0=no) via registry checks"
    $lines += "# TYPE wmi_workaround_pending_reboot gauge"
    $lines += "wmi_workaround_pending_reboot $pendingReboot"
} catch {
    $lines += "# pending reboot collection failed: $($_.Exception.Message)"
}

# --- Process count and top CPU/memory processes (Get-Process, not perflib) ---
try {
    $procCount = (Get-Process | Measure-Object).Count
    $lines += "# HELP wmi_workaround_process_count Total running process count via Get-Process"
    $lines += "# TYPE wmi_workaround_process_count gauge"
    $lines += "wmi_workaround_process_count $procCount"

    $lines += "# HELP wmi_workaround_process_working_set_bytes Working set memory per top process via Get-Process"
    $lines += "# TYPE wmi_workaround_process_working_set_bytes gauge"
    Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 | ForEach-Object {
        $pname = Escape-PromText $_.ProcessName
        $lines += "wmi_workaround_process_working_set_bytes{process=`"$pname`",pid=`"$($_.Id)`"} $($_.WorkingSet64)"
    }
} catch {
    $lines += "# process collection failed: $($_.Exception.Message)"
}

# --- Windows Defender status (Get-MpComputerStatus, not perflib; skips quietly if Defender isn't in use) ---
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $rtEnabled = if ($mp.RealTimeProtectionEnabled) { 1 } else { 0 }
    $lines += "# HELP wmi_workaround_defender_realtime_protection_enabled Defender real-time protection state (1=enabled) via Get-MpComputerStatus"
    $lines += "# TYPE wmi_workaround_defender_realtime_protection_enabled gauge"
    $lines += "wmi_workaround_defender_realtime_protection_enabled $rtEnabled"
    $lines += "# HELP wmi_workaround_defender_signature_age_days Defender signature age in days via Get-MpComputerStatus"
    $lines += "# TYPE wmi_workaround_defender_signature_age_days gauge"
    $lines += "wmi_workaround_defender_signature_age_days $($mp.AntivirusSignatureAge)"
} catch {
    $lines += "# Defender status collection skipped: not present or inaccessible ($($_.Exception.Message))"
}

# --- Recent Error/Critical event log counts (Get-WinEvent, not perflib) ---
try {
    $since = (Get-Date).AddHours(-1)
    $appErrors = (Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=$since} -ErrorAction SilentlyContinue | Measure-Object).Count
    $sysErrors = (Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=$since} -ErrorAction SilentlyContinue | Measure-Object).Count
    $lines += "# HELP wmi_workaround_eventlog_errors_last_hour Error/Critical event count in the last hour via Get-WinEvent"
    $lines += "# TYPE wmi_workaround_eventlog_errors_last_hour gauge"
    $lines += "wmi_workaround_eventlog_errors_last_hour{log=`"Application`"} $appErrors"
    $lines += "wmi_workaround_eventlog_errors_last_hour{log=`"System`"} $sysErrors"
} catch {
    $lines += "# event log collection failed: $($_.Exception.Message)"
}

# --- Windows Time Service (w32tm /query /status, domain controllers only) ---
# Monitors NTP sync health - critical on DCs since time skew > 5 minutes breaks
# Kerberos authentication across the domain. Skips quietly on non-DC hosts where
# w32tm may not be running or relevant.
try {
    $w32tmOutput = & w32tm.exe /query /status 2>$null
    if ($w32tmOutput) {
        # Parse key fields from w32tm output lines
        $sourceStr = ($w32tmOutput | Select-String "Source:") -replace ".*Source:\s*", "" -replace "\s*$", ""
        $stratum   = ($w32tmOutput | Select-String "Stratum:") -replace ".*Stratum:\s*", "" -replace "\s*$", ""
        $lastSync  = ($w32tmOutput | Select-String "Last Successful Sync Time:") -replace ".*Last Successful Sync Time:\s*", "" -replace "\s*$", ""
        $pollInterval = ($w32tmOutput | Select-String "Poll Interval:") -replace ".*Poll Interval:\s*", "" -replace "\s*$", ""

        # Stratum as numeric gauge (1=primary, 2=secondary DC, etc; 16=unsynced)
        $stratumNum = 16
        if ($stratum -match '^\d+') { $stratumNum = [int]($stratum -replace '[^\d].*', '') }
        $lines += "# HELP wmi_workaround_w32tm_stratum NTP stratum level via w32tm (1=primary, 16=unsynced/error)"
        $lines += "# TYPE wmi_workaround_w32tm_stratum gauge"
        $lines += "wmi_workaround_w32tm_stratum $stratumNum"

        # Source as label
        $safeSource = Escape-PromText ($sourceStr.Trim())
        $lines += "# HELP wmi_workaround_w32tm_source_info NTP source info via w32tm (1=reporting only)"
        $lines += "# TYPE wmi_workaround_w32tm_source_info gauge"
        $lines += "wmi_workaround_w32tm_source_info{source=`"$safeSource`"} 1"

        # Last successful sync as Unix timestamp - parse as local time then convert to UTC
        if ($lastSync -and $lastSync -ne "" -and $lastSync -ne "unspecified") {
            try {
                $lastSyncDt = [datetime]::Parse($lastSync)
                $lastSyncUtc = $lastSyncDt.ToUniversalTime()
                $epoch = [datetime]::Parse("1970-01-01T00:00:00Z").ToUniversalTime()
                $lastSyncUnix = [int](($lastSyncUtc - $epoch).TotalSeconds)
                $lines += "# HELP wmi_workaround_w32tm_last_sync_timestamp_seconds Unix timestamp of last successful NTP sync via w32tm"
                $lines += "# TYPE wmi_workaround_w32tm_last_sync_timestamp_seconds gauge"
                $lines += "wmi_workaround_w32tm_last_sync_timestamp_seconds $lastSyncUnix"
            } catch {
                $lines += "# w32tm last sync time parse failed: $($_.Exception.Message)"
            }
        }

        # Seconds since last sync - computed in UTC to avoid timezone double-counting
        if ($lastSync -and $lastSync -ne "" -and $lastSync -ne "unspecified") {
            try {
                $lastSyncDt2 = [datetime]::Parse($lastSync).ToUniversalTime()
                $syncAgeSec = [int](((Get-Date).ToUniversalTime() - $lastSyncDt2).TotalSeconds)
                $lines += "# HELP wmi_workaround_w32tm_seconds_since_last_sync Seconds elapsed since last successful NTP sync via w32tm"
                $lines += "# TYPE wmi_workaround_w32tm_seconds_since_last_sync gauge"
                $lines += "wmi_workaround_w32tm_seconds_since_last_sync $syncAgeSec"
            } catch {
                $lines += "# w32tm sync age calculation failed: $($_.Exception.Message)"
            }
        }
    } else {
        $lines += "# w32tm collection skipped: w32tm /query /status returned no output"
    }
} catch {
    $lines += "# w32tm collection skipped: $($_.Exception.Message)"
}

# --- Last run timestamp and script duration (so staleness/health can be monitored in Prometheus) ---
# Same culture-invariant Unix-seconds conversion as the cert expiry section above.
$scriptDurationSeconds = ((Get-Date) - $ScriptStart).TotalSeconds
$lastRunUnix = [int](($ScriptStart.ToUniversalTime() - [datetime]"1970-01-01T00:00:00Z").TotalSeconds)
$lines += "# HELP wmi_workaround_last_run_timestamp_seconds Unix timestamp when this script last ran"
$lines += "# TYPE wmi_workaround_last_run_timestamp_seconds gauge"
$lines += "wmi_workaround_last_run_timestamp_seconds $lastRunUnix"
$lines += "# HELP wmi_workaround_script_duration_seconds How long this collection run took"
$lines += "# TYPE wmi_workaround_script_duration_seconds gauge"
$lines += "wmi_workaround_script_duration_seconds $scriptDurationSeconds"

# Write atomically: build in a temp file, then move into place.
# The textfile collector can read mid-write otherwise.
#
# Write atomically via temp file then move into place.
# Use -Encoding Ascii (safe for all Prometheus metric content which is pure ASCII)
# to avoid both the BOM that -Encoding UTF8 adds on PS 5.1 AND the .NET type
# constructor calls that Constrained Language Mode blocks.
$lines | Set-Content -Path $TmpFile -Encoding Ascii -Force
Move-Item -Path $TmpFile -Destination $OutFile -Force
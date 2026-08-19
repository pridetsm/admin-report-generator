namespace PrometheusIngest.Data;

// ----------------------------------------------------------------------------
//  CONFIG / TOPOLOGY  (synced from systems_config.yml — the source of truth)
// ----------------------------------------------------------------------------

/// <summary>A monitored system (RTGS, Temenos, ...). One row per `systems:` block.</summary>
public class MonitoredSystem
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public int DisplayOrder { get; set; }

    public List<Host> Hosts { get; set; } = new();
    public List<ServiceCheck> ServiceChecks { get; set; } = new();
    public List<LinkCheck> LinkChecks { get; set; } = new();
    public List<ReadingConfig> ReadingConfigs { get; set; } = new();

    /// <summary>OPTIONAL — null for a system with no `backups:` block.</summary>
    public BackupConfig? BackupConfig { get; set; }
}

/// <summary>A host row (a Prometheus target). Feeds the Memory, CPU and Disk tables.</summary>
public class Host
{
    public int Id { get; set; }
    public int SystemId { get; set; }
    public MonitoredSystem? System { get; set; }

    public string? Role { get; set; }
    public string Label { get; set; } = "";
    public string Instance { get; set; } = "";   // "ip:port"
    public string Os { get; set; } = "";          // "linux" | "windows"
}

/// <summary>A service health check spec (its per-poll result lands in ServiceStatusSample).</summary>
public class ServiceCheck
{
    public int Id { get; set; }
    public int SystemId { get; set; }
    public MonitoredSystem? System { get; set; }

    public string Name { get; set; } = "";
    public string Class { get; set; } = "system";   // "system" | "offered"
    public string CheckType { get; set; } = "";      // windows_service|systemd|host_up|http_probe|metric

    public string? Query { get; set; }
    public string? NameLabel { get; set; }
    public string? Service { get; set; }
    public string? Unit { get; set; }
    public string? UnitType { get; set; }
    public string? Instance { get; set; }
    public string? Target { get; set; }

    public List<ServiceMember> Members { get; set; } = new();
}

/// <summary>An expected member series for a `metric` check (e.g. a T24 TSA service name).</summary>
public class ServiceMember
{
    public int Id { get; set; }
    public int ServiceCheckId { get; set; }
    public ServiceCheck? ServiceCheck { get; set; }
    public string Name { get; set; } = "";
}

/// <summary>A web link (blackbox probe). SystemId is null for the "other" bucket.</summary>
public class LinkCheck
{
    public int Id { get; set; }
    public int? SystemId { get; set; }
    public MonitoredSystem? System { get; set; }
    public string Url { get; set; } = "";
}

/// <summary>A headline scalar reading spec, e.g. Key="cob", Expr="cob_time".</summary>
public class ReadingConfig
{
    public int Id { get; set; }
    public int SystemId { get; set; }
    public MonitoredSystem? System { get; set; }
    public string Key { get; set; } = "";
    public string Expr { get; set; } = "";
}

/// <summary>OPTIONAL backup monitoring config. One (or none) per system.</summary>
public class BackupConfig
{
    public int Id { get; set; }
    public int SystemId { get; set; }
    public MonitoredSystem? System { get; set; }
    public string Instance { get; set; } = "";
    public string? Tracks { get; set; }

    /// <summary>How many calendar days old this host's newest backup may be and still count as
    /// CURRENT. Null = daily default (today or yesterday). Set this for a host that backs up on
    /// a slower cycle (e.g. every 3rd day), otherwise the days between its runs are misreported
    /// as NO BACKUP even though the policy is being met — mirrors BACKUP_MAX_AGE_DAYS in
    /// send_report/generate_report.py; keep the two in step.</summary>
    public int? MaxAgeDays { get; set; }
}

// ----------------------------------------------------------------------------
//  SAMPLES  (one set per PollRun — the time series captured from Prometheus)
// ----------------------------------------------------------------------------

public enum PollStatus { Running = 0, Succeeded = 1, Failed = 2 }

/// <summary>One capture cycle. Groups every *Sample row written during that poll.</summary>
public class PollRun
{
    public long Id { get; set; }
    public DateTime StartedAt { get; set; }        // UTC
    public DateTime? CompletedAt { get; set; }     // UTC
    public string PromUrl { get; set; } = "";
    public PollStatus Status { get; set; }
    public string? Error { get; set; }
    public int SystemsPolled { get; set; }
    public int SamplesWritten { get; set; }
    public int AttentionImmediate { get; set; }
    public int AttentionWatch { get; set; }
}

public class DiskSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int HostId { get; set; }
    public string Mountpoint { get; set; } = "";   // linux mountpoint or windows volume
    public double? UsedPct { get; set; }
    public double? FreeGb { get; set; }
    public double? SizeGb { get; set; }
}

public class MemorySample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int HostId { get; set; }
    public double UsedPct { get; set; }
}

public class CpuSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int HostId { get; set; }
    public double UsedPct { get; set; }            // CPU busy % (100 - idle, 5-min avg)
}

public class HostReachabilitySample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int HostId { get; set; }
    public bool IsUp { get; set; }                 // Prometheus `up` >= 1
}

public class ServiceStatusSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int ServiceCheckId { get; set; }
    public string MemberName { get; set; } = "";   // the concrete service (== check name for single-named checks)
    public bool IsUp { get; set; }
}

public class LinkProbeSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int LinkCheckId { get; set; }
    public bool IsUp { get; set; }
    public int? HttpCode { get; set; }
    public bool? Ssl { get; set; }
    public double? CertDays { get; set; }
    public string? TlsVersion { get; set; }
    public double? DurationSeconds { get; set; }
}

// -- Backup samples: OPTIONAL data. Written ONLY for systems with a BackupConfig. --
public class BackupFileSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int BackupConfigId { get; set; }
    public string FileName { get; set; } = "";
    public string? Day { get; set; }               // "today" | "yesterday" | ...
    public double MtimeUnix { get; set; }          // file mtime (unix secs) = when it was generated
    public bool IsFresh { get; set; }              // mtime >= host's cutoff (yesterday-midnight, or wider per BackupConfig.MaxAgeDays)
}

public class BackupCheckSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int BackupConfigId { get; set; }
    public int? FileCount { get; set; }
    public bool? Success { get; set; }             // backup_check_success
    public double? CheckTimestampUnix { get; set; }
    public bool AnyFresh { get; set; }             // did the host have >= 1 fresh file this poll?
}

public class ReadingSample
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public int SystemId { get; set; }
    public string Key { get; set; } = "";          // "cob" | "swift"
    public double? Value { get; set; }
}

/// <summary>
/// The derived, human-facing verdict per poll: the report's two-band model.
/// Severity is "Immediate" (failing now) or "Watch" (degrading, not yet failing).
/// </summary>
public class AttentionItem
{
    public long Id { get; set; }
    public long PollRunId { get; set; }
    public string Severity { get; set; } = "";     // "Immediate" | "Watch"
    public string Category { get; set; } = "";     // MissingBackup|Unreachable|ServiceDown|DiskNearFull|HighDisk|HighRam|HighCpu|SslExpiry|LinkDown|UntrackedBackup
    public string SystemName { get; set; } = "";
    public string? HostLabel { get; set; }
    public string Detail { get; set; } = "";
}

using YamlDotNet.Serialization;

namespace PrometheusIngest.Config;

/// <summary>
/// Object model for systems_config.yml — the single source of truth. Mirrors the
/// keys documented in that file's header. Every system has hosts/services/links/
/// readings; `backups` is OPTIONAL (null for systems without backup monitoring).
/// </summary>
public sealed class SystemsConfig
{
    public Dictionary<string, SystemDef> Systems { get; set; } = new();

    /// <summary>The "other / unassigned" bucket (hosts + links with no home system).</summary>
    public SystemDef? Other { get; set; }
}

public sealed class SystemDef
{
    public List<HostDef> Hosts { get; set; } = new();
    public List<ServiceDef> Services { get; set; } = new();
    public List<string> Links { get; set; } = new();

    /// <summary>Headline scalars, e.g. { cob: "cob_time", swift: "swift_transactions_total" }.</summary>
    public Dictionary<string, string> Readings { get; set; } = new();

    /// <summary>OPTIONAL backup monitoring. Null / empty means this system has no backups.</summary>
    public BackupDef? Backups { get; set; }
}

public sealed class HostDef
{
    public string? Role { get; set; }
    public string Label { get; set; } = "";
    public string Instance { get; set; } = "";
    public string Os { get; set; } = "";
}

public sealed class ServiceDef
{
    public string Name { get; set; } = "";
    public string Class { get; set; } = "system";
    public CheckDef Check { get; set; } = new();
}

public sealed class CheckDef
{
    public string Type { get; set; } = "";

    // windows_service / systemd / host_up
    public string? Instance { get; set; }
    public string? Service { get; set; }
    public string? Unit { get; set; }

    [YamlMember(Alias = "unit_type")]
    public string? UnitType { get; set; }

    // http_probe
    public string? Target { get; set; }

    // metric (raw PromQL escape hatch)
    public string? Query { get; set; }

    [YamlMember(Alias = "name_label")]
    public string? NameLabel { get; set; }

    public List<string> Members { get; set; } = new();
}

public sealed class BackupDef
{
    public string Instance { get; set; } = "";
    public string? Tracks { get; set; }

    /// <summary>OPTIONAL. How many calendar days old the newest backup may be and still count
    /// as current. Omit for the daily default (today or yesterday); set it for a host that
    /// backs up on a slower cycle (e.g. every 3rd day).</summary>
    [YamlMember(Alias = "max_age_days")]
    public int? MaxAgeDays { get; set; }

    public bool IsEmpty => string.IsNullOrWhiteSpace(Instance);
}

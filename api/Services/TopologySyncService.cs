using Microsoft.EntityFrameworkCore;
using PrometheusIngest.Config;
using PrometheusIngest.Data;
using Host = PrometheusIngest.Data.Host;   // disambiguate from Microsoft.Extensions.Hosting.Host

namespace PrometheusIngest.Services;

/// <summary>
/// Upserts the config/topology tables from systems_config.yml. Idempotent: matches
/// on natural keys (system name, host instance, service name, link url, reading key)
/// and reconciles adds/updates/removes so the DB always mirrors the YAML.
/// </summary>
public sealed class TopologySyncService
{
    public const string UnassignedSystem = "(unassigned)";

    private readonly MonitoringDbContext _db;
    private readonly ILogger<TopologySyncService> _log;

    public TopologySyncService(MonitoringDbContext db, ILogger<TopologySyncService> log)
    {
        _db = db;
        _log = log;
    }

    public async Task SyncAsync(SystemsConfig cfg, CancellationToken ct)
    {
        var defs = new List<(string Name, SystemDef Def)>();
        foreach (var kv in cfg.Systems) defs.Add((kv.Key, kv.Value));
        if (cfg.Other is { } other) defs.Add((UnassignedSystem, other));

        var order = 0;
        var wantedNames = defs.Select(d => d.Name).ToHashSet();

        foreach (var (name, def) in defs)
        {
            var sys = await _db.Systems
                .Include(s => s.Hosts)
                .Include(s => s.ServiceChecks).ThenInclude(sc => sc.Members)
                .Include(s => s.LinkChecks)
                .Include(s => s.ReadingConfigs)
                .Include(s => s.BackupConfig)
                .FirstOrDefaultAsync(s => s.Name == name, ct);

            if (sys is null)
            {
                sys = new MonitoredSystem { Name = name };
                _db.Systems.Add(sys);
            }
            sys.DisplayOrder = order++;

            ReconcileHosts(sys, def.Hosts);
            ReconcileServices(sys, def.Services);
            ReconcileLinks(sys, def.Links);
            ReconcileReadings(sys, def.Readings);
            ReconcileBackups(sys, def.Backups);
        }

        // drop systems that no longer exist in the YAML (cascades to their children)
        var stale = await _db.Systems.Where(s => !wantedNames.Contains(s.Name)).ToListAsync(ct);
        if (stale.Count > 0) _db.Systems.RemoveRange(stale);

        var changes = await _db.SaveChangesAsync(ct);
        _log.LogInformation("Topology sync: {Count} systems, {Changes} row change(s)", defs.Count, changes);
    }

    private static void ReconcileHosts(MonitoredSystem sys, List<HostDef> want)
    {
        sys.Hosts.RemoveAll(h => want.All(w => w.Instance != h.Instance));
        foreach (var w in want)
        {
            var h = sys.Hosts.FirstOrDefault(x => x.Instance == w.Instance);
            if (h is null) { h = new Host { Instance = w.Instance }; sys.Hosts.Add(h); }
            h.Role = w.Role;
            h.Label = w.Label;
            h.Os = w.Os;
        }
    }

    private static void ReconcileServices(MonitoredSystem sys, List<ServiceDef> want)
    {
        sys.ServiceChecks.RemoveAll(s => want.All(w => w.Name != s.Name));
        foreach (var w in want)
        {
            var sc = sys.ServiceChecks.FirstOrDefault(x => x.Name == w.Name);
            if (sc is null) { sc = new ServiceCheck { Name = w.Name }; sys.ServiceChecks.Add(sc); }
            sc.Class = w.Class;
            sc.CheckType = w.Check.Type;
            sc.Query = w.Check.Query;
            sc.NameLabel = w.Check.NameLabel;
            sc.Service = w.Check.Service;
            sc.Unit = w.Check.Unit;
            sc.UnitType = w.Check.UnitType;
            sc.Instance = w.Check.Instance;
            sc.Target = w.Check.Target;

            var members = w.Check.Members ?? new List<string>();
            sc.Members.RemoveAll(m => !members.Contains(m.Name));
            foreach (var mname in members)
                if (sc.Members.All(m => m.Name != mname))
                    sc.Members.Add(new ServiceMember { Name = mname });
        }
    }

    private static void ReconcileLinks(MonitoredSystem sys, List<string> want)
    {
        sys.LinkChecks.RemoveAll(l => !want.Contains(l.Url));
        foreach (var url in want)
            if (sys.LinkChecks.All(l => l.Url != url))
                sys.LinkChecks.Add(new LinkCheck { Url = url });
    }

    private static void ReconcileReadings(MonitoredSystem sys, Dictionary<string, string> want)
    {
        sys.ReadingConfigs.RemoveAll(r => !want.ContainsKey(r.Key));
        foreach (var (key, expr) in want)
        {
            var rc = sys.ReadingConfigs.FirstOrDefault(x => x.Key == key);
            if (rc is null) { rc = new ReadingConfig { Key = key }; sys.ReadingConfigs.Add(rc); }
            rc.Expr = expr;
        }
    }

    private void ReconcileBackups(MonitoredSystem sys, BackupDef? want)
    {
        if (want is null || want.IsEmpty)
        {
            if (sys.BackupConfig is not null) { _db.BackupConfigs.Remove(sys.BackupConfig); sys.BackupConfig = null; }
            return;
        }
        sys.BackupConfig ??= new BackupConfig();
        sys.BackupConfig.Instance = want.Instance;
        sys.BackupConfig.Tracks = want.Tracks;
        sys.BackupConfig.MaxAgeDays = want.MaxAgeDays;
    }
}

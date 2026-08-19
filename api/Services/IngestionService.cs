using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PrometheusIngest.Config;
using PrometheusIngest.Data;
using PrometheusIngest.Options;
using PrometheusIngest.Prometheus;

namespace PrometheusIngest.Services;

/// <summary>
/// One capture cycle: (optionally) sync topology, query Prometheus for every signal
/// described in systems_config.yml, write one set of *Sample rows under a PollRun,
/// and derive the two-band AttentionItems exactly as the xlsx report does.
/// </summary>
public sealed class IngestionService
{
    private sealed class DiskAgg { public double? Used, Free, Size; }
    private sealed class LinkAgg { public bool? Up; public int? Code; public bool? Ssl; public double? CertDays, Duration; public string? Tls; }
    private sealed class BackupAgg { public readonly List<(string File, string Day, double Mtime)> Files = new(); public int? Count; public bool? Ok; public double? Ts; }

    private readonly MonitoringDbContext _db;
    private readonly IPrometheusClient _prom;
    private readonly ISystemsConfigLoader _configLoader;
    private readonly TopologySyncService _topology;
    private readonly ThresholdOptions _thr;
    private readonly IngestOptions _ingest;
    private readonly string _promUrl;
    private readonly ILogger<IngestionService> _log;

    public IngestionService(
        MonitoringDbContext db, IPrometheusClient prom, ISystemsConfigLoader configLoader,
        TopologySyncService topology, IOptions<ThresholdOptions> thr, IOptions<IngestOptions> ingest,
        IOptions<PrometheusOptions> prometheus, ILogger<IngestionService> log)
    {
        _db = db;
        _prom = prom;
        _configLoader = configLoader;
        _topology = topology;
        _thr = thr.Value;
        _ingest = ingest.Value;
        _promUrl = prometheus.Value.BaseUrl;
        _log = log;
    }

    public async Task<PollRun> RunAsync(CancellationToken ct)
    {
        if (_ingest.SyncTopologyEachRun)
            await _topology.SyncAsync(_configLoader.Load(), ct);

        var run = new PollRun { StartedAt = DateTime.UtcNow, PromUrl = _promUrl, Status = PollStatus.Running };
        _db.PollRuns.Add(run);
        await _db.SaveChangesAsync(ct);   // get run.Id

        try
        {
            var disk = await BuildDiskAsync(ct);
            var ram = await BuildRamAsync(ct);
            var cpu = await BuildCpuAsync(ct);
            var up = await BuildUpAsync(ct);
            var links = await BuildLinksAsync(ct);
            var backups = await BuildBackupsAsync(ct);

            var systems = await _db.Systems
                .Include(s => s.Hosts)
                .Include(s => s.ServiceChecks).ThenInclude(sc => sc.Members)
                .Include(s => s.LinkChecks)
                .Include(s => s.ReadingConfigs)
                .Include(s => s.BackupConfig)
                .AsNoTracking()
                .OrderBy(s => s.DisplayOrder)
                .ToListAsync(ct);

            var samples = 0;
            var attention = new List<AttentionItem>();
            var todayMid = ((DateTimeOffset)DateTime.Now.Date).ToUnixTimeSeconds();  // local midnight today
            var missingBackupSeverity = AttentionClassifier.MissingBackupSeverity(DateTime.Now.DayOfWeek);

            foreach (var sys in systems)
            {
                // ---- hosts: disk, memory, reachability -------------------------------
                foreach (var host in sys.Hosts)
                {
                    var unreachable = up.TryGetValue(host.Instance, out var upv) && upv < 1;
                    if (up.TryGetValue(host.Instance, out var reach))
                    {
                        _db.HostReachabilitySamples.Add(new HostReachabilitySample
                        { PollRunId = run.Id, HostId = host.Id, IsUp = reach >= 1 });
                        samples++;
                    }
                    if (unreachable)
                    {
                        attention.Add(Item(run.Id, Severity.Immediate, Category.Unreachable, sys.Name, host.Label,
                            "exporter unreachable — host down / network?"));
                        continue;   // down host: skip its metric-level disk/ram signals
                    }

                    double peakDisk = double.NegativeInfinity; string? peakMount = null;
                    if (disk.TryGetValue(host.Instance, out var mounts))
                    {
                        foreach (var (mount, agg) in mounts)
                        {
                            _db.DiskSamples.Add(new DiskSample
                            { PollRunId = run.Id, HostId = host.Id, Mountpoint = mount, UsedPct = agg.Used, FreeGb = agg.Free, SizeGb = agg.Size });
                            samples++;
                            if (agg.Used is { } u && u > peakDisk) { peakDisk = u; peakMount = mount; }
                        }
                    }
                    if (peakMount is not null && AttentionClassifier.DiskBand(peakDisk, _thr) is { } dband)
                    {
                        var cat = dband == Severity.Immediate ? Category.DiskNearFull : Category.HighDisk;
                        attention.Add(Item(run.Id, dband, cat, sys.Name, host.Label, $"{peakMount} {peakDisk:0}% used"));
                    }

                    if (ram.TryGetValue(host.Instance, out var ramv))
                    {
                        _db.MemorySamples.Add(new MemorySample { PollRunId = run.Id, HostId = host.Id, UsedPct = ramv });
                        samples++;
                        if (AttentionClassifier.RamBand(ramv, _thr) is { } rband)
                            attention.Add(Item(run.Id, rband, Category.HighRam, sys.Name, host.Label, $"{ramv:0}% used"));
                    }

                    if (cpu.TryGetValue(host.Instance, out var cpuv))
                    {
                        _db.CpuSamples.Add(new CpuSample { PollRunId = run.Id, HostId = host.Id, UsedPct = cpuv });
                        samples++;
                        if (AttentionClassifier.CpuBand(cpuv, _thr) is { } cband)
                            attention.Add(Item(run.Id, cband, Category.HighCpu, sys.Name, host.Label, $"{cpuv:0}% busy"));
                    }
                }

                // ---- services --------------------------------------------------------
                foreach (var sc in sys.ServiceChecks)
                {
                    var expr = PromQueries.ServiceSubExpr(sc);
                    if (expr is null) continue;
                    var res = await _prom.QueryAsync(expr, ct);

                    if (PromQueries.IsMultiMember(sc))
                    {
                        var seen = new HashSet<string>(StringComparer.Ordinal);
                        foreach (var s in res)
                        {
                            var member = s.Label("service");
                            if (string.IsNullOrEmpty(member) || !seen.Add(member)) continue;
                            var isUp = s.Value >= 1;
                            _db.ServiceStatusSamples.Add(new ServiceStatusSample
                            { PollRunId = run.Id, ServiceCheckId = sc.Id, MemberName = member, IsUp = isUp });
                            samples++;
                            if (!isUp) attention.Add(Item(run.Id, Severity.Immediate, Category.ServiceDown, sys.Name, member, "DOWN"));
                        }
                    }
                    else
                    {
                        var isUp = res.Any(s => s.Value >= 1);   // single-named: a row means running
                        _db.ServiceStatusSamples.Add(new ServiceStatusSample
                        { PollRunId = run.Id, ServiceCheckId = sc.Id, MemberName = sc.Name, IsUp = isUp });
                        samples++;
                        if (!isUp) attention.Add(Item(run.Id, Severity.Immediate, Category.ServiceDown, sys.Name, sc.Name, "DOWN"));
                    }
                }

                // ---- links (blackbox probes) ----------------------------------------
                foreach (var lc in sys.LinkChecks)
                {
                    var agg = FindLink(links, lc.Url);
                    if (agg is null) continue;   // no probe data -> neutral, no sample
                    _db.LinkProbeSamples.Add(new LinkProbeSample
                    {
                        PollRunId = run.Id, LinkCheckId = lc.Id, IsUp = agg.Up ?? false,
                        HttpCode = agg.Code, Ssl = agg.Ssl, CertDays = agg.CertDays, TlsVersion = agg.Tls, DurationSeconds = agg.Duration
                    });
                    samples++;

                    var host = Display(lc.Url);
                    if (agg.Up == false)
                        attention.Add(Item(run.Id, Severity.Immediate, Category.LinkDown, sys.Name, host,
                            "DOWN" + (agg.Code is { } c ? $" (HTTP {c})" : "")));
                    if (agg.CertDays is { } cd && AttentionClassifier.SslBand(cd, _thr) is { } sband)
                        attention.Add(Item(run.Id, sband, Category.SslExpiry, sys.Name, host,
                            cd < 0 ? $"EXPIRED {Math.Abs(cd):0} day(s) ago" : $"expires in {cd:0} day(s)"));
                }

                // ---- readings (headline scalars) ------------------------------------
                foreach (var rc in sys.ReadingConfigs)
                {
                    var val = await _prom.ScalarAsync(rc.Expr, ct);
                    _db.ReadingSamples.Add(new ReadingSample { PollRunId = run.Id, SystemId = sys.Id, Key = rc.Key, Value = val });
                    samples++;
                }

                // ---- backups (OPTIONAL — only systems with a BackupConfig) -----------
                if (sys.BackupConfig is { } bc)
                {
                    // daily for almost every host (mtime >= yesterday-midnight); wider where the
                    // policy says so (e.g. BSA backs up every 3rd day, not daily) - otherwise the
                    // days between a slower host's runs are misreported as NO BACKUP even though
                    // the policy is being met. Mirrors backup_cutoff() in generate_report.py.
                    var cutoff = todayMid - 86400L * (bc.MaxAgeDays ?? 1);
                    backups.TryGetValue(bc.Instance, out var bagg);
                    var anyFresh = false;
                    if (bagg is not null)
                    {
                        foreach (var (file, day, mtime) in bagg.Files)
                        {
                            var fresh = mtime >= cutoff;
                            anyFresh |= fresh;
                            _db.BackupFileSamples.Add(new BackupFileSample
                            { PollRunId = run.Id, BackupConfigId = bc.Id, FileName = file, Day = day, MtimeUnix = mtime, IsFresh = fresh });
                            samples++;
                        }
                    }
                    _db.BackupCheckSamples.Add(new BackupCheckSample
                    {
                        PollRunId = run.Id, BackupConfigId = bc.Id,
                        FileCount = bagg?.Count, Success = bagg?.Ok, CheckTimestampUnix = bagg?.Ts, AnyFresh = anyFresh
                    });
                    samples++;

                    if (!anyFresh)
                    {
                        var reason = bagg?.Ok == false ? "FOLDER UNREADABLE" : "NO BACKUP";
                        // one row per host on this system that carries the backup instance
                        var host = sys.Hosts.FirstOrDefault(h => h.Instance == bc.Instance)?.Label ?? bc.Instance;
                        attention.Add(Item(run.Id, missingBackupSeverity, Category.MissingBackup, sys.Name, host, reason));
                    }
                }
                else
                {
                    // no backup monitoring configured at all — a blind spot, mirrors the report's
                    // UNTRACKED BACKUPS tile. Distinct from MissingBackup (which is a configured
                    // host that produced nothing fresh).
                    attention.Add(Item(run.Id, Severity.Watch, Category.UntrackedBackup, sys.Name, null,
                        "no backup check configured"));
                }
            }

            _db.AttentionItems.AddRange(attention);
            run.SamplesWritten = samples;
            run.SystemsPolled = systems.Count;
            run.AttentionImmediate = attention.Count(a => a.Severity == Severity.Immediate);
            run.AttentionWatch = attention.Count(a => a.Severity == Severity.Watch);
            run.Status = PollStatus.Succeeded;
            run.CompletedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct);

            _log.LogInformation("Poll #{Id}: {Systems} systems, {Samples} samples, {Imm} immediate / {Watch} watch",
                run.Id, run.SystemsPolled, run.SamplesWritten, run.AttentionImmediate, run.AttentionWatch);
            return run;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Poll #{Id} failed", run.Id);
            run.Status = PollStatus.Failed;
            run.Error = ex.Message;
            run.CompletedAt = DateTime.UtcNow;
            try { await _db.SaveChangesAsync(CancellationToken.None); } catch { /* best effort */ }
            throw;
        }
    }

    // ---- lookup builders (each mirrors capture() in generate_report.py) ----

    private async Task<Dictionary<string, Dictionary<string, DiskAgg>>> BuildDiskAsync(CancellationToken ct)
    {
        var disk = new Dictionary<string, Dictionary<string, DiskAgg>>(StringComparer.Ordinal);
        void Index(IReadOnlyList<PromSeries> res, Action<DiskAgg, double> set, string keyLabel)
        {
            foreach (var s in res)
            {
                var inst = s.Instance; var key = s.Label(keyLabel);
                if (inst is null || key is null) continue;
                if (!disk.TryGetValue(inst, out var mounts)) disk[inst] = mounts = new(StringComparer.Ordinal);
                if (!mounts.TryGetValue(key, out var agg)) mounts[key] = agg = new DiskAgg();
                set(agg, s.Value);
            }
        }
        Index(await _prom.QueryAsync(PromQueries.LinuxDiskUsed, ct), (a, v) => a.Used = v, "mountpoint");
        Index(await _prom.QueryAsync(PromQueries.LinuxDiskFree, ct), (a, v) => a.Free = v, "mountpoint");
        Index(await _prom.QueryAsync(PromQueries.LinuxDiskSize, ct), (a, v) => a.Size = v, "mountpoint");
        Index(await _prom.QueryAsync(PromQueries.WinDiskUsed, ct), (a, v) => a.Used = v, "volume");
        Index(await _prom.QueryAsync(PromQueries.WinDiskFree, ct), (a, v) => a.Free = v, "volume");
        Index(await _prom.QueryAsync(PromQueries.WinDiskSize, ct), (a, v) => a.Size = v, "volume");
        return disk;
    }

    private async Task<Dictionary<string, double>> BuildRamAsync(CancellationToken ct)
    {
        var ram = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var s in await _prom.QueryAsync(PromQueries.LinuxMem, ct)) if (s.Instance is { } i) ram[i] = s.Value;
        foreach (var s in await _prom.QueryAsync(PromQueries.WinMem, ct)) if (s.Instance is { } i) ram[i] = s.Value;
        return ram;
    }

    private async Task<Dictionary<string, double>> BuildCpuAsync(CancellationToken ct)
    {
        var cpu = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var s in await _prom.QueryAsync(PromQueries.LinuxCpu, ct)) if (s.Instance is { } i) cpu[i] = s.Value;
        foreach (var s in await _prom.QueryAsync(PromQueries.WinCpu, ct)) if (s.Instance is { } i) cpu[i] = s.Value;
        return cpu;
    }

    private async Task<Dictionary<string, double>> BuildUpAsync(CancellationToken ct)
    {
        var up = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var s in await _prom.QueryAsync(PromQueries.Up, ct)) if (s.Instance is { } i) up[i] = s.Value;
        return up;
    }

    private async Task<Dictionary<string, LinkAgg>> BuildLinksAsync(CancellationToken ct)
    {
        var links = new Dictionary<string, LinkAgg>(StringComparer.Ordinal);
        LinkAgg Slot(string url) => links.TryGetValue(url, out var a) ? a : links[url] = new LinkAgg();
        async Task Index(string expr, Action<LinkAgg, PromSeries> set)
        {
            foreach (var s in await _prom.QueryAsync(expr, ct))
                if (s.Instance is { } inst && IsUrl(inst)) set(Slot(inst), s);
        }
        await Index(PromQueries.ProbeSuccess, (a, s) => a.Up = s.Value >= 1);
        await Index(PromQueries.ProbeHttpCode, (a, s) => a.Code = (int)s.Value);
        await Index(PromQueries.ProbeHttpSsl, (a, s) => a.Ssl = s.Value >= 1);
        await Index(PromQueries.ProbeCertDays, (a, s) => a.CertDays = s.Value);
        await Index(PromQueries.ProbeDuration, (a, s) => a.Duration = s.Value);
        await Index(PromQueries.ProbeTlsInfo, (a, s) => a.Tls = s.Label("version"));
        return links;
    }

    private async Task<Dictionary<string, BackupAgg>> BuildBackupsAsync(CancellationToken ct)
    {
        var backups = new Dictionary<string, BackupAgg>(StringComparer.Ordinal);
        BackupAgg Slot(string inst) => backups.TryGetValue(inst, out var a) ? a : backups[inst] = new BackupAgg();
        async Task Scan(string expr, Action<BackupAgg, PromSeries> apply)
        {
            foreach (var s in await _prom.QueryAsync(expr, ct))
                if (s.Instance is { } inst) apply(Slot(inst), s);
        }
        await Scan(PromQueries.BackupFile, (d, r) => d.Files.Add((r.Label("file") ?? "", r.Label("day") ?? "", r.Value)));
        await Scan(PromQueries.BackupFileCount, (d, r) => d.Count = (int)r.Value);
        await Scan(PromQueries.BackupSuccess, (d, r) => d.Ok = r.Value >= 1);
        await Scan(PromQueries.BackupTimestamp, (d, r) => d.Ts = r.Value);
        return backups;
    }

    private static bool IsUrl(string s) => s.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                                        || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    private static LinkAgg? FindLink(Dictionary<string, LinkAgg> links, string url)
    {
        if (links.TryGetValue(url, out var a)) return a;
        var alt = url.EndsWith('/') ? url.TrimEnd('/') : url + "/";
        return links.TryGetValue(alt, out var b) ? b : null;
    }

    private static string Display(string url)
    {
        var s = System.Text.RegularExpressions.Regex.Replace(url, "^https?://", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return s.TrimEnd('/');
    }

    private static AttentionItem Item(long runId, string sev, string cat, string system, string? host, string detail)
        => new() { PollRunId = runId, Severity = sev, Category = cat, SystemName = system, HostLabel = host, Detail = detail };
}

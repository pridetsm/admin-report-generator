using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PrometheusIngest.Data;
using PrometheusIngest.Services;

namespace PrometheusIngest.Controllers;

/// <summary>Read models over the most recent poll (or a specific runId).</summary>
[ApiController]
[Route("api/[controller]")]
public sealed class SnapshotController : ControllerBase
{
    private readonly MonitoringDbContext _db;
    public SnapshotController(MonitoringDbContext db) => _db = db;

    private async Task<long?> ResolveRunId(long? runId, CancellationToken ct)
    {
        if (runId is { } id) return id;
        return await _db.PollRuns.Where(r => r.Status == PollStatus.Succeeded)
            .OrderByDescending(r => r.Id).Select(r => (long?)r.Id).FirstOrDefaultAsync(ct);
    }

    /// <summary>The two-band "needs attention" verdict for the latest (or given) run.</summary>
    [HttpGet("attention")]
    public async Task<IActionResult> Attention([FromQuery] long? runId, CancellationToken ct = default)
    {
        var id = await ResolveRunId(runId, ct);
        if (id is null) return NotFound(new { message = "no successful poll yet" });

        var items = await _db.AttentionItems.Where(a => a.PollRunId == id)
            .OrderBy(a => a.Severity).ThenBy(a => a.Category).ThenBy(a => a.SystemName)
            .ToListAsync(ct);

        return Ok(new
        {
            runId = id,
            needsImmediateAttention = items.Where(a => a.Severity == Severity.Immediate),
            needsAttention = items.Where(a => a.Severity == Severity.Watch),
        });
    }

    /// <summary>Per-host disk + memory + cpu + reachability for the latest (or given) run.</summary>
    [HttpGet("hosts")]
    public async Task<IActionResult> Hosts([FromQuery] long? runId, CancellationToken ct = default)
    {
        var id = await ResolveRunId(runId, ct);
        if (id is null) return NotFound(new { message = "no successful poll yet" });

        var hosts = await _db.Hosts.Include(h => h.System).AsNoTracking().ToListAsync(ct);
        var disk = await _db.DiskSamples.Where(d => d.PollRunId == id).ToListAsync(ct);
        var mem = await _db.MemorySamples.Where(m => m.PollRunId == id).ToListAsync(ct);
        var cpu = await _db.CpuSamples.Where(c => c.PollRunId == id).ToListAsync(ct);
        var reach = await _db.HostReachabilitySamples.Where(r => r.PollRunId == id).ToListAsync(ct);

        var result = hosts.Select(h => new
        {
            system = h.System!.Name,
            host = h.Label,
            h.Instance,
            h.Os,
            reachable = reach.FirstOrDefault(r => r.HostId == h.Id)?.IsUp,
            memoryUsedPct = mem.FirstOrDefault(m => m.HostId == h.Id)?.UsedPct,
            cpuUsedPct = cpu.FirstOrDefault(c => c.HostId == h.Id)?.UsedPct,
            disks = disk.Where(d => d.HostId == h.Id)
                        .OrderByDescending(d => d.UsedPct)
                        .Select(d => new { d.Mountpoint, d.UsedPct, d.FreeGb, d.SizeGb }),
        }).OrderBy(x => x.system).ThenBy(x => x.host);

        return Ok(new { runId = id, hosts = result });
    }

    /// <summary>Service check results (grouped by system) for the latest (or given) run.</summary>
    [HttpGet("services")]
    public async Task<IActionResult> Services([FromQuery] long? runId, CancellationToken ct = default)
    {
        var id = await ResolveRunId(runId, ct);
        if (id is null) return NotFound(new { message = "no successful poll yet" });

        var checks = await _db.ServiceChecks.Include(s => s.System).AsNoTracking().ToListAsync(ct);
        var samples = await _db.ServiceStatusSamples.Where(s => s.PollRunId == id).ToListAsync(ct);

        var byCheck = checks.ToDictionary(c => c.Id);
        var result = samples.Select(s => new
        {
            system = byCheck.TryGetValue(s.ServiceCheckId, out var c) ? c.System!.Name : "?",
            @class = byCheck.TryGetValue(s.ServiceCheckId, out var c2) ? c2.Class : null,
            service = s.MemberName,
            up = s.IsUp,
        }).OrderBy(x => x.system).ThenBy(x => x.service);

        return Ok(new { runId = id, services = result });
    }

    /// <summary>The synced topology (systems → hosts / services / links / readings / backups).</summary>
    [HttpGet("topology")]
    public async Task<IActionResult> Topology(CancellationToken ct = default)
    {
        var systems = await _db.Systems
            .Include(s => s.Hosts)
            .Include(s => s.ServiceChecks)
            .Include(s => s.LinkChecks)
            .Include(s => s.ReadingConfigs)
            .Include(s => s.BackupConfig)
            .AsNoTracking().OrderBy(s => s.DisplayOrder).ToListAsync(ct);

        return Ok(systems.Select(s => new
        {
            s.Name,
            hosts = s.Hosts.Select(h => new { h.Role, h.Label, h.Instance, h.Os }),
            services = s.ServiceChecks.Select(c => new { c.Name, c.Class, c.CheckType }),
            links = s.LinkChecks.Select(l => l.Url),
            readings = s.ReadingConfigs.Select(r => new { r.Key, r.Expr }),
            backups = s.BackupConfig is null ? null : new { s.BackupConfig.Instance, s.BackupConfig.Tracks, s.BackupConfig.MaxAgeDays },
        }));
    }
}

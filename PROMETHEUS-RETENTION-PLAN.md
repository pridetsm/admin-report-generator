# Prometheus Disk Retention & Historical Archive (Postgres-based)

## Context

`hre-grafana-01` (runs Prometheus, this webapp, and its Postgres DB, all on one 99.3GB C:
drive) is at 91%+ disk usage, ~9GB free. Root cause: `C:\metrics\prometheus\data` is ~47GB and
climbing — Prometheus has never had a retention flag set (bare NSSM `AppParameters`:
`--config.file=...` `--web.config.file=...` only), so it runs on the unbounded-by-size, 15-day
default, and 6-hour block density has roughly doubled over two weeks tracking this session's
own device-onboarding wave.

**Confirmed live, not guessed**: most of that 47GB is not data any report reads. A direct
cardinality query against this Prometheus shows the estate has 1,273 distinct metric names and
several hundred thousand series, dominated by:
- `windows_service_state`/`windows_service_start_mode`/`windows_service_info` (62,104 /
  44,360 / 8,872 series) — windows_exporter exposes **every installed service on every host,
  in every possible state**, but the app only ever filters to a handful of *named* services
  per host (`win_service()` in `generate_report.py`).
- `node_systemd_unit_state` (41,625) — same story for Linux.
- 13 different interface-table columns (`ifSpeed`, `ifPromiscuousMode`,
  `ifConnectorPresent`, `ifCounterDiscontinuityTime`, `ifLinkUpDownTrapEnable`, etc.), ~4,900
  series each (≈64,000 total) across the estate's ~4,943 interfaces — the app reads maybe 3 of
  these columns (`ifOperStatus`, `ifHighSpeed`, `ifIndex`), never the other 10.
- `dot1dTpFdbPort` (7,402) — full switch MAC-address forwarding tables, read by nothing.

This directly shapes the design below: **the archive should be built from exactly what the
app actually queries, not a guess at what "might be useful"** — and the same inventory that
answers that also identifies what could be dropped from scraping entirely at the source later
(a real, separate follow-on, not required for this plan).

## Decisions made across this discussion (in order, each superseding the last where noted)

1. Native Prometheus TSDB block-level snapshots (`/api/v1/admin/tsdb/snapshot` → copy to a
   network drive) were investigated and **dropped**. They'd give full-fidelity backup, but
   nothing queryable by the app without a manual restore into a throwaway Prometheus instance
   — doesn't serve "the app has access to all historical data," which is the actual goal.
2. Instead: **extract data via PromQL** (the same mechanism `reports/metric_history.py`
   already uses today for its narrow RAM/CPU/Disk/SWIFT/COB capture) into **a dedicated,
   separate Postgres database** — `prometheus_snapshot_db` — not another table in the app's
   main `admin_report` database. Plain SQL rows, queryable by this app or any other tool with
   a connection string, no PromQL/Prometheus/restore step needed to read history.
3. What gets extracted is **derived from a single canonical registry of every metric the app
   actually queries** (extending the discipline `network.py`'s own `CATALOGUE` already uses
   for one report engine, app-wide) — not a hand-picked subset. New queries added to the app
   in future get added to this registry as a matter of course, so "what's archived" and "what
   the app uses" never drift apart. **Still needs a full one-time audit of every PromQL call
   site in `network.py`, `generate_report.py`, `metric_history.py`, `alerting.py`,
   `system_alerts.py` — started, hit the account's spend limit mid-run, not complete.**
4. The existing `MetricSample` table/mechanism is **retired into this new design**, not run
   as a second parallel system — its 5 series become 5 entries in the new registry, its
   316,940 existing rows get migrated into `prometheus_snapshot_db` alongside everything else
   captured by the wider registry, and `report_charts.py`'s read queries get repointed at the
   new database.
5. Prometheus's own live retention **still gets shrunk** (this is what actually relieves the
   disk problem — the archive doesn't reduce local disk on its own, Prometheus pruning its own
   old blocks does) — unchanged goal throughout, now sequenced to happen only *after* the
   current retention window's content is safely captured in the new archive.
6. Weekly **offline backups of the Postgres databases themselves** (`admin_report` AND the new
   `prometheus_snapshot_db`) — `pg_dump`, written locally, copied to the Z: network drive
   (`\\10.100.248.254\g$`, 832GB free, confirmed mapped), then the **local copy deleted** once
   the offline copy is verified, so the backup mechanism never becomes its own new disk
   consumer. Rotated on a retention window (e.g. last 8-12 weeks).

## Logical review findings (fixed below before implementation)

A pre-implementation review surfaced three real gaps, now folded into the phases below —
noted here so they're not lost:
1. **Save-vs-Apply race on `live_window_days`**: if saved-but-not-yet-applied (Prometheus not
   yet restarted with the new value), the routing function reading the *saved* value could ask
   live Prometheus for a window it doesn't actually have yet, silently returning partial/empty
   results instead of falling back to the archive. Fixed: routing reads the last **applied**
   value only (see Phase 4).
2. **Registry needs a reverse mapping, not just a forward template**: `series()` needs to turn
   a stored `metric_key` back into a live, filtered PromQL query for the "recent" half of a
   stitched range — Phase 1's registry must store that explicitly.
3. **Cutover sequencing**: migrating `MetricSample`'s rows, switching the capture job's write
   target, and repointing `report_charts.py`'s reads must land together, not as three
   independently-timed changes (risk of charts going stale in between).

## Phase 1 — Complete the PromQL inventory (blocked on spend-limit reset)

Audit every `prom.query(...)`/`prom.query_range(...)`/`prom.scalar(...)` call site and every
PromQL-building helper (`win_service()`, `systemd()`, `probe()`, `host_up()` in
`generate_report.py`; the `CATALOGUE` list and per-function queries in `network.py`) across:
`webapp/reports/network.py`, `webapp/send_report/generate_report.py`,
`webapp/reports/metric_history.py`, `webapp/reports/alerting.py`,
`webapp/reports/system_alerts.py`, and a broad grep across `webapp/reports/` /
`webapp/send_report/` for any other `.query(`/`.query_range(` caller (e.g. `folders.py`,
`network_sod.py`, `services.py`). Confirm `report_charts.py` only reads `MetricSample`
(Postgres), never live Prometheus directly. For a repeated pattern like `win_service(name,
inst)`, capture the pattern once (it becomes a loop, not N hand-written registry rows), not
every individual call site.

Output: `reports/metric_registry.py` — one entry per distinct metric family: `{key, promql
(or a template + the list of (name, instance) pairs it's called with), live_query_fn,
source_ref, used_by}`. `live_query_fn` is the piece that makes Phase 4's stitching possible:
given one resolved `metric_key` (e.g. `psu_failed:10.100.210.253`), it must return the exact
live PromQL to ask Prometheus for that same series right now — a required field per entry, not
optional, since `series()` cannot reconstruct a live query from an archived key string alone.

This is the list Phase 3's extraction job reads from, and (separately, later) the list that
tells us what's safe to stop scraping/expose at the source.

## Phase 2 — `prometheus_snapshot_db`

New Postgres database, new Django `DATABASES` alias, a database router sending the archive
model(s) there instead of `admin_report`. One model (successor to `MetricSample`, same shape:
`metric_key`, `taken_at`, `value`, unique constraint on `(metric_key, taken_at)`).

**Index choice: benchmark, don't assume.** Earlier draft of this plan recommended switching to
a bare BRIN index on `taken_at` (the existing composite index already costs more than the
table's own data at 316,940 rows). On review, that's premature: every actual read filters by
`metric_key` first (an equality match), which is exactly what the existing composite B-tree on
`(metric_key, taken_at)` is good at — a BRIN on `taken_at` alone doesn't help an equality
filter on a different, uncorrelated column. Keep the composite B-tree as the default; only
move to BRIN (or add it alongside) if a real `EXPLAIN ANALYZE` at the new, wider scale shows
it actually helps this app's specific read pattern.

## Phase 3 — Migrate existing history + one-time backfill, in this order (do not reorder)

1. Stand up `prometheus_snapshot_db` and the new model/migration.
2. **Migrate `MetricSample`'s existing 316,940 rows** from `admin_report` into the new
   database (a straightforward batched copy — small enough to do in one pass).
3. **One-time backfill against the FULL registry from Phase 1**, covering everything
   Prometheus currently holds (~15 days right now — this is the actual "move the 47GB's worth
   of content into Postgres" step) — same mechanism `metric_history.backfill(days)` already
   implements (`query_range`, 1h step), generalized to the wider registry and the new database.
4. **Verify before touching anything live**: spot-check row counts and specific values against
   live Prometheus for the same instants.
5. **Only now** shrink Prometheus's own retention to the configured `live_window_days`
   (default **3 days**, see Phase 4 below) — `--storage.tsdb.retention.time=3d`,
   **`--storage.tsdb.retention.size` deliberately left unset (uncapped)**, per explicit
   direction: the 3-day time window alone is trusted to bound size. At current density
   (~10GB/day) that's ~30GB steady-state, inside the ~54GB budget on this disk — but flagging
   plainly since there's no safety net: if scrape volume grows further with no size cap, a
   3-day window can still grow large. Written via `reports/prometheus_admin.py` (already owns
   `SERVICE_NAME`, `_restart_service()`, `service_status()` — extend it, don't duplicate). This
   is what actually reduces the 47GB, gradually, via Prometheus's own periodic retention sweep
   after restart — not instantly.
6. **Ongoing hourly capture job** (generalized `capture_now()`, same registry, targets
   `prometheus_snapshot_db`) keeps the archive growing forward from here. **Add a daily
   staleness check on this job itself** (same pattern the app already uses for System Alerts'
   checker/exporter mtime watching) — with retention this tight (3 days), a silently-broken
   capture job discovered only at the next *weekly* backup cycle could mean up to several days
   of data gone from both live Prometheus and the archive. A daily check catches it in time to
   still matter.

**Cutover discipline** (fixes review finding #3): steps 2 (row migration), the capture job's
write-target switch, and `report_charts.py`'s read-repoint must ship together in one deploy —
not as independently-timed changes. Landing them apart risks a window where charts read from a
table nothing writes to any more.

## Phase 4 — The live/archive split: one setting, two consumers

**`live_window_days`** (default 3, admin-configurable — see Phase 6) is the single source of
truth for both:
1. **What Prometheus itself retains locally** — Phase 3 step 5 applies this value directly as
   `--storage.tsdb.retention.time`.
2. **Where the app reads a given time range from** — new `reports/historical_query.py`:
   ```python
   def series(metric_key, start, end):
       """Stitches archive + live Prometheus for [start, end], transparently:
          - end   <= now - live_window_days  -> prometheus_snapshot_db only
          - start >  now - live_window_days  -> live Prometheus query_range only (full
            scrape-interval resolution, not resampled -- this is the "fresh, forward-facing"
            data)
          - range spans the boundary          -> archive for the older part, live for the
            newer part, concatenated by timestamp into one series
       """
   ```
   This is what `report_charts.py` calls instead of querying `MetricSample`/`prometheus_
   snapshot_db` directly today — the stitching is invisible to callers, they just ask for a
   range and get one continuous series back regardless of where each point actually lives.

**Critically, these two consumers must never drift apart** — if Prometheus's actual retention
flag and the app's routing split point ever disagree (e.g. one changed without the other),
there's a silent gap: data neither in live Prometheus (already pruned) nor guaranteed captured
by the archive yet. Reading `live_window_days` from the same DB field for both (Phase 3 step 5
and this routing function) is what prevents that — never hardcode "3 days" in a second place.

**Fixes review finding #1 (Save-vs-Apply race)**: `series()` must read the last **applied**
`live_window_days` (the value actually live on the Prometheus service right now), never a
saved-but-not-yet-applied draft — otherwise widening the window on the config screen (Save,
without clicking Apply yet) would make the router ask live Prometheus for a range it doesn't
actually retain, silently returning partial/empty data instead of correctly falling back to
the archive. Given this, **`live_window_days` gets no soft-save state on the config screen at
all** — unlike the heavier Prometheus-retention fields, which may reasonably want "stage, review,
apply later," this one setting is only ever safe as a single apply-immediately action, exactly
because two live systems key off of it simultaneously.

**Resolution jump at the stitch boundary — a deliberate decision, not an oversight.** The live
portion of a stitched range returns full scrape-interval resolution; the archive portion
returns hourly points. A chart spanning the 3-day boundary will visibly change density right
at that line. Decide explicitly during implementation whether to leave this as-is (recent =
detailed, older = trend-level, arguably the right behavior) or resample the live portion down
to hourly when stitching for visual consistency — don't leave it for whoever implements
`series()` to discover and decide ad hoc.

**Does not affect point-in-time reads.** Every *current-state* report/dashboard/alert path
(`network.py`'s `collect()`, the System Health Report, alerting, the Executive Dashboard) asks
"what is true right now," not "give me a range" — those stay exactly as they are, always
querying live Prometheus directly, completely untouched by this routing. Only range/historical
queries (Trend charts today, any future "show me N months ago" feature) go through `series()`.

## Phase 5 — Weekly offline database backups

New scheduled job (`deploy/gms/folder_exporter.yml`, weekly, off-peak): `pg_dump` both
`admin_report` and `prometheus_snapshot_db` to a local temp path, robocopy to
`\\10.100.248.254\g$\postgres-backups\<db>\<date>\`, verify the copy, delete the local dump,
prune destination entries past a configured retention (e.g. 8-12 weeks). **Verify the
destination is actually reachable from whatever account runs this job** — `folder_exporter`
runs as **LocalSystem** (confirmed via `nssm.exe get folder_exporter ObjectName`), and Z: is a
per-session drive letter mapped only in the interactive Administrator session — LocalSystem
needs the UNC path (`\\10.100.248.254\g$\...`) and the machine account
(`HRE-GRAFANA-01$`) needs its own access to that share; do not assume the drive letter is
visible to the service.

## Phase 6 — New admin config screen

`config_retention` (`configuration/retention/`), gated by `_require_admin` (same idiom as
every other config screen), wired into `_CONFIG_CHILDREN` (`views.py`) + `roles.py`'s
`ADMIN_ROLE` reachable-view set + `urls.py`, right after `config_prometheus`. Sections:
- **Live/archive split** — the `live_window_days` field itself (default 3), front and center
  as the primary setting on this screen (per Phase 4, it drives both Prometheus's own
  retention and the app's read-routing from one place). **Single "Apply" action only, no
  separate Save** (per review finding #1's fix) — changing it always restarts Prometheus with
  the new `retention.time` immediately; the routing side reads that same applied value, so the
  two can never be out of sync. Disk-usage readout alongside it, mirroring
  `config_backup_policy`'s revision-history shape for the audit trail (every apply still
  recorded as a revision row, just without a separate unapplied "saved" state).
- **Extraction registry status** — last backfill run, last hourly capture, row counts in
  `prometheus_snapshot_db`.
- **Backup history** — last weekly `pg_dump` runs, ok/failed, destination, size.

## Explicitly out of scope for this pass

- Dropping unused OIDs/collectors at the SNMP-module/windows_exporter level (the
  `windows_service_state`/interface-table waste identified above) — real, worth doing, but a
  separate follow-on once Phase 1's registry exists to confirm what's genuinely never read.
- TimescaleDB or any other storage-engine change — confirmed not installed on this Postgres 17
  instance, a real infra project, not warranted at the modest scale this design lands at.

## Verification

- **Migration correctness**: `prometheus_snapshot_db` row count for the 5 original
  `MetricSample` keys matches the pre-migration `admin_report` count exactly; a spot-check of
  several `(metric_key, taken_at)` pairs match values between old and new.
- **Backfill correctness**: for 3-5 registry entries, compare a captured value against a live
  `query_range` result for the same instant.
- **Retention actually shrinks disk**: `Get-ChildItem C:\metrics\prometheus\data -Recurse |
  Measure-Object Length -Sum` trending down over the following hours/day after the retention
  restart; `nssm.exe get Prometheus AppParameters` confirms the flags are live.
- **Backups work end to end**: run the weekly job once by hand, confirm the destination UNC
  path has a non-trivial `.dump` file, confirm the local temp copy is gone afterward, confirm
  a **restore actually works** at least once (`pg_restore` into a scratch database) — untested
  backups are not backups.
- Full `manage.py test` after each phase.

### Critical files
- `webapp/reports/metric_registry.py` (new)
- `webapp/reports/metric_history.py`, `webapp/reports/models.py`
- `webapp/reports/prometheus_admin.py`
- `webapp/reports/views.py`, `webapp/reports/urls.py`, `webapp/reports/roles.py`
- `webapp/reports/report_charts.py` (repoint reads at the new database)
- `webapp/config/settings.py` (new `DATABASES` alias + router)
- `deploy/gms/folder_exporter.yml`

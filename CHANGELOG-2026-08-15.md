# Session log — 2026-08-15

Explicit record of everything done in today's session across the repo, the live Prometheus
server, and the external mailing pipeline. Written so a future reader (human or AI) can see
exactly what changed, why, and what's still outstanding — without having to reconstruct it
from commit messages alone.

---

## 1. Deployment / redeploy housekeeping

- Restarted the `AdminReportGenerator` Windows service (NSSM-wrapped waitress, the webapp)
  multiple times over the session to pick up code changes. `send_report/generate_report.py`
  and `send_report/mail_report.py` are only imported once at process start, so any change to
  either requires a restart — the topology file (`prometheus.yml`) does NOT, it's re-read
  every request.
- **Found and killed a zombie `runserver` process** left over from an earlier `serve.bat`
  misfire (days before this session): it had been silently listening on port 8000 *alongside*
  waitress the whole time (Windows allowed the dual bind), causing responses to intermittently
  flip between current code (waitress) and stale code (the zombie). Confirmed via
  `Get-NetTCPConnection -LocalPort 8000` showing two owning PIDs; killed the zombie tree.
- Confirmed Prometheus itself (`C:\metrics\prometheus\prometheus.exe`) runs as a **bare
  process, not a Windows service** — no supervisor. Restarting it means: stop the process,
  relaunch with the same flags (`--config.file=... --web.config.file=...` — the latter is
  required once TLS was enabled, see §3), and verify `https://localhost:9090/-/healthy`.
  If it crashes, nothing restarts it automatically.

## 2. Systems wired into the report engine

This session onboarded **four** systems: FRS, BSA, Collateral Registry, EDMS. For each, the
pattern was the same: confirm the host(s) are actually reachable on `9182` (windows_exporter)
or `9100` (node_exporter), query Prometheus live for the *actual* running services (never
guessed), add topology to `prometheus.yml`, add a `SERVICE_CHECKS` entry + `SYSTEM_ORDER`
position in `send_report/generate_report.py`, verify end-to-end, then sync to the external
mailing script copy (see §5) and restart the webapp service. (Two more systems — Asset
Registry and Refinitiv — were onboarded the same day but not in this session; see below.)

### FRS (Fintech Regulatory Sandbox)
- Already had topology + a `LINK_CHECKS` web-probe override, but **no `SERVICE_CHECKS` entry
  at all** — its system-services table was silently empty in every report.
- Host `10.100.245.150:9100` (Linux). Confirmed live: `apache2.service` (forking) +
  `mysql.service` (notify) both active.
- Added `SERVICE_CHECKS["frs"]` with those two services (mirrors the `Intranet` pattern).
- Separately, the `LINK_CHECKS["frs"]` override was stale — written for an old insecure
  IP-based blackbox probe (`10.100.245.150`), but the probe target had since moved to the
  hostname `https://frs.rbz.co.zw/` (trusted Sectigo cert). The override no longer matched
  anything, but the link still attributed correctly via the auto-detect fallback (`frs` is a
  substring of `frs.rbz.co.zw`), so this was cosmetically stale rather than broken. Comment
  was later corrected by the user directly in a separate commit (`5629d7e`).

### BSA
- Turned out to already be in `prometheus.yml` (topology + web link), but the *live* file at
  the repo root (`prometheus.yml`) was a stale copy — BSA had only been added to
  `deploy/prometheus.yml` (the master copy) and never copied into place. This was the trigger
  for the whole single-source-of-truth cleanup in §3.
- Hosts: DB `10.0.206.5:9182` (Windows), reverse-proxy `192.168.25.156:9100` (Linux, nginx),
  app `10.0.206.6:9100` (Linux, Docker).
- Confirmed live: `MSSQLSERVER`, `BSAv50Monitor`, `BSAv50Parser` all running on the DB box;
  `nginx.service` on the proxy; `docker.service` on the app box.
- Added `SERVICE_CHECKS["bsa"]` with all five, plus `"BSA"` to `SYSTEM_ORDER`.
- The BSA web probe URL was later corrected by the user (outside this session's edits, seen
  live in `prometheus.yml`) from the bare root `https://bsa.rbz.co.zw/` to
  `https://bsa.rbz.co.zw/Account/Login/` — the actual valid endpoint. No code changes were
  needed; the auto-detect link attribution still matches on the `bsa` substring regardless of
  path, and this was verified live (200, valid TLS, reachable).

### Collateral Registry
- Brand new system, not previously in `prometheus.yml` at all.
- App `10.0.207.8:9182` (IIS), DB `10.0.207.9:9182` (MSSQL), web `https://collateralregistry.rbz.co.zw/`.
- Confirmed live before wiring: both windows_exporter endpoints reachable; `W3SVC` running on
  the app box, `MSSQLSERVER` on the DB box.
- Added both hosts to `prometheus.yml` (`windows_exporter` job) + the URL to `blackbox_http`;
  restarted the bare Prometheus process to load them; confirmed `up=1` on both via the API
  before touching any code.
- Added `SERVICE_CHECKS["collateralregistry"]` (IIS + MSSQLSERVER) and `"Collateral Registry"`
  to `SYSTEM_ORDER`. No `LINK_CHECKS` override needed (auto-detect matches).

### EDMS
- User-supplied roles were **the reverse of reality**: stated App=`10.0.206.11`/DB=`10.0.206.12`,
  but live data showed `10.0.206.11` running `MSSQLSERVER` (i.e. the DB) and `10.0.206.12`
  running `W3SVC`/IIS (i.e. the App). Confirmed via `windows_service_state` queries on both
  hosts before wiring anything in; user confirmed to trust the live data.
- Wired in with the *corrected* roles: `SERVICE_CHECKS["edms"]` = MSSQLSERVER on `.11`, IIS on
  `.12`; `"EDMS"` added to `SYSTEM_ORDER`; both hosts + `https://edms.rbz.co.zw/` added to
  `prometheus.yml`.
- Relabeling the `display` tags on already-scraped targets produced a few minutes of
  **duplicate stale rows** in live queries (both the old and new label combos briefly inside
  Prometheus's 5-minute instant-query lookback window) — this was investigated and confirmed
  transient/expected, not a bug in the role correction, and cleared on its own.
- **This is also the system behind the "no data" investigation in §6** — its DB host
  (`10.0.206.11:9182`) is fully reachable (`up=1`, CPU and RAM collectors both report fine)
  but its disk collector (`windows_logical_disk_size_bytes`/`_free_bytes`) returns **zero
  series**, while its sibling App host (`.12`) returns 4. Conclusion: `windows_exporter` on
  the EDMS DB box most likely wasn't started with `logical_disk` in `--collectors.enabled`,
  or that collector is erroring silently on that host. **This is a real, unresolved issue on
  that host** — not a monitoring/code bug — and is the user's next task to fix directly on
  the server.

### Not onboarded by this session — found already wired, verified only
Two unrelated pieces of prior work were found already in place when checked and were **not**
part of today's (or this session's) onboarding — corrected here after an earlier draft of
this changelog wrongly grouped them together as if all three were the same kind of change:

- **EBIS** — wired in commit `7f0a110` ("Wire in EBIS system service checks"), dated
  **2026-08-13**. Two days before today; a separate, unrelated earlier session. Mentioned only
  because it was verified alongside the others, not because it happened today.
- **Asset Registry + Refinitiv (Reuters)** — both onboarded together in commit `0a6f2ab`,
  dated today (**2026-08-15, 19:56**) but *before* this session started. That same commit is
  also where **the core network switch was reclassified**: `SKIP_SYSTEMS` gained `"rbz
  network"` so a `system: "RBZ Network"` label (the SNMP-monitored core switch) is now
  excluded from the System Admin systems list entirely and handled instead by the separate
  Network Admin Report — a structural recategorization, not a new system being onboarded.

For all three, no action was needed in this session beyond verifying they load and capture
correctly, which they do (final system count 27 by the end of the session).
Asset Registry's own exporter data revealed a real, currently-failing systemd unit on that
host (`assetsmgt.service`, stuck in `activating` and never reaching `active`) — surfaced
correctly as a live finding, not a monitoring bug.

## 3. `prometheus.yml`: eliminated the duplicate-copy problem

**Root cause of the BSA/EDMS "why isn't this showing up" confusion**: there were **three
separate copies** of the topology file — the actual live Prometheus config
(`C:\metrics\prometheus\prometheus.yml`), a "master" deployment copy (`deploy/prometheus.yml`),
and a repo-root copy (`prometheus.yml`) that `generate_report.py` actually read. Someone would
update the live server config, remember to also update `deploy/`, and forget the repo-root
copy — which then silently went stale.

**Fix**: `send_report/config.ini`'s `[prometheus] yml` setting now points **directly** at
`C:\metrics\prometheus\prometheus.yml` — the real Prometheus server's own scrape config.
Prometheus and the webapp run on the same host, so this just works. Deleted the repo-root
`prometheus.yml` and `deploy/prometheus.yml` entirely — there is now exactly one file to edit.

Docs updated to match and to prevent this from being reintroduced:
- `deploy/PLACEMENT.txt` — removed the `prometheus.yml` copy-into-place step, added a note
  explaining the direct-path approach and what to do if a future deployment puts Prometheus on
  a different host.
- `README.md` — "Topology" section rewritten; "Repository layout" comment updated.
- `deployment.txt` — sections 1, 4, 11, 12, 13 updated (data sources, sensitive-files copy
  step, verification steps, troubleshooting table gained a new row: "Added a system to
  Prometheus but it's not showing up in the webapp").

Committed as `84ba59b` ("Docs: prometheus.yml has one copy now, not three").

## 4. Prometheus TLS upgrade (discovered mid-session, not done by this session)

The user upgraded the internal Prometheus server to serve HTTPS with a self-signed cert
(`server.crt`/`server.key`, `web-config.yml`, dated 2026-08-14) independently of this session.
Effects observed and adapted to:
- `send_report/config.ini` and the external copy's `config.ini` both now have
  `url = https://10.100.248.249:9090` and `verify_tls = false`.
- Restarting the bare Prometheus process now requires the extra
  `--web.config.file=C:\metrics\prometheus\web-config.yml` flag, or it silently comes back up
  on plain HTTP and the app's HTTPS client can't reach it. This was nearly missed on one
  restart — always check the *current* process's command line
  (`Get-CimInstance Win32_Process -Filter "Name='prometheus.exe'"`) before restarting, don't
  assume the old bare invocation still applies.
- A `prometheus.yml` scrape job for Prometheus's own `/metrics` was updated (by the user) to
  `scheme: https` with `insecure_skip_verify: true`.

## 5. Mailing pipeline: found a third, undocumented deployment

Discovered a **completely separate, standalone copy of the report engine** at
`C:\metrics\prometheus\send_report\` — outside the git repo entirely — with its own
`config.ini`, `mail_report.py`, `generate_report.py`, `run.bat`, `runmailing.bat`. This is what
the **`SystemAdminReport-Daily-0700` scheduled task** actually runs every morning
(`runmailing.bat` → `run.bat` → `mail_report.py --send`, confirmed via
`Get-ScheduledTask -TaskName "SystemAdminReport-Daily-0700"`), completely independent of the
webapp's on-demand "Generate & e-mail" flow.

### 5a. SMTP credential rotation
Old mailbox `noreply@rbz.co.zw` replaced with the new service account **`monitoring@rbz.co.zw`**
(password rotated). Updated in **three places** (all git-ignored, so none of this touched
version control):
- `send_report/config.ini` (repo)
- `deploy/config.ini` (master copy for future redeployments)
- `C:\metrics\prometheus\send_report\config.ini` (the standalone script — found and fixed
  after being missed in the first pass; this is what the daily 07:00 email actually uses)

New credentials verified with a live SMTP AUTH test (STARTTLS + login, no message sent) before
relying on them.

### 5b. `mail_report.py`'s own duplicate `SERVICE_CHECKS`/`SYSTEM_ORDER` was stale
`mail_report.py` deliberately keeps a **self-contained copy** of the topology/service-check
logic (so its link-only preview mode doesn't need the full `openpyxl`/`Pillow`-dependent
engine). That copy had not been updated past `Intranet` — it was silently missing FRS, BSA,
Collateral Registry, EDMS, EBIS, Refinitiv, and Asset Registry entirely, and `SYSTEM_ORDER`
stopped at `Paytyme`. Because the **daily scheduled email runs without `--attach`**, it was
using exactly this stale, incomplete copy the whole time — not the up-to-date engine.

Fixed by copying the current `SERVICE_CHECKS` entries and extending `SYSTEM_ORDER` to match
`generate_report.py` exactly (confirmed byte-for-byte identical afterward).

### 5c. Two real, quantified bugs found and fixed in `mail_report.py`
1. **Services KPI undercounted by exactly the web-link count.** The xlsx's "SERVICES" total
   is `services + web links` (`generate_report.py`'s `services_down()`/its total-services
   calc); `mail_report.py`'s own `nsvc`/`down` calculations were missing `+ len(store.links)`
   entirely. Live-verified: 63 (services only) + 15 (links) = 78 (the xlsx's real number) vs.
   63 (what the email showed). Fixed both the total and the down-count the same way.
2. **Severity labels were never updated when the IMMINENT/CRITICAL/WARNING vocabulary was
   introduced** (that redesign — `generate_report.py`'s `SEVERITY` dict, `webapp/reports/services.py`'s
   banner-severity derivation — only touched the xlsx and the webapp screen, not the email).
   Relabeled all six of `mail_report.py`'s own banner blocks (LDAP, unreachable, disk-near-full,
   SSL certs, COB, SWIFT) plus its top summary banner, and reordered them to match
   `generate_report.py`'s severity rank (imminent → critical → warning).

### 5d. "No data" severity feature — built, then reverted
Investigating a specific EDMS finding ("no data — exporter up, metric missing") led to
building a whole new capability: treating a *reachable* host's silently-missing metric
(RAM/CPU/disk collector returning nothing) as equally severe as full unreachability
("IMMINENT" — per the `SEVERITY` dict's own definition: *"an outage is underway, OR we have
lost the ability to see one"*). This was implemented properly in the shared layer so it would
apply everywhere at once:
- `generate_report.py`: new `nodata_components()` function (mirrors `unreachable()`'s shape);
  `flagged_for_system()` gained a new `"nodata"` `Flag` category (red-banded); the xlsx gained
  a "NO DATA" overview banner and its Memory/CPU table cells changed from a muted "—" dash to
  a red "NO DATA" chip.
- `webapp/reports/services.py`: `build_overview()` gained a matching "No data" banner
  (`severity: "imminent"`), `FlagVM`'s category comment updated.
- `mail_report.py`: its pre-existing separate `nodata` finding list (this part already
  existed before today) was re-styled to match — moved from a muted, last-place "check
  exporters" footnote to an IMMINENT-red section right after Unreachable.

**Then fully reverted** at the user's request, after establishing that EDMS's issue is a
real, single-host exporter misconfiguration to fix directly — not something the reporting
layer needs to escalate specially. The revert was surgical for `mail_report.py` (its diff
also contained the §5a–5c fixes, which were kept):
- `generate_report.py` and `webapp/reports/services.py`: reverted in full
  (`git checkout -- <file>`) — both were 100% no-data feature code.
- `mail_report.py`: hand-reverted just the no-data-specific hunks (top banner condition,
  the IMMINENT no-data section and its position, `plain_summary()`'s ordering) back to the
  original muted "No data (check exporters)" treatment, while keeping the SERVICE_CHECKS
  sync, severity relabeling, and services+links count fix from §5b/§5c.
- One duplicated comment introduced during the manual revert was caught and cleaned up.
- Re-synced to the external copy and confirmed the webapp/xlsx/email are all back to their
  pre-feature no-data behavior; EDMS itself remains fully wired in as a monitored system.

### 5e. External copy kept in sync throughout
Every fix in §5a–5d was copied to `C:\metrics\prometheus\send_report\` immediately after being
made in the repo, and diffed to confirm byte-identical before moving on. This copy is **not**
git-tracked — nothing here shows up in `git status`.

## 6. Reports sent during this session

Several live reports were generated and emailed to **pmoyo2@rbz.co.zw** while verifying fixes
along the way (via both the repo copy and, later, explicitly through the external
`C:\metrics\prometheus\send_report\mail_report.py --to pmoyo2@rbz.co.zw --attach --send`
path — the same one the daily 07:00 scheduled task uses). These were verification sends, not
a change to any config.

## 7. Git commits made this session

```
84ba59b Docs: prometheus.yml has one copy now, not three
4a50323 Wire in FRS, BSA and Collateral Registry system service checks
32cc18c Serve static files via WhiteNoise (no reverse proxy in front yet)
```
All pushed to `origin/main`. Also pulled incoming commits mid-session
(`5629d7e`, `caadda8`, then `8227115`/`27abd22`/`cd67d4b`, then `3ae2169`) — see git log for
details; no conflicts, verified via diff after each merge, `generate_report.py` re-synced to
the external mailing script copy after each pull that touched it.

Also fixed this repo's git identity (was falling back to `unknown@hre-grafana-01...`) —
set to `Pride T.S. Moyo <pridethabo.moyo@gmail.com>` at the repo level and amended the one
affected commit's author.

## 8. Outstanding / not yet committed

- `send_report/mail_report.py` has uncommitted changes: the SERVICE_CHECKS sync (§5b) +
  severity relabeling + services/links count fix (§5c), with the no-data feature (§5d)
  cleanly backed out again. Not yet committed or pushed — ask before doing so.
- **EDMS DB's disk collector gap is still unresolved** — this is the user's next task,
  directly on that host (`10.0.206.11`), not a code change here.
- `C:\metrics\prometheus\send_report\` (the external mailing script) is up to date with the
  repo as of the end of this session but has no version control of its own — a future change
  to the repo's `mail_report.py`/`generate_report.py` needs to be manually copied there again
  (see §5e) until/unless that gets automated.

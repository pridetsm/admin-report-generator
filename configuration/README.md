# configuration/

Reference samples for the files the webapp's **Configuration** menu (Administrator role)
generates and rewrites at runtime. None of the real files live in this repo — each is either
DB-versioned (a `*ConfigRevision` model, applied to the live path on Save & Apply) or a plain
live file the engine re-reads on every report — see `webapp/reports/*_admin.py` for the exact
mechanics behind each screen. What's here is the SHAPE of each file, for reference and for
bootstrapping a fresh install, the same way `../config.sample.ini` and `../prometheus.sample.yml`
already do for the two files that exist outside the Configuration menu entirely.

| Configuration screen | Manages (live path, not in this repo)                              | Sample here                  | Backed by                          |
|-----------------------|----------------------------------------------------------------------|-------------------------------|--------------------------------------|
| Prometheus / Topology | `C:\metrics\prometheus\prometheus.yml`                               | [`../prometheus.sample.yml`](../prometheus.sample.yml) (repo root — predates this folder, not duplicated here) | `PrometheusConfigRevision` |
| Prometheus (rule files) | `C:\metrics\prometheus\alerts.yml`, `t24_services.yml`, `folder_exporter_rules.yml` | [`rules/`](rules/)          | `PrometheusRuleFileRevision` |
| Grafana                | `C:\Program Files\GrafanaLabs\grafana\conf\custom.ini`               | [`grafana.custom.sample.ini`](grafana.custom.sample.ini) | `GrafanaConfigRevision` |
| SNMP                   | `<snmp_exporter dir>\snmp.yml` — just the `auths:` block; `modules:` is generator output this screen never touches | [`snmp.auths.sample.yml`](snmp.auths.sample.yml) | `SnmpConfigRevision` |
| Backup policy           | `send_report/backup_policy.json` (both the webapp's own copy and the scheduled `C:\metrics\prometheus\send_report` deployment) | [`backup_policy.sample.json`](backup_policy.sample.json) | `BackupPolicyRevision` |
| Data sources            | `SystemConfig` row — Prometheus/Grafana URL overrides, DB-only, nothing to sample | — | `SystemConfig` |
| Role scopes             | `RoleScope` rows — which systems each role's picker shows, DB-only, nothing to sample | — | `RoleScope` |

Every DB-versioned screen bootstraps its very first revision FROM the live file (or the
hardcoded defaults, for Backup policy), so a fresh install's live files can start out looking
exactly like the samples here and the first admin edit takes it from there — no different from
copying `config.sample.ini`, just versioned from that point on instead of hand-maintained.

# Exporter Hardening — Systems to Prioritize

**Status:** Flagging only. Nothing in this document has been implemented — no exporter,
Prometheus config, or firewall rule has been touched. This is a prioritized list for whoever
does the hardening work.

**Scope:** every exporter target currently scraped by `C:\metrics\prometheus\prometheus.yml`
(`windows_exporter` :9182, `node_exporter` :9100, `folder_exporter` :9847, `postgres_exporter`
:9187, `snmp_exporter` :9116) talks **plain HTTP with no authentication**. Prometheus's own
scrape configs have no `tls_config` or `basic_auth`/`bearer_token` block anywhere except the
SNMP job. That means: anyone who can reach an exporter port on the network gets the full metric
set — hostnames, service state, disk paths, process names — with no credential, and anyone who
can reach Prometheus itself (or sit on the wire between it and a target) can read or spoof that
traffic.

**What "hardened" means here** (for whoever implements it later): each exporter binary
(`windows_exporter`, `node_exporter`, `folder_exporter`) supports a `--web.config.file` /
equivalent flag for TLS + `basic_auth_users`. Once that's turned on per-host, the matching
`scrape_configs` entry in `prometheus.yml` needs `scheme: https`, a `tls_config` (at minimum
`insecure_skip_verify` off with the right CA, or per-host certs), and `basic_auth` /
`authorization` credentials. Both sides have to change together or the scrape breaks.

---

## Tier 1 — Public-facing (has a domain / reverse-proxy in front, or reachable outside the
internal network)

These are confirmed public-facing because they're probed over HTTPS by the `blackbox_http` job
in `prometheus.yml`, and/or have a `role: reverse-proxy` host in the topology. A compromise of
the front door here puts an attacker directly on the same network segment as the exporter.
**Highest priority.**

| System | Public URL | Exporter hosts (currently plain HTTP, no auth) |
|---|---|---|
| RBZ Website | https://www.rbz.co.zw/ | 10.100.245.46:9100 |
| RTGS | https://rtgs.rbz.co.zw/ | 10.100.249.244:9100, 10.100.249.243:9100, 10.100.249.24:9100, 10.100.249.220:9100, 10.100.246.70:9100 (reverse proxy) |
| CMS | https://cms.rbz.co.zw/ | 10.100.248.10:9100, 10.100.248.11:9100 |
| CEPECS | https://cepecsrpt.excon.rbz.co.zw/ | 10.100.248.27:9100, 10.100.248.23:9100, 10.100.200.203:9100, 192.168.25.159:9100 (reverse proxy) |
| CEBAS | https://forex.rbz.co.zw/cebas/ | 10.100.248.28:9100, 10.100.248.22:9100, 10.100.200.207:9100, 192.168.25.155:9100 (reverse proxy) |
| LMS | https://lms.rbz.co.zw/ | 10.100.246.144:9100, 10.100.246.145:9100, 10.100.246.146:9100 |
| ESF | https://esf.rbz.co.zw/ | 10.100.245.70:9100 |
| BDTRS | https://bdctrs.rbz.co.zw/ | 10.100.248.20:9100, 10.100.248.21:9100 |
| FRS | https://frs.rbz.co.zw/ | 10.100.245.150:9100 (also runs Apache2/MySQL exporters via systemd checks, same host) |
| BSA | https://bsa.rbz.co.zw/Account/Login/ | 10.0.206.5:9182 (DB), 192.168.25.156:9100 (reverse proxy), 10.0.206.6:9100 (app) |
| Collateral Registry | https://collateralregistry.rbz.co.zw/ | 10.0.207.8:9182 (app), 10.0.207.9:9182 (db) |
| EDMS | https://edms.rbz.co.zw/ | 10.0.206.11:9182 (db), 10.0.206.12:9182 (app) |
| Temenos / T24 | http://10.0.212.3:9089/BrowserWeb/ **(note: app itself is plain HTTP, not just the exporter — separate finding, flag to whoever owns that app)** | 10.0.212.3:9182, 10.0.212.4:9182, plus folder_exporter :9847 and postgres_exporter (proxied via 10.0.207.11:9187) |
| SmartHR | http://10.100.245.133/smartess/ **(same note — app front door is plain HTTP)** | 10.100.245.133:9182, 10.100.245.134:9182 |

**EBIS** (10.0.207.20 app / 10.0.207.21 db, added 2026-08-13) is not yet in the `blackbox_http`
probe list, but it was wired in with the exact same App(IIS)+DB(MSSQL) shape as EDMS and
Collateral Registry, both of which are public-facing. Confirm whether EBIS has (or will get) a
public front door — if so it belongs in this tier; treat it as Tier 1 in the meantime out of
caution.

---

## Tier 2 — High-risk, no confirmed public front door

Financial/critical-function systems where the topology shows no `blackbox_http` entry or
reverse-proxy role today (i.e., nothing indicates they're reachable from outside the internal
network), but the data/function is sensitive enough that internal-network compromise is still a
serious outcome. Still worth hardening exporter access to limit lateral movement, just not the
same urgency as Tier 1.

| System | Why high-risk | Exporter hosts |
|---|---|---|
| CSD (Central Securities Depository) | securities settlement | 10.100.245.11:9100, 10.100.250.82:9100 |
| Efin (Efinancials / Oracle) | core financial/accounting data | 10.0.201.3:9182, 10.0.201.2:9182 |
| CRB (Credit Registry) | credit-bureau PII, has a "Web" role host (`CRB Web` 10.100.245.58) that may be more exposed than the others — worth confirming | 10.100.240.116:9182, 10.100.245.58:9182, 10.100.8.248:9182 |
| GCMS (Gold Coin Management) | asset/reserve management | 10.100.247.23:9182 |
| RTGSTEST | same family as RTGS (Tier 1); lower stakes since it's a test environment, but often gets forgotten in hardening passes precisely because it's "just test" | 10.100.249.67:9100 |
| ESFEXEC | same family as ESF (Tier 1), no public front door confirmed | 10.100.245.240:9100 |
| Paytyme | name suggests a payments system; no public URL currently probed — **confirm classification** | 10.0.212.16:9182 |

---

## Cross-cutting, non-obvious priorities

- **`vault.rbz.co.zw`** — the org auth endpoint the webapp (and reportedly other apps) log in
  against, probed via `blackbox_ldap`/`blackbox_http`. It isn't an "exporter" in this topology,
  but it's the authentication backbone: a compromise here has blast radius across every system
  that trusts it. Not in scope for exporter hardening, but flagging because it's the single
  highest-value target on this whole list.
- **GMS (10.100.248.249:9182)** — this is the monitoring host itself (Grafana + Prometheus).
  Its own `windows_exporter` is scraped the same unauthenticated way as everything else. If this
  box is compromised, an attacker doesn't just get one system's metrics — they get read access
  to (and potentially can spoof data for) every system in this file. Recommend hardening this
  one first as a proof-of-concept before rolling out to the rest, since it's both highest-value
  and the box you already control end-to-end.
- **SNMP (`10.100.210.253`, RBZ Network)** is the one target in this config that already has
  *some* auth — `auth: [RBZ_v3]` (SNMPv3). Worth confirming that module actually uses
  `authPriv` (auth **and** encryption) and not just `authNoPriv`, since v3 config commonly gets
  set up with authentication but not privacy/encryption by mistake.
- **Eagle** (10.100.220.29/32/38/36, 4 hosts: app/db/bkp/dr) and **Intranet**
  (10.100.248.40, WordPress) have no public front door in this config and aren't obviously
  financial-critical — lower priority than everything above, but WordPress specifically is a
  common opportunistic target if it's ever exposed, worth a second look before deprioritizing.

---

## Suggested order of operations (once hardening actually starts)

1. GMS (the monitoring host) — prove out the TLS + basic-auth pattern on a box you fully
   control before touching production systems.
2. Tier 1 table, roughly in order of public exposure severity (RBZ Website and RTGS first —
   most visible / most critical).
3. Tier 2 table.
4. Revisit Eagle/Intranet once the rest are done.

Each step is: turn on `--web.config.file` (TLS cert + `basic_auth_users`) on the exporter,
then update that target's block in `prometheus.yml` to `scheme: https` + `tls_config` +
`basic_auth`, together, then confirm the target still shows `up` in Prometheus before moving to
the next host.

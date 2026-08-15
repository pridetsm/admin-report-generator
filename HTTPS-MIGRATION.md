# HTTP → HTTPS Migration — 2026-08-14

**Status:** Prometheus, Grafana, and the webapp are all now serving HTTPS, sharing one
self-signed cert. A real wildcard cert has been issued and is mid-swap-in (blocked — see
"Open items"). Written the same day this work happened, for whoever picks it up next.

---

## 1. Before this session

- Prometheus: plain HTTP on `:9090`.
- Grafana: plain HTTP on `:3000`.
- The webapp (`AdminReportGenerator` service, Django + waitress): plain HTTP, first on
  `:8000`, then moved to bare `:80` (`0.0.0.0:80`) earlier this week so
  `http://monitoring.rbz.co.zw/` worked without a port in the URL. No reverse proxy, no TLS
  anywhere in the stack.
- `deployment.txt` §9 already documented IIS+ARR as the intended production reverse proxy,
  but it had never been implemented.

## 2. What triggered this work

You upgraded Prometheus to HTTPS yourself (self-signed cert, `CN=prometheus.internal`,
generated 2026-08-14, valid 1 year). That broke every plain-HTTP client talking to it — the
webapp, the standalone report/mailing scripts, and Grafana's datasource — so the rest of this
session was making the whole stack consistent with that change, then extending HTTPS to
Grafana and the webapp too, then starting the move from self-signed to a real cert.

## 3. Code changes (webapp + send_report engine)

The report engine (`send_report/generate_report.py`) and the standalone mailer
(`send_report/mail_report.py`, which has its **own duplicated** `Config`/`Prometheus`
classes — not just imports from `generate_report.py`) both talk to Prometheus over
`urllib.request`, which does full TLS certificate verification by default. Against a
self-signed cert that fails immediately (`CERTIFICATE_VERIFY_FAILED`).

Added a `verify_tls` config option, mirroring the existing pattern already used for
`[auth]`/`[keycloak]`:

- `Config.verify_tls: bool = True` (new field, both `generate_report.py` and
  `mail_report.py`'s own `Config` class)
- `load_config()` reads it from `config.ini`'s `[prometheus]` section: `verify_tls = false`
- `Prometheus.__init__` now takes `verify_tls` and builds an unverified `ssl` context when
  it's `False` (`ssl._create_unverified_context()`), passed to every `urllib.request.urlopen`
  call

Threaded through **every** `Prometheus(...)` call site in the codebase (found by grepping the
whole repo, not just the obvious ones — several were missed on the first pass and had to be
caught in a follow-up):

- `send_report/generate_report.py` — the CLI's own `main()`
- `send_report/mail_report.py` — both its own `Prometheus(...)` and the
  `engine.Prometheus(...)` call (via the `--attach` path that reuses `generate_report.py`)
- `send_report/generate_os_inventory.py` — a separate report generator added earlier this
  week; also had a hardcoded `Prometheus(args.prom)` with no `verify_tls`, would have broken
  silently the first time someone ran it
- `webapp/reports/services.py` — `capture_snapshot()`, the main dashboard capture path
- `webapp/reports/folders.py` — the "Folder Watch" feature's own Prometheus client
- `webapp/reports/connect.py` — the host-reachability (`fetch_up()`) check

Also fixed stale links that assumed the old scheme/port, since they'd otherwise silently
point somewhere dead:

- `Config.grafana` / `Config.prom` **defaults** in both `generate_report.py` and
  `mail_report.py` — `http://` → `https://`
- `REPORT_GENERATOR_URL` in `mail_report.py` (the "Grafana Report Generator" link in every
  daily email) — went through **two** revisions today: first `http://10.100.248.249:8000` →
  `http://monitoring.rbz.co.zw` (matching the domain assignment from earlier this week), then
  `http://` → `https://monitoring.rbz.co.zw` once the webapp itself went HTTPS-only and port
  80 stopped serving the app directly (see §5).

`webapp/config/settings.py` — added:

```python
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

so Django knows a request forwarded from the IIS proxy was originally HTTPS (needed for
correct `request.is_secure()`, secure-cookie behavior, etc.). This header is only safe to
trust because waitress is bound to loopback only (§5) — if it were reachable directly, anyone
could spoof that header and fake a "secure" request.

## 4. `config.ini` changes (both copies)

`send_report/config.ini` exists in **two places** that must be kept in sync manually — the
repo copy (`send_report/config.ini`) and the **real, live** one used by the scheduled daily
mailing task (`C:\metrics\prometheus\send_report\config.ini`). Both got:

```ini
[prometheus]
url = https://10.100.248.249:9090
verify_tls = false

[grafana]
url = https://10.100.248.249:3000/d/...  ; was http://
```

**Recurring gotcha this session:** several fixes landed only in the repo copy and had to be
re-applied to the standalone copy after the fact (or vice versa — once, syncing the repo copy
*over* the standalone one accidentally reverted a fix that had only ever been made locally).
There is no automation keeping these two in step; every code change to `generate_report.py` /
`mail_report.py` needs a manual `cp` to `C:\metrics\prometheus\send_report\` afterward, and
every `config.ini` value change needs to be applied to both files by hand.

## 5. Grafana → HTTPS

Wired Grafana to use the **same** cert Prometheus already had
(`C:\metrics\prometheus\server.crt` / `server.key`, `CN=prometheus.internal`) rather than
issuing a separate one — one file to swap later instead of three.

`C:\Program Files\GrafanaLabs\grafana\conf\custom.ini`:

```ini
[server]
protocol = https
cert_file = C:\metrics\prometheus\server.crt
cert_key = C:\metrics\prometheus\server.key
root_url = https://10.100.248.249:3000

[security]
allow_embedding = true   ; added earlier this session, unrelated to TLS — allows iframe embedding
```

Grafana's own Prometheus **datasource** also had to be updated separately (it's stored in
Grafana's DB, not a config file) — done via the HTTP API:

```
PUT /api/datasources/1
  url: https://localhost:9090
  jsonData.tlsSkipVerify: true
```

Confirmed via `/api/datasources/1/health` → `"status":"OK"` and a live proxied query.

## 6. Webapp → HTTPS (the big one: IIS + ARR reverse proxy)

`waitress` (the WSGI server the Django app runs under) has no real native TLS support and was
never meant to terminate production HTTPS directly — the standard pattern (and what
`deployment.txt` §9 already called for) is a reverse proxy in front. On Windows that's
**IIS + Application Request Routing (ARR) + URL Rewrite**.

### 6.1 Installing IIS + ARR

- IIS base role: installed via `Install-WindowsFeature` — works from local Windows sources,
  no internet needed.
- **URL Rewrite** and **ARR** are *not* Windows features — separate Microsoft downloads. This
  server initially had **no internet access**, which blocked this entirely; internet access
  was fixed partway through the session, then both `.msi` installers were pulled directly
  from `download.microsoft.com` and installed silently (`msiexec /qn`).

### 6.2 The cert

The self-signed `server.crt`/`server.key` (same file Prometheus and Grafana use) was combined
into a PFX (`openssl pkcs12 -export`, using Git-for-Windows' bundled `openssl.exe` since none
was on `PATH`) and imported into `Cert:\LocalMachine\My` via `Import-PfxCertificate`
(thumbprint `77DC3C03325C55F9305420FCA058CD99FCB5FB6D`). The temporary PFX file was deleted
immediately after import — the private key lives only in the Windows cert store from that
point on.

### 6.3 IIS site layout (current live state)

Two sites, both bound by host header `monitoring.rbz.co.zw` (no dedicated hostname exists for
Grafana or Prometheus, which is *why* only the webapp got this treatment — see the answer
given when asked "why not do this for Grafana too?" in conversation: it would need either a
new DNS subdomain or moving Grafana off its conventional `:3000` HTTPS address):

| Site | ID | Binding | Physical path | Purpose |
|---|---|---|---|---|
| `MonitoringProxy` | 2 | `*:443:monitoring.rbz.co.zw` | `C:\inetpub\monitoring-proxy` | Reverse-proxies everything to waitress |
| `MonitoringRedirect` | 3 | `*:80:monitoring.rbz.co.zw` | `C:\inetpub\monitoring-redirect` | 301-redirects everything to `https://` |

`Default Web Site` (the IIS-installed placeholder, never used) was deleted.

**`MonitoringProxy`'s `web.config`** (reverse proxy rule):
```xml
<rule name="ReverseProxyToWaitress" stopProcessing="true">
    <match url="(.*)" />
    <action type="Rewrite" url="http://127.0.0.1:8000/{R:1}" />
    <serverVariables>
        <set name="HTTP_X_FORWARDED_PROTO" value="https" />
        <set name="HTTP_X_FORWARDED_HOST" value="{HTTP_HOST}" />
    </serverVariables>
</rule>
```
Required `Set-WebConfigurationProperty ... system.webServer/proxy enabled=True` (ARR's proxy
feature is off by default) and `appcmd unlock config /section:system.webServer/rewrite/allowedServerVariables`
(that section is locked at the server level by default; without unlocking it, setting the
`X-Forwarded-*` server variables 500s with "This configuration section cannot be used at this
path").

**`MonitoringRedirect`'s `web.config`** (HTTP → HTTPS redirect):
```xml
<rule name="RedirectToHttps" stopProcessing="true">
    <match url="(.*)" />
    <conditions><add input="{HTTPS}" pattern="off" ignoreCase="true" /></conditions>
    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
</rule>
```

### 6.4 Two real infrastructure bugs hit along the way

**(a) IPv6 is disabled on this server's adapter**, but IIS's `*` (wildcard) binding always
tries to bind the IPv6 wildcard `[::]:80` too, regardless of what per-site IP address you
specify (a host-header-based binding structurally can't avoid this — confirmed empirically:
even binding the site to the literal IPv4 address `10.100.248.249` instead of `*` still tried
`[::]:80` and failed). Every attempt to start the redirect site failed with a `0x80070020`
"sharing violation" or, with a literal IP, a "did not construct valid URLs" error (IIS embeds
a literal non-`*` IP into the URL prefix it builds internally, which produces an invalid
multi-colon string).

**Fix:** `netsh http add iplisten ipaddress=0.0.0.0` — a machine-wide HTTP.sys setting that
restricts it to IPv4-only for all wildcard registrations. After that, the standard `*` binding
worked immediately. (Diagnosed via `Get-WinEvent -LogName System` — the
`Microsoft-Windows-HttpEvent` / `Microsoft-Windows-IIS-W3SVC` event log entries had the real
error; the PowerShell cmdlet error messages themselves were misleading.)

**(b) Once `MonitoringRedirect` (`*:80`) existed, waitress could no longer bind
`127.0.0.1:80`**, even though it had been running there without issue *before* that IIS site
existed. A wildcard (`*`/`0.0.0.0`) HTTP.sys registration claims the **entire** port across
*all* local addresses at the kernel level — including loopback — which conflicts with any
other process trying to bind that same port via a raw (non-HTTP.sys) socket, which is what
waitress does.

**Fix:** moved waitress off port 80 entirely, onto a dedicated backend port,
`127.0.0.1:8000`, and updated `MonitoringProxy`'s rewrite rule to match. This is also the
current live backend port — see the table in §6.3.

### 6.5 Current service configuration

`AdminReportGenerator` (nssm-wrapped Windows service):
```
AppParameters = -m waitress --listen=127.0.0.1:8000 config.wsgi:application
```
Deliberately **loopback-only** — after IIS took over port 80/443 as the sole public entry
points, waitress was locked to `127.0.0.1` so it can't be reached directly, bypassing the
proxy (which would otherwise make the `X-Forwarded-Proto` trust in `SECURE_PROXY_SSL_HEADER`
spoofable — see §3).

### 6.6 End-to-end verified behavior

```
http://monitoring.rbz.co.zw/   → 301 → https://monitoring.rbz.co.zw/
https://monitoring.rbz.co.zw/  → 302 → /accounts/login/?next=/  → 200
http://monitoring.rbz.co.zw:80/ (direct, bypassing IIS)         → connection refused (loopback-only backend)
```

## 7. Real cert: wildcard `*.rbz.co.zw`

An opportunity came up mid-session to get a real (CA-issued) wildcard cert instead of staying
on the self-signed one indefinitely.

**CSR generated** (`openssl req -new -newkey rsa:2048 -nodes`):
- `C:\metrics\prometheus\wildcard-rbz-co-zw.key` — 2048-bit RSA private key
- `C:\metrics\prometheus\wildcard-rbz-co-zw.csr` — CSR, `CN=*.rbz.co.zw`,
  `subjectAltName=DNS:*.rbz.co.zw,DNS:rbz.co.zw`, subject `/C=ZW/ST=Harare/L=Harare/O=Reserve
  Bank of Zimbabwe`

That CSR was submitted to the CA (Sectigo, via whatever internal process handles cert
requests here) and a signed cert came back the same day as a zip,
`C:\metrics\prometheus\__rbz_co_zw.zip`, extracted to `C:\metrics\prometheus\new-cert\`:

| File | Contents |
|---|---|
| `__rbz_co_zw_cert.cer` / `__rbz_co_zw.pem` | the leaf cert, `CN=*.rbz.co.zw`, issued by Sectigo, valid 2026-01-26 → 2027-02-26 |
| `__rbz_co_zw_interm.cer` | intermediate: Sectigo Public Server Authentication CA OV R36 |
| `__rbz_co_zw_interm (1).cer` / `__rbz_co_zw.cer` | the (cross-signed) USERTrust RSA root |
| `__rbz_co_zw.crt` / `__rbz_co_zw.p7b` | the same thing bundled as PKCS7 (full chain, leaf → OV R36 → Root R46 → USERTrust root) |

## 8. Open items / not yet done

- **Cert swap is BLOCKED.** The issued leaf cert's public key does **not** match the private
  key generated alongside our CSR (`wildcard-rbz-co-zw.key`) — confirmed by comparing RSA
  modulus MD5 hashes, they differ. No private key was included in the zip either. This means
  whoever actually submitted the request to the CA generated a *different* key/CSR pair than
  the one made in this session (§7) — quite possibly via IIS's own "Create Certificate
  Request" wizard, which keeps its private key in the Windows certificate store's pending
  **Certificate Enrollment Requests** area rather than as a file on disk. **Next step:** check
  `Cert:\LocalMachine\REQUEST` for a pending request matching `CN=*.rbz.co.zw` — if found, IIS's
  "Complete Certificate Request" flow (or `certreq -accept`) should pair it with the issued
  cert automatically. This was interrupted mid-investigation and needs to be picked up.
- **Grafana and Prometheus do not have an HTTP→HTTPS redirect** the way the webapp now does.
  Both can only serve one protocol at a time on their port, so replicating the redirect would
  mean moving their real service to a different port and standing up an IIS site pair for
  each — more invasive, and lower priority since neither is normally typed directly into a
  browser by end users (Prometheus especially — it's mostly hit by Grafana and the report
  scripts, not humans).
- **Once a working real cert is in place**, it needs to be swapped into three places:
  1. `C:\metrics\prometheus\server.crt` / `server.key` (Prometheus, `web-config.yml`)
  2. Same two file paths, referenced by Grafana's `custom.ini` (no change needed there if the
     new cert reuses the same file paths — just overwrite the files and restart both services)
  3. Re-imported into the IIS certificate store (`Cert:\LocalMachine\My`) and rebound to
     `MonitoringProxy`'s `:443` binding (`$binding.AddSslCertificate(...)`), replacing
     thumbprint `77DC3C03325C55F9305420FCA058CD99FCB5FB6D`
- The **`.gitignore`d config files** (`webapp/.env`, `send_report/config.ini` — both copies)
  hold the operative TLS settings (`verify_tls`, HTTPS URLs) and are **not** captured by git
  at all. If this server is ever rebuilt from the repo alone, all of §4's `config.ini` changes
  and the `DJANGO_ALLOWED_HOSTS`/domain work from earlier in the week need to be redone by
  hand — nothing here automates that.

## 9. Quick reference — what's committed to git vs. server-only

**Committed** (commit `cde8578`, "Trust the internal Prometheus/Grafana/webapp TLS chain..."):
`verify_tls` plumbing, HTTPS link fixes, `SECURE_PROXY_SSL_HEADER` — i.e., all of §3.

**Server-only, not in git, not backed up anywhere else:**
- Both `config.ini` copies (§4)
- Grafana's `custom.ini` (§5) and its datasource DB row
- The entire IIS configuration: sites, bindings, `web.config` rewrite rules, the imported
  cert in the Windows cert store, the `netsh http iplisten` setting (§6)
- The cert files themselves: `server.crt`/`server.key`, and the wildcard cert
  material in `C:\metrics\prometheus\` (§7)
- waitress's `--listen` port in the nssm service config (§6.5)

If this server is rebuilt, **all of the above must be redone from this document** — none of it
is recoverable from `git pull` alone.

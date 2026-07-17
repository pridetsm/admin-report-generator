# System Admin — Report Builder (Django)

A slick, login-gated web form that lets admins **annotate and generate** the System Admin
report (light or dark theme) on demand. It reuses the existing report engine in
`../send_report/generate_report.py` — nothing is duplicated.

## What it does

1. Captures a **live** snapshot from Prometheus (the same `capture()` the CLI report uses).
2. Shows every flagged item per system (high CPU/RAM/disk, services down, missing/untracked
   backups, unreachable, expired certs) and lets the admin mark **Fix needed / Resolved**,
   add a **per-system comment**, sign as **author**, and pick a **Dark or Light** theme.
3. Generates the `.xlsx` with those answers **baked into the Notes panels** and downloads it.
4. Saves an **audit row** (who, when, theme, counts, and the full answers) — browsable at
   `/history` and in the Django admin.

## Data source decision

Metrics come from **Prometheus live**, not the MSSQL ingestion DB. A report is a point-in-time
snapshot of *now*; the DB is a 5-minute-polled downstream mirror, better suited to the
historical/trend features to come. This keeps the web report identical to the trusted CLI
report and avoids coupling to the C# ingestion service.

## Run it (development)

```bash
# from webapp/  (a .venv is already created here)
.venv/Scripts/python.exe -m pip install -r requirements.txt   # first time only
.venv/Scripts/python.exe manage.py migrate
.venv/Scripts/python.exe manage.py createsuperuser            # make your admin login
.venv/Scripts/python.exe manage.py runserver
```

Then open http://127.0.0.1:8000/ and sign in.

The report engine reads its Prometheus URL + topology from `../send_report/config.ini` and
`../prometheus.yml` — no separate configuration here. If Prometheus is unreachable the form
shows a clear error instead of a stack trace.

## Database (PostgreSQL)

All app data — **users, profiles, roles, report submissions, recipients** — persists in
PostgreSQL in production. It's configured by env vars; **without them the app falls back to
SQLite** for local dev, and the same (DB-agnostic) migrations apply to both:

```bash
POSTGRES_DB=sysdash POSTGRES_USER=sysdash POSTGRES_PASSWORD=… \
POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=5432 \
.venv/Scripts/python.exe manage.py migrate
```

Uses `psycopg` (v3). Extended user data lives on a `UserProfile` (OneToOne to the auth `User`,
which keeps username/password/**optional** email); every user gets a profile automatically, and
it's filled from the directory on first LDAP login or by an admin. Users edit their own at
`/profile/`.

## Configuration (env vars, all optional)

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | dev key | **set in production** |
| `DJANGO_DEBUG` | `1` | set `0` in production |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | comma-separated |
| `REPORT_SNAPSHOT_TTL` | `300` | seconds a captured snapshot stays valid |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_HOST` / `POSTGRES_PORT` | — | production DB (SQLite if unset) |

## Tests

```bash
.venv/Scripts/python.exe manage.py test reports
```

The tests patch the live capture with a synthetic snapshot, so they exercise auth, the form,
the generate/download path, and the audit row without needing a Prometheus server.

## Org sign-in (JSON auth endpoint)

Sign-in can be delegated to the org auth endpoint (e.g. `vault.rbz.co.zw:7272`), which takes a
JSON body `{"username", "password"}` and returns pass/fail. Driven by `send_report/config.ini`
`[auth]`, **off until enabled** (local accounts work meanwhile). To activate:

1. Set `url` to the exact endpoint (confirm path + http/https), then `enabled = true`, restart.
2. If success isn't a plain HTTP 2xx, set `success_field` to the JSON key that signals success.
3. Optionally set `email_field` / `name_field` to response keys that carry the user's details.

Users then sign in with their org credentials (auto-provisioned as ordinary Django users; the
local `admin` still works as a fallback). Standard library only — no extra dependency. This
endpoint authenticates only (not a directory), so the "e-mail report to" list stays the curated
one in the admin.

## Roles (Keycloak)

Authentication is the `[auth]` endpoint; **Keycloak is only the role store**. The four roles
(System Admin, Network Admin, Gov Systems Admin, Administrator) are Keycloak **realm roles**;
the app mirrors a user's roles into Django groups **at login** (`sync_user_roles`), and the
**Administrator console** (`/roles/`) reads/writes them back through Keycloak's admin API.
A signed-in user with no role lands on the request page and can request roles; an Administrator
approves them (which grants the Keycloak role).

Driven by `send_report/config.ini` `[keycloak]` (secret via env `KEYCLOAK_CLIENT_SECRET`),
**off until enabled** — while disabled, roles are managed locally in the Django groups the
console/admin edit. To activate: fill `base_url`, `realm`, `client_id` (a confidential client
whose service account has `manage-users`/`view-users`), set the secret, `enabled = true`.
The four role names must exist as realm roles in Keycloak. Standard library only.

## Notes for production

- The snapshot is cached in-process (LocMemCache) between the form and generation. If you run
  **multiple workers**, point `CACHES` at Redis/Memcached so both requests see the same snapshot.
- Serve behind a real WSGI server (gunicorn/uwsgi/waitress) with `DEBUG=0`, run
  `collectstatic`, and set a real `DJANGO_SECRET_KEY`.
- Only report generation is implemented for now; the app is structured so more features
  (history detail, trends off the MSSQL DB, email delivery) drop in as new views.

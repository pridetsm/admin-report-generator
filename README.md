# Admin Report Generator

A Django web app for generating the **System Admin Report** (an `.xlsx`) from
**live Prometheus metrics**. Administrators load a live snapshot, answer the
flagged items and add comments, then **download or e-mail** the report. Every
report is kept in an auditable **history**, and user access is governed by
**roles**.

> **Deploying this? Read [`deployment.txt`](deployment.txt) first — it covers everything in detail.**

## Repository layout

```
admin-report-generator/
├── webapp/              Django project (run/serve this)
│   ├── config/          settings, urls, wsgi
│   ├── reports/         the app: views, models, auth, services, migrations
│   ├── templates/  static/     UI
│   └── requirements.txt
├── send_report/         Report ENGINE, imported by the webapp (keep as a sibling)
│   ├── generate_report.py   builds the .xlsx
│   ├── mail_report.py       renders + sends the e-mail
│   └── logo.png
├── config.sample.ini        sample engine config  (real one -> send_report/config.ini)
├── prometheus.sample.yml    sample topology for local dev only — production points
│                            config.ini's `yml` setting straight at the real Prometheus
│                            server's own scrape config instead (see deploy/PLACEMENT.txt)
├── deploy/                   SENSITIVE files, delivered out-of-band (git-ignored)
└── deployment.txt           full deployment guide
```

## Quick start (development)

```bash
# 1. put the real config in place (or copy the samples and edit)
cp config.sample.ini      send_report/config.ini
cp prometheus.sample.yml  prometheus.yml

# 2. python env
python -m venv webapp/.venv
# Windows: webapp\.venv\Scripts\Activate.ps1   ·   *nix: source webapp/.venv/bin/activate
pip install -r webapp/requirements.txt

# 3. database + first admin (SQLite is used automatically when POSTGRES_DB is unset)
python webapp/manage.py migrate
python webapp/manage.py createsuperuser

# 4. run
python webapp/manage.py runserver 0.0.0.0:8000
```

Then open http://127.0.0.1:8000/ and log in.

## Configuration

- **Django / runtime env** → `webapp/.env` (auto-loaded). See
  [`deploy/env.example`](deploy/env.example): `DJANGO_SECRET_KEY`,
  `DJANGO_ALLOWED_HOSTS`, `POSTGRES_*`, …
- **Engine / data sources** → `send_report/config.ini` (Prometheus URL, Grafana
  link, SMTP, org auth, Keycloak). See [`config.sample.ini`](config.sample.ini).
- **Topology** → whatever file `[prometheus] yml` in `send_report/config.ini` points
  at (system→host mapping). In production this points DIRECTLY at the real Prometheus
  server's own scrape config (e.g. `C:\metrics\prometheus\prometheus.yml`) — Prometheus
  and this app run on the same host, so there is exactly one topology file, no copied
  snapshot to go stale. See [`deploy/PLACEMENT.txt`](deploy/PLACEMENT.txt).

**Secrets are never committed.** `webapp/.env`, `send_report/config.ini`,
`prometheus.yml` (if you're using a local copy for dev) and the whole `deploy/` folder
are git-ignored.

## Tests

```bash
python webapp/manage.py test reports
```

## License / ownership

Internal tooling for the Reserve Bank of Zimbabwe. Not for public distribution.

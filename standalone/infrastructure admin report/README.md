# Infrastructure Report — standalone

Self-contained tool that pulls live metrics from Prometheus, renders a themed,
tree-nested Excel dashboard (`Infrastructure Report - <date> (<theme>).xlsx`) and
e-mails a styled summary of everything that needs attention.

Covers today: the two Active Directory root domain controllers (RBZHQ-ROOT-01,
RBZ-HQ-ROOT-02) and the HCI Cluster. Standalone DB Hosts and any additional Private
Cloud Cluster Hosts are **not onboarded yet** — no Prometheus scrape config exists
for them anywhere in this deployment. They will appear here automatically, with no
code change, the moment real targets are added (see `generate_report.py`'s own
module docstring for exactly where).

## Contents
| File | Purpose |
|---|---|
| `generate_report.py` | **The report engine.** Captures live metrics from Prometheus and builds the ReportData tree. Also imported directly by `mail_report.py --attach`. |
| `report_generator.py` | **The rendering engine.** Pure data-model -> .xlsx (dataclasses + `build_report()`), no Prometheus, no Django — ported from the approved Infrastructure Report template. The webapp's own Infrastructure Admin report uses the identical module (`send_report/infrastructure_report.py`), kept in sync with this file by hand. |
| `verify_layout.py` | QA tool — checks a rendered .xlsx's table alignment/spacing against the layout model. Not a runtime dependency. |
| `mail_report.py` | Analyse the data and e-mail a styled HTML summary — with the XLSX attached (`--attach`). |
| `config.ini` | **All settings** — Prometheus URL, output path, SMTP, and the mailing list (`[recipients]`). Not committed to this repo (see Configuration below) — create it locally. |
| `requirements.txt` | Python dependencies (`openpyxl` only). |
| `run_and_mail.bat` | One capture -> builds + attaches the report + sends. |

## Run it
```
run_and_mail.bat        # capture once -> build the report -> e-mail it attached
```
Installs requirements if missing and sends to the mailing list in `config.ini`.

## Manual use
```
python generate_report.py                        # build the xlsx only
python mail_report.py                             # DRY-RUN: preview email, send nothing
python mail_report.py --send                      # send (link-only body, no attachment)
python mail_report.py --attach --send             # send WITH the xlsx attached
python mail_report.py --to me@rbz.co.zw --send    # override recipients
```

## Report options
| Flag | Effect | Where |
|---|---|---|
| `--prom URL` | override the Prometheus base URL | both |
| `--out PATH` | override the output xlsx path | `generate_report.py` |
| `--author "P. Moyo"` | name written into each group's "By" field | both |
| `--summary "text"` | free text noted alongside Summary Notes | both |
| `--stamp` | write a date/time-stamped filename instead of overwriting `--out` | `generate_report.py` |
| `--theme dark\|light` | accepted for CLI parity with the other reports — the current renderer ships one dark theme only, so this has no visible effect yet | both |
| `--report PATH` | attach an existing xlsx rather than generating one | `mail_report.py` |
| `--keep-report PATH` | also save the generated xlsx there | `mail_report.py` |

```
python generate_report.py --author "P. Moyo" --stamp
python mail_report.py --attach --author "P. Moyo" --send
```

## What this report is honest about
Two things this codebase deliberately does NOT collect yet show up as plain notes
rather than fabricated numbers:
- **Root DC host resources.** Only the windows_exporter *service* collector
  (ADWS/DNS/Netlogon/KDC) is currently enabled on the two root domain controllers —
  CPU/RAM/disk read no data. The Active Directory group says so directly instead of
  showing a 0%.
- **Cluster Storage** (a vSAN-style pool used%/size for the HCI Cluster). No metric
  source for it exists in this codebase yet, so that panel is simply absent rather
  than invented.

## Configuration
Create **`config.ini`** next to this file (gitignored — not committed, same as the
System Admin Report's own):
```ini
[prometheus]
url = http://PROMETHEUS_HOST:9090
verify_tls = true

[report]
output = Infrastructure Report.xlsx

[smtp]
host = smtp.office365.com
port = 587
user = noreply@example.org
password = CHANGE_ME
from_address = noreply@example.org
from_name = Infrastructure Report
starttls = true
skip_verify = false

[recipients]
to = ops@example.org
```

## Security note
`config.ini` holds the SMTP password in plaintext. Keep the folder access-controlled,
and consider moving the password to an environment variable in a hardened deployment.

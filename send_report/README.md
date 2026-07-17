# System Admin Report — send_report

Self-contained tool that pulls live metrics from Prometheus, renders a themed
Excel report (`System Admin Report.xlsx`) and e-mails a styled summary of
everything that needs attention.

## Contents
| File | Purpose |
|---|---|
| `generate_report.py` | Capture metrics from Prometheus and build the XLSX report. |
| `mail_report.py` | Analyse the data and e-mail a styled HTML summary (report attached). |
| `config.ini` | **All settings** — Prometheus/Grafana URLs, thresholds, logo placement, SMTP, and the **mailing list** (`[recipients]`). |
| `requirements.txt` | Python dependencies (`openpyxl`). |
| `logo.png` | Company logo (transparent, with reflection). |
| `run.bat` | Checks requirements, generates the report, then e-mails it. |

## Run it
```
run.bat
```
That installs requirements if missing, builds the report, and sends it to the
mailing list in `config.ini`.

## Manual use
```
python generate_report.py                       # build the xlsx only
python mail_report.py                            # DRY-RUN: preview email, send nothing
python mail_report.py --send                     # send to the config.ini mailing list
python mail_report.py --to me@rbz.co.zw --send   # override recipients
```

## Configuration
Edit **`config.ini`** — every setting lives there. To change who gets the report,
edit the `[recipients]` section:
```
[recipients]
to = pmoyo2@rbz.co.zw, ops@rbz.co.zw, dba@rbz.co.zw
```

## Security note
`config.ini` holds the SMTP password in plaintext. Keep the folder access-controlled,
and consider moving the password to an environment variable in a hardened deployment.

# System Admin Report — send_report

Self-contained tool that pulls live metrics from Prometheus, renders a themed
Excel report (`System Admin Report.xlsx`) and e-mails a styled summary of
everything that needs attention.

## Contents
| File | Purpose |
|---|---|
| `generate_report.py` | **The report engine.** Captures metrics from Prometheus and builds the XLSX report. Also imported directly by `mail_report.py --attach` and by the Django Report Generator webapp (`webapp/reports/services.py`), so all three produce the same workbook. |
| `mail_report.py` | Analyse the data and e-mail a styled HTML summary — with the XLSX attached (`--attach`) and a link to the Report Generator webapp. |
| `config.ini` | **All settings** — Prometheus/Grafana URLs, thresholds, logo placement, SMTP, and the **mailing list** (`[recipients]`). |
| `requirements.txt` | Python dependencies (`openpyxl`, `PyYAML`, `Pillow`). |
| `logo.png` | Company logo (transparent, with reflection). |
| `run.bat` | Two steps: builds the report to disk, then e-mails it. |
| `runmailing.bat` | **The scheduled daily mailing.** One capture → builds + attaches the report + sends. |

## Run it
```
runmailing.bat        # capture once -> build the report -> e-mail it attached
run.bat               # same, but also leaves the xlsx on disk (two captures)
```
Either installs requirements if missing and sends to the mailing list in `config.ini`.

## Manual use
```
python generate_report.py                        # build the xlsx only
python mail_report.py                            # DRY-RUN: preview email, send nothing
python mail_report.py --send                     # send (link only, no attachment)
python mail_report.py --attach --send            # send WITH the xlsx attached
python mail_report.py --to me@rbz.co.zw --send   # override recipients
```

## Report options
`generate_report.py` and `mail_report.py --attach` take the same report flags, which
mirror what the webapp offers:

| Flag | Effect |
|---|---|
| `--theme dark\|light` | Palette. `light` matches the approved reference workbook. Default `dark`. |
| `--author "P. Moyo"` | Fills the master **By** field, mirrored across every card. |
| `--summary "text"` | Free text for the Summary Notes box. |
| `--systems "RTGS,CRB"` | Scope to those systems only. Web links and SSL certs are scoped too, so a partial report never leaks another system's endpoints. |
| `--stamp` (generate only) | Write `System Admin Report - YYYY-MM-DD HHMM (theme).xlsx` instead of overwriting one file. |
| `--report PATH` (mail only) | Attach an existing xlsx rather than generating one. |
| `--keep-report PATH` (mail only) | Also save the generated xlsx there. Dry runs keep it in this folder by default; sends use a temp file. |

```
python generate_report.py --theme light --author "P. Moyo" --stamp
python mail_report.py --attach --theme light --systems "RTGS,T24" --send
```

### Attachment vs. link
The e-mail carries both, and they are different things:
- **the attachment** is the automated, unannotated snapshot for that run;
- **the Grafana Report Generator link** is where an admin builds a report with their own
  sign-off — per-system answers, notes, an author, and only the systems they pick.

If `openpyxl`/`Pillow` are missing, `--attach` logs a warning and sends the e-mail
link-only rather than failing the run.

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

"""Renders the SYNTHETIC test-fire path's per-category e-mail ('positive' kind only — see
alerting.render_test_email) as Outlook-safe HTML: table-based layout, literal inline hex
colors, no CSS custom properties, no flexbox/grid, no inline SVG.

reports/alert_email_samples/*.html (the ORIGINAL hand-designed files, still served as-is by
config_alert_template_preview for the read-only "Alert templates" gallery) use all three of
those, because they're a design reference meant to be opened in a browser. Outlook desktop's
HTML renderer is Microsoft Word, not a browser engine: it drops var()-based colors, collapses
flex/grid layouts, and does not render inline SVG at all -- confirmed live (screenshot from a
real recipient, 2026-09-03): the navy header background, the radial gauge, the flow-diagram
icons and the banner text all vanished, leaving only stray leftover text. This module produces
a DIFFERENT, plainer rendering of the same information that Outlook actually displays
correctly, reusing the shared header/flow/notice/footer skeleton and the shape-per-category
grouping (gauge / ring / grid / bar) as a design language, not the files themselves.

Only system/severity/group and each shape's illustrative numbers vary; wording is fixed per
category, matching what the original hand-designed samples said.
"""
from __future__ import annotations

import base64
import html
import math
import re
from pathlib import Path

from email.utils import make_msgid

from . import alert_email_images

# The exact bell glyph from the hand-built reference sample (2026-09-04) -- a small flat PNG,
# not the "\u{1F514}" emoji glyph the header used before, which every mail client/OS renders
# with its own (inconsistent) bell artwork. Embedded the same way every other image in this
# module is (CID for a real send, base64 data URI for a browser preview -- see _shell's own
# for_browser handling) rather than referencing an external URL, per this app's own
# no-external-fetch rule for e-mail images.
_BELL_ICON_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAB7ElEQVR4nO2cS26EMBBEe6Isc6icJIfLSXKo7JMV"
    "EhqBMa7+VI/qLVlg+1G22yDxMFJ+f77+nq99fH4/Kvoy4q26A0ccyRtdr4RO4JUkNolUAmflMEmkEtgRCQSRQBAJ"
    "BKESOFvnMdWDVALNruUwyTMjFDiCTZ5ZM4GM0D3RmSKZKYkUHUFOFtUyyxqPOI5VyCxZA6POshVn5NQnljnArDSm"
    "JTA7HVntpTylO4OZSY73/RDCBc4OdmWgkfeeJVRgVk1XWTuGCbwaVMSAKtosKWOi0vAydeAoCdGDHN0/Ymd2F1gp"
    "b6Ydb4l6GwOSJjB7fWp5EmH6XjvCs58pCax65ZTRrtZAEDeBZ9Oi+oXnWfte01gJBJFAEAkEeUdv0KV0OWLf99W1"
    "GhZ4RvXmsWffFx3lyJBAEEgga+03wrsuVAJBJBBEAkEkEEQCQZYFdtyBNzx3YiUQRAJBJBBEAkEkEEQCQZYEdi5h"
    "NrxKGSUQRAJBJBBEAkEkEOS2wFfYgTc8dmK3z5qdvw8jaAqDSCDI8rr1ilN2ZR1XAkEkEIS29Ojy/0C6DnX76QTV"
    "FNbv7wDuSmGRSCOwKxQCV9PEkEIKgZ2RQBAJBJFAEAqBq4UxQ0FNIbAzNALvpokhfWZEAs16/oSWpiPPdHkbI0D+"
    "AW+P0rphemIfAAAAAElFTkSuQmCC"
)

# Kept for reports/views.py's config_alert_templates gallery, which serves these RAW files
# unmodified (browser-viewed design reference, not sent) -- unrelated to render() below.
SAMPLES_DIR = Path(__file__).resolve().parent / "alert_email_samples"
FILE_BY_CATEGORY = {
    "disk": "disk-usage.html",
    "ram": "ram-usage.html",
    "cpu": "cpu-usage.html",
    "service": "service-down.html",
    "backup": "backup-missing.html",
    "unreachable": "component-unreachable.html",
    "untracked": "backup-untracked.html",
    "folder": "folder-over-size.html",
    "backup_uncleared": "uncleared-backups.html",
}
SHAPE_BY_CATEGORY = {
    "disk": "gauge", "ram": "gauge", "cpu": "gauge",
    "service": "ring", "unreachable": "ring",
    "backup": "grid", "untracked": "grid", "backup_uncleared": "grid",
    "folder": "bar",
}

# Literal hex, matching send_report/mail_report.py's OWN palette exactly (NAVY/GOLD/RED/AMBER/
# GREEN/CRITICAL) rather than the earlier hand-designed samples' unrelated tokens -- these are
# the SAME colors the daily System Admin Report e-mail already uses, so an alert e-mail reads
# as the same product rather than a different tool with its own palette (2026-09-04, on
# request: "you are also using a wrong severity scale"). Outlook doesn't honour
# prefers-color-scheme any more reliably than it honours var(), and mail_report.py's own
# e-mail has no dark mode either, so neither does this.
INK, INK_SOFT = "#0E2A47", "#1C3F66"          # mail_report.NAVY, a lighter navy for the gradient
PAPER, CARD = "#EEF1F5", "#FFFFFF"
GOLD = "#C8A24B"                              # mail_report.GOLD
RED, RED_SOFT, RED_LINE = "#C0392B", "#FDECEA", "#E3B3AC"          # mail_report.RED/RED_T
AMBER_SOFT, AMBER_LINE = "#FEF6E7", "#E7CE99"                      # mail_report.AMBER_T
TEXT, MUTED, LINE, TRACK = "#1B2430", "#6B7785", "#DDE3EA", "#E4E8EE"   # MUTED = mail_report.MUTED
GREEN, GREEN_SOFT, GREEN_LINE = "#1E7D4F", "#E8F5EE", "#BFE5D1"    # mail_report.GREEN/GREEN_T
# IMMINENT is its own, DARKER red -- mail_report.CRITICAL (#8e1f1f), "reserved for unreachable
# components alone: the highest-severity finding, since it means Prometheus itself has lost
# visibility" (generate_report.py's own Theme.CHIP comment). Distinct from AMBER (the honest
# "GOLD" used for chrome/links elsewhere) -- this module already had a GOLD for that role, so
# reusing the name for a severity color would have meant two different things by one name.
IMMINENT, IMMINENT_SOFT, IMMINENT_LINE = "#8E1F1F", "#F8E0DF", "#D89A96"
# EVENT notifications (2026-09-04: "event notifications should be blue themed to indicate
# neatrality") are a deliberately DIFFERENT colour family from every severity above -- blue
# appears nowhere in the red/amber/green vocabulary, so an event can never be mistaken for an
# alert at a glance, which is the whole point of the two being separate notification types.
BLUE, BLUE_SOFT, BLUE_LINE = "#1E5FA8", "#E8F0FB", "#B9CFEA"
# SYSTEM ALERTS (2026-09-05: "the services checker metrics for t24 have been stale for a
# really long time... we definitely need a notification for this... we are introducing the
# concept of system alerts") are a THIRD notification family, answering yet another
# different question again -- not "is a monitored value over a threshold" (the red/amber/
# green/imminent vocabulary above) and not "did a discrete thing happen" (EVENT's blue) but
# "is our own monitoring pipeline still telling the truth." Purple, outside every other
# family's palette, so it reads as neither "something on a system is wrong" nor "something
# happened" but "we may not actually be able to see something on a system any more."
SYSTEM, SYSTEM_SOFT, SYSTEM_LINE = "#5B3E96", "#EFEAFB", "#C9BCE8"
FONT = "Arial, 'Segoe UI', sans-serif"
MONO = "'Courier New', monospace"

# The three-level severity vocabulary generate_report.SEVERITY already establishes for the
# rest of this product -- IMMINENT (an outage is underway, or we've lost the ability to see
# one) / CRITICAL (not down yet, but will take the service down if left) / WARNING (needs
# attention, nothing failing because of it right now) -- reused here rather than the raw
# "RED"/"AMBER" band a Flag carries internally, which said WHAT COLOR, never WHAT KIND of
# problem. "unreachable" is the one category that means "we've lost visibility" in the sense
# that definition names -- mail_report._services_down_block's own precedent labels a stopped
# SERVICE "CRITICAL", not IMMINENT, since the host is still reachable and being measured; only
# a truly unreachable component matches IMMINENT's own definition.
#
# "disk" joined "unreachable" here 2026-09-07 (on request: "treat disk near full alerts as
# captured in banners in the report generation logic as IMMINENT Alert Notifications") --
# NOT a new threshold: a disk Flag's own band=="red" already fires at exactly
# generate_report.cfg.chip_red, the SAME percentage the daily report's own "DISK NEAR-FULL"
# banner uses (send_report/generate_report.py's disk_near_full()) -- the report's own banner
# already treated this as an imminent-reads condition in its wording ("DISK NEAR-FULL") even
# though its own severity rank was "critical", not "imminent"; this brings the ALERT e-mail's
# own label in line with that same urgency. A disk finding this severe genuinely can take a
# service down imminently (the disk fills, the service stops), the same reasoning IMMINENT
# was built for in the first place.
def _severity(category: str, band: str) -> dict:
    if band == "red" and category in ("unreachable", "disk"):
        return {"label": "IMMINENT", "fg": IMMINENT, "soft": IMMINENT_SOFT, "line": IMMINENT_LINE}
    if band == "red":
        return {"label": "CRITICAL", "fg": RED, "soft": RED_SOFT, "line": RED_LINE}
    return {"label": "WARNING", "fg": GOLD, "soft": AMBER_SOFT, "line": AMBER_LINE}

_METRIC_KEY = {
    "disk": "disk", "ram": "ram_usage", "cpu": "cpu_usage",
    "service": "service_down", "unreachable": "component_unreachable",
    "backup": "backup_missing", "untracked": "backup_untracked",
    "backup_uncleared": "uncleared_backups", "folder": "folder_over_expected_size",
}
# The SAME human labels AlertGroup.CATEGORY_CHOICES carries (webapp/reports/models.py) --
# duplicated here as a plain dict, not imported, so this module keeps its existing
# no-Django-models dependency (alerting.py is the only place that touches the ORM). Kept in
# sync by hand; CATEGORY_CHOICES' own comment on the "folder"/"undrained_folders" naming pair
# is the source of truth if these two ever drift.
_CATEGORY_LABEL = {
    "disk": "Disk usage", "ram": "Ram usage", "cpu": "Cpu usage",
    "service": "Service down", "unreachable": "Component unreachable",
    "backup": "Backup missing", "untracked": "Backup untracked",
    "backup_uncleared": "Backup & log drainage",
    "folder": "Size monitoring", "undrained_folders": "Drainage monitoring",
}
# The badge word each compact row shows on the left (see _fired_row/_resolved_row) -- plain
# text in a colored pill, not a drawn icon or a cryptic abbreviation ("DRN" for Drainage
# monitoring reads as nothing at a glance, the opposite of the whole point of this design).
# A real word, short enough to keep the pill a fixed width across every row (see
# _BADGE_COL_WIDTH) but still recognizable on its own -- "Unreachable" is the longest and
# sets that width. On request (2026-09-04): "worried about longer words like folder... a
# rounded rectangle for these longer alert types" -- a circle sized for 3 letters was never
# going to hold a real word, so the shape became a pill (auto-width text in a fixed-width
# column) instead of trying to squeeze more letters into a circle.
# All-lowercase, including the acronyms ("cpu"/"ram"): Title-casing an acronym into a single
# capital+lowercase word ("Cpu") reads as a typo, not a word -- on request (2026-09-04),
# "Cpu does not make sense... use lowercase for this little badge be it a word or acronym".
_CATEGORY_BADGE = {
    "disk": "disk", "ram": "ram", "cpu": "cpu",
    "service": "service", "unreachable": "unreachable",
    "backup": "backup", "untracked": "untracked", "backup_uncleared": "uncleared",
    "folder": "folder", "undrained_folders": "drainage",
}
_BADGE_COL_WIDTH = 76   # fits "Unreachable" (the longest badge word) at 10px bold with padding

# The right-hand readout for a fired row when _headline_value found no real number to show
# (service/unreachable/backup/untracked/backup_uncleared carry none in their real wording --
# see _synthetic_flag's own docstring). Used to be the severity word (CRITICAL/WARNING/
# IMMINENT) repeated there -- redundant with the banner immediately above, which already
# states the severity once for the whole digest (on request, 2026-09-04: "why duplicate the
# word critical"). A short, plain description of WHAT'S WRONG instead -- two words where two
# words say it, one where one already does.
_STATUS_FALLBACK = {
    "disk": "High Usage", "ram": "High Usage", "cpu": "High Usage",
    "service": "Service Down", "unreachable": "Unreachable",
    "backup": "Missing Backup", "untracked": "Not Tracked", "backup_uncleared": "Not Cleared",
    "folder": "Over Size", "undrained_folders": "Not Draining",
}

# disk/ram/cpu's own real wording (generate_report.flagged_for_system) is always
# "{component label} · {word} {N}%", e.g. "Eagle DB · E: 92%" (disk) or "CEPECS DB · RAM 91%"
# (ram) -- everything before the number IS the component/drive detail that matters for these
# three (on request, 2026-09-04: alerts "were not specifying the system components as well as
# the drive which is important for this alert"). The number itself is already the row's own
# big readout (see _headline_value), so this strips it back out rather than showing it twice.
_DETAIL_STRIP_PCT = re.compile(r"^(.*?)\s+\d+(?:\.\d+)?%.*$")


def _row_detail(category: str, raw_text: str, *, limit: int = 60) -> str:
    """The WHERE/WHAT-specifically part of a row's subtitle -- the category word is already
    the badge on the left, so this is free to carry the finding's own real detail (which
    component, which drive, which host) instead of repeating the category name a second time.
    Every category's real wording (generate_report.flagged_for_system /
    alerting._folder_flags_by_system / _undrained_folder_flags_by_system) already names the
    specific thing affected, so the fix here is showing it at all, not inventing new copy.
    Truncated defensively so a long sentence (untracked/folder/undrained_folders can run to
    80+ characters) never wraps a compact row onto a third line."""
    if category in ("disk", "ram", "cpu"):
        m = _DETAIL_STRIP_PCT.match(raw_text)
        if m:
            raw_text = m.group(1)
    raw_text = raw_text.strip()
    if len(raw_text) > limit:
        # Word-boundary truncation, not a raw character cut -- "...not draining" at limit=60
        # was landing mid-word ("...not drainin", the final "g" sheared off, 2026-09-04) for
        # exactly the long undrained_folders/folder/untracked wording this function's own
        # docstring already calls out as running to 80+ characters. Falls back to the raw cut
        # only if there's no space to break on within a reasonable distance of the limit (an
        # unbroken run of 60+ non-space characters), so this never produces an EMPTIER result
        # than the old behaviour, just never a mangled word.
        cut = raw_text[:limit - 1].rstrip()
        last_space = cut.rfind(" ")
        if last_space > limit * 0.6:
            cut = cut[:last_space]
        raw_text = cut + "…"
    return raw_text
# Best-effort "the one number that matters" pulled out of a Flag's free-text description, for
# a card's own big emphasized readout ("time the file has been in in red... these shouldn't be
# things I have to look for" -- on request). Deliberately narrow: covers the three patterns
# that carry a REAL number in this app's own real Flag wording (generate_report.
# flagged_for_system's disk/ram/cpu percentages, alerting._folder_flags_by_system's "over
# expected size: N GB", alerting._undrained_folder_flags_by_system's "oldest ... old") and
# nothing else -- a mis-extracted number would read as authoritative in giant severity-colored
# text, so silence (no separate readout, just the severity label) is the safer failure mode
# than a plausible-looking wrong one for a category this doesn't recognize (unreachable/
# service/backup/untracked/backup_uncleared carry no number in their real wording at all --
# see flagged_for_system's own Flag() call sites -- so they correctly fall back every time).
_HEADLINE_PATTERNS = [re.compile(r"(\d+(?:\.\d+)?%)"), re.compile(r"(\d+(?:\.\d+)?GB)"),
                      re.compile(r"oldest ([\w:]+) old")]


def _headline_value(text: str):
    for pat in _HEADLINE_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    return None


# generate_report.Flag.key's own prefix convention (see every Flag(f"{category}:...") call
# site in generate_report.py) IS the category, with one exception: alerting.py's own
# undrained-folder Flags use "undrained:..." while the real category is "undrained_folders" --
# both listed explicitly rather than assumed, since AlertFinding has no separate category
# column and a resolved digest (render_resolved) only has flag_key to recover one from.
_FLAG_KEY_CATEGORY = {
    "disk": "disk", "ram": "ram", "cpu": "cpu", "service": "service",
    "backup": "backup", "unreachable": "unreachable", "untracked": "untracked",
    "folder": "folder", "undrained": "undrained_folders",
}


def _category_from_flag_key(key: str) -> str:
    prefix, _, rest = key.partition(":")
    # _synthetic_flag (alerting.py) builds keys as "synthetic:{category}" for test/preview
    # sends -- never a real capture, but render_resolved's synthetic "resolved" preview still
    # needs a real category out of it to pick the right icon/label.
    if prefix == "synthetic":
        return rest or prefix
    return _FLAG_KEY_CATEGORY.get(prefix, prefix)


_KIND_NOTE = {
    "gauge": "This is a synthetic test reading generated for preview — it does not reflect a real measurement on the system.",
    "ring": "This is a synthetic test event generated for preview — it does not reflect a real outage or connectivity loss.",
    "grid": "This is a synthetic test finding generated for preview — it does not reflect real backup history.",
    "bar": "This is a synthetic test reading generated for preview — it does not reflect a real folder on disk.",
}


def _chip(label: str, value: str, *, emphasis=None) -> str:
    """emphasis=None -> neutral chip; emphasis={'fg','soft','line'} -> the severity chip.
    inline-block (not flex) so wrapping and the box itself both survive Outlook's renderer."""
    if emphasis:
        style = (f"font-family:{MONO};font-size:12px;font-weight:bold;color:{emphasis['fg']};"
                f"background:{emphasis['soft']};border:1px solid {emphasis['line']};"
                f"padding:4px 9px;display:inline-block;margin:0 6px 6px 0;")
    else:
        style = (f"font-family:{MONO};font-size:12px;color:{MUTED};background:{PAPER};"
                f"border:1px solid {LINE};padding:4px 9px;display:inline-block;margin:0 6px 6px 0;")
    return f'<span style="{style}">{label}: {value}</span>'


def _chip_row(system: str, category: str, band: str) -> str:
    c = _severity(category, band)
    return (_chip("system", system) + _chip("metric", _METRIC_KEY[category])
           + _chip("severity", c["label"], emphasis=c))


def _hero_detail(*, chips: str, headline: str, note: str) -> str:
    return f"""<td valign="top">
      <div style="margin-bottom:10px;line-height:0;">{chips}</div>
      <div style="font-family:{FONT};font-size:17px;font-weight:bold;color:{TEXT};line-height:1.35;margin-bottom:6px;">{headline}</div>
      <div style="font-family:{FONT};font-size:13.5px;color:{MUTED};line-height:1.5;">{note}</div>
    </td>"""


def _flow_table(*, system: str, metric_label: str, metric_value: str,
               finding_value: str, category: str, band: str) -> str:
    c = _severity(category, band)
    cell = (f'<td width="33%" valign="top" style="background:{PAPER};border:1px solid {LINE};padding:12px;">'
           f'<div style="font-family:{FONT};font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:{MUTED};margin-bottom:4px;">{{label}}</div>'
           f'<div style="font-family:{MONO};font-size:13.5px;font-weight:bold;color:{TEXT};">{{value}}</div></td>')
    finding_cell = (f'<td width="34%" valign="top" style="background:{c["soft"]};border:1px solid {c["line"]};padding:12px;">'
                    f'<div style="font-family:{FONT};font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:{MUTED};margin-bottom:4px;">Finding</div>'
                    f'<div style="font-family:{MONO};font-size:13.5px;font-weight:bold;color:{c["fg"]};">{finding_value}</div></td>')
    spacer = f'<td width="10" style="font-size:1px;line-height:1px;">&nbsp;</td>'
    return (f'<div style="font-family:{FONT};font-size:12.5px;color:{MUTED};margin:24px 0 14px;">How this finding was traced</div>'
           f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
           f'{cell.format(label="System", value=system)}{spacer}'
           f'{cell.format(label=metric_label, value=metric_value)}{spacer}'
           f'{finding_cell}</tr></table>')


def _notice(text: str) -> str:
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="margin-top:20px;background:{AMBER_SOFT};border:1px dashed {AMBER_LINE};"><tr>'
           f'<td style="padding:11px 13px;font-family:{FONT};font-size:12.5px;line-height:1.5;color:{MUTED};">'
           f'<b style="color:{TEXT};">Fabricated for preview.</b> {text}</td></tr></table>')


def _gauge_hero(category: str, *, system: str, band: str) -> tuple:
    label = {"disk": "DISK USAGE", "ram": "RAM USAGE", "cpu": "CPU USAGE"}[category]
    noun = {"disk": "Disk usage", "ram": "Ram usage", "cpu": "Cpu usage"}[category]
    word = {"disk": "disk", "ram": "memory", "cpu": "cpu"}[category]
    pct = 97 if band == "red" else 88
    threshold_phrase = "well past the critical" if band == "red" else "above the warning"
    headline = f"{noun} on {system} is reading {pct}%, {threshold_phrase} threshold."
    notice = (f"The {pct}% reading is a synthetic test value used to demonstrate this alert "
             f"layout — no real {word} metric triggered it.")
    sev = _severity(category, band)
    image_bytes = alert_email_images.render_gauge(pct, sev["fg"], label)
    gauge = f"""<td width="150" valign="top" align="center">
      <img src="__IMG_hero__" width="148" height="148" alt="{pct}% {label}" style="display:block;border:0;">
      <div style="font-family:{MONO};font-size:11px;color:{MUTED};margin-top:8px;"><span style="color:{GOLD};">&#9679;</span> warn 70% &nbsp; <span style="color:{RED};">&#9679;</span> critical 90%</div>
    </td>"""
    detail = _hero_detail(chips=_chip_row(system, category, band), headline=headline,
                          note=_KIND_NOTE["gauge"])
    hero = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="padding-bottom:20px;border-bottom:1px solid {LINE};"><tr>{gauge}'
           f'<td width="20" style="font-size:1px;line-height:1px;">&nbsp;</td>{detail}</tr></table>')
    flow = _flow_table(system=system, metric_label="Metric", metric_value=_METRIC_KEY[category],
                       finding_value=f"{pct}%", category=category, band=band)
    return hero, flow, notice, {"hero": image_bytes}


def _ring_hero(category: str, *, system: str, band: str) -> tuple:
    c = _severity(category, band)
    if category == "service":
        state, elapsed = "DOWN", ("4" if band == "amber" else "14")
        headline = f"The {system} service has been down for {elapsed} minutes."
        notice = ("The outage shown here is a synthetic test event used to demonstrate this "
                 "alert layout — no real service went down.")
        metric_label, metric_value = "Metric", _METRIC_KEY[category]
    else:
        state, elapsed = "UNREACHABLE", ("2" if band == "amber" else "6")
        headline = f"The auth-gateway component on {system} has been unreachable for {elapsed} minutes."
        notice = ("The connectivity loss shown here is a synthetic test event used to "
                 "demonstrate this alert layout — nothing real is unreachable.")
        metric_label, metric_value = "Component", "auth-gateway"
    image_bytes = alert_email_images.render_ring(state, f"{elapsed}m elapsed", c["fg"])
    ring = f"""<td width="150" valign="top" align="center">
      <img src="__IMG_hero__" width="148" height="148" alt="{state} {elapsed}m elapsed" style="display:block;border:0;">
      <div style="font-family:{MONO};font-size:10px;color:{MUTED};margin-top:8px;"><span style="color:{c['fg']};">&#9679;</span> no signal since drop</div>
    </td>"""
    detail = _hero_detail(chips=_chip_row(system, category, band), headline=headline, note=_KIND_NOTE["ring"])
    hero = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="padding-bottom:20px;border-bottom:1px solid {LINE};"><tr>{ring}'
           f'<td width="20" style="font-size:1px;line-height:1px;">&nbsp;</td>{detail}</tr></table>')
    flow = _flow_table(system=system, metric_label=metric_label, metric_value=metric_value,
                       finding_value=state, category=category, band=band)
    return hero, flow, notice, {"hero": image_bytes}


def _grid_hero(category: str, *, system: str, band: str) -> tuple:
    c = _severity(category, band)
    old_aff, total = {"backup": (5, 24), "untracked": (3, 18), "backup_uncleared": (7, 20)}[category]
    aff = old_aff if band == "red" else max(1, old_aff - 3)
    sub = {"backup": "backups missing", "untracked": "backups untracked",
          "backup_uncleared": "backups uncleared"}[category]
    headline = {
        "backup": f"{aff} of {total} expected backups did not run on {system}.",
        "untracked": f"{aff} of {total} backups on {system} are not being tracked by the console.",
        "backup_uncleared": f"{aff} of {total} backups on {system} are still uncleared.",
    }[category]
    notice = {
        "backup": "The missing-backup count shown here is a synthetic test value used to demonstrate this alert layout — no real backups were affected.",
        "untracked": "The untracked-backup count shown here is a synthetic test value used to demonstrate this alert layout — no real backups were affected.",
        "backup_uncleared": "The uncleared-backup count shown here is a synthetic test value used to demonstrate this alert layout — no real backups were affected.",
    }[category]

    image_bytes = alert_email_images.render_grid(total, aff, c["fg"])
    img_w, img_h = _grid_display_size(total)
    visual = f"""<td width="150" valign="top" align="center">
      <img src="__IMG_hero__" width="{img_w}" height="{img_h}" alt="Grid of {total} backups, {aff} flagged" style="display:block;border:0;">
      <div style="font-family:{MONO};font-size:20px;font-weight:bold;color:{TEXT};margin-top:10px;">{aff}/{total}</div>
      <div style="font-family:{MONO};font-size:11px;color:{MUTED};margin-top:2px;">{sub}</div>
    </td>"""
    detail = _hero_detail(chips=_chip_row(system, category, band), headline=headline, note=_KIND_NOTE["grid"])
    hero = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="padding-bottom:20px;border-bottom:1px solid {LINE};"><tr>{visual}'
           f'<td width="20" style="font-size:1px;line-height:1px;">&nbsp;</td>{detail}</tr></table>')
    flow = _flow_table(system=system, metric_label="Metric", metric_value=_METRIC_KEY[category],
                       finding_value=f"{aff}/{total}", category=category, band=band)
    return hero, flow, notice, {"hero": image_bytes}


def _grid_display_size(total: int, cols: int = 6) -> tuple:
    """The rendered image is native-resolution (41px cells, 9px gaps -- see
    alert_email_images.render_grid's own docstring); displayed at roughly half that, matching
    the reference images' own display-width convention (e.g. 290px native shown at 132px)."""
    rows = math.ceil(total / cols)
    native_w = cols * 41 + (cols - 1) * 9
    native_h = rows * 41 + (rows - 1) * 9
    return round(native_w / 2.2), round(native_h / 2.16)


def _bar_hero(category: str, *, system: str, band: str) -> tuple:
    c = _severity(category, band)
    expected = 32.0
    actual = 48.2 if band == "red" else 34.5
    delta = actual - expected
    headline = f"/data/exports on {system} has grown to {actual} GB, above its {expected:.0f} GB expected size."
    notice = (f"The {actual} GB reading is a synthetic test value used to demonstrate this "
             f"alert layout — no real folder on disk was measured.")

    image_bytes = alert_email_images.render_bar(actual, expected, c["fg"])
    bar = f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="font-family:{MONO};font-size:26px;font-weight:bold;color:{c['fg']};">{actual} GB</td>
      <td align="right" style="font-family:{MONO};font-size:12.5px;font-weight:bold;color:{c['fg']};background:{c['soft']};border:1px solid {c['line']};padding:3px 8px;">+{delta:.1f} GB over</td>
    </tr></table>
    <img src="__IMG_hero__" width="584" height="40" alt="Bar showing {actual} GB actual against {expected:.0f} GB expected" style="display:block;border:0;width:100%;height:auto;margin-top:6px;">"""

    chips = _chip_row(system, category, band)
    hero = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="padding-bottom:20px;border-bottom:1px solid {LINE};">'
           f'<tr><td style="padding-bottom:20px;">{bar}</td></tr>'
           f'<tr><td>'
           f'<div style="margin-bottom:10px;line-height:0;">{chips}</div>'
           f'<div style="font-family:{FONT};font-size:17px;font-weight:bold;color:{TEXT};line-height:1.35;margin-bottom:6px;">{headline}</div>'
           f'<div style="font-family:{FONT};font-size:13.5px;color:{MUTED};line-height:1.5;">{_KIND_NOTE["bar"]}</div>'
           f'</td></tr></table>')
    flow = _flow_table(system=system, metric_label="Folder", metric_value="/data/exports",
                       finding_value=f"{actual} GB", category=category, band=band)
    return hero, flow, notice, {"hero": image_bytes}


_HERO_BUILDERS = {"gauge": _gauge_hero, "ring": _ring_hero, "grid": _grid_hero, "bar": _bar_hero}


def _shell(*, title: str, banner_bg: str, banner_fg: str, banner_text: str, body_html: str,
          group_name: str, min_severity: str, hero_images: dict, for_browser: bool,
          compact: bool = False, detail_text: str = "") -> tuple:
    """The header/banner/footer wrapper shared by EVERY alert e-mail this module renders --
    fired (title "Alert notification") and resolved (title "Alert resolved") alike -- so a
    resolved e-mail is visually the same product as a fired one: same header, same white bold
    title treatment (just different words), same footer, only the banner color and the body
    content differ.

    `compact=True` (2026-09-04, on request: a reference sample the user built by hand, "much
    cleaner lighter more minimalistic") drops the header's gradient image for a flat navy
    fill, narrows the card to 440px, and tightens every padding/font-size to match that
    sample -- used by render_fired/render_resolved, the REAL digest e-mails, which no longer
    carry any per-item hero image of their own (see _fired_row/_resolved_row). render()'s own
    single-category synthetic preview keeps the original wider, gradient-header look
    (compact=False, the default) since its fixed-size gauge/ring/grid/bar hero images are
    sized for that wider card and are unrelated to this request.

    Returns (html, inline_images) -- see render()'s own docstring for the for_browser/cid
    split, unchanged here."""
    images = {"bell": _BELL_ICON_PNG} if compact else {"header": alert_email_images.header_gradient_png()}
    images.update(hero_images)

    inline_images: dict = {}
    src = {}
    for name, png_bytes in images.items():
        if for_browser:
            src[name] = "data:image/png;base64," + base64.b64encode(png_bytes).decode("ascii")
        else:
            cid = make_msgid()[1:-1]      # strip the <...> -- re-added by mail_report.send_email
            src[name] = f"cid:{cid}"
            inline_images[cid] = png_bytes

    for name, addr in src.items():
        body_html = body_html.replace(f"__IMG_{name}__", addr)

    width = 440 if compact else 640
    header_pad = "16px 20px" if compact else "24px 28px"
    icon_box = 20 if compact else 38
    icon_font = "10px" if compact else "18px"
    title_size = "15px" if compact else "20px"
    sub_size = "12px" if compact else "12px"
    banner_pad = "10px 20px" if compact else "12px 28px"
    banner_font = "13px" if compact else "14px"
    body_pad = "0" if compact else "28px"
    footer_pad = "12px 20px" if compact else "18px 28px"
    # Blue, not the same muted grey as the "what's wrong" line right above it in compact mode
    # -- otherwise the two read as one paragraph (on request, 2026-09-04: "so it's not
    # confusing"). render()'s own wider design has no such line next to it, so its footer
    # keeps the original grey.
    footer_color = INK_SOFT if compact else MUTED
    header_attr = f'bgcolor="{INK}"' if compact else f'background="{src["header"]}" bgcolor="{INK}"'

    html_out = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<title>{title}</title>
</head>
<body style="margin:0;padding:0;background:{PAPER};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{PAPER};">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="{width}" cellpadding="0" cellspacing="0" border="0" style="max-width:{width}px;width:100%;background:{CARD};border:1px solid {LINE};">

  <tr><td style="background:{INK};padding:{header_pad};" {header_attr}>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="{icon_box}" valign="middle">{
        f'<img src="{src.get("bell", "")}" width="{icon_box}" height="{icon_box}" alt="Alert" style="display:block;border:0;">'
        if compact else
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td width="{icon_box}" height="{icon_box}" align="center" valign="middle" bgcolor="{INK_SOFT}" '
        f'style="background:{INK_SOFT};border:1px solid #3a5878;font-size:{icon_font};">&#128276;</td>'
        f'</tr></table>'
      }</td>
      <td width="12" style="font-size:1px;line-height:1px;">&nbsp;</td>
      <td valign="middle" style="font-family:{FONT};">
        <span style="font-size:{title_size};font-weight:bold;color:#FFFFFF;line-height:1.3;">{title}</span><br>
        <span style="font-size:{sub_size};color:#9FB3C8;line-height:1.3;">Reserve Bank of Zimbabwe &middot; <span style="color:#D9C79A;">RBZ Monitoring Console</span></span>
      </td>
    </tr></table>
  </td></tr>

  <tr><td style="background:{banner_bg};padding:{banner_pad};border-bottom:1px solid #E6E8EC;" bgcolor="{banner_bg}">
    <span style="font-family:{FONT};color:{banner_fg};font-weight:bold;font-size:{banner_font};">&#9679; {banner_text}</span>
  </td></tr>

  <tr><td style="padding:{body_pad};">
    {body_html}
  </td></tr>

  <tr><td style="padding:{footer_pad};border-top:1px solid {LINE};background:#F7F8FA;" bgcolor="#F7F8FA">
    {f'<div style="font-family:{FONT};font-size:12px;color:{MUTED};line-height:1.6;margin-bottom:8px;">{detail_text}</div>' if detail_text else ''}
    <div style="font-family:{FONT};font-size:12px;color:{footer_color};line-height:1.6;">Automated notification from the RBZ Monitoring Console.</div>
    <div style="margin-top:6px;font-family:{FONT};font-size:12px;"><a href="https://monitoring.rbz.co.zw" style="color:{GOLD};font-weight:bold;text-decoration:none;">Manage this group's systems, metrics and stakeholders &rarr;</a></div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""
    return html_out, inline_images


def render(category: str, *, system: str, band: str, group_name: str, min_severity: str,
          for_browser: bool = False) -> tuple:
    """Renders one category's synthetic test finding. Raises KeyError for a category with no
    shape mapping yet (see SHAPE_BY_CATEGORY).

    Returns (html, inline_images): for a REAL send (for_browser=False, the default), the hero
    image and header gradient are referenced via `cid:...` and returned in `inline_images`
    ({cid: png_bytes}) for the caller to hand to mail_report.send_email's own `inline_images`
    parameter -- the standard MIME shape for an inline (not attached-as-a-file) image. For the
    in-browser preview endpoint (for_browser=True), there is no MIME envelope for a `cid:` to
    resolve against, so the SAME images are embedded directly as base64 data: URIs instead, and
    `inline_images` comes back empty. Preview and a real send always show pixel-identical
    images either way -- only how the browser/mail-client fetches the bytes differs.

    `system` and `group_name` are escaped once, here, before anything downstream interpolates
    them raw -- system comes from an admin-picked dropdown (topology names), but group_name is
    free text (AlertGroup.name), so this is the one place that matters."""
    system = html.escape(system)
    group_name = html.escape(group_name)
    min_severity = html.escape(min_severity)
    shape = SHAPE_BY_CATEGORY[category]
    hero, flow, notice_text, hero_images = _HERO_BUILDERS[shape](category, system=system, band=band)
    banner = _severity(category, band)
    body_html = f"{hero}\n    {flow}\n    {_notice(notice_text)}"

    return _shell(title=f"Alert notification for {group_name}", banner_bg=banner["soft"],
                 banner_fg=banner["fg"], banner_text="1 new finding &middot; 0 still open",
                 body_html=body_html, group_name=group_name, min_severity=min_severity,
                 hero_images=hero_images, for_browser=for_browser)


_SEVERITY_RANK = {"IMMINENT": 0, "CRITICAL": 1, "WARNING": 2}   # matches generate_report.SEVERITY


def _ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def reminder_label(n: int, total, *, upper: bool = False) -> str:
    """Human label for the n-th of `total` scheduled reminders -- can't be a fixed {1,2,3}
    lookup any more since the count is admin-editable per group (see AlertGroup.reminder_minutes).
    Mirrors the exact wording asked for: "first reminder second reminder then final
    reminder" -- ordinal words for the first couple, "final" for whichever one is actually
    last regardless of how many are configured, a plain ordinal (4th, 5th, ...) for anything
    in between a longer schedule.

    `total=None` (2026-09-04) is a PERSISTENT reminder with no final one at all -- an IMMINENT
    finding's own indefinite repeat until resolved (see reports.alerting._decide's own
    imminent branch) -- so it is never labelled "final" just because n happens to reach some
    OTHER, unrelated capped schedule's length; it stays a plain ordinal forever."""
    if total is None:
        label = "reminder" if n <= 0 else (
            "first reminder" if n == 1 else
            "second reminder" if n == 2 else f"{_ordinal(n)} reminder")
    elif total <= 0:
        label = "reminder"
    elif n >= total:
        label = "final reminder"
    elif n == 1:
        label = "first reminder"
    elif n == 2:
        label = "second reminder"
    else:
        label = f"{_ordinal(n)} reminder"
    return label.upper() if upper else label


def _badge_pill(category: str, fg: str, soft: str) -> str:
    """A colored pill (rounded rectangle, not a circle) holding a real category word --
    "Unreachable"/"Drainage" don't fit a circle sized for 3 letters, so the shape auto-widths
    to the text instead of the text being cut down to fit the shape (2026-09-04, on request).
    Sits inside a FIXED-width column (_BADGE_COL_WIDTH) in the caller so every row's name/
    value columns still line up regardless of which category's row it is."""
    word = html.escape(_CATEGORY_BADGE.get(category, category.replace("_", " ").lower()))
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
           f'style="background-color:{soft};border-radius:11px;" bgcolor="{soft}"><tr>'
           f'<td style="padding:5px 9px;font-family:{FONT};font-size:10px;font-weight:bold;'
           f'color:{fg};white-space:nowrap;">{word}</td></tr></table>')


def _fired_row(system: str, category: str, band: str, raw_text: str, action: str,
               reminder_number, total_reminders, *, last: bool) -> str:
    """One `<tr>` in the compact digest table (2026-09-04, reproducing a hand-built reference
    sample): a colored pill naming the category instead of a drawn icon, system name +
    category/status as a two-line label, and -- where a real number exists in the finding
    text -- a large severity-colored readout on the right, exactly the reference's own "91%"
    treatment. No per-row image: the badge is plain HTML/CSS (background + text), which is
    also why this digest no longer needs a Pillow render per finding the way the old
    icon-per-card design did."""
    c = _severity(category, band)
    if action == "new":
        status = "New"
    elif action == "open":
        # Genuinely still open, but not itself due for a reminder this poll -- appears only
        # for situational awareness alongside some OTHER finding in the same group that IS
        # due this cycle (2026-09-05). Deliberately not an ordinal reminder_label(): this row
        # carries no reminder-count information of its own here (that count is unaffected --
        # see reports.alerting.run_alert_cycle's per_group_still_open, which never touches
        # this finding's own reminder bookkeeping).
        status = "Still open"
    else:
        status = reminder_label(reminder_number, total_reminders)
    headline = _headline_value(raw_text)
    detail = html.escape(_row_detail(category, raw_text))

    status_word = _STATUS_FALLBACK.get(category, c["label"])
    value_html = (f'<span style="font-family:{MONO};font-size:22px;font-weight:bold;color:{c["fg"]};">{html.escape(headline)}</span>'
                 if headline else
                 f'<span style="font-family:{FONT};font-size:13px;font-weight:bold;color:{c["fg"]};">{html.escape(status_word)}</span>')

    border = "" if last else f"border-bottom:1px solid {LINE};"
    return f"""<tr><td style="padding:14px 20px;{border}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td width="{_BADGE_COL_WIDTH}" style="vertical-align:middle;">{_badge_pill(category, c["fg"], c["soft"])}</td>
<td style="padding-left:12px;vertical-align:middle;">
<div style="font-family:{FONT};font-size:14px;font-weight:bold;color:{TEXT};">{html.escape(system)}</div>
<div style="font-family:{FONT};font-size:12px;color:{MUTED};">{detail} &middot; {status}</div>
</td>
<td align="right" style="vertical-align:middle;padding-left:10px;">{value_html}</td>
</tr></table>
</td></tr>"""


def _section_divider(label: str) -> str:
    """A plain-text divider row (no rule, no background) marking where a fired digest's rows
    stop being "why this e-mail was sent" and start being "also worth knowing" -- used only
    for the "Also still open" section (2026-09-05) so those rows never look like they're part
    of the New/reminder count the banner and subject line are actually about."""
    return (f'<tr><td style="padding:14px 20px 2px 20px;"><span style="font-family:{FONT};'
           f'font-size:11px;font-weight:bold;color:{MUTED};text-transform:uppercase;'
           f'letter-spacing:.04em;">{html.escape(label)}</span></td></tr>')


def render_fired(items: list, *, group_name: str, min_severity: str, total_reminders: int = 3,
                 for_browser: bool = False, still_open: list | None = None) -> tuple:
    """Renders one or more NEW/reminder findings for ONE group -- the REAL production digest
    (reports.alerting.run_alert_cycle / send_test_alert's "Run live check now"), which can
    carry several different categories/systems in one poll, unlike the single-category
    synthetic test in render(). Same title/header/footer shell as render() and
    render_resolved() (title "Alert notification", matching every other alert e-mail this
    feature sends), banner colored/labeled by the WORST severity present (IMMINENT beats
    CRITICAL beats WARNING, generate_report.SEVERITY's own rank order) rather than a flat
    red/amber. One ROW per finding in a single table (2026-09-04, reproducing a hand-built
    reference sample -- see _fired_row/_shell's own "compact" docstrings), not a card per
    finding with its own border/radius/image the way this used to look -- lighter and easier
    to scan down in one motion, which is what the reference was built to demonstrate.

    Each row is tagged New, or an ordinal reminder tag from reminder_label() (First/Second/
    .../Final reminder) so a recipient can tell at a glance how many times they've already
    been told about this exact finding -- each group's own admin-configurable reminder
    schedule (AlertGroup.reminder_minutes; ships as 10/40/60 minutes after first notification,
    then silence).

    `items`: [(system, Flag, action, reminder_number, item_total), ...] where action is "new"
    or "remind" and reminder_number is 1..item_total when action is "remind", else None (see
    reports.alerting's own action vocabulary). `item_total` travels WITH each item rather than
    being one shared value for the whole digest (2026-09-04) -- a persistent IMMINENT reminder
    (component unreachable, no daily cap, see reports.alerting._decide's own imminent branch)
    carries item_total=None, meaning "unbounded, no final reminder", so it is never mislabeled
    "final" just because it has out-lived some OTHER, unrelated finding's own capped schedule
    length in the same digest. `total_reminders` (this function's own parameter) is now only a
    fallback for a caller whose items don't set a real per-item total at all; defaults to 3
    (the shipped default's own length) as a last-resort safety net. Escaping happens inside
    _fired_row, AFTER _headline_value has had a chance to pattern-match the RAW text --
    escaping first would not break the patterns used today, but there is no reason to risk it
    mattering for a future one.

    `still_open`: [(system, Flag), ...] -- OTHER findings in this same group that are
    currently open but weren't themselves due for a new/reminder event this poll (2026-09-05,
    on request: a RAM alert for system Y shouldn't leave system X's own still-high RAM
    unmentioned just because X's reminder isn't due yet). Rendered as its own "Also still
    open" section below the New/reminder rows, status-labeled "Still open" rather than an
    ordinal reminder -- these rows carry no reminder-count information (reports.alerting
    never touches that finding's own reminder_count/first_notified_at/last_notified_at for
    appearing here) and exist purely for situational awareness."""
    group_name = html.escape(group_name)
    min_severity = html.escape(min_severity)
    new_items = [(s, f) for s, f, a, _n, _t in items if a == "new"]
    reminders = [(s, f, n, t) for s, f, a, n, t in items if a == "remind"]
    still_open = still_open or []
    total_rows = len(new_items) + len(reminders) + len(still_open)

    rows_html = []
    worst_rank = 3
    # Counted alongside worst_rank, not derived from it afterward -- 2026-09-08, on request:
    # "each notification message may have alerts of different severities so its better to
    # update this notification banner... to show all issues". worst_rank alone tells you the
    # WORST thing in this digest, but a single "IMMINENT" banner label on a digest that's
    # actually 1 IMMINENT + 1 CRITICAL + 1 WARNING reads as if every row is IMMINENT, which
    # isn't true -- this tallies every distinct severity actually present so the banner can
    # name all of them, not just the worst one.
    severity_counts: dict = {}

    def _tally(f):
        sev = _severity(f.category, f.band)
        severity_counts[sev["label"]] = severity_counts.get(sev["label"], 0) + 1
        return _SEVERITY_RANK[sev["label"]]

    for i, (s, f) in enumerate(new_items):
        worst_rank = min(worst_rank, _tally(f))
        rows_html.append(_fired_row(s, f.category, f.band, f.text, "new", None, total_reminders,
                                    last=(i == total_rows - 1)))
    for i, (s, f, n, t) in enumerate(reminders):
        worst_rank = min(worst_rank, _tally(f))
        # t is None ONLY for a persistent imminent reminder (reports.alerting always sets a
        # real int otherwise) -- passed through as-is, not defaulted, so reminder_label()
        # itself decides how an unbounded reminder reads.
        rows_html.append(_fired_row(s, f.category, f.band, f.text, "remind", n, t,
                                    last=(len(new_items) + i == total_rows - 1)))
    if still_open:
        rows_html.append(_section_divider("Also still open"))
        for i, (s, f) in enumerate(still_open):
            worst_rank = min(worst_rank, _tally(f))
            rows_html.append(_fired_row(s, f.category, f.band, f.text, "open", None, None,
                                        last=(len(new_items) + len(reminders) + i == total_rows - 1)))
    body_html = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                f'{"".join(rows_html)}</table>')

    worst_label = {0: "IMMINENT", 1: "CRITICAL", 2: "WARNING"}.get(worst_rank, "WARNING")
    banner = {"IMMINENT": {"fg": IMMINENT, "soft": IMMINENT_SOFT},
             "CRITICAL": {"fg": RED, "soft": RED_SOFT},
             "WARNING": {"fg": GOLD, "soft": AMBER_SOFT}}[worst_label]
    # Every severity actually present, worst first -- not just worst_label alone (see
    # severity_counts' own comment above). Still colored/labeled by the single worst severity
    # (banner_bg/banner_fg above) since that's the right visual urgency cue either way; this
    # text just stops implying every row shares that one severity.
    severity_breakdown = " &middot; ".join(
        f"{lbl} {severity_counts[lbl]}" for lbl in ("IMMINENT", "CRITICAL", "WARNING")
        if severity_counts.get(lbl))
    banner_text = f"{severity_breakdown} &middot; {len(new_items)} new issue(s), {len(reminders)} reminder(s)"
    if still_open:
        banner_text += f", {len(still_open)} also open"
    # WHAT is wrong, not how the notification system works (on request, 2026-09-04: "talk
    # about the alert... tell the user what is wrong in as few words as possible, don't give
    # us metainfo") -- the distinct category labels this digest actually carries, nothing
    # about severity (already the banner's own job, see _STATUS_FALLBACK's own docstring on
    # not repeating that word twice).
    seen_cats: list = []
    for _s, _f in new_items:
        if _f.category not in seen_cats:
            seen_cats.append(_f.category)
    for _s, _f, _n, _t in reminders:
        if _f.category not in seen_cats:
            seen_cats.append(_f.category)
    for _s, _f in still_open:
        if _f.category not in seen_cats:
            seen_cats.append(_f.category)
    detail_text = html.escape(", ".join(_CATEGORY_LABEL.get(c, c) for c in seen_cats))

    return _shell(title=f"Alert notification for {group_name}", banner_bg=banner["soft"],
                 banner_fg=banner["fg"], banner_text=banner_text, body_html=body_html,
                 group_name=group_name, min_severity=min_severity, hero_images={},
                 for_browser=for_browser, compact=True, detail_text=detail_text)


def _resolved_row(system: str, category: str, band: str, raw_text: str, duration: str, *,
                  last: bool) -> str:
    """One `<tr>` in the compact resolved-digest table -- same shape as _fired_row (round
    badge, system name, category subtitle), but green throughout and the right-hand slot
    shows how long the finding was open instead of a live bad-value readout, since there is
    no current damage to headline any more. `band` is what the finding USED TO BE (never
    escalates/de-escalates after the fact) -- named in the subtitle as "was <severity>"."""
    c = _severity(category, band)
    detail = html.escape(_row_detail(category, raw_text))
    border = "" if last else f"border-bottom:1px solid {LINE};"
    return f"""<tr><td style="padding:14px 20px;{border}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td width="{_BADGE_COL_WIDTH}" style="vertical-align:middle;">{_badge_pill(category, GREEN, GREEN_SOFT)}</td>
<td style="padding-left:12px;vertical-align:middle;">
<div style="font-family:{FONT};font-size:14px;font-weight:bold;color:{TEXT};">{html.escape(system)}</div>
<div style="font-family:{FONT};font-size:12px;color:{MUTED};">{detail} &middot; was {c["label"]}</div>
</td>
<td align="right" style="vertical-align:middle;padding-left:10px;">
<span style="font-family:{MONO};font-size:16px;font-weight:bold;color:{GREEN};">{duration}</span>
</td>
</tr></table>
</td></tr>"""


def render_resolved(items: list, *, group_name: str, min_severity: str,
                    for_browser: bool = False) -> tuple:
    """Renders one or more cleared findings for ONE group -- the same title/header/footer
    shell as render_fired (title "Alert resolved", matching "Alert notification"'s own white
    bold styling and sentence-case convention), a green banner instead of red/amber, and one
    ROW per item in a single table (2026-09-04, reproducing a hand-built reference sample --
    see _resolved_row/_shell's own "compact" docstrings) rather than a card per item, since a
    resolved digest can carry several DIFFERENT categories/systems at once (unlike a single
    synthetic test) and no one hero shape fits an arbitrary mix.

    `items`: [(system, band, text, duration_label, flag_key), ...] -- band is what it USED TO
    be (never escalates/de-escalates after the fact), duration_label a pre-formatted string
    like "2h 14m" (see alerting._duration_str), flag_key recovers the category for this row's
    badge/label since AlertFinding has no separate category column (see
    _category_from_flag_key's own docstring). Escaping happens inside _resolved_row, same
    reasoning as render_fired's own docstring."""
    group_name = html.escape(group_name)
    min_severity = html.escape(min_severity)
    rows_html = [
        _resolved_row(s, _category_from_flag_key(flag_key), band, text, duration,
                     last=(i == len(items) - 1))
        for i, (s, band, text, duration, flag_key) in enumerate(items)
    ]
    body_html = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                f'{"".join(rows_html)}</table>')
    banner_text = f"{len(items)} finding(s) cleared"
    # WHAT cleared, not how the notification system works -- same reasoning as render_fired's
    # own detail_text (2026-09-04, on request).
    seen_cats: list = []
    for _s, _band, _text, _duration, _flag_key in items:
        cat = _category_from_flag_key(_flag_key)
        if cat not in seen_cats:
            seen_cats.append(cat)
    detail_text = html.escape(", ".join(_CATEGORY_LABEL.get(c, c) for c in seen_cats) + " cleared")

    return _shell(title=f"Alert resolved for {group_name}", banner_bg=GREEN_SOFT, banner_fg=GREEN,
                 banner_text=banner_text, body_html=body_html, group_name=group_name,
                 min_severity=min_severity, hero_images={}, for_browser=for_browser, compact=True,
                 detail_text=detail_text)


# =========================================================================================
#  EVENT NOTIFICATIONS -- a separate, deliberately UNrelated notification type (2026-09-04:
#  "decouple notifications from alerts... I want to have notification types, alert
#  notification and event notification"). An alert is a threshold/state: something is
#  currently wrong, with a severity, that can resolve and reminds you while it doesn't. An
#  event is a single discrete OCCURRENCE -- something happened, once -- so there is no band,
#  no category badge, no reminder schedule and nothing to "resolve" here; these functions
#  deliberately do NOT reuse _fired_row/_severity/reminder_label, only the shared _shell
#  chrome. Blue throughout (BLUE/BLUE_SOFT, this module's own constants) so an event can never
#  be mistaken for an alert at a glance, on request: "Event notifications should be blue
#  themed to indicate neatrality."
# =========================================================================================
def _event_row(system: str, detail: str, *, last: bool) -> str:
    """One <tr> for a single event -- system name + a plain-text detail line, no severity
    chip and no numeric headline (events don't have either)."""
    border = "" if last else f"border-bottom:1px solid {LINE};"
    badge = _badge_pill("event", BLUE, BLUE_SOFT)
    return (f'<tr><td style="padding:10px 0;{border}" valign="top">'
           f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"><tr>'
           f'<td width="{_BADGE_COL_WIDTH}" valign="top">{badge}</td>'
           f'<td style="padding-left:10px;font-family:{FONT};">'
           f'<div style="font-size:13px;font-weight:bold;color:{TEXT};">{html.escape(system)}</div>'
           f'<div style="font-size:12px;color:{MUTED};margin-top:2px;">{html.escape(detail)}</div>'
           f'</td></tr></table></td></tr>')


def render_event(items: list, *, group_name: str, event_label: str,
                 for_browser: bool = False) -> tuple:
    """Renders one or more occurrences of the SAME event type for ONE event group -- the
    compact digest shell every notification in this app uses (see _shell's own "compact"
    docstring), blue-banered instead of red/amber/green, with no severity concept anywhere.

    `items`: [(system, detail), ...] -- detail is a short, already-human-readable line (e.g.
    "BACKUP_20260904_0200.bak" for a backup-file-dropped event); `event_label` names the
    event type itself (e.g. "Backup file dropped"), used as both the banner text and the
    e-mail title."""
    group_name_esc = html.escape(group_name)
    event_label_esc = html.escape(event_label)
    rows_html = [_event_row(s, d, last=(i == len(items) - 1)) for i, (s, d) in enumerate(items)]
    body_html = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                f'{"".join(rows_html)}</table>')
    banner_text = f"{event_label_esc} &middot; {len(items)} system(s)"
    html_out, inline_images = _shell(
        title=f"{event_label_esc} — {group_name_esc}", banner_bg=BLUE_SOFT, banner_fg=BLUE,
        banner_text=banner_text, body_html=body_html, group_name=group_name_esc,
        min_severity="", hero_images={}, for_browser=for_browser, compact=True)
    return html_out, inline_images


def _system_alert_row(label: str, detail: str, status: str, *, last: bool) -> str:
    """One <tr> for a single stale checker -- same label/detail layout as _fired_row, minus
    its right-hand numeric readout (a checker's own age isn't a threshold value with a
    headline number the way disk/ram/cpu are). `status` is "New" or an ordinal reminder_label
    (total=None, since a stale checker's reminders are persistent -- see
    reports.system_alerts._decide's own docstring)."""
    border = "" if last else f"border-bottom:1px solid {LINE};"
    badge = _badge_pill("stale", SYSTEM, SYSTEM_SOFT)
    return f"""<tr><td style="padding:14px 20px;{border}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
<td width="{_BADGE_COL_WIDTH}" style="vertical-align:middle;">{badge}</td>
<td style="padding-left:12px;vertical-align:middle;">
<div style="font-family:{FONT};font-size:14px;font-weight:bold;color:{TEXT};">{html.escape(label)}</div>
<div style="font-family:{FONT};font-size:12px;color:{MUTED};">{html.escape(detail)} &middot; {html.escape(status)}</div>
</td>
</tr></table>
</td></tr>"""


def render_system_alert(items: list, *, group_name: str, for_browser: bool = False) -> tuple:
    """Renders one or more stale-checker findings for ONE AlertGroup (alert_type=System
    Alert, alert_subtype=Staleness Alert) -- the THIRD
    notification family (2026-09-05), alongside render_fired (a value over a threshold) and
    render_event (a discrete occurrence). Answers "is our own monitoring pipeline still
    telling the truth", not "is something on a system currently wrong" -- purple banner,
    explicitly explained in the footer's detail line since this is a genuinely different kind
    of message than either of the other two ("a monitoring SOURCE has stopped reporting", not
    "a monitored VALUE is bad").

    `items`: [(label, detail, action, reminder_number), ...] -- label is "system · check
    name", detail is an already-human-readable line (e.g. "Not updated in 12d 2h (expected
    within 2h)"), action is "new" or "remind" (reports.system_alerts._decide's own
    vocabulary), reminder_number is 1.. when action is "remind", else None. There is no
    total_reminders here at all -- staleness reminders are persistent (total=None passed
    straight to reminder_label), the same shape as an IMMINENT alert finding, since there is
    no capped schedule to run out of."""
    group_name_esc = html.escape(group_name)
    rows_html = []
    for i, (label, detail, action, reminder_number) in enumerate(items):
        status = "New" if action == "new" else reminder_label(reminder_number, None)
        rows_html.append(_system_alert_row(label, detail, status, last=(i == len(items) - 1)))
    body_html = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                f'{"".join(rows_html)}</table>')
    # "Staleness Alert" (2026-09-05, on request) is this check's own user-facing name --
    # the System Alerts umbrella's first (and so far only) check type, named the same way
    # Events' "Backup file dropped" names its own first type without renaming EventGroup.
    banner_text = f"STALENESS ALERT &middot; {len(items)} checker(s) not reporting fresh data"
    html_out, inline_images = _shell(
        title=f"Staleness alert — {group_name_esc}", banner_bg=SYSTEM_SOFT, banner_fg=SYSTEM,
        banner_text=banner_text, body_html=body_html, group_name=group_name_esc,
        min_severity="", hero_images={}, for_browser=for_browser, compact=True,
        detail_text="A monitoring source itself has stopped reporting fresh data — the "
                    "system(s) it watches may be silently unmonitored until this clears.")
    return html_out, inline_images

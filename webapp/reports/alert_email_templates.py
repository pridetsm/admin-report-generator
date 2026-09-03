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
from pathlib import Path

from email.utils import make_msgid

from . import alert_email_images

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

# Literal hex, lifted from the design samples' own :root token block -- light-mode only.
# Outlook doesn't honour prefers-color-scheme any more reliably than it honours var(), and
# mail_report.py's own daily-report e-mail (the product these are meant to match) has no dark
# mode either, so neither does this.
INK, INK_SOFT = "#0E2238", "#163455"
PAPER, CARD = "#EEF1F5", "#FFFFFF"
GOLD = "#B9873E"
RED, RED_SOFT, RED_LINE = "#B23A32", "#F8E6E3", "#E3B3AC"
AMBER_SOFT, AMBER_LINE = "#FBF1DE", "#E7CE99"
TEXT, MUTED, LINE, TRACK = "#1B2430", "#64707D", "#DDE3EA", "#E4E8EE"
GREEN, GREEN_SOFT, GREEN_LINE = "#1E7D4F", "#E8F5EE", "#BFE5D1"
FONT = "Arial, 'Segoe UI', sans-serif"
MONO = "'Courier New', monospace"

_METRIC_KEY = {
    "disk": "disk", "ram": "ram_usage", "cpu": "cpu_usage",
    "service": "service_down", "unreachable": "component_unreachable",
    "backup": "backup_missing", "untracked": "backup_untracked",
    "backup_uncleared": "uncleared_backups", "folder": "folder_over_expected_size",
}
_KIND_NOTE = {
    "gauge": "This is a synthetic test reading generated for preview — it does not reflect a real measurement on the system.",
    "ring": "This is a synthetic test event generated for preview — it does not reflect a real outage or connectivity loss.",
    "grid": "This is a synthetic test finding generated for preview — it does not reflect real backup history.",
    "bar": "This is a synthetic test reading generated for preview — it does not reflect a real folder on disk.",
}


def _band_colors(band: str) -> dict:
    if band == "red":
        return {"fg": RED, "soft": RED_SOFT, "line": RED_LINE}
    return {"fg": GOLD, "soft": AMBER_SOFT, "line": AMBER_LINE}


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
    c = _band_colors(band)
    return (_chip("system", system) + _chip("metric", _METRIC_KEY[category])
           + _chip("severity", band.upper(), emphasis=c))


def _hero_detail(*, chips: str, headline: str, note: str) -> str:
    return f"""<td valign="top">
      <div style="margin-bottom:10px;line-height:0;">{chips}</div>
      <div style="font-family:{FONT};font-size:17px;font-weight:bold;color:{TEXT};line-height:1.35;margin-bottom:6px;">{headline}</div>
      <div style="font-family:{FONT};font-size:13.5px;color:{MUTED};line-height:1.5;">{note}</div>
    </td>"""


def _flow_table(*, system: str, metric_label: str, metric_value: str,
               finding_value: str, band: str) -> str:
    c = _band_colors(band)
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
    noun = {"disk": "Disk usage", "ram": "RAM usage", "cpu": "CPU usage"}[category]
    word = {"disk": "disk", "ram": "memory", "cpu": "CPU"}[category]
    pct = 97 if band == "red" else 88
    threshold_phrase = "well past the critical" if band == "red" else "above the warning"
    headline = f"{noun} on {system} is reading {pct}%, {threshold_phrase} threshold."
    notice = (f"The {pct}% reading is a synthetic test value used to demonstrate this alert "
             f"layout — no real {word} metric triggered it.")
    image_bytes = alert_email_images.render_gauge(pct, band, label)
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
                       finding_value=f"{pct}% &middot; {band.upper()}", band=band)
    return hero, flow, notice, {"hero": image_bytes}


def _ring_hero(category: str, *, system: str, band: str) -> tuple:
    c = _band_colors(band)
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
    image_bytes = alert_email_images.render_ring(state, f"{elapsed}m elapsed", band)
    ring = f"""<td width="150" valign="top" align="center">
      <img src="__IMG_hero__" width="148" height="148" alt="{state} {elapsed}m elapsed" style="display:block;border:0;">
      <div style="font-family:{MONO};font-size:10px;color:{MUTED};margin-top:8px;"><span style="color:{c['fg']};">&#9679;</span> no signal since drop</div>
    </td>"""
    detail = _hero_detail(chips=_chip_row(system, category, band), headline=headline, note=_KIND_NOTE["ring"])
    hero = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="padding-bottom:20px;border-bottom:1px solid {LINE};"><tr>{ring}'
           f'<td width="20" style="font-size:1px;line-height:1px;">&nbsp;</td>{detail}</tr></table>')
    flow = _flow_table(system=system, metric_label=metric_label, metric_value=metric_value,
                       finding_value=f"{state} &middot; {band.upper()}", band=band)
    return hero, flow, notice, {"hero": image_bytes}


def _grid_hero(category: str, *, system: str, band: str) -> tuple:
    c = _band_colors(band)
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

    image_bytes = alert_email_images.render_grid(total, aff, band)
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
                       finding_value=f"{aff}/{total} &middot; {band.upper()}", band=band)
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
    c = _band_colors(band)
    expected = 32.0
    actual = 48.2 if band == "red" else 34.5
    delta = actual - expected
    headline = f"/data/exports on {system} has grown to {actual} GB, above its {expected:.0f} GB expected size."
    notice = (f"The {actual} GB reading is a synthetic test value used to demonstrate this "
             f"alert layout — no real folder on disk was measured.")

    image_bytes = alert_email_images.render_bar(actual, expected, band)
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
                       finding_value=f"{actual} GB &middot; {band.upper()}", band=band)
    return hero, flow, notice, {"hero": image_bytes}


_HERO_BUILDERS = {"gauge": _gauge_hero, "ring": _ring_hero, "grid": _grid_hero, "bar": _bar_hero}


def _shell(*, title: str, banner_bg: str, banner_fg: str, banner_text: str, body_html: str,
          group_name: str, min_severity: str, hero_images: dict, for_browser: bool) -> tuple:
    """The header/banner/footer wrapper shared by EVERY alert e-mail this module renders --
    fired (title "Alert notification") and resolved (title "Alert resolved") alike -- so a
    resolved e-mail is visually the same product as a fired one: same navy gradient header,
    same white bold title treatment (just different words), same footer, only the banner color
    and the body content differ.

    Returns (html, inline_images) -- see render()'s own docstring for the for_browser/cid
    split, unchanged here."""
    images = {"header": alert_email_images.header_gradient_png()}
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

    body_html = body_html.replace("__IMG_hero__", src.get("hero", ""))
    header_attr = f'background="{src["header"]}" bgcolor="{INK}"'

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
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;width:100%;background:{CARD};border:1px solid {LINE};">

  <tr><td style="background:{INK};padding:24px 28px;" {header_attr}>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="38" valign="top">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td width="38" height="38" align="center" valign="middle" bgcolor="{INK_SOFT}" style="background:{INK_SOFT};border:1px solid #3a5878;font-size:18px;">&#128276;</td>
        </tr></table>
      </td>
      <td width="14" style="font-size:1px;line-height:1px;">&nbsp;</td>
      <td valign="top" style="font-family:{FONT};">
        <span style="font-size:20px;font-weight:bold;color:#FFFFFF;">{title}</span><br>
        <span style="font-size:12px;color:#9FB3C8;">Reserve Bank of Zimbabwe &middot; <span style="color:#D9C79A;">RBZ Monitoring Console</span></span>
      </td>
    </tr></table>
  </td></tr>

  <tr><td style="background:{banner_bg};padding:12px 28px;border-bottom:1px solid #E6E8EC;" bgcolor="{banner_bg}">
    <span style="font-family:{FONT};color:{banner_fg};font-weight:bold;font-size:14px;">&#9679; {banner_text}</span>
  </td></tr>

  <tr><td style="padding:28px;">
    {body_html}
  </td></tr>

  <tr><td style="padding:18px 28px;border-top:1px solid {LINE};background:#F7F8FA;" bgcolor="#F7F8FA">
    <div style="font-family:{FONT};font-size:12px;color:{MUTED};line-height:1.6;">Automated alert from the RBZ Monitoring Console for the <b style="color:{TEXT};">{group_name}</b> group &middot; minimum severity: {min_severity}.</div>
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
    banner = _band_colors(band)
    body_html = f"{hero}\n    {flow}\n    {_notice(notice_text)}"

    return _shell(title="Alert notification", banner_bg=banner["soft"], banner_fg=banner["fg"],
                 banner_text="1 new finding &middot; 0 still open", body_html=body_html,
                 group_name=group_name, min_severity=min_severity, hero_images=hero_images,
                 for_browser=for_browser)


_REMINDER_TAGS = {1: "FIRST REMINDER", 2: "SECOND REMINDER", 3: "FINAL REMINDER"}


def _fired_item_card(system: str, category: str, band: str, text: str, action: str,
                     reminder_number=None) -> str:
    c = _band_colors(band)
    tag = "NEW" if action == "new" else _REMINDER_TAGS.get(reminder_number, "REMINDER")
    tag_chip = (f'<span style="display:inline-block;font-family:{MONO};font-size:11px;font-weight:bold;'
               f'color:{c["fg"]};background:{c["soft"]};border:1px solid {c["line"]};padding:4px 9px;'
               f'margin:0 6px 6px 0;">{tag}</span>')
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="margin-bottom:10px;border:1px solid {LINE};border-radius:10px;"><tr>'
           f'<td style="padding:14px 16px;">'
           f'<div style="margin-bottom:8px;line-height:0;">'
           f'{_chip("system", system)}{_chip("metric", category)}{tag_chip}</div>'
           f'<div style="font-family:{FONT};font-size:14.5px;font-weight:600;color:{TEXT};">{text}</div>'
           f'<div style="font-family:{MONO};font-size:11px;color:{MUTED};margin-top:4px;">severity '
           f'<span style="color:{c["fg"]};font-weight:bold;">{band.upper()}</span></div>'
           f'</td></tr></table>')


def render_fired(items: list, *, group_name: str, min_severity: str,
                 for_browser: bool = False) -> tuple:
    """Renders one or more NEW/reminder findings for ONE group -- the REAL production digest
    (reports.alerting.run_alert_cycle / send_test_alert's "Run live check now"), which can
    carry several different categories/systems in one poll, unlike the single-category
    synthetic test in render(). Same title/header/footer shell as render() and
    render_resolved() (title "Alert notification", matching every other alert e-mail this
    feature sends), red banner if anything here is red, amber otherwise, one card per finding
    instead of a per-category hero visual, for the same reason render_resolved() uses cards --
    no one hero shape fits an arbitrary mix of categories at once. Each card is tagged NEW,
    FIRST/SECOND/FINAL REMINDER (see _REMINDER_TAGS) so a recipient can tell at a glance how
    many times they've already been told about this exact finding -- reports.alerting's own
    fixed 3-reminder schedule (10/40/60 minutes after first notification, then silence).

    `items`: [(system, Flag, action, reminder_number), ...] where action is "new" or "remind"
    and reminder_number is 1/2/3 when action is "remind", else None (see reports.alerting's
    own action vocabulary) -- escaped here, same reasoning as render()'s own docstring:
    Flag.text/category/system aren't user free text, but are escaped anyway since nothing
    downstream should assume that."""
    group_name = html.escape(group_name)
    min_severity = html.escape(min_severity)
    new_items = [(s, f) for s, f, a, _n in items if a == "new"]
    reminders = [(s, f, n) for s, f, a, n in items if a == "remind"]
    any_red = any(f.band == "red" for s, f in new_items) or any(f.band == "red" for s, f, n in reminders)
    banner = _band_colors("red" if any_red else "amber")
    banner_text = f"{len(new_items)} new finding(s), {len(reminders)} still open"
    cards = ("".join(_fired_item_card(html.escape(s), html.escape(f.category), f.band,
                                      html.escape(f.text), "new") for s, f in new_items)
            + "".join(_fired_item_card(html.escape(s), html.escape(f.category), f.band,
                                       html.escape(f.text), "remind", n) for s, f, n in reminders))

    return _shell(title="Alert notification", banner_bg=banner["soft"], banner_fg=banner["fg"],
                 banner_text=banner_text, body_html=cards, group_name=group_name,
                 min_severity=min_severity, hero_images={}, for_browser=for_browser)


def _resolved_item_card(system: str, band: str, text: str, duration: str) -> str:
    c = _band_colors(band)
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
           f'style="margin-bottom:10px;border:1px solid {LINE};border-radius:10px;"><tr>'
           f'<td style="padding:14px 16px;">'
           f'{_chip("system", system)}'
           f'<div style="font-family:{FONT};font-size:14.5px;font-weight:600;color:{TEXT};margin:8px 0 4px;">{text}</div>'
           f'<div style="font-family:{MONO};font-size:11px;color:{MUTED};">was '
           f'<span style="color:{c["fg"]};font-weight:bold;">{band.upper()}</span>'
           f' &middot; open for {duration}</div></td></tr></table>')


def render_resolved(items: list, *, group_name: str, min_severity: str,
                    for_browser: bool = False) -> tuple:
    """Renders one or more cleared findings for ONE group -- the same title/header/footer
    shell as render() (title "Alert resolved", matching "Alert notification"'s own white bold
    styling and sentence-case convention), a green banner instead of red/amber, and one card
    per item instead of a single category's hero visual, since a resolved digest can carry
    several DIFFERENT categories/systems at once (unlike a single synthetic test) and no one
    hero shape fits an arbitrary mix.

    `items`: [(system, band, text, duration_label), ...] -- band is what it USED TO be (never
    escalates/de-escalates after the fact), duration_label a pre-formatted string like "2h 14m"
    (see alerting._duration_str). Escaped here, same reasoning as render()'s own system/
    group_name escaping -- `text` comes from a live generate_report.Flag, not user free text,
    but is escaped anyway since nothing downstream should ever assume otherwise."""
    group_name = html.escape(group_name)
    min_severity = html.escape(min_severity)
    cards = "".join(_resolved_item_card(html.escape(s), band, html.escape(text), duration)
                    for s, band, text, duration in items)
    body_html = cards
    banner_text = f"{len(items)} finding(s) cleared"

    return _shell(title="Alert resolved", banner_bg=GREEN_SOFT, banner_fg=GREEN,
                 banner_text=banner_text, body_html=body_html, group_name=group_name,
                 min_severity=min_severity, hero_images={}, for_browser=for_browser)

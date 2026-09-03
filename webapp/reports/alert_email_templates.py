"""Renders the 9 designed per-category e-mail samples (reports/alert_email_samples/*.html)
with a real system/severity/group substituted in, for the SYNTHETIC test-fire path only
(alerting.render_test_email / send_test_email, kind="positive").

These are single-finding hero layouts -- there is no design yet for a digest carrying several
simultaneous findings at once, so the real live poller (run_alert_cycle) and "Run live check
now" still use the older, simpler multi-item table digest (alerting._render_fired_email). Only
system/severity/group are substituted here; the shape-specific illustrative numbers (a gauge's
%, a grid's affected/total, a bar's actual/expected GB, a ring's elapsed time) stay fixed per
category and band, matching how alerting._synthetic_flag already picks a representative 97%
(red) / 88% (amber) reading rather than taking a number nobody has entered anywhere.

The shared CSS in every sample only defines RED severity colors (chip.severity, flow-node.
finding, the gauge's progress arc, a bar's fill, a grid's flagged cells) -- an amber band is
rendered by injecting one small CSS override block (_AMBER_OVERRIDE) right before </head>,
plus swapping the couple of colors set as raw SVG attributes rather than CSS classes.
"""
from __future__ import annotations

from pathlib import Path

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

# One small CSS override, injected only for an amber-band send, that redirects every place the
# shared stylesheet hardcodes a RED severity accent to the existing --gold/--amber-soft/
# --amber-line tokens instead. Later rules of equal specificity win the cascade, so appending
# this right before </head> is enough -- nothing in the base stylesheet needs touching.
_AMBER_OVERRIDE = """<style>
  .chip.severity { color: var(--gold) !important; background: var(--amber-soft) !important; border-color: var(--amber-line) !important; }
  .flow-node.finding { background: var(--amber-soft) !important; border-color: var(--amber-line) !important; }
  .flow-node.finding .icn { border-color: var(--amber-line) !important; }
  .flow-node.finding .icn svg { stroke: var(--gold) !important; }
  .flow-node.finding .value { color: var(--gold) !important; }
  .ring-dot { fill: var(--gold) !important; }
  .backup-grid .cell.flag { background: var(--gold) !important; }
  .bar-fill { background: var(--gold) !important; }
  .bar-numbers .actual { color: var(--gold) !important; }
  .bar-numbers .delta { color: var(--gold) !important; background: var(--amber-soft) !important; border-color: var(--amber-line) !important; }
  .count-strip { background: rgba(185,135,62,0.22) !important; border-color: rgba(185,135,62,0.4) !important; }
  .count-strip .dot { background: var(--gold) !important; }
</style>
</head>"""


def _load(category: str) -> str:
    return (SAMPLES_DIR / FILE_BY_CATEGORY[category]).read_text(encoding="utf-8")


def _apply_common(text: str, *, band: str, group_name: str, min_severity: str) -> str:
    """Substitutions shared by every shape: footer group name/min-severity, and the amber
    color override (a no-op string-append for a red band, since the base CSS is already red)."""
    text = text.replace(
        'Automated alert from the RBZ Monitoring Console for the <b style="color:var(--text)">RTGS Team</b> '
        'group &middot; minimum severity: red.',
        f'Automated alert from the RBZ Monitoring Console for the <b style="color:var(--text)">'
        f'{group_name}</b> group &middot; minimum severity: {min_severity}.')
    if band == "amber":
        text = text.replace("</head>", _AMBER_OVERRIDE, 1)
    return text


def _gauge(category: str, *, system: str, band: str) -> str:
    text = _load(category)
    noun_word = {"disk": ("Disk usage", "disk"), "ram": ("RAM usage", "memory"),
                "cpu": ("CPU usage", "CPU")}[category]
    noun, word = noun_word
    old_system = {"disk": "CRB", "ram": "RTGS", "cpu": "ESFEXEC"}[category]
    old_pct = {"disk": 97, "ram": 93, "cpu": 96}[category]
    pct = 97 if band == "red" else 88
    dashoffset = round(502.65 * (1 - pct / 100), 2)
    old_dashoffset = round(502.65 * (1 - old_pct / 100), 2)
    old_headline = {
        "disk": f"Disk usage on {old_system} is reading {old_pct}%, well past the critical threshold.",
        "ram": f"RAM usage on {old_system} is reading {old_pct}%, past the critical threshold.",
        "cpu": f"CPU usage on {old_system} is reading {old_pct}%, past the critical threshold.",
    }[category]
    threshold_phrase = "well past the critical" if band == "red" else "above the warning"
    headline = f"{noun} on {system} is reading {pct}%, {threshold_phrase} threshold."
    old_notice = (f"The {old_pct}% reading is a synthetic test value used to demonstrate this "
                 f"alert layout — no real {word} metric triggered it.")
    notice = (f"The {pct}% reading is a synthetic test value used to demonstrate this alert "
             f"layout — no real {word} metric triggered it.")

    text = text.replace(f'stroke-dasharray="502.65" stroke-dashoffset="{old_dashoffset}"',
                        f'stroke-dasharray="502.65" stroke-dashoffset="{dashoffset}"')
    text = text.replace(f'class="gauge-num">{old_pct}%<', f'class="gauge-num">{pct}%<')
    text = text.replace(f'>system: {old_system}<', f'>system: {system}<')
    text = text.replace(f'<h2>{old_headline}</h2>', f'<h2>{headline}</h2>')
    text = text.replace(f'<div class="value">{old_system}</div>', f'<div class="value">{system}</div>')
    text = text.replace(f'{old_pct}% &middot; RED</div>', f'{pct}% &middot; {band.upper()}</div>')
    text = text.replace(old_notice, notice)
    if band == "amber":
        text = text.replace('<span class="chip severity">severity: RED</span>',
                            '<span class="chip severity">severity: AMBER</span>')
    return text


def _ring(category: str, *, system: str, band: str) -> str:
    text = _load(category)
    if category == "service":
        old_system, elapsed, old_elapsed = "Paytime", ("4m" if band == "amber" else "14m"), "14m"
        old_headline = f"The {old_system} service has been down for {old_elapsed.rstrip('m')} minutes."
        headline = f"The {system} service has been down for {elapsed.rstrip('m')} minutes."
    else:  # unreachable -- no per-component input exists in the Test tools UI yet, so the
        # illustrative component name stays fixed, matching this module's own docstring.
        old_system, elapsed, old_elapsed = "ESF", ("2m" if band == "amber" else "6m"), "6m"
        old_headline = f"The auth-gateway component on {old_system} has been unreachable for {old_elapsed.rstrip('m')} minutes."
        headline = f"The auth-gateway component on {system} has been unreachable for {elapsed.rstrip('m')} minutes."

    text = text.replace(f'font-size="10">{old_elapsed} elapsed<', f'font-size="10">{elapsed} elapsed<')
    text = text.replace(f'>system: {old_system}<', f'>system: {system}<')
    text = text.replace(f'<h2>{old_headline}</h2>', f'<h2>{headline}</h2>')
    text = text.replace(f'<div class="value">{old_system}</div>', f'<div class="value">{system}</div>')
    tail = "DOWN" if category == "service" else "UNREACHABLE"
    text = text.replace(f'{tail} &middot; RED</div>', f'{tail} &middot; {band.upper()}</div>')
    if band == "amber":
        text = text.replace('<span class="chip severity">severity: RED</span>',
                            '<span class="chip severity">severity: AMBER</span>')
    return text


def _grid(category: str, *, system: str, band: str) -> str:
    text = _load(category)
    old_system, (old_aff, old_total) = {
        "backup": ("LMS", (5, 24)), "untracked": ("CSD", (3, 18)),
        "backup_uncleared": ("RBZ Website", (7, 20)),
    }[category]
    aff, total = (old_aff, old_total) if band == "red" else (max(1, old_aff - 3), old_total)
    old_cells = "".join(['<div class="cell flag"></div>'] * old_aff + ['<div class="cell"></div>'] * (old_total - old_aff))
    cells = "".join(['<div class="cell flag"></div>'] * aff + ['<div class="cell"></div>'] * (total - aff))
    noun = {"backup": "expected backups did not run on", "untracked": "backups on",
           "backup_uncleared": "backups on"}[category]
    old_headline = {
        "backup": f"{old_aff} of {old_total} expected backups did not run on {old_system}.",
        "untracked": f"{old_aff} of {old_total} backups on {old_system} are not being tracked by the console.",
        "backup_uncleared": f"{old_aff} of {old_total} backups on {old_system} are still uncleared.",
    }[category]
    headline = {
        "backup": f"{aff} of {total} expected backups did not run on {system}.",
        "untracked": f"{aff} of {total} backups on {system} are not being tracked by the console.",
        "backup_uncleared": f"{aff} of {total} backups on {system} are still uncleared.",
    }[category]

    text = text.replace(old_cells, cells)
    text = text.replace(f'<div class="grid-caption">{old_aff}/{old_total}</div>',
                        f'<div class="grid-caption">{aff}/{total}</div>')
    text = text.replace(f'>system: {old_system}<', f'>system: {system}<')
    text = text.replace(f'<h2>{old_headline}</h2>', f'<h2>{headline}</h2>')
    text = text.replace(f'<div class="value">{old_system}</div>', f'<div class="value">{system}</div>')
    text = text.replace(f'{old_aff}/{old_total} &middot; RED</div>', f'{aff}/{total} &middot; {band.upper()}</div>')
    if band == "amber":
        text = text.replace('<span class="chip severity">severity: RED</span>',
                            '<span class="chip severity">severity: AMBER</span>')
    return text


def _bar(category: str, *, system: str, band: str) -> str:
    text = _load(category)
    old_system = "RTGS"
    old_actual, expected = 48.2, 32.0
    actual = old_actual if band == "red" else 34.5
    old_delta, delta = old_actual - expected, actual - expected
    old_fill, fill = 87.0, 87.0                       # actual is always drawn to this fixed mark
    old_marker = 57.7                                 # literal value in the sample file (not a
                                                       # clean formula result -- hand-set there)
    marker = old_marker if band == "red" else round((expected / actual) * fill, 1)

    text = text.replace(f'<span class="actual">{old_actual} GB</span>', f'<span class="actual">{actual} GB</span>')
    text = text.replace(f'<span class="delta">+{old_delta:.1f} GB over</span>', f'<span class="delta">+{delta:.1f} GB over</span>')
    text = text.replace(f'style="width:{old_fill}%"', f'style="width:{fill}%"')
    text = text.replace(f'style="left:{old_marker}%"', f'style="left:{marker}%"')
    text = text.replace(f'>system: {old_system}<', f'>system: {system}<')
    text = text.replace(
        f"/data/exports on {old_system} has grown to {old_actual} GB, above its {expected:.0f} GB expected size.",
        f"/data/exports on {system} has grown to {actual} GB, above its {expected:.0f} GB expected size.")
    text = text.replace(f'<div class="value">{old_system}</div>', f'<div class="value">{system}</div>')
    text = text.replace(f'{old_actual} GB &middot; RED</div>', f'{actual} GB &middot; {band.upper()}</div>')
    if band == "amber":
        text = text.replace('<span class="chip severity">severity: RED</span>',
                            '<span class="chip severity">severity: AMBER</span>')
    return text


_RENDERERS = {"gauge": _gauge, "ring": _ring, "grid": _grid, "bar": _bar}


def render(category: str, *, system: str, band: str, group_name: str, min_severity: str) -> str:
    """The full HTML for one category's designed sample, with system/severity/group
    substituted in. Raises KeyError for a category with no sample yet (see FILE_BY_CATEGORY)."""
    shape = SHAPE_BY_CATEGORY[category]
    text = _RENDERERS[shape](category, system=system, band=band)
    return _apply_common(text, band=band, group_name=group_name, min_severity=min_severity)

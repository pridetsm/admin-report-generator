"""Renders the four hero visuals (radial gauge, signal-loss ring, backup grid, threshold bar)
that the original hand-designed samples drew as inline SVG/CSS -- unrenderable in Outlook
desktop -- as actual PNG images instead.

Every drawing parameter here (stroke widths, radii, dash pattern, corner radii, bar height,
marker width/position) was measured pixel-by-pixel off the reference "Outlook-safe" PNGs
supplied directly (rbz-alert-templates-outlook-safe/images/, 2026-09-03) using PIL's own
getpixel() to find exact color-transition boundaries -- not redrawn from memory or aesthetic
judgement. This module reproduces THAT reference exactly, parametrized for arbitrary band/
percentage/counts instead of the reference's one fixed example value per shape. See each
render_* function's docstring for the specific measurements backing its constants.

Uses Pillow (already a project dependency -- see requirements.txt) and Windows' own bundled
Consolas/Arial TTFs. Every image is drawn supersampled and downscaled with LANCZOS resampling
for anti-aliased edges, matching the reference images' own 2x-native-size convention (e.g. a
148x148 display size ships as a 296x296 PNG).
"""
from __future__ import annotations

import io
import math
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

_FONTS = "C:/Windows/Fonts"

# Literal hex, matching alert_email_templates.py's own palette (mail_report.py's colors --
# kept independent, no cross-import between these two small modules, but sourced from the
# SAME numbers so an image never looks like a slightly different red to its own HTML).
TRACK = (228, 232, 238)         # #E4E8EE
TEXT = (27, 36, 48)             # #1B2430
MUTED = (107, 119, 133)         # #6B7785 -- mail_report.MUTED
INK, INK_SOFT = (14, 42, 71), (28, 63, 102)     # #0E2A47 / #1C3F66 -- mail_report.NAVY + a tint


def _hex_to_rgb(h: str):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


@lru_cache(maxsize=4)
def _font(name: str, size: int):
    return ImageFont.truetype(f"{_FONTS}/{name}", size)


def _text_center(draw, xy, text, font, fill):
    bbox = draw.textbbox((0, 0), text, font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x, y = xy
    draw.text((x - w / 2 - bbox[0], y - h / 2 - bbox[1]), text, font=font, fill=fill)


def render_gauge(pct: int, color_hex: str, label: str) -> bytes:
    """148x148 @2x = 296x296. Measured off gauge-disk-usage.png (97%, red): outer radius
    touches the canvas edge exactly (r=148, no margin), stroke width 20px (ring spans x=0-19
    and x=277-295 along the horizontal centerline of a 296px-wide canvas), colors RED/TRACK.
    No tick marks are baked into the image at all -- the reference's "warn 70 / crit 90"
    legend is plain HTML text below the image, reproduced as such in alert_email_templates.py,
    not drawn here.

    `color_hex` is the caller's already-resolved SEVERITY color (IMMINENT/CRITICAL/WARNING --
    see alert_email_templates._severity), not a raw red/amber band: severity classification
    lives in exactly one place (that function), not duplicated here as a second band->color
    mapping that could drift from it."""
    size = 296
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    stroke = 20
    r = size / 2 - stroke / 2
    bbox = (cx - r, cy - r, cx + r, cy + r)
    color = _hex_to_rgb(color_hex)

    draw.arc(bbox, 0, 359.9, fill=TRACK, width=stroke)
    sweep = 360 * max(0, min(100, pct)) / 100
    if sweep > 0:
        draw.arc(bbox, -90, -90 + sweep, fill=color, width=stroke)

    _text_center(draw, (cx, cy - 16), f"{pct}%", _font("consolab.ttf", 40), TEXT)
    _text_center(draw, (cx, cy + 33), label, _font("consola.ttf", 15), MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_ring(state_word: str, elapsed_label: str, line_hex: str) -> bytes:
    """148x148 @2x = 296x296. Measured off ring-service-down.png (DOWN, red): outer radius
    also touches the canvas edge (r=148), stroke width ~16px (15-16px measured), a dash
    pattern of 24 evenly-spaced ~7deg-on/8deg-off segments (not the sparse "mostly gap" pattern
    used in the original CSS/SVG design) in the severity's LINE tint color (not the solid
    color) -- and NO center dot marker; the reference has none.

    `line_hex` is the caller's already-resolved severity LINE tint (see render_gauge's own
    docstring on why severity classification isn't duplicated here)."""
    size = 296
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    stroke = 16
    r = size / 2 - stroke / 2
    bbox = (cx - r, cy - r, cx + r, cy + r)
    line_color = _hex_to_rgb(line_hex)

    dash_deg, gap_deg = 7, 8
    a = 0.0
    while a < 360:
        draw.arc(bbox, a, min(a + dash_deg, 360), fill=line_color, width=stroke)
        a += dash_deg + gap_deg

    _text_center(draw, (cx, cy - 12), state_word, _font("consolab.ttf", 32), TEXT)
    _text_center(draw, (cx, cy + 33), elapsed_label, _font("consola.ttf", 15), MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_grid(total: int, affected: int, color_hex: str, cols: int = 6) -> bytes:
    """Measured off grid-backup-missing.png (5/24, red): 41x41 rounded-rect cells (corner
    radius ~5px), 9px gaps, colors RED/TRACK. Canvas size grows with `total`'s row count
    (ceil(total/cols) rows) -- the reference's own 4 files (24, 18 and 20 total) are 4, 3 and 4
    rows respectively, all built off this exact cell/gap/radius geometry.

    `color_hex` is the caller's already-resolved severity color (see render_gauge's own
    docstring)."""
    cell, gap, radius = 41, 9, 5
    rows = math.ceil(total / cols)
    w = cols * cell + (cols - 1) * gap
    h = rows * cell + (rows - 1) * gap
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = _hex_to_rgb(color_hex)

    for i in range(total):
        row, col = divmod(i, cols)
        x0, y0 = col * (cell + gap), row * (cell + gap)
        fill = color if i < affected else TRACK
        draw.rounded_rectangle((x0, y0, x0 + cell, y0 + cell), radius=radius, fill=fill)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_bar(actual: float, expected: float, color_hex: str) -> bytes:
    """1168x80 (fixed canvas, matching the reference exactly). Measured off
    bar-folder-over-size.png (48.2GB actual / 32GB expected, red): a fully-rounded ("pill")
    bar spanning the full canvas width, height 28px (y=44-72 of an 80px-tall canvas, corner
    radius = half-height = 14px), filled to a fixed 87% mark (the reference's own illustrative
    fill -- it represents "how full the bar reads visually", not actual/expected's real ratio,
    same as alert_email_templates.py's existing `fill = 87` constant) in RED/AMBER with TRACK
    for the remainder, plus a 4px vertical marker line in INK_SOFT positioned at
    expected/actual*fill (measured at x=673.5 of 1168 = 57.7% for the reference's own 32/48.2
    ratio, confirming this is the same formula already used elsewhere in this feature) running
    from y=28 to the canvas bottom, with an "expected NGB" label centered exactly on the
    marker's x position, above it."""
    w, h = 1168, 80
    bar_top, bar_h, radius = 44, 28, 14
    fill_pct = 87
    marker_pct = round(min(99, (expected / actual) * fill_pct), 1) if actual else 0

    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = _hex_to_rgb(color_hex)
    fill_x = round(w * fill_pct / 100)

    # The pill's rounded silhouette is defined ONCE, as a mask -- both the track and the fill
    # are plain rectangles composited through it, so the fill/track boundary partway across
    # the bar comes out as a flat vertical cut (matching the reference) while the pill's own
    # two ends stay rounded, instead of every rectangle's own four corners getting rounded
    # independently (which would incorrectly round the INTERNAL fill/track seam too).
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, bar_top, w - 1, bar_top + bar_h), radius=radius, fill=255)
    pill = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(pill).rectangle((0, bar_top, w - 1, bar_top + bar_h), fill=TRACK)
    ImageDraw.Draw(pill).rectangle((0, bar_top, fill_x, bar_top + bar_h), fill=color)
    img.paste(pill, (0, 0), mask)
    draw = ImageDraw.Draw(img)

    marker_x = round(w * marker_pct / 100)
    draw.rectangle((marker_x - 2, 28, marker_x + 2, h - 1), fill=INK_SOFT)

    label = f"expected {expected:.0f}GB"
    _text_center(draw, (marker_x, 12), label, _font("consola.ttf", 15), MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@lru_cache(maxsize=1)
def header_gradient_png() -> bytes:
    """The header's 165deg navy gradient (mail_report.NAVY #0E2A47 -> a lighter tint), baked
    once (fixed colors/size, never changes between sends) and reused via lru_cache --
    referenced through the legacy HTML `background=` attribute on the header <td> in
    alert_email_templates.py, which Outlook's Word engine DOES honour for table cells, unlike
    a CSS background-image."""
    w, h = 640, 100
    top, bottom = INK, INK_SOFT
    img = Image.new("RGB", (w, h))
    px = img.load()
    diag = w * math.cos(math.radians(165 - 90))
    for x in range(w):
        t = max(0.0, min(1.0, (x * math.cos(math.radians(165 - 90))) / diag))
        color = tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        for y in range(h):
            px[x, y] = color
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# --------------------------------------------------------------------------------- category icons
# Drawn locally with Pillow's own line primitives, not fetched from anywhere -- a card's category
# glyph needs to be exactly as Outlook-safe and dependency-free as everything else this module
# produces (2026-09-04, on request for stronger at-a-glance visual identity per finding: "System
# in question, Folder icon to show that this is a folder issue"). One simple, consistent line-icon
# language across all 8 categories rather than hunting down a matching external icon per one --
# same stroke weight, same badge treatment, so the set reads as one family.
def _icon_disk(draw, box, fg, stroke):
    x0, y0, x1, y1 = box
    draw.rounded_rectangle(box, radius=(x1 - x0) * 0.12, outline=fg, width=stroke)
    midy = (y0 + y1) / 2
    draw.line((x0 + stroke, midy, x1 - stroke, midy), fill=fg, width=stroke)
    r = (x1 - x0) * 0.07
    cx, cy = x1 - (x1 - x0) * 0.22, midy
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=fg)


def _icon_ram(draw, box, fg, stroke):
    x0, y0, x1, y1 = box
    draw.rounded_rectangle(box, radius=(x1 - x0) * 0.08, outline=fg, width=stroke)
    w, h = x1 - x0, y1 - y0
    for i in range(1, 4):
        x = x0 + w * i / 4
        draw.line((x, y1, x, y1 + h * 0.14), fill=fg, width=stroke)


def _icon_cpu(draw, box, fg, stroke):
    x0, y0, x1, y1 = box
    w, h = x1 - x0, y1 - y0
    pad = w * 0.16
    inner = (x0 + pad, y0 + pad, x1 - pad, y1 - pad)
    draw.rectangle(inner, outline=fg, width=stroke)
    for frac in (0.32, 0.68):
        x, y = x0 + w * frac, y0 + h * frac
        draw.line((x, y0, x, y0 - pad * 0.7), fill=fg, width=stroke)
        draw.line((x, y1, x, y1 + pad * 0.7), fill=fg, width=stroke)
        draw.line((x0, y, x0 - pad * 0.7, y), fill=fg, width=stroke)
        draw.line((x1, y, x1 + pad * 0.7, y), fill=fg, width=stroke)


def _icon_service(draw, box, fg, stroke):
    x0, y0, x1, y1 = box
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    r = (x1 - x0) * 0.26
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=fg, width=stroke)
    ir = r * 0.42
    draw.ellipse((cx - ir, cy - ir, cx + ir, cy + ir), outline=fg, width=stroke)
    tooth = r * 0.4
    for i in range(8):
        ang = math.radians(i * 45)
        tx0, ty0 = cx + math.cos(ang) * r, cy + math.sin(ang) * r
        tx1, ty1 = cx + math.cos(ang) * (r + tooth), cy + math.sin(ang) * (r + tooth)
        draw.line((tx0, ty0, tx1, ty1), fill=fg, width=round(stroke * 1.5))


def _icon_unreachable(draw, box, fg, stroke):
    x0, y0, x1, y1 = box
    draw.ellipse(box, outline=fg, width=stroke)
    inset = (x1 - x0) * 0.24
    draw.line((x0 + inset, y1 - inset, x1 - inset, y0 + inset), fill=fg, width=stroke)


def _icon_backup(draw, box, fg, stroke):
    x0, y0, x1, y1 = box
    w, h = x1 - x0, y1 - y0
    draw.rounded_rectangle(box, radius=w * 0.08, outline=fg, width=stroke)
    draw.line((x1 - w * 0.3, y0, x1, y0 + h * 0.3), fill=fg, width=stroke)
    label = (x0 + w * 0.22, y0 + stroke, x1 - w * 0.22, y0 + h * 0.4)
    draw.rectangle(label, outline=fg, width=max(1, round(stroke * 0.75)))
    slot = (x0 + w * 0.3, y1 - h * 0.24, x1 - w * 0.3, y1 - h * 0.12)
    draw.rectangle(slot, fill=fg)


def _icon_folder(draw, box, fg, stroke, *, mark: str = "") -> None:
    x0, y0, x1, y1 = box
    w, h = x1 - x0, y1 - y0
    tabw, tabh = w * 0.42, h * 0.16
    draw.rounded_rectangle((x0, y0, x0 + tabw, y0 + tabh * 1.6), radius=tabh * 0.5, outline=fg, width=stroke)
    draw.rounded_rectangle((x0, y0 + tabh, x1, y1), radius=h * 0.08, outline=fg, width=stroke)
    if mark == "clock":
        cx, cy, r = x1 - w * 0.22, y1 - h * 0.24, w * 0.17
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(255, 255, 255, 255), outline=fg,
                    width=max(1, round(stroke * 0.8)))
        draw.line((cx, cy, cx, cy - r * 0.6), fill=fg, width=max(1, round(stroke * 0.7)))
        draw.line((cx, cy, cx + r * 0.5, cy), fill=fg, width=max(1, round(stroke * 0.7)))
    elif mark == "grow":
        cx, cy = x1 - w * 0.22, y1 - h * 0.3
        draw.line((cx, cy + h * 0.12, cx, cy - h * 0.12), fill=fg, width=stroke)
        draw.line((cx, cy - h * 0.12, cx - w * 0.09, cy - h * 0.02), fill=fg, width=stroke)
        draw.line((cx, cy - h * 0.12, cx + w * 0.09, cy - h * 0.02), fill=fg, width=stroke)


_ICON_DRAWERS = {
    "disk": _icon_disk,
    "ram": _icon_ram,
    "cpu": _icon_cpu,
    "service": _icon_service,
    "unreachable": _icon_unreachable,
    "backup": _icon_backup,
    "untracked": _icon_backup,
    "backup_uncleared": _icon_backup,
    "folder": lambda d, b, f, s: _icon_folder(d, b, f, s, mark="grow"),
    "undrained_folders": lambda d, b, f, s: _icon_folder(d, b, f, s, mark="clock"),
}


def render_category_icon(category: str, fg_hex: str, soft_hex: str, size: int = 64) -> bytes:
    """A small square badge: a soft-tinted rounded background in the finding's own severity
    color, with a simple line glyph naming the CATEGORY on top -- system/metric/severity are
    already chips text on the card; this is the one thing a reader has to notice before
    reading anything, which is why it exists at all ("Folder icon to show that this is a
    folder issue... these shouldn't be things I have to look for")."""
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((0, 0, s - 1, s - 1), radius=round(s * 0.22), fill=_hex_to_rgb(soft_hex))
    pad = round(s * 0.26)
    stroke = max(2, round(s * 0.045))
    box = (pad, pad, s - pad, s - pad)
    drawer = _ICON_DRAWERS.get(category)
    if drawer:
        drawer(draw, box, _hex_to_rgb(fg_hex), stroke)
    img = img.resize((size, size), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

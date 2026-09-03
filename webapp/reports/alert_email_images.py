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

# Literal hex, matching alert_email_templates.py's own palette (kept independent -- no
# cross-import between these two small modules).
TRACK = (228, 232, 238)         # #E4E8EE
TEXT = (27, 36, 48)             # #1B2430
MUTED = (100, 112, 125)         # #64707D
INK_SOFT = (22, 52, 85)         # #163455
GOLD = (185, 135, 62)           # #B9873E
RED = (178, 58, 50)             # #B23A32
RED_LINE = (227, 179, 172)      # #E3B3AC
AMBER_LINE = (231, 206, 153)    # #E7CE99


def _band_rgb(band: str):
    return RED if band == "red" else GOLD


def _band_line_rgb(band: str):
    return RED_LINE if band == "red" else AMBER_LINE


@lru_cache(maxsize=4)
def _font(name: str, size: int):
    return ImageFont.truetype(f"{_FONTS}/{name}", size)


def _text_center(draw, xy, text, font, fill):
    bbox = draw.textbbox((0, 0), text, font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x, y = xy
    draw.text((x - w / 2 - bbox[0], y - h / 2 - bbox[1]), text, font=font, fill=fill)


def render_gauge(pct: int, band: str, label: str) -> bytes:
    """148x148 @2x = 296x296. Measured off gauge-disk-usage.png (97%, red): outer radius
    touches the canvas edge exactly (r=148, no margin), stroke width 20px (ring spans x=0-19
    and x=277-295 along the horizontal centerline of a 296px-wide canvas), colors RED/TRACK.
    No tick marks are baked into the image at all -- the reference's "warn 70 / crit 90"
    legend is plain HTML text below the image, reproduced as such in alert_email_templates.py,
    not drawn here."""
    size = 296
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    stroke = 20
    r = size / 2 - stroke / 2
    bbox = (cx - r, cy - r, cx + r, cy + r)
    color = _band_rgb(band)

    draw.arc(bbox, 0, 359.9, fill=TRACK, width=stroke)
    sweep = 360 * max(0, min(100, pct)) / 100
    if sweep > 0:
        draw.arc(bbox, -90, -90 + sweep, fill=color, width=stroke)

    _text_center(draw, (cx, cy - 16), f"{pct}%", _font("consolab.ttf", 40), TEXT)
    _text_center(draw, (cx, cy + 33), label, _font("consola.ttf", 15), MUTED)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_ring(state_word: str, elapsed_label: str, band: str) -> bytes:
    """148x148 @2x = 296x296. Measured off ring-service-down.png (DOWN, red): outer radius
    also touches the canvas edge (r=148), stroke width ~16px (15-16px measured), a dash
    pattern of 24 evenly-spaced ~7deg-on/8deg-off segments (not the sparse "mostly gap" pattern
    used in the original CSS/SVG design) in the band's LINE tint color (RED_LINE/AMBER_LINE,
    not the solid band color) -- and NO center dot marker; the reference has none."""
    size = 296
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    stroke = 16
    r = size / 2 - stroke / 2
    bbox = (cx - r, cy - r, cx + r, cy + r)
    line_color = _band_line_rgb(band)

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


def render_grid(total: int, affected: int, band: str, cols: int = 6) -> bytes:
    """Measured off grid-backup-missing.png (5/24, red): 41x41 rounded-rect cells (corner
    radius ~5px), 9px gaps, colors RED/TRACK. Canvas size grows with `total`'s row count
    (ceil(total/cols) rows) -- the reference's own 4 files (24, 18 and 20 total) are 4, 3 and 4
    rows respectively, all built off this exact cell/gap/radius geometry."""
    cell, gap, radius = 41, 9, 5
    rows = math.ceil(total / cols)
    w = cols * cell + (cols - 1) * gap
    h = rows * cell + (rows - 1) * gap
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = _band_rgb(band)

    for i in range(total):
        row, col = divmod(i, cols)
        x0, y0 = col * (cell + gap), row * (cell + gap)
        fill = color if i < affected else TRACK
        draw.rounded_rectangle((x0, y0, x0 + cell, y0 + cell), radius=radius, fill=fill)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_bar(actual: float, expected: float, band: str) -> bytes:
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
    color = _band_rgb(band)
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
    """The header's 165deg navy gradient (#0E2238 -> #163455), baked once (fixed colors/size,
    never changes between sends) and reused via lru_cache -- referenced through the legacy
    HTML `background=` attribute on the header <td> in alert_email_templates.py, which
    Outlook's Word engine DOES honour for table cells, unlike a CSS background-image."""
    w, h = 640, 100
    top, bottom = (14, 34, 56), (22, 52, 85)
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

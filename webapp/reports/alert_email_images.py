"""Renders the two circular hero visuals (radial gauge, signal-loss ring) that the original
hand-designed samples drew as inline SVG -- unrenderable in Outlook desktop (see
alert_email_templates.py's own docstring) -- as actual PNG images instead, so the finished
picture looks the same in every client, Outlook included, rather than degrading to a bar/badge
approximation.

Uses Pillow (already a project dependency -- see requirements.txt, "lets openpyxl embed the
company logo") and Windows' own bundled Consolas/Arial TTFs; nothing new to install.

Every image is drawn supersampled (4x the final pixel size) and downscaled with LANCZOS
resampling, the standard trick for anti-aliased circles/text out of Pillow's otherwise
hard-edged drawing primitives -- without it, the ring/arc edges come out visibly jagged at
e-mail resolution.
"""
from __future__ import annotations

import io
import math
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

_FONTS = "C:/Windows/Fonts"
_SCALE = 4               # supersampling factor

# Same literal hex palette as alert_email_templates.py (kept independent -- this module has no
# other reason to import that one, and duplicating nine color constants is cheaper than a
# cross-import for two small modules that could otherwise be read standalone).
TRACK = (228, 232, 238)
TEXT = (27, 36, 48)
MUTED = (100, 112, 125)
GOLD = (185, 135, 62)
RED = (178, 58, 50)


def _band_rgb(band: str):
    return RED if band == "red" else GOLD


@lru_cache(maxsize=4)
def _font(name: str, size: int):
    return ImageFont.truetype(f"{_FONTS}/{name}", size)


def _text_center(draw, xy, text, font, fill):
    bbox = draw.textbbox((0, 0), text, font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x, y = xy
    draw.text((x - w / 2 - bbox[0], y - h / 2 - bbox[1]), text, font=font, fill=fill)


def render_gauge(pct: int, band: str, label: str) -> bytes:
    """A 148x148 PNG matching the original SVG gauge's proportions: a light track ring, a
    colored progress arc for `pct` (0-100) starting at 12 o'clock going clockwise, two small
    warn/critical tick marks at 70%/90%, and the percentage + metric label centered inside."""
    size = 148 * _SCALE
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    stroke = round(size * 0.108)
    r = size / 2 - stroke / 2 - 4 * _SCALE
    bbox = (cx - r, cy - r, cx + r, cy + r)
    color = _band_rgb(band)

    draw.arc(bbox, 0, 359.9, fill=TRACK, width=stroke)
    sweep = 360 * max(0, min(100, pct)) / 100
    if sweep > 0:
        draw.arc(bbox, -90, -90 + sweep, fill=color, width=stroke)

    for tick_pct, tick_color in ((70, GOLD), (90, RED)):
        angle = math.radians(-90 + 360 * tick_pct / 100)
        r1, r2 = r - stroke * 0.9, r - stroke * 1.6
        x1, y1 = cx + r1 * math.cos(angle), cy + r1 * math.sin(angle)
        x2, y2 = cx + r2 * math.cos(angle), cy + r2 * math.sin(angle)
        draw.line([(x1, y1), (x2, y2)], fill=tick_color, width=round(size * 0.02))

    _text_center(draw, (cx, cy - size * 0.05), f"{pct}%", _font("consolab.ttf", round(size * 0.135)), TEXT)
    _text_center(draw, (cx, cy + size * 0.11), label, _font("consola.ttf", round(size * 0.05)), MUTED)

    img = img.resize((148, 148), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_ring(state_word: str, elapsed_label: str, band: str) -> bytes:
    """A 148x148 PNG matching the original SVG signal-loss ring: a dashed circle (no live
    animation -- see this module's own docstring) with a solid dot at 12 o'clock, and the
    state word + elapsed time centered inside."""
    size = 148 * _SCALE
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx = cy = size / 2
    stroke = round(size * 0.065)
    r = size / 2 - stroke / 2 - 4 * _SCALE
    bbox = (cx - r, cy - r, cx + r, cy + r)
    color = _band_rgb(band)
    line_color = tuple(round(c * 0.45 + 255 * 0.55) for c in color)  # the sample's --*-line tint

    # Mirrors the original SVG's own fine stroke-dasharray="3 9" (mostly gap, thin dashes) --
    # a sparse ring of short ticks rather than a solid or chunky-dashed circle.
    dash_deg, gap_deg = 4, 10
    a = 0.0
    while a < 360:
        draw.arc(bbox, a, min(a + dash_deg, 360), fill=line_color, width=stroke)
        a += dash_deg + gap_deg

    dot_r = stroke * 0.9
    draw.ellipse((cx - dot_r, cy - r - dot_r, cx + dot_r, cy - r + dot_r), fill=color)

    _text_center(draw, (cx, cy - size * 0.04), state_word, _font("consolab.ttf", round(size * 0.105)), TEXT)
    _text_center(draw, (cx, cy + size * 0.12), elapsed_label, _font("consola.ttf", round(size * 0.05)), MUTED)

    img = img.resize((148, 148), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@lru_cache(maxsize=1)
def header_gradient_png() -> bytes:
    """The header's 165deg navy gradient, baked once (fixed colors/size, never changes between
    sends) and reused via lru_cache -- referenced through the legacy HTML `background=`
    attribute on the header <td> (see alert_email_templates.py), which Outlook's Word engine
    DOES honour for table cells, unlike a CSS background-image."""
    w, h = 640, 100                                    # baked once -- no need to supersample
    top, bottom = (14, 34, 56), (22, 52, 85)          # #0E2238 -> #163455
    img = Image.new("RGB", (w, h))
    px = img.load()
    # 165deg from vertical: almost entirely a left-to-right sweep with a barely-perceptible
    # downward component -- one t-per-column, applied to every row in that column, matches the
    # CSS gradient's endpoints exactly without an O(w*h) per-pixel angle projection.
    diag = w * math.cos(math.radians(165 - 90))
    for x in range(w):
        t = max(0.0, min(1.0, (x * math.cos(math.radians(165 - 90))) / diag))
        color = tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        for y in range(h):
            px[x, y] = color
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

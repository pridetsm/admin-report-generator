"""Static chart images for the Automated Reports PDF (templates/reports/automated_report_
pdf.html). xhtml2pdf's renderer can't run JavaScript or render a <canvas>, so the same charts
the web view builds live with Chart.js (see automated_report_download.html) are pre-rendered
here as PNGs and inlined as base64 data URIs instead.

matplotlib, not Plotly/Bokeh: those export static images through "kaleido"/a headless-
Chromium renderer -- a large, fragile binary dependency to add on a locked-down Windows
server with no guarantee it installs cleanly. matplotlib is pure-Python (plus numpy, both
with prebuilt Windows wheels, no compiler needed) and is the de facto standard choice for
exactly this "render a chart to a static image, server-side, no browser" use case.

Every chart here is a rendered PNG (an <img>, not an HTML gauge/bar built from nested tags),
in part because xhtml2pdf's own HTML rendering has sharp edges worth remembering if that
ever changes: a <div> nested inside another <div> with its own background is silently
dropped (no error, the fill just never appears) -- confirmed by direct test. A plain <img>
sidesteps that entirely, which is one more reason these are pre-rendered images rather than
CSS-drawn shapes.

ONE COLLECTIVE CHART PER DATASET, NOT ONE PER ROW (2026-09-07, on request): an earlier version
of this module put a bar-gauge on every Recurring Issues row -- technically correct, but it
doubled the PDF's row count and added more visual clutter than the numbers already in the
table. issue_occurrence_heatmap below replaces that per-row micro-chart with one chart per
dataset instead -- the Recurring Issues section's own chart went through one more iteration on
the same principle: a coverage-% distribution histogram (superseded, since removed) told "how
persistent is this week's
trouble, in aggregate" but not which system or which issue type it was; the heatmap answers
both at once, per system AND per issue type, in the same one-chart-per-dataset spirit.

COLOUR (2026-09-07, on request): every colour here is one of the console's own four status
colours -- reports/../static/css/app.css already defines --red/--amber/--green/--accent for
exactly this purpose (chips, KPI states, banners, elsewhere in the app), and re-deriving a
different-looking palette from the report's own navy/gold branding just for these charts was
the mistake being corrected: readers already know what red/amber/green mean in this console,
and a report-branded amber/gold that looks nothing like the app's own warning colour defeats
that. Hex values below are copied from app.css's LIGHT theme (matplotlib/the PDF have no
dark-mode concept); the Chart.js web charts instead read the live CSS custom properties at
render time so they follow the page's actual theme -- see automated_report_download.html's
own script block.

  RED    -- requires attention (an ongoing/persistent problem, a red worst_band)
  AMBER  -- warning (a recurring-but-not-constant problem, an amber worst_band)
  GREEN  -- healthy (no active issue at all)
  BLUE   -- neutral / informational (not yet confirmed as a real pattern: a potential fluke,
            a one-off, a comment theme count -- none of these assert good or bad)
"""
from __future__ import annotations

import base64
import io

import matplotlib
matplotlib.use("Agg")   # headless -- no display, no GUI backend needed on a server
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap, Normalize

_INK = "#16233A"
_MUTED = "#6B6558"
_LINE = "#DAD4C6"

# The console's own status palette (app.css, light theme) -- see module docstring.
_RED = "#d14a3a"
_AMBER = "#b8790a"
_GREEN = "#0e9c74"
_BLUE = "#1a6fc4"
_BLUE_SOFT = "#7fa8d1"   # a lighter tint of the same blue, for a second "neutral" series
                        # (One-off) that needs to read as distinct from Potential fluke's blue
                        # without introducing a fifth, unrelated hue.

# A continuous ramp for the occurrence heatmap below -- white (lowest/no occurrences) through
# the console's own amber up to its own red (highest occurrence count) -- an actual HEAT
# gradient (cool/pale -> hot), not the cool blue ramp this used at first, which read as a
# "cold map" instead. Still built from colours this module already uses elsewhere (_AMBER/
# _RED), not a new invented hue -- unlike the red/amber used for a binary pass/fail verdict
# elsewhere in this module, here they're just the warm end of one continuous scale, with no
# threshold where "amber" or "red" starts meaning something categorically different.
_HEATMAP_CMAP = LinearSegmentedColormap.from_list("issue_heat", ["#FFFFFF", _AMBER, _RED])

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 9,
    "text.color": _INK,
    "axes.edgecolor": _LINE,
    "axes.labelcolor": _MUTED,
    "xtick.color": _MUTED,
    "ytick.color": _MUTED,
    "svg.fonttype": "none",
})


def _to_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=170, bbox_inches="tight", transparent=True)
    plt.close(fig)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


_LOGO_DATA_URI: str | None = None


def logo_data_uri() -> str | None:
    """The app's own brand-mark PNG (static/img/brand-mark.png -- the exact file base.html's
    own header already uses everywhere else in the console) as a base64 data URI, for the PDF
    masthead specifically (2026-09-10, item 32: "pull the same logo file the app already uses
    elsewhere... rather than sourcing or re-exporting a new one"). xhtml2pdf's pisa.CreatePDF
    is called with no `link_callback` (see build_automated_report_pdf), so a plain `/static/...`
    URL never resolves server-side the way a browser resolves it for the web template (which
    uses {% static %} directly, unaffected by any of this) -- self-contained like every other
    PDF image this module already produces, not a live file/HTTP read at render time. Cached
    module-level after the first read since the file doesn't change between requests. Returns
    None (never raises) if the asset is missing, so a logo problem degrades to no logo, not a
    broken PDF."""
    global _LOGO_DATA_URI
    if _LOGO_DATA_URI is None:
        try:
            from pathlib import Path

            from django.conf import settings
            path = Path(settings.BASE_DIR) / "static" / "img" / "brand-mark.png"
            _LOGO_DATA_URI = "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")
        except Exception:                       # noqa: BLE001
            _LOGO_DATA_URI = ""
    return _LOGO_DATA_URI or None


def _donut(pairs: list, figsize=(4.6, 2.6)) -> str | None:
    pairs = [(l, v, c) for l, v, c in pairs if v > 0]
    if not pairs:
        return None
    labels, values, colors = zip(*pairs)
    fig, ax = plt.subplots(figsize=figsize)
    wedges, _ = ax.pie(values, colors=colors, startangle=90, counterclock=False,
                       wedgeprops={"width": 0.42})
    ax.legend(wedges, [f"{l}  ({v})" for l, v in zip(labels, values)],
             loc="center left", bbox_to_anchor=(1.02, 0.5), frameon=False, fontsize=9.5)
    ax.set_aspect("equal")
    return _to_data_uri(fig)


def issue_breakdown_donut(persistent: int, recurring: int, flukes: int, one_off: int) -> str | None:
    """Persistent/Recurring/Potential fluke/One-off as a donut -- the KPI strip already gives
    the four raw counts; this gives their PROPORTION at a glance. Persistent/Recurring are
    confirmed-active problems (red/amber); Potential fluke/One-off are explicitly UNCONFIRMED
    (section 6: "not every unusual data point represents a genuine trend"), so both get the
    neutral blue rather than a severity colour -- calling a one-off "amber" would misrepresent
    exactly the distinction section 6 asks the report to preserve."""
    return _donut([("Persistent", persistent, _RED), ("Recurring", recurring, _AMBER),
                  ("Potential fluke", flukes, _BLUE), ("One-off", one_off, _BLUE_SOFT)])


def estate_health_donut(healthy: int, amber: int, red: int) -> str | None:
    """Every system in the topology, not just the ones already in trouble -- the KPI strip
    and the "requiring attention" bar below both only ever show systems WITH an issue, so
    there was previously no way to see "how much of the estate is actually fine" at all. Green
    appears here and nowhere else in this module on purpose: it's the one status this report
    otherwise never states explicitly."""
    return _donut([("Healthy", healthy, _GREEN), ("Warning", amber, _AMBER),
                  ("Requires attention", red, _RED)], figsize=(4.2, 2.6))


def system_attention_bar(rows: list, limit: int = 12) -> str | None:
    """Horizontal STACKED bar per system with an active issue, ranked -- replaces scanning a
    table column by eye with an immediate "who's worst, and of what kind" read. A stacked bar
    (persistent segment + recurring segment, same red/amber the KPI tiles/donut already use for
    those two labels) rather than one combined-total bar (2026-09-10, item 10): the combined
    total alone couldn't say whether a system's issues were mostly persistent or mostly
    recurring -- a real distinction, since a persistent-heavy system rarely clears on its own
    and a recurring-heavy one already comes and goes. This chart is now the SOLE presentation
    of system_attention data -- the table this used to sit above/below has been dropped
    entirely (item 10: "verified against the data... every row in §06 is reconstructable from
    §04" -- system_attention itself is computed FROM §04's own two findings lists, so a
    separate table here was a full derived rollup of data §04 already shows, not new
    information)."""
    rows = list(rows[:limit])
    if not rows:
        return None
    systems = [r["system"] for r in rows][::-1]
    persistent = [r["persistent_count"] for r in rows][::-1]
    recurring = [r["recurring_count"] for r in rows][::-1]
    totals = [p + r for p, r in zip(persistent, recurring)]

    fig, ax = plt.subplots(figsize=(6.6, max(1.2, 0.4 * len(rows) + 0.4)))
    ax.barh(systems, persistent, color=_RED, height=0.62, label="Persistent")
    ax.barh(systems, recurring, left=persistent, color=_AMBER, height=0.62, label="Recurring")
    max_total = max(totals) or 1
    for y, v in enumerate(totals):
        ax.text(v + max_total * 0.02, y, str(v), va="center", fontsize=8.5, color=_INK)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color(_LINE)
    ax.tick_params(left=False)
    ax.set_xticks([])
    ax.set_xlim(0, max_total * 1.15)
    ax.legend(loc="lower right", frameon=False, fontsize=8, ncol=2,
             bbox_to_anchor=(1.0, -0.25 / max(1, len(rows))))
    fig.tight_layout()
    return _to_data_uri(fig)


def pareto_chart(attention_rows: list, limit: int = 15) -> str | None:
    """Bars (active-issue count per system, ranked) + a cumulative-% line -- 2026-09-10, item
    11: backs the "82% concentration" claim §01 already states in prose (see ai_narrative.py's
    pareto_concentration) with an actual chart, replacing the need to restate that stat as text
    in three places. Cumulative % is computed against the TOTAL active-issue count across EVERY
    system with an open issue (not just the `limit` shown), the identical denominator offline_
    insights.pareto_concentration itself uses (`running / len(active)`), so this chart's own
    line and the prose "82%" claim can never quietly disagree."""
    rows = sorted(attention_rows, key=lambda r: r["persistent_count"] + r["recurring_count"],
                 reverse=True)
    if not rows:
        return None
    total = sum(r["persistent_count"] + r["recurring_count"] for r in rows)
    shown = rows[:limit]
    systems = [r["system"] for r in shown]
    counts = [r["persistent_count"] + r["recurring_count"] for r in shown]
    running = 0
    cumulative = []
    for r in rows:   # cumulative % walks the FULL ranked list, not just `shown`
        running += r["persistent_count"] + r["recurring_count"]
        cumulative.append(running / total * 100)
    cumulative = cumulative[:limit]

    fig, ax = plt.subplots(figsize=(6.8, 3.4))
    xs = range(len(systems))
    ax.bar(xs, counts, color=_RED, width=0.6, zorder=2)
    ax.set_ylabel("Active issues", fontsize=8.5, color=_INK)
    ax.set_xticks(list(xs))
    ax.set_xticklabels(systems, fontsize=8, rotation=40, ha="right")
    ax.spines[["top"]].set_visible(False)
    ax.spines[["left", "bottom", "right"]].set_color(_LINE)
    ax.tick_params(axis="y", labelsize=8, colors=_MUTED)

    ax2 = ax.twinx()
    ax2.plot(xs, cumulative, color=_INK, marker="o", markersize=4, linewidth=1.6, zorder=3)
    ax2.axhline(80, color=_AMBER, linewidth=0.9, linestyle="--", zorder=1)
    ax2.set_ylim(0, 105)
    ax2.set_ylabel("Cumulative %", fontsize=8.5, color=_INK)
    ax2.spines[["top"]].set_visible(False)
    ax2.tick_params(axis="y", labelsize=8, colors=_MUTED)
    fig.tight_layout()
    return _to_data_uri(fig)


def category_breakdown_chart(recurring_issues: list) -> str | None:
    """What share of active (Persistent + Recurring) load is disk vs RAM vs CPU vs
    unreachable, etc. -- 2026-09-10, item 12: backs §02's "68% of load is disk category" claim
    (see offline_insights.category_concentration, which only returns the TOP category; this
    shows the full breakdown, not just the winner). Same category label set/order the two
    heatmaps' own columns already use (issue_occurrence_matrix), so a category reads the same
    way everywhere in this report."""
    from collections import Counter

    counts = Counter(i.get("category", "") for i in recurring_issues)
    if not counts:
        return None
    pairs = counts.most_common()
    labels = [_CATEGORY_LABELS.get(c, c.replace("_", " ").title()) for c, _ in pairs]
    values = [n for _c, n in pairs]
    total = sum(values)
    # Cycle through the report's own status colours (see this module's own docstring) rather
    # than an arbitrary categorical palette -- a category slice being red/amber/blue here
    # carries no severity meaning (it's just "which bucket"), so colour is assigned by ORDER
    # (most common first) purely to keep adjacent wedges visually distinct, not to imply rank.
    palette = [_RED, _AMBER, _BLUE, _GREEN, _BLUE_SOFT, _MUTED]
    colors = [palette[i % len(palette)] for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(4.8, 2.8))
    wedges, _texts = ax.pie(values, colors=colors, startangle=90, counterclock=False,
                            wedgeprops={"width": 0.42})
    ax.legend(wedges, [f"{l}  ({v}, {v / total * 100:.0f}%)" for l, v in zip(labels, values)],
             loc="center left", bbox_to_anchor=(1.02, 0.5), frameon=False, fontsize=9)
    ax.set_aspect("equal")
    return _to_data_uri(fig)


def onset_timeline_chart(recurring_issues: list) -> str | None:
    """First-onset date per system, as a dot-plot along a shared time axis -- 2026-09-10, item
    13: visually confirms (or doesn't) the Emerging Risks "N systems had new issues appear
    within 2 days of each other" claim (offline_insights.coincident_onsets), rather than just
    asserting it in prose. Excludes Persistent issues for the SAME reason coincident_onsets
    itself does (see that function's own docstring): a Persistent issue's first_seen is clipped
    to the window's own start whenever the issue predates the window, which is indistinguishable
    from a genuine new onset by timestamp alone -- only Recurring/Potential fluke/One-off onsets
    are meaningful here. One dot per SYSTEM (its own earliest onset among its non-persistent
    issues), not one per issue -- the claim is about systems clustering, not issue count."""
    import datetime as _dt

    earliest: dict = {}
    for i in recurring_issues:
        if i.get("label") == "Persistent":
            continue
        fs = i.get("first_seen")
        if not fs:
            continue
        d = _dt.datetime.fromisoformat(fs).date()
        if i["system"] not in earliest or d < earliest[i["system"]]:
            earliest[i["system"]] = d
    if not earliest:
        return None
    rows = sorted(earliest.items(), key=lambda kv: kv[1])
    systems = [s for s, _d in rows][::-1]
    dates = [d for _s, d in rows][::-1]

    fig, ax = plt.subplots(figsize=(6.6, max(1.2, 0.35 * len(rows) + 0.4)))
    ax.scatter(dates, range(len(systems)), color=_BLUE, s=48, zorder=3)
    ax.set_yticks(range(len(systems)))
    ax.set_yticklabels(systems, fontsize=8.5)
    ax.tick_params(axis="x", labelsize=8, colors=_MUTED, rotation=30)
    ax.grid(axis="x", color=_LINE, linewidth=0.6, zorder=0)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color(_LINE)
    fig.tight_layout()
    return _to_data_uri(fig)


def totals_sparklines_chart(all_series: dict) -> str | None:
    """Small multiples -- one sparkline per watched aggregate total (services monitored,
    backup-tracked hosts, certs monitored, expired certs), showing the actual series across the
    window instead of a single before→after snippet -- 2026-09-10, item 14: "ties directly to
    the known fluctuating-totals bug already tracked separately" (reports.totals_integrity).
    `all_series` is totals_integrity.all_totals_series' own output -- every watched metric that
    had at least one data point this window, decreased or not (unlike totals_anomalies, which
    only ever carries the ones that DID decrease)."""
    import datetime as _dt

    items = list(all_series.items())
    if not items:
        return None
    n = len(items)
    cols = min(2, n)
    rows = (n + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(6.8, 1.7 * rows), squeeze=False)
    for idx, (_key, data) in enumerate(items):
        ax = axes[idx // cols][idx % cols]
        points = data["series"]
        xs = [_dt.datetime.fromisoformat(at) for at, _v in points]
        ys = [v for _at, v in points]
        dipped = any(b < a for a, b in zip(ys, ys[1:]))
        ax.plot(xs, ys, color=_RED if dipped else _BLUE, linewidth=1.4)
        ax.fill_between(xs, ys, min(ys), color=_RED if dipped else _BLUE, alpha=0.08)
        ax.set_title(f"{data['label']}  (now: {ys[-1]})", fontsize=8.5, color=_INK, loc="left")
        ax.set_xticks([])
        ax.tick_params(axis="y", labelsize=7, colors=_MUTED)
        ax.spines[["top", "right"]].set_visible(False)
        ax.spines[["left", "bottom"]].set_color(_LINE)
    # Blank out any unused grid cells (n doesn't evenly fill rows*cols -- e.g. 3 metrics in a
    # 2-column grid leaves one empty).
    for idx in range(n, rows * cols):
        axes[idx // cols][idx % cols].axis("off")
    fig.tight_layout()
    return _to_data_uri(fig)


def theme_bar_chart(themes: list, limit: int = 10) -> str | None:
    """Administrator comment themes ranked by mention count (Administrator Observations
    Digest) -- a categorical comparison (section 3's "group similar comments into meaningful
    themes"), currently only stated as running prose. Neutral blue throughout: a theme count
    is a fact about what admins talk about, not a severity verdict."""
    rows = list(themes[:limit])
    if not rows:
        return None
    labels = [r["label"] for r in rows][::-1]
    values = [r["count"] for r in rows][::-1]

    fig, ax = plt.subplots(figsize=(6.6, max(1.2, 0.4 * len(rows) + 0.4)))
    ax.barh(labels, values, color=_BLUE, height=0.62)
    max_v = max(values) or 1
    for y, v in enumerate(values):
        ax.text(v + max_v * 0.02, y, str(v), va="center", fontsize=8.5, color=_INK)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color(_LINE)
    ax.tick_params(left=False)
    ax.set_xticks([])
    ax.set_xlim(0, max_v * 1.2)
    fig.tight_layout()
    return _to_data_uri(fig)


def finding_table(issues: list, limit: int = 20) -> list:
    """Every Persistent/Recurring finding, one row each: system, flag, coverage %, and distinct
    days -- superseding finding_coverage_bar/finding_bar_data's bar chart (2026-09-08, on
    request, after noticing most Persistent findings tie at the exact same coverage/days once
    an issue has simply been active for the report's ENTIRE window: classify_all's own
    window-bounded first_seen can't see further back than the window edge, so an issue that
    predates the window looks IDENTICAL to one that started exactly at the edge -- 12 of 15
    Persistent findings in a real report tied at "88% · 7d" the day this was noticed. A bar
    chart's whole premise is that length ranks severity at a glance; once most rows are the
    same length, it's carrying no more information than the heatmap already gives (which
    system, which issue type, how many days -- issue_occurrence_matrix), just less legibly. A
    plain table reads correctly whether values tie or not, so it replaces the chart rather than
    trying to make ties look more different than they are.

    `issues` is already ranked by significance (classify_all's own ordering, preserved through
    every filter this data has passed through since) -- sliced to `limit`, same reasoning the
    old bar chart used: the least significant findings are the least likely to be worth the
    space."""
    rows = list(issues[:limit])
    return [{
        "system": i["system"], "flag_key": i["flag_key"],
        "coverage_pct": round(i["coverage"] * 100), "days": i["distinct_days"],
        "band": i["worst_band"],
        # Snapshotted admin action fields (2026-09-10, item 10a) -- carried straight through
        # from the already-frozen AutomatedReport.content row, not re-derived here.
        "action_comment": i.get("action_comment", ""),
        "action_fix_needed": i.get("action_fix_needed", ""),
        "action_resolved": i.get("action_resolved", ""),
        "action_unset": i.get("action_unset", True),
    } for i in rows]


def spike_categories(recurring_issues: list) -> list:
    """Distinct categories present in `report.recurring_issues` (Persistent+Recurring
    combined) -- the same category set the two heatmaps' own columns are built from
    (issue_occurrence_matrix), so "one Hourly Activity chart per issue type" (2026-09-07, on
    request) always matches "as there are issues appearing in the heat map" exactly, rather
    than drifting from a second, independently-computed category list. Sorted for a stable,
    reproducible chart order across renders of the same report."""
    return sorted({i["category"] for i in recurring_issues if i.get("category")})


def spike_systems_for_category(recurring_issues: list, category: str) -> list:
    """Distinct systems carrying `category` in `report.recurring_issues` (Persistent+Recurring
    combined) -- "all systems affected" by this one issue type (2026-09-08, on request: "for
    each issue... separate per system linegraphs... for all systems affected"), superseding the
    estate-wide Pareto cut (reports.alert_spikes.pareto_cut_systems) the combined-line version of
    this chart used until now. That cut is a top-80%-of-the-WHOLE-ESTATE's-issue-days set --
    correct for "which systems deserve attention overall", but it could omit a system that's
    genuinely affected by THIS category yet doesn't rank in the estate-wide top 80%, which is
    exactly wrong for a chart whose whole point is now "every affected system, one line each".
    Same category set spike_categories' own columns come from, so a category's chart list here
    always matches the heatmap row set for that column. Sorted for a stable chart order."""
    return sorted({i["system"] for i in recurring_issues
                  if i.get("category") == category})


# cpu/ram/disk are genuinely a PERCENTAGE reading (0-100%, straight off Prometheus) --
# unreachable/service/backup* are a binary up/down STATE with no such reading to plot. Only the
# first group gets resource_percent_series' live line below (2026-09-08, on request: "shouldn't
# it be the percentage reading... wouldn't it be easier to read" than a 0/1/2 concurrent-
# incident count); the rest keep spike_line_data_single/issue_spike_line_single's count-based
# chart, which is the correct measure for a state that has no magnitude to read.
PERCENT_CATEGORIES = {"cpu", "ram", "disk"}


def spike_flag_keys_for_category(recurring_issues: list, category: str) -> list:
    """Distinct (system, flag_key) pairs carrying `category` -- the per-COMPONENT granularity
    resource_percent_series needs (2026-09-08). spike_systems_for_category's plain system list
    isn't fine-grained enough here: a system with two hosts BOTH flagged for the same category
    (e.g. EDMS's DB and App both running high CPU) are two physically different readings, and
    averaging or picking one to represent both would misrepresent whichever host it silently
    dropped -- a COUNT chart can validly sum them into "2 active", but a PERCENTAGE chart cannot
    validly blend two hosts' readings into one line. Sorted for a stable chart order."""
    return sorted({(i["system"], i["flag_key"]) for i in recurring_issues
                  if i.get("category") == category})


def _percent_expr(category: str, instance: str, mount: str | None) -> str | None:
    """The exact PromQL each percentage category is built from, copied verbatim from
    generate_report.capture()'s own instant-query expressions, scoped to one instance (and, for
    disk, one mount) and left range-queryable. `or` between the linux/windows variant picks
    whichever side actually has data for this instance, the same way capture() merges both
    dicts by instance into one already -- no need to know the Component's own `.os` to choose."""
    import generate_report as gr

    if category == "ram":
        return (f'100*(1-node_memory_MemAvailable_bytes{{instance="{instance}"}}'
                f'/node_memory_MemTotal_bytes{{instance="{instance}"}}) '
                f'or 100*(1-windows_memory_physical_free_bytes{{instance="{instance}"}}'
                f'/windows_memory_physical_total_bytes{{instance="{instance}"}})')
    if category == "cpu":
        return ('100 - (avg(rate(node_cpu_seconds_total'
                f'{{instance="{instance}", mode="idle"}}[5m])) * 100) '
                'or 100 - (avg(rate(windows_cpu_time_total'
                f'{{instance="{instance}", mode="idle"}}[5m])) * 100)')
    if category == "disk" and mount:
        return (f'100*(1-node_filesystem_avail_bytes{{{gr._FS}, instance="{instance}", mountpoint="{mount}"}}'
                f'/node_filesystem_size_bytes{{{gr._FS}, instance="{instance}", mountpoint="{mount}"}}) '
                f'or 100*(1-windows_logical_disk_free_bytes{{{gr._VOL}, instance="{instance}", volume="{mount}"}}'
                f'/windows_logical_disk_size_bytes{{{gr._VOL}, instance="{instance}", volume="{mount}"}})')
    return None


def resource_percent_series(system: str, flag_key: str, category: str, days: int = 7) -> dict | None:
    """A system's own historical RAM/CPU/Disk % reading over the window, straight off Prometheus
    (query_range) -- the actual magnitude a percentage-bearing category's Hourly Activity chart
    should show (2026-09-08, on request), not a count of how many distinct incidents were open
    (which for one system+component can only ever read 0 or 1 and says nothing about how bad
    the reading got).

    `flag_key` is generate_report.Flag.key ("ram:{label}" / "cpu:{label}" /
    "disk:{label}:{mount}", the same convention unacknowledged_table already parses) -- used to
    find which Component's instance to query and, for disk, which mount.

    Computed fresh against LIVE Prometheus (services.live_prom_client -- cfg + topology + a
    connected client, without paying for a full metrics capture()). Returns
    {"hours":, "values":, "red": red_threshold_pct} or None -- never raises -- if the category
    isn't a percentage one, the system/component/mount can no longer be found in the current
    topology, or Prometheus can't be reached, so one unreachable chart never breaks the rest of
    the report. `red` is this exact reading's own red threshold (RAM_THRESHOLD_OVERRIDES-aware
    for ram, cfg.chip_red otherwise) -- the same boundary flagged_for_system itself used to
    raise this issue in the first place, so a point crossing it on the chart is marked using the
    identical definition of "red" the rest of this report already uses, not a second,
    independently-chosen one (e.g. the statistical mean+2stdev spike_mask the count-based chart
    uses, which has no meaning for a threshold-defined reading like this)."""
    if category not in PERCENT_CATEGORIES:
        return None
    # maxsplit=2, NOT a plain split(":") -- a Windows drive-letter mount ("D:") carries its OWN
    # colon, which a plain split(":") would itself cut on, truncating "disk:DB:D:" into
    # ["disk","DB","D",""] instead of the intended ["disk","DB","D:"] (confirmed live, 2026-09-08:
    # every Windows disk flag_key ending in a drive letter silently produced no chart until this
    # was maxsplit-limited to stop after the label).
    parts = flag_key.split(":", 2)
    label = parts[1] if len(parts) > 1 else None
    mount = parts[2] if category == "disk" and len(parts) > 2 else None
    if not label or (category == "disk" and not mount):
        return None

    import time as _time

    from . import services

    try:
        import generate_report as gr

        prom, cfg, systems = services.live_prom_client()
        sysm = next((s for s in systems if s.name == system), None)
        comp = next((c for c in sysm.components if c.label == label), None) if sysm else None
        if not comp:
            return None
        expr = _percent_expr(category, comp.instance, mount)
        if not expr:
            return None
        end = _time.time()
        start = end - days * 24 * 3600
        rows = prom.query_range(expr, start, end, "1h")
        red = (gr.ram_thresholds(comp.instance, cfg.chip_amber, cfg.chip_red)[1]
              if category == "ram" else cfg.chip_red)
    except Exception:
        return None
    if not rows or not rows[0]["values"]:
        return None

    import datetime as _dt

    points = rows[0]["values"]
    return {
        "hours": [_dt.datetime.fromtimestamp(t) for t, _v in points],
        "values": [v for _t, v in points],
        "red": red,
    }


def resource_percent_line_data(system: str, flag_key: str, category: str, days: int = 7) -> dict | None:
    """resource_percent_series' own data, shaped for the web view's live Chart.js line chart --
    same {label, color, values, spikes} dataset shape spike_line_data_single already produces,
    so automated_report_download.html's existing Chart.js wiring needs no changes to render
    either kind. `spikes` here means "at/above this reading's own red threshold", not the
    statistical mean+2stdev flag the count-based version uses (see resource_percent_series'
    own docstring for why those two charts need different definitions of "spike")."""
    series = resource_percent_series(system, flag_key, category, days=days)
    if not series:
        return None
    values = series["values"]
    return {
        "labels": [h.strftime("%d %b %H:%M") for h in series["hours"]],
        "datasets": [{"label": system, "color": _BLUE, "values": values,
                     "spikes": [v >= series["red"] for v in values]}],
    }


def resource_percent_chart_single(system: str, flag_key: str, category: str, days: int = 7,
                                  title: str | None = None) -> str | None:
    """resource_percent_series' own PNG for the PDF -- issue_spike_line_single's counterpart for
    a percentage-bearing category (2026-09-08). A dashed line at this reading's own red
    threshold gives the same "how close to the line" read at a glance that the numeric flag
    text already states in words elsewhere in this report."""
    series = resource_percent_series(system, flag_key, category, days=days)
    if not series:
        return None
    hours, values, red = series["hours"], series["values"], series["red"]

    fig, ax = plt.subplots(figsize=(6.6, 2.4))
    xs = range(len(hours))
    ax.plot(xs, values, color=_BLUE, linewidth=1.3)
    spike_idx = [i for i, v in enumerate(values) if v >= red]
    if spike_idx:
        ax.scatter(spike_idx, [values[i] for i in spike_idx], color=_RED, s=22,
                  zorder=5, edgecolors="none")
    ax.axhline(red, color=_RED, linewidth=0.8, linestyle="--", alpha=0.6)

    tick_step = max(1, len(hours) // 10)
    tick_idx = list(range(0, len(hours), tick_step))
    ax.set_xticks(tick_idx)
    ax.set_xticklabels([hours[i].strftime("%d %b\n%H:%M") for i in tick_idx], fontsize=7)
    ax.set_ylabel("%", fontsize=8.5)
    ax.set_ylim(0, 100)
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color(_LINE)
    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color=_INK, loc="left")
    fig.tight_layout()
    return _to_data_uri(fig)


def swift_transaction_series(days: int = 7) -> dict | None:
    """SWIFT message volume (systems_config.yml Temenos readings.swift ->
    swift_transactions_total, the same scalar generate_report.capture() reads for the System
    Admin Report's own AT A GLANCE reading) as an hourly trend over the window -- 2026-09-08,
    on request: "add trend analyses for swift transactions as well... very similar to existing
    line graphs".

    PLOTS THE RAW COUNTER, NOT increase() (2026-09-09, on request, after confirming live: "we
    average around a thousand swift transactions per day, and peaks happen at end of day then
    we go back to 0 on the next day, this doesn't seem to be what the line graph is showing").
    `swift_transactions_total` is T24's own DAILY running total -- it climbs from 0 through the
    business day and is reset to 0 at the next day's first sample (confirmed live: a clean ramp
    0 -> ~800-2000, flat overnight, then straight back to 0) -- not an ever-increasing
    Prometheus counter. An hourly increase()/rate() answers "how many happened in this specific
    hour", which is mostly near-zero outside the morning processing window and never shows the
    "builds up across the day, peaks right before reset" shape the business actually described
    wanting. Plotting the raw value directly reproduces that shape exactly, and needs no
    reset-handling of its own -- the reset back to 0 IS the point being shown.

    Computed fresh against LIVE Prometheus, same as resource_percent_series. Returns
    {"hours":, "values":} or None -- never raises -- if Prometheus can't be reached or the
    metric doesn't exist, so this one chart can't take the rest of the report down with it."""
    import datetime as _dt
    import time as _time

    from . import services

    try:
        prom, cfg, systems = services.live_prom_client()
        end = _time.time()
        start = end - days * 24 * 3600
        rows = prom.query_range("swift_transactions_total", start, end, "1h")
    except Exception:
        return None
    if not rows or not rows[0]["values"]:
        return None

    points = rows[0]["values"]
    return {
        "hours": [_dt.datetime.fromtimestamp(t) for t, _v in points],
        "values": [max(0.0, v) for _t, v in points],
    }


def swift_transaction_line_data(days: int = 7) -> dict | None:
    """swift_transaction_series' own data, shaped for the web view's live Chart.js line chart --
    the same dataset shape resource_percent_line_data/spike_line_data_single already produce, so
    automated_report_download.html's existing Chart.js wiring needs no changes to render this
    too. No spike marking (2026-09-09) -- mean+2stdev over a series that legitimately ramps to a
    daily peak and resets to 0 every single day would flag most of every afternoon as a
    "spike", which isn't a real anomaly, just this metric's normal daily shape."""
    series = swift_transaction_series(days=days)
    if not series:
        return None
    values = series["values"]
    return {
        "labels": [h.strftime("%d %b %H:%M") for h in series["hours"]],
        "datasets": [{"label": "SWIFT", "color": _BLUE, "values": values,
                     "spikes": [False] * len(values)}],
    }


def swift_transaction_chart(days: int = 7, title: str | None = None) -> str | None:
    """swift_transaction_series' own PNG for the PDF -- resource_percent_chart_single's
    counterpart for a throughput metric with no fixed red threshold (see
    swift_transaction_line_data for why there's no spike marking here)."""
    series = swift_transaction_series(days=days)
    if not series:
        return None
    hours, values = series["hours"], series["values"]

    fig, ax = plt.subplots(figsize=(6.6, 2.4))
    xs = range(len(hours))
    ax.plot(xs, values, color=_BLUE, linewidth=1.3)

    tick_step = max(1, len(hours) // 10)
    tick_idx = list(range(0, len(hours), tick_step))
    ax.set_xticks(tick_idx)
    ax.set_xticklabels([hours[i].strftime("%d %b\n%H:%M") for i in tick_idx], fontsize=7)
    ax.set_ylabel("Messages (daily total)", fontsize=8.5)
    ax.set_ylim(bottom=0)
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color(_LINE)
    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color=_INK, loc="left")
    fig.tight_layout()
    return _to_data_uri(fig)


def spike_line_data_single(system: str, category: str, days: int = 7) -> dict | None:
    """One system's own Hourly Activity line, standalone -- issue_spike_lines' old combined,
    one-chart-per-category-with-N-lines shape split one step further (2026-09-08, on request:
    a spike on one system's line no longer has to be visually picked out from every OTHER
    affected system's line sharing the same axes; each system gets its own chart under its
    issue's own heading instead). Returns None if this system had zero incidents of this
    category in the window -- see report_charts.spike_systems_for_category for the caller-side
    loop that already only asks for systems known to have this category at all, so this should
    be rare in practice, not the common case."""
    from . import alert_spikes

    data = alert_spikes.hourly_alert_series([system], days=days, category=category)
    hours = data["hours"]
    values = data["series"][system]
    if not any(values):
        return None
    mask = alert_spikes.spike_mask(values)
    return {
        "labels": [h.strftime("%d %b %H:%M") for h in hours],
        "datasets": [{"label": system, "color": _BLUE, "values": values, "spikes": mask}],
    }


def issue_occurrence_heatmap(systems: list,
                             title: str = "Issue occurrence across all systems") -> str | None:
    """Every system x every issue type as one grid, shaded by occurrence count -- readable as
    a ROW scan ("what's wrong with web-app-01, and how much of it") or a COLUMN scan ("which
    systems actually have High CPU, and how badly"), which N separate per-system tables or bar
    charts can't offer side by side.

    `systems` is [{"system": name, "issues": {issue_type: count, ...}}, ...]. Issue types are
    collected from the data itself, not hardcoded -- `sorted({k for s in systems for k in
    s["issues"]})` -- so a newly-introduced category becomes a new column automatically, the
    same "generalised, not per-item" principle the rest of this module already follows. A
    system missing a given issue type entirely is treated as 0 for that cell, same as an
    explicit 0 -- see below.

    Every (system, issue type) PAIR gets a cell, including 0s -- a system with no High CPU
    flags still shows a "0" cell, not a gap. Silently omitting zero cells would make "no
    problem" and "no data" look identical, which is exactly the ambiguity the rest of this
    report is careful to avoid (compare estate_health_donut's own reasoning for why "Healthy"
    is stated outright rather than left as an absence).

    Shading is a single continuous ramp (_HEATMAP_CMAP, white -> amber -> red -- a literal
    heat gradient, cool/pale to hot), unlike the same red/amber elsewhere in this module, which
    mark a binary KNOWN-bad verdict at a fixed threshold. Here there's no such threshold -- a
    cell just gets warmer as its own count rises relative to this chart's own data, it isn't
    asserting that a high count is a confirmed problem the way a red worst_band does elsewhere.
    The scale is relative to THIS chart's own data (0..max observed count),
    recomputed every render -- a fixed absolute scale would wash out an all-quiet week (every
    cell reading pale even though it's the highest count that week actually has) or blow out a
    single outlier month.

    Each cell's printed number switches between white and the module's dark ink colour based
    on the actual rendered cell colour's luminance, not a fixed threshold on the raw count --
    shading is relative to the data (see above), so a fixed count threshold for text colour
    would pick the wrong contrast whenever the data's own range changes."""
    systems = [s for s in systems if s.get("issues")]
    if not systems:
        return None

    issue_types = sorted({k for s in systems for k in s["issues"]})
    names = [s["system"] for s in systems]
    matrix = [[s["issues"].get(t, 0) for t in issue_types] for s in systems]

    n_rows, n_cols = len(names), len(issue_types)
    # Scales with the data on both axes -- more systems add rows (taller figure), more issue
    # types add columns (wider figure), no fixed grid size to redesign around.
    fig_w = max(7.5, 0.95 * n_cols + 3.2)
    fig_h = max(2.8, 0.42 * n_rows + 2.2)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))

    flat = [v for row in matrix for v in row]
    vmax = max(flat) if flat and max(flat) > 0 else 1
    norm = Normalize(vmin=0, vmax=vmax)
    im = ax.imshow(matrix, cmap=_HEATMAP_CMAP, norm=norm, aspect="auto")

    ax.set_xticks(range(n_cols))
    # Rotated and anchored at its own bottom-left corner (nearest the column, since ticks sit
    # on TOP) -- long, now-doubled-up labels ("High Disk · Persistent" next to "High Disk ·
    # Recurring") would collide with their neighbours if printed flat; tilting shrinks each
    # label's horizontal footprint far more than widening the figure alone could.
    ax.set_xticklabels(issue_types, fontsize=8.5, rotation=40, ha="left", rotation_mode="anchor")
    ax.xaxis.set_ticks_position("top")
    ax.xaxis.set_label_position("top")
    ax.tick_params(axis="x", length=0)

    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(names, fontsize=8.5)
    ax.tick_params(axis="y", length=0)

    # Thin gridlines between cells, on minor ticks offset a half-cell from the labelled major
    # ticks -- distinct from cell shading (this module's own _LINE colour, used for every other
    # axis border/spine) rather than relying on shading contrast alone to separate cells.
    ax.set_xticks([x - 0.5 for x in range(n_cols + 1)], minor=True)
    ax.set_yticks([y - 0.5 for y in range(n_rows + 1)], minor=True)
    ax.grid(which="minor", color=_LINE, linewidth=1)
    ax.tick_params(which="minor", length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)

    for i in range(n_rows):
        for j in range(n_cols):
            v = matrix[i][j]
            r, g, b, _a = im.cmap(norm(v))
            luminance = 0.299 * r + 0.587 * g + 0.114 * b
            text_color = "#FFFFFF" if luminance < 0.5 else _INK
            ax.text(j, i, str(v), ha="center", va="center", fontsize=8.5,
                    color=text_color, fontweight="bold")

    # Positioned off the right edge (fraction/pad below) so it never crowds the row labels,
    # which sit on the left.
    cbar = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02)
    cbar.ax.tick_params(labelsize=7.5, length=0)
    cbar.outline.set_visible(False)

    # Column labels already sit above the grid (xaxis moved to "top" above) -- the title needs
    # enough clearance above THAT, not just above the axes, or the two collide.
    fig.suptitle(title, fontsize=10.5, fontweight="bold", color=_INK, y=1.05)
    fig.tight_layout()
    return _to_data_uri(fig)


def heatmap_grid(systems: list) -> dict | None:
    """issue_occurrence_heatmap's own data, shaped for a server-rendered HTML <table> instead
    of a static PNG -- the web view's interactive counterpart (2026-09-07, on request: hovering
    a cell should show a description, and the page should animate in the way the rest of this
    report's live Chart.js canvases already do; a PNG can do neither). Same colour ramp, same
    luminance-based text contrast, same relative-to-this-chart's-own-data scale as the
    matplotlib version -- only the OUTPUT shape differs, not the visual logic.

    Returns {"columns": [...], "rows": [{"system":, "cells": [{"value":, "bg":, "color":,
    "tooltip":}, ...]}]} -- everything the template needs to print the grid directly, with no
    further computation or a second source of truth for what a cell's colour means."""
    systems = [s for s in systems if s.get("issues")]
    if not systems:
        return None

    issue_types = sorted({k for s in systems for k in s["issues"]})
    flat = [s["issues"].get(t, 0) for s in systems for t in issue_types]
    vmax = max(flat) if flat and max(flat) > 0 else 1
    norm = Normalize(vmin=0, vmax=vmax)

    rows = []
    for s in systems:
        cells = []
        for t in issue_types:
            v = s["issues"].get(t, 0)
            r, g, b, _a = _HEATMAP_CMAP(norm(v))
            bg = "#{:02x}{:02x}{:02x}".format(round(r * 255), round(g * 255), round(b * 255))
            luminance = 0.299 * r + 0.587 * g + 0.114 * b
            color = "#FFFFFF" if luminance < 0.5 else _INK
            cells.append({"value": v, "bg": bg, "color": color,
                         "tooltip": f"{s['system']} — {t}: {v} day{'s' if v != 1 else ''}"})
        rows.append({"system": s["system"], "cells": cells})
    return {"columns": issue_types, "rows": rows}


# reports.trend_classification.Flag/FlagVM category values -> the issue-type column labels
# issue_occurrence_heatmap shows. New categories fall back to a title-cased version of the raw
# key (see issue_occurrence_matrix) rather than being dropped, so an uncatalogued category
# still gets a readable column instead of silently vanishing from the grid.
_CATEGORY_LABELS = {
    "cpu": "High CPU", "ram": "High RAM", "disk": "High Disk",
    "unreachable": "Unreachable", "service": "Service Down", "backup": "Missing Backup",
}


# A separate, bare-noun mapping from _CATEGORY_LABELS above -- that one reads correctly as a
# HEATMAP COLUMN header ("High Disk" = a count of days this ran high), but repeating "High" in
# a table row that already names the specific finding ("Resource Type: Disk", "Location:
# Application:/") would be redundant, not descriptive. unacknowledged_table below is the one
# consumer; kept separate rather than stripping "High " out of _CATEGORY_LABELS at render time
# so neither mapping has to know about the other's phrasing.
_RESOURCE_TYPE_LABELS = {
    "cpu": "CPU", "ram": "RAM", "disk": "Disk",
    "unreachable": "Unreachable", "service": "Service", "backup": "Backup",
}


def resource_type_label(category: str) -> str:
    """Public wrapper around _RESOURCE_TYPE_LABELS -- used both by unacknowledged_table below
    and by the per-category Hourly Activity chart titles (2026-09-07, "split it per issue"),
    so a category reads the same bare-noun way ("RAM", not "High RAM") everywhere it's named
    outside a heatmap column header."""
    return _RESOURCE_TYPE_LABELS.get(category, category.replace("_", " ").title())


def flag_location(flag_key: str) -> str:
    """Whatever follows the category in a flag_key (generate_report.Flag.key is always
    "category:..." or "category:sub:...") -- the specific component/mount/service the bare
    category alone doesn't name, e.g. "disk:Application:/" -> "Application:/". Shared by
    unacknowledged_table's own "location" column and the per-component Hourly Activity chart
    titles below (resource_percent_series' callers) -- both need the identical parse."""
    return flag_key.split(":", 1)[1] if ":" in flag_key else flag_key


def issue_occurrence_matrix(system_attention: list) -> list:
    """`report.system_attention` (already-serialized SystemAttention rows, each carrying its
    own Persistent/Recurring IssueClassification dicts) reshaped into
    issue_occurrence_heatmap's own [{"system":, "issues": {type: count}}] input -- same
    Persistent+Recurring scope system_attention_bar already charts, just broken down by issue
    type instead of collapsed to one total per system.

    Per-cell count is DISTINCT DAYS (_issue_to_dict's own `distinct_days`), not a raw per-
    scrape hit count -- this report never keeps the latter (see trend_classification's module
    docstring: distinct calendar days, not run count, is the deliberate measure throughout this
    whole report, precisely because raw run count varies with how often someone happens to
    click "generate" that day). Using the same measure here keeps this chart's numbers
    consistent with the Days column already printed in the per-classification tables below it,
    rather than introducing a second, differently-counted "occurrences" figure that would
    disagree with it.

    Deliberately does NOT fold Persistent/Recurring into the column label (an earlier version
    did, e.g. "High Disk · Persistent"/"High Disk · Recurring" as separate columns in one
    combined chart): a raw distinct-days COUNT can't distinguish the two anyway -- 40 days out
    of a 50-day span (Persistent, 80% coverage) and 40 days out of a 200-day span (Recurring,
    20% coverage) both show "40" -- so a viewer could not actually intuit persistence from a
    combined grid regardless of the column split; confirmed and agreed 2026-09-07. Persistent
    and Recurring get their own SEPARATE charts instead (persistent_issue_matrix/
    recurring_issue_matrix below), each answering one question at a time."""
    out = []
    for row in system_attention:
        counts: dict = {}
        for i in row.get("issues", []):
            label = _CATEGORY_LABELS.get(i["category"], i["category"].replace("_", " ").title())
            counts[label] = counts.get(label, 0) + i["distinct_days"]
        out.append({"system": row["system"], "issues": counts})
    return out


def _issue_matrix_for_label(recurring_issues: list, label: str) -> list:
    by_system: dict = {}
    for i in recurring_issues:
        if i.get("label") == label:
            by_system.setdefault(i["system"], []).append(i)
    return issue_occurrence_matrix(
        [{"system": s, "issues": issues} for s, issues in by_system.items()])


def persistent_issue_matrix(recurring_issues: list) -> list:
    """issue_occurrence_matrix's own input shape, filtered to Persistent only (trend_
    classification.PERSISTENT: 70%+ day-coverage across its own span -- "never really clears").
    `label` is the exact string automated_reports._issue_to_dict serializes it as."""
    return _issue_matrix_for_label(recurring_issues, "Persistent")


def recurring_issue_matrix(recurring_issues: list) -> list:
    """persistent_issue_matrix's own Recurring-only counterpart (trend_classification.
    RECURRING: the same 3+ distinct-day minimum, but BELOW 70% coverage -- "comes and goes").
    Note this takes `report.recurring_issues`, the FLAT Persistent+Recurring pool
    (_system_attention_rows' own source), then filters down to Recurring here -- despite the
    parameter's name matching the wider pool it comes from, not the narrower thing this
    function returns."""
    return _issue_matrix_for_label(recurring_issues, "Recurring")


def issue_spike_line_single(system: str, category: str, days: int = 7,
                            title: str | None = None) -> str | None:
    """One system's own Hourly Activity line, standalone -- the PNG/PDF counterpart of
    spike_line_data_single (see its own docstring for why this replaced the old one-chart-
    per-category-with-every-affected-system's-line-on-it shape, 2026-09-08). A static PNG like
    every other chart in this module, not the live/interactive Chart.js version the web page
    uses -- matching this report's own convention (the heatmaps above are static images too)
    rather than keeping a second, differently-styled widget.

    Backed by reports.models.IssueOccurrence (see that model's own docstring), NOT this
    report's own recurring_issues/heatmap data -- that comes from report-GENERATION events
    (irregular, sparse at hourly resolution), this from a dedicated incident log written every
    5-minute alert-poller cycle. Computed fresh at render time (unlike every other chart in
    this module, which takes already-serialized `content` data) because it answers a live
    question -- "what's active right now" -- that a stored report snapshot from whenever it was
    generated can't retroactively answer.

    Returns None if this system had zero incidents of this category in the window."""
    from . import alert_spikes

    data = alert_spikes.hourly_alert_series([system], days=days, category=category)
    hours = data["hours"]
    values = data["series"][system]
    if not any(values):
        return None
    mask = alert_spikes.spike_mask(values)

    fig, ax = plt.subplots(figsize=(6.6, 2.4))
    xs = range(len(hours))
    ax.plot(xs, values, color=_BLUE, linewidth=1.3)
    spike_idx = [i for i, m in enumerate(mask) if m]
    if spike_idx:
        ax.scatter(spike_idx, [values[i] for i in spike_idx], color=_RED, s=22,
                  zorder=5, edgecolors="none")

    tick_step = max(1, len(hours) // 10)
    tick_idx = list(range(0, len(hours), tick_step))
    ax.set_xticks(tick_idx)
    ax.set_xticklabels([hours[i].strftime("%d %b\n%H:%M") for i in tick_idx], fontsize=7)
    ax.set_ylabel("Issues active", fontsize=8.5)
    ax.set_ylim(bottom=0)
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color(_LINE)
    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color=_INK, loc="left")
    fig.tight_layout()
    return _to_data_uri(fig)


def chart_data_json(content: dict, persistent_count: int, recurring_count: int,
                    total_systems: int = 0) -> dict:
    """Raw {labels, values, colors} structures for the Chart.js web view -- the browser-side
    counterpart to the matplotlib functions above, which render the same shapes as static
    PNGs for the PDF instead. Colours travel as literal hex here too (rather than letting
    Chart.js read CSS variables per-series) so a system's colour is decided by its
    worst_band/label the same way in both renderings; only truly page-wide styling (fonts,
    default text colour) is pulled from CSS custom properties in the page's own script."""
    donut_pairs = [(l, v, c) for l, v, c in
                  [("Persistent", persistent_count, _RED), ("Recurring", recurring_count, _AMBER),
                   ("Potential fluke", len(content.get("anomalies", [])), _BLUE),
                   ("One-off", len(content.get("one_off_issues", [])), _BLUE_SOFT)]
                  if v > 0]
    attention_rows = content.get("system_attention", [])
    red_systems = sum(1 for r in attention_rows if r["worst_band"] == "red")
    amber_systems = len(attention_rows) - red_systems
    healthy_systems = max(0, total_systems - len(attention_rows))
    attention_rows = attention_rows[:12]
    themes = content.get("themes", [])[:10]
    return {
        "donut": {
            "labels": [l for l, _v, _c in donut_pairs],
            "values": [v for _l, v, _c in donut_pairs],
            "colors": [c for _l, _v, c in donut_pairs],
        },
        "estateHealth": {
            "labels": ["Healthy", "Warning", "Requires attention"],
            "values": [healthy_systems, amber_systems, red_systems],
            "colors": [_GREEN, _AMBER, _RED],
        } if total_systems else None,
        # Stacked (persistent + recurring, 2026-09-10, item 10) -- same two-series shape
        # system_attention_bar's own matplotlib PNG uses, so the web chart and the PDF/email
        # chart never disagree about which portion of a system's total is which label.
        "attention": {
            "labels": [r["system"] for r in attention_rows],
            "persistent": [r["persistent_count"] for r in attention_rows],
            "recurring": [r["recurring_count"] for r in attention_rows],
        },
        "themes": {
            "labels": [t["label"] for t in themes][::-1],
            "values": [t["count"] for t in themes][::-1],
        },
    }

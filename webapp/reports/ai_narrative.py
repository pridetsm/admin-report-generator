"""AI narrative provider for the Automated Reports engine (Phase 4, sections 12-15 of the
spec "New Promt.txt": "so what" framing, fact/hypothesis distinction, confidence-graded
prose) -- the parts of the spec that need real judgment on unstructured text, which pure
occurrence-counting code (reports.trend_classification) cannot do.

TWO-PRONGED, on request (2026-09-07): a report ALWAYS generates, whatever happens to the AI
call. If the configured provider is unreachable, unconfigured, or errors for ANY reason
(missing key, network failure, auth failure, rate limit, a malformed response), the pipeline
falls back to OfflineNarrativeProvider rather than failing the report -- and the report
records which provider actually ran (see run_narrative's own NarrativeResult), so nobody
mistakes a statistics-only fallback for a genuine AI-reviewed report.

Providers:
  AnthropicNarrativeProvider -- real, working implementation (the `anthropic` SDK), used for
      the evaluation/reference report while the company sets up its own Copilot access.
  CopilotNarrativeProvider -- a RESERVED SLOT, not a working integration. Microsoft 365
      Copilot has no simple universal chat-completion REST endpoint the way Anthropic/OpenAI
      do -- it's normally reached through Graph API extensions or Copilot Studio, which needs
      real product-specific wiring once the company's own API access exists (they hold a 365
      licence but no API key yet, per the same request). Selecting "copilot" today always
      raises NotImplementedProvider, caught by run_narrative and treated exactly like any
      other provider failure -- report still generates, flagged offline.
  OfflineNarrativeProvider -- always succeeds, deterministic, no network call. Does not use an
      LLM, but is not a bare restatement of counts either: it runs the fixed, literature-
      grounded heuristics in reports.offline_insights (Pareto concentration, root-cause
      fan-in, stale-acknowledgement detection, unacknowledged-persistence, coincident onset,
      category concentration) against the same classified evidence an AI provider would see.
      Same input always produces the same output (explicit instruction, 2026-09-07: the
      offline report "can't just be completely devoid of any valuable insights").
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional


class NotImplementedProvider(Exception):
    """Raised by a provider with no working implementation yet (Copilot today) -- caught by
    run_narrative exactly like a real network/auth failure."""


NARRATIVE_SECTION_KEYS = [
    "executive_summary", "overall_trend", "key_trends", "administrator_observations",
    "emerging_risks", "operational_inefficiencies", "management_recommendations",
    "decisions_supported", "further_investigation", "conclusion",
]

# Section 12's own headings, for the 10 keys that are narrative PROSE -- the other 3 headings
# in section 12 (Recurring Issues, System Areas Requiring Attention, Potential Anomalies) are
# TABLES built directly from reports.trend_classification data, not narrative text, so they
# aren't part of this dict; templates render them from AutomatedReport's own list fields.
NARRATIVE_SECTION_LABELS = {
    "executive_summary": "Executive Summary",
    "overall_trend": "Overall Environment Trend",
    "key_trends": "Key Trends",
    "administrator_observations": "Administrator Observations",
    "emerging_risks": "Emerging Risks",
    "operational_inefficiencies": "Operational Inefficiencies",
    "management_recommendations": "Management Recommendations",
    "decisions_supported": "Decisions Supported by the Data",
    "further_investigation": "Areas Requiring Further Investigation",
    "conclusion": "Conclusion",
}


#: This narrative key's position in section 12's FULL numbering, which also counts the 3
#: table sections (04 Recurring Issues, 06 System Areas Requiring Attention, 08 Potential
#: Anomalies) interleaved between the prose ones -- so these numbers are not consecutive.
NARRATIVE_SECTION_NUMBERS = {
    "executive_summary": "01", "overall_trend": "02", "key_trends": "03",
    "administrator_observations": "05", "emerging_risks": "07",
    "operational_inefficiencies": "09", "management_recommendations": "10",
    "decisions_supported": "11", "further_investigation": "12", "conclusion": "13",
}


def narrative_sections(narrative: dict) -> list:
    """[{"key", "label", "text", "bits", "num"}, ...] in section-12 order -- what the detail/
    e-mail/download templates iterate over, so no template needs a dynamic dict-key-by-variable
    lookup (Django templates can't do `dict.key_from_a_loop_variable` without a custom filter).

    `bits` is `text` split on "\\n" -- one entry per idea/finding, for the templates' own
    bulleted-list rendering (2026-09-07, on request: terse bullet points, one idea per line,
    not a flowing paragraph). `text` itself is kept too, unsplit, for any consumer that still
    wants one flowing string (e.g. a plain-text e-mail body)."""
    return [{"key": k, "label": NARRATIVE_SECTION_LABELS[k], "text": narrative.get(k, ""),
            "bits": (narrative.get(k, "") or "").split("\n"),
            "num": NARRATIVE_SECTION_NUMBERS[k]} for k in NARRATIVE_SECTION_KEYS]


@dataclass
class NarrativeResult:
    provider: str                    # "anthropic" | "copilot" | "offline" -- whichever actually ran
    sections: dict                   # {section_key: prose string}, every NARRATIVE_SECTION_KEYS present
    requested_provider: str          # what SystemConfig asked for, even if it didn't end up running
    error: Optional[str] = None      # set when the requested provider failed and this is the fallback


REPORT_TYPE_FRAMING = {
    "quarterly_summary": (
        "This is the Quarterly Management Summary -- the audience is non-technical "
        "management, not engineers. Avoid jargon and statistical terminology; write in "
        "plain business language focused on impact, risk, and cost, not mechanism."),
    "admin_observations": (
        "This is the Administrator Observations Digest -- focus primarily on the comment "
        "THEMES provided below (not the raw issue list), correlate them with the monitoring "
        "data, and explicitly separate operational-process patterns (e.g. close-of-business "
        "processing, manual intervention, backup-policy timing) from genuine infrastructure "
        "patterns (network, database, capacity)."),
    "anomaly_log": (
        "This is the Anomaly / Fluke Log -- informational only, not an alarm. Its purpose is "
        "to record what was investigated and ruled out as noise so that history isn't lost, "
        "not to demand action. Use a calm, neutral tone; do not use urgent or alarmed "
        "language even for red-band items, since everything here has already been assessed "
        "as likely noise."),
    "monthly_recurring": (
        "This is the Monthly Recurring Issues Report -- the primary input for "
        "prioritisation decisions, so rank and discuss issues by frequency + duration + "
        "severity + persistence together, not by any single one of those alone."),
    "system_attention": (
        "This is the System Attention Report -- a live, continuously-updated view. Focus on "
        "which systems currently warrant attention and why, not on historical trend framing."),
}


class NarrativeProvider:
    name = "base"

    def generate(self, *, issues: list, window_days: int, report_type: str = "weekly_trend",
                themes: list | None = None, totals_anomalies: list | None = None,
                action_unset_count: int = 0) -> dict:
        """issues: list[reports.trend_classification.IssueClassification], already ranked.
        themes: reports.comment_themes.theme_digest() output, populated only for
        report_type == "admin_observations". totals_anomalies: reports.totals_integrity
        output (JSON-safe dicts), populated for every report_type.
        Returns {section_key: prose string} for every key in NARRATIVE_SECTION_KEYS."""
        raise NotImplementedError


class OfflineNarrativeProvider(NarrativeProvider):
    """No network call, cannot fail -- the guaranteed floor every report can fall back to."""
    name = "offline"

    def generate(self, *, issues: list, window_days: int, report_type: str = "weekly_trend",
                themes: list | None = None, totals_anomalies: list | None = None,
                action_unset_count: int = 0) -> dict:
        from .trend_classification import BORDERLINE, ONE_OFF, PERSISTENT, RECURRING
        from . import offline_insights as oi

        themes = themes or []
        totals_anomalies = totals_anomalies or []
        plain = report_type == "quarterly_summary"    # drop literature jargon for management

        by_label: dict = {}
        for i in issues:
            by_label.setdefault(i.label, []).append(i)
        emerging = [i for i in issues if i.emerging]
        commented = [i for i in issues if i.comments]

        def _list(items, n=5):
            return "; ".join(f"{i.system} {i.flag_key}" for i in items[:n]) or "none in this window"

        def _names(names, n=5):
            names = list(names)
            return ", ".join(names[:n]) + (" …" if len(names) > n else "")

        def _totals_bits(totals_anomalies):
            bits = []
            for t in totals_anomalies[:4]:
                bits.append(
                    f"'{t['label']}' moved non-monotonically this window ({t['occurrences']} "
                    f"decrease(s) observed, e.g. {t['example_drop']['from']} → "
                    f"{t['example_drop']['to']}) — worth investigating, though a legitimate "
                    f"cause (a host decommissioned, a certificate renewed) is equally "
                    f"possible; see the totals-anomaly evidence for the full series.")
            return bits

        pareto = oi.pareto_concentration(issues)
        fanin = oi.root_cause_fanin(issues)
        stale = oi.stale_acknowledgements(issues)
        unacked = oi.unacknowledged_persistent(issues)
        coincident = oi.coincident_onsets(issues)
        cat_conc = oi.category_concentration(issues)

        # Every *_bits list below is joined with "\n", not " " (2026-09-07, on request: the
        # report's narrative sections should render as terse bullet points, one idea per line,
        # not a flowing paragraph -- the same shape each finding was already built in, one bit
        # per distinct fact/recommendation, just previously flattened into one run-on sentence
        # at the last step). narrative_sections() (this module) and the two report templates
        # split back on "\n" to build the bulleted list. An older stored report's narrative
        # (space-joined, from before this change) has no "\n" in it, so it still degrades
        # gracefully to one single bullet -- never a crash, never a rendering change forced
        # retroactively onto history already saved.
        exec_bits = [
            f"{len(issues)} distinct issues were observed in the last {window_days} days: "
            f"{len(by_label.get(PERSISTENT, []))} persistent, "
            f"{len(by_label.get(RECURRING, []))} recurring, "
            f"{len(by_label.get(BORDERLINE, []))} potential flukes, "
            f"{len(by_label.get(ONE_OFF, []))} one-off."]
        if pareto:
            top_systems, share = pareto
            concentration_phrase = "" if plain else " (a Pareto concentration)"
            exec_bits.append(
                f"{len(top_systems)} of {len({i.system for i in issues})} systems "
                f"({_names(top_systems)}) account for {share * 100:.0f}% of active "
                f"(persistent/recurring) issues{concentration_phrase} — worth prioritising "
                f"over treating every issue as equally urgent.")
        if report_type == "anomaly_log":
            exec_bits.append(
                "This log is informational: everything below has already been assessed as "
                "likely noise, and nothing here requires immediate action unless a pattern "
                "recurs.")
        # No offline/AI-availability disclosure bullet here (2026-09-08, on request: "remove
        # any mention of AI in these reports if AI assistance is disabled") -- when this
        # provider is the one running, AI is by definition not in use, so the report simply
        # presents its findings without narrating its own narrative-generation mechanism.
        executive_summary = "\n".join(exec_bits)

        trend_bits = []
        if cat_conc:
            category, share = cat_conc
            trend_bits.append(
                f"Active issues are concentrated in the '{category}' category "
                f"({share * 100:.0f}% of persistent/recurring load), indicating the dominant "
                f"strain this window is a capacity/resource-type pattern rather than "
                f"scattered, unrelated faults.")
        if fanin:
            trend_bits.append(
                f"{len(fanin)} system(s) ({_names(fanin.keys())}) each show "
                f"{oi.FANIN_MIN_METRICS}+ distinct metrics simultaneously active, consistent "
                f"with a single shared host-level cause rather than independent per-metric "
                f"issues.")
        if themes:
            process_n = sum(t["count"] for t in themes if t["kind"] == "process")
            infra_n = sum(t["count"] for t in themes if t["kind"] == "infrastructure")
            top = themes[0]
            trend_bits.append(
                f"Across {process_n + infra_n} theme-tagged comment(s), {process_n} describe "
                f"operational-process patterns (close-of-business, manual intervention, "
                f"backup-policy timing) and {infra_n} describe infrastructure conditions "
                f"(network, database, capacity) — the most common single theme is "
                f"'{top['label']}' ({top['count']} mention(s) across {_names(top['systems'])}).")
        overall_trend = "\n".join(trend_bits) if trend_bits else (
            "No dominant concentration pattern was detected this window; active issues are "
            "spread across systems and categories without a single common driver.")

        # 2026-09-10, item 7: this section used to just re-list the top 5 rows §04's own
        # Persistent table already shows. Keeps the "which issues" list (still useful context)
        # but adds the one number that ISN'T already tabulated anywhere -- what share of the
        # window's total persistent/recurring day-coverage those 5 findings alone represent.
        pr_issues = by_label.get(PERSISTENT, []) + by_label.get(RECURRING, [])
        total_pr_days = sum(i.distinct_days for i in pr_issues)
        top5_days = sum(i.distinct_days for i in issues[:5])
        if total_pr_days and top5_days:
            key_trends = (
                f"The 5 highest-significance issues this period ({_list(issues)}) account for "
                f"{top5_days / total_pr_days * 100:.0f}% of this window's total "
                f"persistent/recurring day-coverage — a small handful of findings represent a "
                f"disproportionate share of the window's actual issue-days.")
        else:
            key_trends = f"Highest-significance issues this period: {_list(issues)}."

        obs_bits = [(
            f"{len(commented)} of {len(issues)} issues have at least one administrator "
            f"comment on record; see the Recurring Issues table for the exact text.")
            if commented else
            "No administrator comments were recorded against any issue in this window."]
        if stale:
            deviance_phrase = "" if plain else " ('normalization of deviance')"
            obs_bits.append(
                f"{len(stale)} issue(s) ({_names(f'{i.system} {i.flag_key}' for i in stale)}) "
                f"show the same administrator comment repeated near-verbatim across their "
                f"last {oi.STALE_COMMENT_MIN}+ occurrences while the condition remains "
                f"active — worth distinguishing from genuine resolution progress"
                f"{deviance_phrase}.")
        if themes:
            for t in themes[:5]:
                examples = "; ".join(f"{e['system']}: \"{e['quote']}\"" for e in t["examples"][:2])
                obs_bits.append(
                    f"Theme '{t['label']}' ({t['kind']}): {t['count']} comment(s) across "
                    f"{_names(t['systems'])} — e.g. {examples}.")
        administrator_observations = "\n".join(obs_bits)

        risk_bits = [f"Flagged as emerging (accelerating recently): {_list(emerging)}."]
        for day, systems in coincident:
            risk_bits.append(
                f"{len(systems)} systems ({_names(systems)}) had new issues first appear "
                f"within {oi.COINCIDENT_WINDOW_DAYS} days of each other starting "
                f"{day.isoformat()} — worth checking for a shared dependency (power, "
                f"network, hypervisor) before treating these as unrelated.")
        totals_bits = _totals_bits(totals_anomalies)
        if totals_bits:
            risk_bits.append(
                f"{len(totals_anomalies)} aggregate total(s) moved non-monotonically this "
                f"window (see Areas Requiring Further Investigation for detail).")
        emerging_risks = "\n".join(risk_bits)

        ineff_bits = []
        # 2026-09-10, item 10a: this bullet now counts the SAME population the highlighted
        # rows in §04's own Persistent/Recurring tables show (no Fix needed?/Resolved ever
        # recorded), not the older, separate "zero admin comments" signal -- the standalone
        # table this used to reference has been retired entirely (see that item's own note:
        # "don't build a separate table... let §09's text become a one-line summary count
        # referencing those highlighted rows").
        if action_unset_count:
            ineff_bits.append(
                f"{action_unset_count} persistent/recurring issue(s) have no Fix needed?/"
                f"Resolved status recorded yet — see the highlighted rows in the "
                f"Persistent/Recurring tables above (§04). A triage gap under standard "
                f"alerting-hygiene practice (every active issue should have a recorded "
                f"owner/response).")
        if stale:
            ineff_bits.append(
                "See Administrator Observations for issues whose commentary has not changed "
                "across repeated occurrences.")
        operational_inefficiencies = "\n".join(ineff_bits) if ineff_bits else (
            "No unrecorded Fix needed?/Resolved status or stale-comment patterns were "
            "detected this window.")

        rec_bits = []
        if report_type == "anomaly_log":
            rec_bits.append(
                "No action is recommended from this log by default — items are listed for "
                "reference. Revisit a specific item only if it stops being a one-off/fluke "
                "and starts recurring in a future window.")
        else:
            for system, items in list(fanin.items())[:3]:
                rec_bits.append(
                    f"Prioritise {system} for a consolidated review covering "
                    f"{_names(i.flag_key for i in items)} together, since these metrics are "
                    f"simultaneously active and more likely share one root cause than "
                    f"requiring separate fixes.")
            if unacked:
                rec_bits.append(
                    f"Assign an owner and record an initial response for the {len(unacked)} "
                    f"currently-uncommented persistent/recurring issue(s).")
            if pareto:
                # Cross-reference §01, don't restate the same system list/share a second time
                # (2026-09-10, item 6: "keep the claim in one place... reference it rather than
                # restate the list").
                rec_bits.append(
                    "Direct capacity-remediation effort at the concentration named in the "
                    "Executive Summary (§01) first — it accounts for the bulk of this "
                    "window's active issues.")
        management_recommendations = "\n".join(rec_bits) if rec_bits else (
            "No concentration, fan-in, or acknowledgement-gap pattern reached the threshold "
            "for a targeted recommendation this window.")

        decisions_supported = (
            "This analysis supports prioritisation of capacity/remediation effort toward the "
            "systems and categories identified above as concentrated or fan-in root-cause "
            "candidates, and supports a triage-process review for any issues flagged as "
            "unacknowledged or subject to stale, repeated commentary.")

        further_bits = []
        if coincident:
            further_bits.append(
                "Confirm whether the coincident-onset cluster(s) above share an "
                "infrastructure dependency.")
        if stale:
            further_bits.append(
                "Follow up directly on issues with stale/repeated commentary to confirm "
                "whether remediation is actually progressing.")
        if unacked:
            further_bits.append(
                "Establish whether the unacknowledged persistent issues above have been "
                "triaged at all.")
        further_bits.extend(totals_bits)
        further_investigation = "\n".join(further_bits) if further_bits else (
            "No specific follow-up items were flagged by the deterministic checks this "
            "window.")

        conclusion = (
            f"Over the {window_days}-day window, {len(by_label.get(PERSISTENT, []))} issues "
            f"were persistent and {len(by_label.get(RECURRING, []))} recurring. "
            + (f"'{cat_conc[0]}' was the dominant active category ({cat_conc[1] * 100:.0f}%). "
               if cat_conc else "")
            + (f"{len(fanin)} system(s) show multi-metric fan-in worth a consolidated "
               f"review. " if fanin else "")
            + (f"{len(stale)} issue(s) show stale/repeated commentary. " if stale else "")
            + (f"{len(unacked)} issue(s) are unacknowledged. " if unacked else "")
            + (f"{len(totals_anomalies)} aggregate total(s) moved non-monotonically. "
               if totals_anomalies else ""))

        return {
            "executive_summary": executive_summary,
            "overall_trend": overall_trend,
            "key_trends": key_trends,
            "administrator_observations": administrator_observations,
            "emerging_risks": emerging_risks,
            "operational_inefficiencies": operational_inefficiencies,
            "management_recommendations": management_recommendations,
            "decisions_supported": decisions_supported,
            "further_investigation": further_investigation,
            "conclusion": conclusion,
        }


def _issues_payload(issues: list) -> list:
    """The evidence handed to the LLM -- exactly what a human analyst would look at: the
    classification, the evidence behind it, and the real admin commentary. Nothing here is
    invented; the model only ever sees what actually happened. Capped to the top-ranked 40
    issues so the prompt stays a bounded size regardless of how noisy a given window is."""
    out = []
    for i in issues[:40]:
        out.append({
            "system": i.system, "flag_key": i.flag_key, "category": i.category,
            "latest_text": i.latest_text, "label": i.label, "confidence": i.confidence,
            "emerging": i.emerging, "distinct_days": i.distinct_days,
            "span_days": i.span_days, "coverage": i.coverage,
            "first_seen": str(i.first_seen), "last_seen": str(i.last_seen),
            "worst_band": i.worst_band,
            "admin_comments": [c for _dt, c in i.comments[-3:]],
        })
    return out


def _build_prompt(payload: list, window_days: int, *, report_type: str = "weekly_trend",
                  themes: list | None = None, totals_anomalies: list | None = None) -> str:
    framing = REPORT_TYPE_FRAMING.get(report_type, "")
    themes_block = ""
    if themes:
        themes_block = (
            "\n\nAdministrator comment themes observed this window (keyword-bucketed, "
            "deterministic -- interpret and correlate against the issues above, don't just "
            "restate the counts):\n" + json.dumps(themes, indent=2))
    totals_block = ""
    if totals_anomalies:
        totals_block = (
            "\n\nAggregate totals that moved non-monotonically this window (e.g. a total "
            "that should generally only grow, decreasing at some point) -- a legitimate "
            "cause is possible, but flag these as at minimum worth investigating, per "
            "standard practice for totals-integrity checks:\n"
            + json.dumps(totals_anomalies, indent=2))

    return f"""You are a senior data analyst producing a formal management trend-analysis \
report for a central bank's IT monitoring console, covering the last {window_days} days.
{(chr(10) + framing + chr(10)) if framing else ""}
You are given a list of classified operational issues below. Each has ALREADY been \
statistically classified (Persistent / Recurring / Potential fluke / One-off) with a \
confidence level, based on how many distinct days it was observed and how continuously. \
Do NOT re-classify or contradict the given label -- your job is to INTERPRET the evidence \
and correlate it with the admin_comments, writing the analytical narrative a human analyst \
would.

Rules:
- Never present an administrator's comment as an established fact if it is speculative \
("expected to reduce", "should be resolved soon") -- frame it as the administrator's own \
explanation, not a verified outcome.
- Distinguish observed fact / analytical conclusion / possible explanation / unconfirmed \
hypothesis explicitly wherever it matters.
- Every recommendation must trace back to a specific issue in the data below -- no generic \
advice untethered from evidence.
- Answer "so what" for each major point -- explain why it matters, not just what happened.
- Do not simply summarise or count issues; interpret their operational meaning.
- Do not restate the SAME statistic, system list, or named finding across multiple sections. \
State a specific claim (a Pareto concentration, a named fan-in system, a coverage stat) in \
the ONE section it belongs most, and in every other section that would otherwise repeat it, \
reference that section by name instead (e.g. "see the concentration in the Executive \
Summary") rather than restating the figure or the system list a second time.

Issues (JSON):
{json.dumps(payload, indent=2)}{themes_block}{totals_block}

Call the emit_narrative tool with your analysis. Each field is 2-5 sentences of plain prose \
(no bullet points, no headings, no markdown).
"""


_NARRATIVE_TOOL = {
    "name": "emit_narrative",
    "description": "Emit the completed narrative report, one field per section.",
    "input_schema": {
        "type": "object",
        "properties": {key: {"type": "string"} for key in NARRATIVE_SECTION_KEYS},
        "required": NARRATIVE_SECTION_KEYS,
    },
}


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return json.loads(text)


class AnthropicNarrativeProvider(NarrativeProvider):
    name = "anthropic"
    MODEL = "claude-sonnet-5"

    def __init__(self, api_key: str):
        if not api_key:
            raise NotImplementedProvider("No Anthropic API key configured.")
        self._api_key = api_key

    def generate(self, *, issues: list, window_days: int, report_type: str = "weekly_trend",
                themes: list | None = None, totals_anomalies: list | None = None,
                action_unset_count: int = 0) -> dict:
        import anthropic

        client = anthropic.Anthropic(api_key=self._api_key)
        prompt = _build_prompt(_issues_payload(issues), window_days, report_type=report_type,
                               themes=themes, totals_anomalies=totals_anomalies)
        resp = client.messages.create(
            model=self.MODEL, max_tokens=8192,
            tools=[_NARRATIVE_TOOL],
            tool_choice={"type": "tool", "name": "emit_narrative"},
            messages=[{"role": "user", "content": prompt}],
        )
        data = next(
            (block.input for block in resp.content if block.type == "tool_use"), None)
        if data is None:
            raise ValueError("Anthropic response had no emit_narrative tool call.")
        return {key: data.get(key, "") for key in NARRATIVE_SECTION_KEYS}


class CopilotNarrativeProvider(NarrativeProvider):
    """Reserved slot -- see this module's own docstring. Always raises; never actually
    called with real intent to succeed until the company's own Copilot API access exists."""
    name = "copilot"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def generate(self, *, issues: list, window_days: int, report_type: str = "weekly_trend",
                themes: list | None = None, totals_anomalies: list | None = None,
                action_unset_count: int = 0) -> dict:
        raise NotImplementedProvider(
            "Microsoft 365 Copilot has no working integration yet — this is a reserved slot "
            "until the company's own Copilot API access is wired in.")


def run_narrative(issues: list, *, window_days: int, report_type: str = "weekly_trend",
                  themes: list | None = None, totals_anomalies: list | None = None,
                  action_unset_count: int = 0, sc=None) -> NarrativeResult:
    """Reads reports.models.SystemConfig.narrative_provider, tries to run it, and falls back
    to OfflineNarrativeProvider on ANY failure -- missing key, not-yet-implemented provider,
    network error, auth error, a response that doesn't parse as the expected JSON, anything.
    Never raises. This is the ONE place "the report must still generate even if the AI is
    unreachable" (2026-09-07) is actually enforced -- every caller gets a usable
    NarrativeResult every time."""
    from .models import SystemConfig

    sc = sc or SystemConfig.get()
    requested = sc.narrative_provider or ""

    try:
        if requested == "anthropic":
            provider = AnthropicNarrativeProvider(sc.anthropic_api_key())
        elif requested == "copilot":
            provider = CopilotNarrativeProvider(sc.copilot_api_key())
        else:
            provider = OfflineNarrativeProvider()
        sections = provider.generate(issues=issues, window_days=window_days,
                                     report_type=report_type, themes=themes,
                                     totals_anomalies=totals_anomalies,
                                     action_unset_count=action_unset_count)
        missing = [k for k in NARRATIVE_SECTION_KEYS if not sections.get(k)]
        if missing:
            raise ValueError(f"Provider response missing sections: {missing}")
        return NarrativeResult(provider=provider.name, sections=sections,
                               requested_provider=requested or "offline")
    except Exception as exc:   # noqa: BLE001 -- ANY failure falls back to offline, by design
        offline = OfflineNarrativeProvider()
        return NarrativeResult(
            provider="offline",
            sections=offline.generate(issues=issues, window_days=window_days,
                                      report_type=report_type, themes=themes,
                                      totals_anomalies=totals_anomalies,
                                      action_unset_count=action_unset_count),
            requested_provider=requested or "offline",
            error=str(exc) if requested else None,
        )

"""Markdown report renderer."""
from __future__ import annotations

from .schema import SystemModel

_SEV_ICON = {"Critical": "🟥", "High": "🟧", "Medium": "🟨", "Low": "🟦", "Informational": "⬜"}


def _md_escape_cell(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def render_markdown(enforced, model: SystemModel, meta: dict) -> str:
    ex = enforced.export
    story = next((f for f in ex.findings if f.type == "Story"), None)
    risks = [f for f in ex.findings if f.type == "Risk"]
    out: list[str] = [f"# {ex.epic.title}", ""]
    out.append(f"_Generated {meta.get('created_utc', '')} by Lysis "
               f"v{meta.get('tool_version', '')}. Artifacts: {len(meta.get('artifacts', []))}"
               + (f", code repo: `{meta['repo']}`" if meta.get("repo") else ", design-level only (no code)")
               + "._")
    out.append("")

    if enforced.skipped_min_input:
        out += ["## Review not performed", "",
                "The input lacks the minimum information (purpose, data flows, users) needed for a "
                "threat model. See assumptions and gaps below.", ""]

    if story:
        out += ["## Decision", "", story.description.replace("\n", "  \n"), ""]

    if risks:
        counts = {}
        for f in risks:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        out += ["## Summary", "",
                " · ".join(f"{_SEV_ICON[s]} {s}: {counts[s]}" for s in
                           ["Critical", "High", "Medium", "Low", "Informational"] if s in counts), "",
                "| # | Severity | Title | STRIDE | Confidence | Action | Owner |",
                "|---|---|---|---|---|---|---|"]
        for i, f in enumerate(risks, 1):
            out.append(f"| {i} | {_SEV_ICON[f.severity]} {f.severity} | {_md_escape_cell(f.title)} | "
                       f"{f.stride_category} | {f.confidence} | {f.actionability} | "
                       f"{_md_escape_cell(f.suggested_owner)} |")
        out.append("")

    out += ["## System model", "", f"**Purpose:** {model.purpose or 'not stated'}", ""]
    if model.users:
        out.append("**Users:** " + "; ".join(u.name for u in model.users))
    if model.components:
        out.append("**Components:** " + "; ".join(
            c.name + (f" ({', '.join(c.technologies)})" if c.technologies else "") for c in model.components))
    if model.trust_boundaries:
        out.append("**Trust boundaries:** " + "; ".join(t.name for t in model.trust_boundaries))
    if model.authn or model.authz:
        out.append(f"**AuthN:** {model.authn or 'not stated'}  \n**AuthZ:** {model.authz or 'not stated'}")
    if model.data_flows:
        out += ["", "| Source | Destination | Data | Crosses boundary |", "|---|---|---|---|"]
        for d in model.data_flows:
            out.append(f"| {_md_escape_cell(d.source)} | {_md_escape_cell(d.destination)} | "
                       f"{_md_escape_cell(d.data)} | {'yes — ' + d.boundary if d.crosses_trust_boundary else 'no'} |")
    out.append("")

    gates = meta.get("gate_assessments") or []
    num = {f.id: i for i, f in enumerate(enforced.findings, 1)}
    if gates:
        out += ["## Control gates", "", "| Gate | Answer | Evidence | Finding |", "|---|---|---|---|"]
        for g in gates:
            out.append(f"| {g['gate_id']} | {g['answer']} | {_md_escape_cell(g.get('evidence', ''))[:300]} | "
                       f"{'#' + str(num[g['finding_ref']]) if g.get('finding_ref') in num else ''} |")
        out.append("")

    if risks:
        out += ["## Findings", ""]
    for i, f in enumerate(risks, 1):
        out += [f"### {i}. {f.title}", "",
                f"**{_SEV_ICON[f.severity]} {f.severity}** · Confidence {f.confidence} · Priority {f.priority}"
                f" · {f.stride_category}" + (f" · CVSS {f.cvss}" if f.cvss is not None else "")
                + (f" · {f.cwe}" if f.cwe else "") + f" · Size {f.tshirt_size} · **{f.actionability}**", "",
                f.description, "",
                f"**Attacker path.** {f.attacker_path}", "",
                f"**Risk.** {f.risk}", "",
                f"**Worst case.** {f.worst_case_scenario}", ""]
        if f.mitigating_factors:
            out += [f"**Mitigating factors.** {f.mitigating_factors}", ""]
        out += [f"**Remediation.** {f.remediation}", ""]
        if f.interim_guidance:
            out += [f"**Interim guidance.** {f.interim_guidance}", ""]
        out += ["**Evidence.**", "", "```", f.evidence, "```", ""]
        if f.framework_refs:
            out += ["**References.** " + ", ".join(f.framework_refs), ""]
        if f.reviewer_questions:
            out += ["**Reviewer questions.**", ""] + [f"- {q}" for q in f.reviewer_questions] + [""]
        out += [f"_Owner: {f.suggested_owner} · Team: {f.suggested_team} · Tags: {', '.join(f.tags)}_", ""]

    rc = ex.review_context
    if rc.possible_unconfirmed_threats:
        out += ["## Possible unconfirmed threats", ""]
        for t in rc.possible_unconfirmed_threats:
            out.append(f"- **{t.title}** — {t.why_unconfirmed} _Potential impact:_ {t.potential_impact}")
        out.append("")
    if rc.assumptions:
        out += ["## Assumptions", ""]
        for a in rc.assumptions:
            out.append(f"- {a.assumption} _If wrong:_ {a.impact}")
        out.append("")
    if model.gaps:
        out += ["## Input gaps", ""] + [f"- {g}" for g in model.gaps] + [""]

    enf = meta.get("enforcement") or {}
    if enf.get("fixes") or enf.get("warnings"):
        out += ["## Validator log", "",
                "Deterministic checks applied after the model passes.", ""]
        for e in enf.get("fixes", []):
            out.append(f"- 🔧 `{e['rule']}` ({e['finding']}): {e['detail']}")
        for e in enf.get("warnings", []):
            out.append(f"- ⚠️ `{e['rule']}` ({e['finding']}): {e['detail']}")
        out.append("")

    usage = (meta.get("usage") or {}).get("totals") or {}
    if usage:
        out += ["---", f"_Tokens: {usage.get('input_tokens', 0):,} in "
                       f"(+{usage.get('cache_read_tokens', 0):,} cache read, "
                       f"{usage.get('cache_write_tokens', 0):,} cache write), "
                       f"{usage.get('output_tokens', 0):,} out, {usage.get('calls', 0)} calls, "
                       f"{meta.get('seconds', '?')}s._"]
    return "\n".join(out) + "\n"

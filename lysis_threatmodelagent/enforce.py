"""Deterministic enforcement.

Rules that can be checked in code are checked in code rather than requested in the prompt.
Every change is recorded in an enforcement log, so reviewers can see what was adjusted and
prompt tuning can see what the model keeps getting wrong.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional

from .config import Profile
from .schema import (SEVERITY_ORDER, Assumption, ExportFinding, Epic, Final, Finding, GateAssessment,
                     ReviewContext, ReviewExport, ScopedDecision, SystemModel, sev_rank)


# ================================================================== log

@dataclass
class EnforcementLog:
    entries: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)

    def fix(self, finding: str, rule: str, detail: str):
        self.entries.append({"finding": finding, "rule": rule, "detail": detail})

    def warn(self, finding: str, rule: str, detail: str):
        self.warnings.append({"finding": finding, "rule": rule, "detail": detail})


# ================================================================== CVSS 3.1

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_CVSS_RE = re.compile(r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$")


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31_score(vector: str) -> Optional[float]:
    """CVSS v3.1 base score from a vector string; None if the vector is malformed."""
    v = (vector or "").strip()
    if not _CVSS_RE.match(v):
        return None
    m = dict(part.split(":") for part in v.split("/")[1:])
    s = m["S"]
    iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[s][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if s == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def cvss_band(score: float) -> str:
    if score == 0:
        return "Informational"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


# ================================================================== reference validation

_NIST_FAMILIES = {"AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM",
                  "PS", "PT", "RA", "SA", "SC", "SI", "SR"}
_REF_PATTERNS = [
    re.compile(r"^OWASP A(0[1-9]|10):20(21|25)$"),
    re.compile(r"^OWASP API([1-9]|10):2023$"),
    re.compile(r"^ATT&CK T\d{4}(\.\d{3})?$"),
    re.compile(r"^NIST 800-53 (?P<fam>[A-Z]{2})-\d{1,2}(\(\d{1,2}\))?$"),
    re.compile(r"^NIST 800-207$"),
    re.compile(r"^CIS \d{1,2}(\.\d{1,2})?$"),
    re.compile(r"^CSA CCM [A-Z]{3}-\d{2}$"),
]


def valid_ref(ref: str) -> bool:
    ref = ref.strip()
    for rx in _REF_PATTERNS:
        m = rx.match(ref)
        if m:
            fam = m.groupdict().get("fam") if m.groupdict() else None
            return fam is None or fam in _NIST_FAMILIES
    return False


_CWE_RE = re.compile(r"^CWE-\d{1,4}$")


# ================================================================== evidence checks

def _norm(s: str) -> str:
    s = (s or "").replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", s).strip().lower()


def verify_quotes(f: Finding, searchable: dict[str, str], unverifiable: set[str], log: EnforcementLog):
    corpus_all = None
    for q in f.evidence_quotes:
        if q.artifact in unverifiable:
            q.verified = None  # images: can't check
            continue
        text = searchable.get(q.artifact)
        if text is None:  # model named the artifact loosely; search everything
            if corpus_all is None:
                corpus_all = _norm("\n".join(searchable.values()))
            q.verified = _norm(q.quote) in corpus_all and len(_norm(q.quote)) >= 8
        else:
            q.verified = _norm(q.quote) in _norm(text) and len(_norm(q.quote)) >= 8
        if q.verified is False:
            log.fix(f.id, "quote_not_found", f"quote not found in {q.artifact!r}: {q.quote[:80]!r} (removed)")
    f.evidence_quotes = [q for q in f.evidence_quotes if q.verified is not False]


def verify_code_evidence(f: Finding, repo, log: EnforcementLog):
    if repo is None:
        if f.code_evidence:
            log.fix(f.id, "code_evidence_without_repo", "code evidence cited but no repo supplied (removed)")
            f.code_evidence = []
        return
    kept = []
    for ce in f.code_evidence:
        ce.verified = repo.snippet_matches(ce.file, ce.line_start, ce.line_end, ce.snippet)
        if ce.verified:
            kept.append(ce)
        else:
            log.fix(f.id, "code_snippet_not_found",
                    f"{ce.file}:{ce.line_start}-{ce.line_end} snippet not found (removed)")
    f.code_evidence = kept


# ================================================================== per-finding rules

_PERSON_RE = re.compile(r"^[A-Z][a-z]+(?: [A-Z]\.)? [A-Z][a-z'\-]+$")
_ROLE_WORDS = ("team", "owner", "engineering", "ops", "security", "admin", "platform", "iam",
               "infrastructure", "devops", "sre", "lead", "architect", "developer", "network",
               "cloud", "data", "identity", "application", "product", "compliance", "it")
_SIZE_ORDER = ["XS", "S", "M", "L", "XL", "XXL"]


def enforce_finding(f: Finding, profile: Profile, log: EnforcementLog) -> None:
    fid = f.id

    # --- evidence basis consistency
    if f.evidence_basis == "code_verified" and not f.code_evidence:
        f.evidence_basis = "inference"
        log.fix(fid, "basis_downgrade", "code_verified without verified code evidence -> inference")
    if f.evidence_basis == "direct" and not f.evidence_quotes:
        f.evidence_basis = "inference"
        log.fix(fid, "basis_downgrade", "direct without a verified quote -> inference")

    # --- missing documentation can't carry a Critical/High
    if f.evidence_basis == "absence_of_documentation" and sev_rank(f.severity) < sev_rank("Medium"):
        log.fix(fid, "severity_cap_missing_docs", f"{f.severity} -> Medium (absence of documentation)")
        f.severity = "Medium"

    # --- no evidence at all -> Low confidence
    if not (f.evidence.strip() or f.evidence_quotes or f.code_evidence):
        if f.confidence != "Low":
            log.fix(fid, "confidence_no_evidence", f"{f.confidence} -> Low (no evidence)")
            f.confidence = "Low"
    if f.evidence_basis == "absence_of_documentation" and f.confidence == "High":
        f.confidence = "Medium"
        log.fix(fid, "confidence_missing_docs", "High -> Medium (absence of documentation)")

    # --- CWE format
    if f.cwe and not _CWE_RE.match(f.cwe.strip()):
        log.fix(fid, "cwe_format", f"invalid CWE {f.cwe!r} (cleared)")
        f.cwe = ""

    # --- framework refs
    good = [r for r in f.framework_refs if valid_ref(r)]
    for r in f.framework_refs:
        if r not in good:
            log.fix(fid, "framework_ref_format", f"unrecognized reference {r!r} (removed)")
    f.framework_refs = list(dict.fromkeys(good))

    # --- standards: only those in the pack
    known = profile.standard_names
    for s in f.standards_cited:
        if s not in known:
            log.fix(fid, "unknown_standard", f"cited standard {s!r} not in pack (removed)")
    f.standards_cited = [s for s in f.standards_cited if s in known]

    # --- CVSS
    if f.cvss_vector:
        score = cvss31_score(f.cvss_vector)
        if score is None:
            log.fix(fid, "cvss_vector_invalid", f"invalid vector {f.cvss_vector!r} (cleared)")
            f.cvss_vector = ""
        elif abs(sev_rank(cvss_band(score)) - sev_rank(f.severity)) >= 2:
            log.warn(fid, "cvss_severity_mismatch",
                     f"CVSS {score} ({cvss_band(score)}) vs rubric severity {f.severity}")

    # --- reviewer questions
    if f.confidence == "High" and f.reviewer_questions:
        f.reviewer_questions = []
        log.fix(fid, "questions_high_conf", "cleared reviewer_questions on High-confidence finding")
    elif f.confidence != "High":
        if len(f.reviewer_questions) > 4:
            f.reviewer_questions = f.reviewer_questions[:4]
            log.fix(fid, "questions_max", "trimmed reviewer_questions to 4")
        if len(f.reviewer_questions) < 2:
            log.warn(fid, "questions_min", f"{f.confidence} confidence but {len(f.reviewer_questions)} reviewer questions")

    # --- owner must be a role
    owner = f.suggested_owner.strip()
    owner_words = set(re.findall(r"[a-z]+", owner.lower()))
    if not owner or (_PERSON_RE.match(owner) and not owner_words & set(_ROLE_WORDS)):
        new = "System Owner"
        if owner:
            log.fix(fid, "owner_is_person", f"suggested_owner {owner!r} looks like a person -> {new}")
        f.suggested_owner = new

    # --- required narrative fields
    for fld in ("attacker_path", "worst_case_scenario", "remediation", "evidence"):
        if not getattr(f, fld).strip():
            log.warn(fid, "missing_field", f"{fld} is empty")
    if not f.interim_guidance.strip() and _SIZE_ORDER.index(f.tshirt_size) >= _SIZE_ORDER.index("M"):
        log.warn(fid, "interim_guidance_missing", f"tshirt {f.tshirt_size} remediation but no interim_guidance")


def derive_actionability(f: Finding) -> str:
    if f.confidence == "Low" or f.severity in ("Low", "Informational"):
        return "Informational"
    if f.confidence == "Medium":
        return "NeedsReview"
    # High confidence, Critical/High/Medium
    if f.evidence_basis in ("direct", "code_verified"):
        return "CreateTicket"
    return "NeedsReview"  # high confidence but exploit details unverified


# ================================================================== dedupe

def _tokens(s: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", s.lower()) if len(t) > 2}


def dedupe(findings: list[Finding], log: EnforcementLog) -> list[Finding]:
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda x: (sev_rank(x.severity), x.id)):
        tf = _tokens(f.title)
        dup = None
        for k in kept:
            tk = _tokens(k.title)
            if tf and tk and len(tf & tk) / len(tf | tk) >= 0.8:
                dup = k
                break
        if dup:
            log.fix(f.id, "duplicate", f"merged into {dup.id} (near-identical title)")
            dup.evidence_quotes += f.evidence_quotes
            dup.code_evidence += f.code_evidence
        else:
            kept.append(f)
    return kept


# ================================================================== gates

def gate_findings(final: Final, profile: Profile, findings: list[Finding], log: EnforcementLog) -> list[Finding]:
    """Ensure every failed gate is covered by a finding; synthesize one if not."""
    rules = profile.get("gate_rules") or {}
    unknown_creates = rules.get("unknown_creates_finding", True)
    sev = rules.get("finding_severity", "Medium")
    by_id = {f.id: f for f in findings}
    answers = {g.gate_id: g for g in final.gate_assessments}
    out = list(findings)
    n = 0
    for gate in profile.gates:
        gid = gate["id"]
        ga = answers.get(gid)
        if ga is None:
            ga = GateAssessment(gate_id=gid, answer="Unknown", evidence="")
            final.gate_assessments.append(ga)
            log.fix(f"gate:{gid}", "gate_unanswered", "model did not answer gate -> Unknown")
        yes_no_evidence = ga.answer == "Yes" and not ga.evidence.strip()
        failed = ga.answer == "No" or yes_no_evidence or (ga.answer == "Unknown" and unknown_creates)
        if not failed:
            continue
        covering = by_id.get(ga.finding_ref) if ga.finding_ref else None
        if covering is None:
            covering = next((f for f in out if f.gate_id == gid), None)
        if covering is not None:
            covering.gate_id = gid
            continue
        n += 1
        why = {"No": "answered No", "Yes": "answered Yes without evidence",
               "Unknown": "could not be determined from the input"}[ga.answer]
        basis = "direct" if ga.answer == "No" and ga.evidence.strip() else "absence_of_documentation"
        f = Finding(
            id=f"G{n}", scope="", gate_id=gid,
            title=(gate.get("title") or f"Control gate not met: {gate.get('category', gid)}")
                  + ("" if ga.answer == "No" else " (unverified)"),
            description=f"Mandatory control gate '{gid}' {why}. Gate: {gate['question']}",
            attacker_path=gate.get("attacker_path") or (
                "If this control is absent, an attacker who compromises an account or component in "
                "this system faces reduced detection and containment."),
            risk="Absence of a baseline control increases the impact and dwell time of any compromise.",
            worst_case_scenario="A compromise goes undetected or cannot be contained quickly.",
            mitigating_factors="",
            severity=sev, confidence="High" if ga.answer == "No" and ga.evidence.strip() else "Medium",
            evidence_basis=basis, remediation=gate.get("remediation", ""),
            interim_guidance="", category=gate.get("category", "Control Gate"),
            stride_category=gate.get("stride", "Repudiation"),
            evidence=(f"Gate answer: {ga.answer}. " + (ga.evidence or "No evidence provided in the input.")),
            reviewer_questions=[] if ga.answer == "No" and ga.evidence.strip() else [
                f"What evidence shows that this is in place: {gate['question']}",
                "Who owns this control for the system, and where is it documented or configured?"],
            suggested_owner=gate.get("owner", "System Owner"), tshirt_size="S",
            domain_tags=["Control Gate"],
        )
        ga.finding_ref = f.id
        log.fix(f.id, "gate_finding_generated", f"gate {gid} {why}; generated finding")
        out.append(f)
    return out


# ================================================================== decisions

def enforce_decisions(decisions: list[ScopedDecision], findings: list[Finding], scopes: list[str],
                      log: EnforcementLog) -> list[ScopedDecision]:
    if not decisions:
        decisions = [ScopedDecision(scope=scopes[0] if scopes else "System",
                                    decision="Approved for Go-Live", rationale="")]
        log.fix("story", "decision_missing", "no decision returned; derived from findings")
    single = len(decisions) == 1
    for d in decisions:
        in_scope = findings if single else [f for f in findings if f.scope == d.scope or not f.scope]
        crit = sum(f.severity == "Critical" for f in in_scope)
        high = sum(f.severity == "High" for f in in_scope)
        if d.decision == "Approved for Go-Live" and (crit or high):
            d.decision = "Conditional Approval"
            log.fix("story", "decision_inconsistent",
                    f"{d.scope}: Approved with {crit} Critical/{high} High -> Conditional Approval")
            if not d.rationale:
                d.rationale = f"{crit} Critical and {high} High findings must be addressed or compensated."
        if crit >= 2 and d.decision != "Not Approved":
            log.fix("story", "decision_multiple_critical", f"{d.scope}: {crit} Critical -> Not Approved")
            d.decision = "Not Approved"
        if not crit and not high and d.decision != "Approved for Go-Live":
            log.warn("story", "decision_stricter_than_rubric",
                     f"{d.scope}: {d.decision} with zero Critical/High findings")
        if d.decision == "Conditional Approval" and not d.conditions:
            log.warn("story", "conditions_missing", f"{d.scope}: Conditional Approval without conditions")
        if not d.rationale:
            d.rationale = "No Critical or High findings." if not (crit or high) else ""
    return decisions


# ================================================================== assembly

def _renumber(text: str, idmap: dict[str, int]) -> str:
    def sub(m):
        k = m.group(1)
        return f"#{idmap[k]}" if k in idmap else m.group(0)
    return re.sub(r"\[([RG]\d+)\]", sub, text)


def _evidence_text(f: Finding) -> str:
    parts = [f.evidence.strip()] if f.evidence.strip() else []
    for q in f.evidence_quotes:
        parts.append(f"[{q.artifact}] \"{q.quote.strip()}\"")
    for c in f.code_evidence:
        parts.append(f"[{c.file}:{c.line_start}-{c.line_end}] `{c.snippet.strip()[:200]}`"
                     + (f" — {c.note}" if c.note else ""))
    if f.standards_cited:
        parts.append("Standards: " + ", ".join(f.standards_cited))
    return "\n".join(parts)


@dataclass
class EnforcedReview:
    export: ReviewExport
    findings: list[Finding]           # working findings, final order
    decisions: list[ScopedDecision]
    gate_assessments: list[GateAssessment]
    log: EnforcementLog
    skipped_min_input: bool = False
    attack_chains: list = field(default_factory=list)  # list[AttackChain], steps validated to real ids


def assemble(final: Final, model: SystemModel, profile: Profile, searchable: dict[str, str],
             unverifiable: set[str], repo=None) -> EnforcedReview:
    log = EnforcementLog()
    system = model.system_name.strip() or "System"
    epic = Epic(title=f"Threat Model – {system}")

    # ---- minimum input
    flags = [model.has_purpose, model.has_data_flows, model.has_users]
    mode = profile.get("min_input_mode", "all_missing")
    insufficient = (not any(flags)) if mode == "all_missing" else (not all(flags))
    if insufficient:
        log.fix("review", "min_input", f"insufficient input (purpose={flags[0]}, flows={flags[1]}, "
                                       f"users={flags[2]}); findings suppressed")
        rc = final.review_context.model_copy(deep=True)
        for gap in model.gaps:
            rc.assumptions.append(Assumption(assumption=f"Input gap: {gap}",
                                             impact="Review not performed until this is provided"))
        return EnforcedReview(ReviewExport(epic=epic, findings=[], review_context=rc), [], [],
                              final.gate_assessments, log, skipped_min_input=True)

    # ---- per-finding
    findings = [f.model_copy(deep=True) for f in final.findings]
    for f in findings:
        verify_quotes(f, searchable, unverifiable, log)
        verify_code_evidence(f, repo, log)
        enforce_finding(f, profile, log)
    findings = dedupe(findings, log)
    findings = gate_findings(final, profile, findings, log)  # generated gate findings are code-built

    cap = profile.get("max_findings_soft_cap")
    if cap and len(findings) > cap:
        log.warn("review", "soft_cap", f"{len(findings)} findings exceeds soft cap {cap}")

    # ---- order: severity, then confidence
    conf_rank = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (sev_rank(f.severity), conf_rank[f.confidence], f.id))
    idmap = {f.id: i for i, f in enumerate(findings, 1)}

    # ---- decisions + story
    decisions = enforce_decisions([d.model_copy(deep=True) for d in final.decisions], findings,
                                  model.scopes, log)
    emoji = profile.get("decision_emoji") or {}
    story_lines = []
    for d in decisions:
        story_lines.append(f"{emoji.get(d.decision, '')} {d.decision} — {d.scope}".strip())
        if d.rationale:
            story_lines.append(_renumber(d.rationale.strip(), idmap))
        for c in d.conditions:
            story_lines.append(f"- Condition: {_renumber(c, idmap)}")
        story_lines.append("")
    prio_map = profile.get("priority_from_severity") or {}
    tags_cfg = profile.get("tags") or {}
    team = profile.get("suggested_team", "Security")

    exported: list[ExportFinding] = []
    for f in findings:
        prio = prio_map.get(f.severity, "Low")
        tags = list(dict.fromkeys(list(tags_cfg.get("risk_required", [])) + f.domain_tags))
        exported.append(ExportFinding(
            type="Risk", title=f.title, description=_renumber(f.description, idmap),
            attacker_path=f.attacker_path, risk=f.risk, worst_case_scenario=f.worst_case_scenario,
            mitigating_factors=f.mitigating_factors, severity=f.severity, confidence=f.confidence,
            priority=prio, cvss=cvss31_score(f.cvss_vector) if f.cvss_vector else None,
            cwe=f.cwe, remediation=f.remediation, interim_guidance=f.interim_guidance,
            category=f.category, stride_category=f.stride_category, framework_refs=f.framework_refs,
            evidence=_evidence_text(f), reviewer_questions=f.reviewer_questions,
            suggested_owner=f.suggested_owner, suggested_team=team, tags=tags,
            tshirt_size=f.tshirt_size, actionability=derive_actionability(f)))

    story_prio = "Low"
    for e in exported:
        if ["High", "Medium", "Low"].index(e.priority) < ["High", "Medium", "Low"].index(story_prio):
            story_prio = e.priority
    story = ExportFinding(
        type="Story", title=f"Risk Assessment – {system}", description="\n".join(story_lines).strip(),
        attacker_path="", risk="", worst_case_scenario="", mitigating_factors="",
        severity="Informational", confidence="High", priority=story_prio, cvss=None, cwe="",
        remediation="", interim_guidance="", category="Risk Assessment", stride_category="",
        framework_refs=[], evidence="", reviewer_questions=[], suggested_owner="",
        suggested_team=team, tags=list(tags_cfg.get("story_exact", [])), tshirt_size="XS",
        actionability="CreateTicket")

    export = ReviewExport(epic=epic, findings=[story] + exported, review_context=final.review_context)
    chains = [c.model_copy(deep=True) for c in getattr(final, "attack_chains", [])]
    return EnforcedReview(export, findings, decisions, final.gate_assessments, log, attack_chains=chains)

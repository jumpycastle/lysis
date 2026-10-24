"""The review pipeline: extract -> draft -> verify (code) -> critique -> finalize -> enforce."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import __version__
from .code_tools import RepoSandbox
from .config import Profile, prompt_text, render_gates, render_policy, render_standards
from .diagram import build_diagram
from .enforce import EnforcedReview, assemble
from .intake import Bundle
from .llm import CACHE, LLM, with_cache_marker
from .render import render_markdown
from .schema import Critique, Draft, Final, PriorAssessment, SystemModel, Verification


@dataclass
class ReviewOptions:
    repo: Optional[str] = None
    system_name: Optional[str] = None
    skip_critique: bool = False
    out_dir: str = "runs"
    prior_names: list[str] = field(default_factory=list)  # artifact names that are prior assessments
    make_diagram: bool = True
    log: Callable[[str], None] = print


@dataclass
class ReviewResult:
    run_dir: Path
    enforced: EnforcedReview
    system_model: SystemModel
    draft: Draft
    verification: Optional[Verification]
    critique: Optional[Critique]
    final: Final
    prior: Optional[PriorAssessment] = None
    ledger: dict = field(default_factory=dict)


def _j(obj) -> str:
    return json.dumps(obj.model_dump() if hasattr(obj, "model_dump") else obj, indent=1, ensure_ascii=False)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:50] or "review"


def run_review(bundle: Bundle, profile: Profile, llm: LLM, opts: ReviewOptions) -> ReviewResult:
    log = opts.log
    t0 = time.time()
    repo = RepoSandbox(opts.repo) if opts.repo else None

    system = [
        {"type": "text", "text": render_policy(profile)},
        {"type": "text", "text": render_standards(profile)},
        {"type": "text", "text": render_gates(profile), "cache_control": CACHE},
    ]
    artifacts = with_cache_marker(bundle.content_blocks())

    def content(*texts: str) -> list[dict]:
        return artifacts + [{"type": "text", "text": "\n\n".join(t for t in texts if t)}]

    # ---------------------------------------------------------------- 1. extract
    log(f"artifacts: {len(bundle.artifacts)} (~{bundle.estimated_tokens():,} tokens); "
        f"passes will take a few minutes on large bundles")
    log("[1/5] extracting system model")
    hint = f"The system under review is called: {opts.system_name}" if opts.system_name else ""
    model: SystemModel = llm.structured(
        pass_name="extract", model=profile.model_for("extract"), system=system,
        content=content(prompt_text("extract"), hint),
        tool_name="submit_system_model", out_model=SystemModel)
    if opts.system_name:
        model.system_name = opts.system_name
    if not model.scopes:
        model.scopes = [model.system_name]
    log(f"      system: {model.system_name} | {len(model.components)} components, "
        f"{len(model.data_flows)} flows, scopes: {', '.join(model.scopes)}")

    model_block = f"<system_model>\n{_j(model)}\n</system_model>"

    # ---------------------------------------------------------------- prior assessment
    prior: Optional[PriorAssessment] = None
    prior_names = _detect_prior(bundle, profile, opts)
    if prior_names:
        log(f"      prior assessment detected: {', '.join(prior_names)}")
        prior = llm.structured(
            pass_name="prior", model=profile.model_for("extract"), system=system,
            content=content(model_block, prompt_text("prior"),
                            "The prior-assessment artifacts are: " + ", ".join(prior_names)),
            tool_name="submit_prior", out_model=PriorAssessment)
        log(f"      extracted {len(prior.findings)} prior findings")
    prior_block = f"<prior_findings source=\"{prior.source_kind}\">\n{_j(prior)}\n</prior_findings>" if prior else ""

    # device/IoT/OT lens: applied to the draft pass when the system looks like it includes hardware
    device_block = prompt_text("device_lens") if _is_device_system(model, profile) else ""
    if device_block:
        log("      device/OT/instrument components detected — applying the device lens")

    # ---------------------------------------------------------------- 2. draft
    log("[2/5] enumerating threats (draft)")
    draft: Draft = llm.structured(
        pass_name="draft", model=profile.model_for("draft"), system=system,
        content=content(model_block, prompt_text("draft"), device_block),
        tool_name="submit_draft", out_model=Draft)
    log(f"      {len(draft.findings)} draft findings, "
        f"{len(draft.review_context.possible_unconfirmed_threats)} unconfirmed threats")

    # ---------------------------------------------------------------- 3. verify
    verification: Optional[Verification] = None
    if repo is not None and draft.findings:
        log("[3/5] verifying against code")
        cands = [{"id": f.id, "title": f.title, "severity": f.severity, "attacker_path": f.attacker_path,
                  "description": f.description} for f in draft.findings]
        verification = llm.agent(
            pass_name="verify", model=profile.model_for("verify"), system=system,
            content=content(model_block, prompt_text("verify"),
                            f"<candidate_findings>\n{json.dumps(cands, indent=1)}\n</candidate_findings>",
                            f"<repo_map>\n{repo.repo_map()}\n</repo_map>"),
            tools=repo.tool_specs(), handlers=repo.handlers(),
            submit_name="submit_verification", submit_model=Verification,
            max_tool_calls=int(profile.get("verify_max_tool_calls", 40)),
            log=lambda m: log("     " + m))
        counts: dict[str, int] = {}
        for r in verification.results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
        log(f"      verdicts: {counts or 'none'}; {len(verification.code_observations)} code observations")
    else:
        log("[3/5] code verification skipped" + (" (no repo)" if repo is None else " (no findings)"))

    ver_block = f"<code_verification>\n{_j(verification)}\n</code_verification>" if verification else \
        "<code_verification>No repository was provided; findings are design-level only.</code_verification>"
    draft_block = f"<draft>\n{_j(draft)}\n</draft>"

    # ---------------------------------------------------------------- 4. critique
    critique: Optional[Critique] = None
    if not opts.skip_critique:
        log("[4/5] adversarial critique")
        critique = llm.structured(
            pass_name="critique", model=profile.model_for("critique"), system=system,
            content=content(model_block, draft_block, ver_block, prompt_text("critique")),
            tool_name="submit_critique", out_model=Critique)
        acts: dict[str, int] = {}
        for it in critique.items:
            acts[it.action] = acts.get(it.action, 0) + 1
        log(f"      {acts or 'no items'}; {len(critique.missed_threats)} missed threats")
    else:
        log("[4/5] critique skipped")

    # ---------------------------------------------------------------- 5. finalize
    log("[5/5] finalizing")
    crit_block = f"<critique>\n{_j(critique)}\n</critique>" if critique else ""
    final: Final = llm.structured(
        pass_name="finalize", model=profile.model_for("finalize"), system=system,
        content=content(model_block, draft_block, ver_block, crit_block, prior_block, prompt_text("finalize")),
        tool_name="submit_final", out_model=Final)

    # carry confirmed code evidence forward if finalize dropped it
    if verification:
        by_id = {r.finding_id: r for r in verification.results}
        for f in final.findings:
            r = by_id.get(f.id)
            if r and r.verdict in ("confirmed", "partially_mitigated") and not f.code_evidence and r.evidence:
                f.code_evidence = [e.model_copy() for e in r.evidence]
                if r.verdict == "confirmed" and f.evidence_basis in ("inference", "absence_of_documentation"):
                    f.evidence_basis = "code_verified"

    # ---------------------------------------------------------------- enforce
    unverifiable = {a.name for a in bundle.artifacts if a.kind == "image"}
    enforced = assemble(final, model, profile, bundle.searchable(), unverifiable, repo)
    if verification:
        by_id = {r.finding_id: r for r in verification.results}
        for f in enforced.findings:
            r = by_id.get(f.id)
            if r and r.verdict == "mitigated":
                enforced.log.warn(f.id, "kept_despite_mitigated",
                                  f"code verification found this mitigated, finalize kept it at {f.severity}")

    # ---------------------------------------------------------------- persist
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(opts.out_dir) / f"{_slug(model.system_name)}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "findings.json").write_text(_j(enforced.export), encoding="utf-8")
    (run_dir / "system_model.json").write_text(_j(model), encoding="utf-8")
    (run_dir / "draft.json").write_text(_j(draft), encoding="utf-8")
    if verification:
        (run_dir / "verification.json").write_text(_j(verification), encoding="utf-8")
    if critique:
        (run_dir / "critique.json").write_text(_j(critique), encoding="utf-8")
    (run_dir / "final_raw.json").write_text(_j(final), encoding="utf-8")
    ledger = {"passes": [p.__dict__ for p in llm.ledger.passes], "totals": llm.ledger.totals()}
    meta = {
        "tool_version": __version__,
        "created_utc": stamp,
        "seconds": round(time.time() - t0, 1),
        "profile": profile.get("_path"),
        "models": profile.get("models"),
        "artifacts": [{"name": a.name, "kind": a.kind, "sha256": a.sha256, "bytes": a.bytes}
                      for a in bundle.artifacts],
        "skipped_artifacts": bundle.skipped,
        "repo": opts.repo,
        "standards": sorted(profile.standard_names),
        "usage": ledger,
        "enforcement": {"fixes": enforced.log.entries, "warnings": enforced.log.warnings},
        "gate_assessments": [g.model_dump() for g in enforced.gate_assessments],
        "decisions": [d.model_dump() for d in enforced.decisions],
        "skipped_min_input": enforced.skipped_min_input,
        "working_findings": [f.model_dump() for f in enforced.findings],
    }
    if prior:
        (run_dir / "prior_findings.json").write_text(_j(prior), encoding="utf-8")
    (run_dir / "run.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False), encoding="utf-8")
    (run_dir / "report.md").write_text(render_markdown(enforced, model, meta), encoding="utf-8")
    if opts.make_diagram and not enforced.skipped_min_input:
        try:
            html = build_diagram(model, enforced.findings, meta, prior, enforced.attack_chains)
            (run_dir / "threat-model.html").write_text(html, encoding="utf-8")
            log(f"      diagram: {run_dir / 'threat-model.html'}")
        except Exception as e:  # a diagram failure must never fail the review
            log(f"      diagram skipped ({type(e).__name__}: {e})")
    log(f"done in {meta['seconds']}s -> {run_dir}")
    return ReviewResult(run_dir, enforced, model, draft, verification, critique, final, prior, ledger)


_DEVICE_RX = re.compile(
    r"hardware|firmware|\bdevice\b|gateway|instrument|\bsensor\b|appliance|\bplc\b|\bics\b|scada|"
    r"\bot\b|embedded|wlan|modbus|\bserial\b|rs-?232|rs-?485|zigbee|\bmqtt\b|\bota\b", re.I)


def _is_device_system(model: SystemModel, profile: Profile) -> bool:
    """Whether to apply the device/IoT/OT lens: profile override, else auto-detect from the model."""
    pref = profile.get("device_lens", "auto")
    if pref is True or pref == "always":
        return True
    if pref is False or pref == "never":
        return False
    hay = [model.deployment_context or ""]
    for c in model.components:
        hay += [c.kind or "", c.name or "", c.trust_zone or "", " ".join(c.technologies or [])]
    return bool(_DEVICE_RX.search(" ".join(hay)))


def _detect_prior(bundle: Bundle, profile: Profile, opts: ReviewOptions) -> list[str]:
    """Artifact names that look like a prior assessment: explicit opt-in, or a filename match."""
    names = [a.name for a in bundle.artifacts]
    chosen = [n for n in names if any(_slug(p) in _slug(n) for p in opts.prior_names)] if opts.prior_names else []
    pats = profile.get("prior_patterns") or [
        "pentest", "penetration", "pen-test", "pen test", "prior-findings", "prior findings",
        "security-assessment", "vuln", "audit-findings"]
    rx = re.compile("|".join(re.escape(p) for p in pats), re.I)
    for n in names:
        if n not in chosen and rx.search(n):
            chosen.append(n)
    return chosen

"""Eval harness: re-run known reviews and score them against expectations.

A case lives in evals/cases/<name>/:
  artifacts/        review inputs (required)
  repo/             optional source tree for code verification
  context.md        optional additional context
  expected.yaml     expectations (see evals/README.md)
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import load_profile
from .intake import load_bundle
from .llm import LLM
from .pipeline import ReviewOptions, run_review
from .schema import sev_rank

_DECISION_RANK = {"Approved for Go-Live": 0, "Conditional Approval": 1, "Not Approved": 2}


@dataclass
class CaseScore:
    case: str
    must_find_hit: list[str] = field(default_factory=list)
    must_find_miss: list[str] = field(default_factory=list)
    severity_low: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    decision_expected: str = ""
    decision_actual: str = ""
    gate_mismatches: list[str] = field(default_factory=list)
    n_findings: int = 0
    max_findings: int | None = None
    validator_fixes: int = 0
    run_dir: str = ""
    error: str = ""

    @property
    def recall(self) -> float:
        n = len(self.must_find_hit) + len(self.must_find_miss)
        return len(self.must_find_hit) / n if n else 1.0

    @property
    def passed(self) -> bool:
        return (not self.error and not self.must_find_miss and not self.false_positives
                and not self.severity_low and not self.gate_mismatches
                and (not self.decision_expected or self.decision_expected == self.decision_actual)
                and (self.max_findings is None or self.n_findings <= self.max_findings))


def _matches(text: str, groups: list[list[str]]) -> bool:
    t = text.lower()
    return all(any(k.lower() in t for k in g) for g in groups)


def _norm_groups(spec) -> list[list[str]]:
    if not spec:
        return []
    if isinstance(spec[0], str):
        return [spec]
    return spec


def score_case(name: str, expected: dict, result) -> CaseScore:
    ex = result.enforced.export
    risks = [f for f in ex.findings if f.type == "Risk"]
    sc = CaseScore(case=name, n_findings=len(risks), max_findings=expected.get("max_findings"),
                   validator_fixes=len(result.enforced.log.entries), run_dir=str(result.run_dir))
    for m in expected.get("must_find", []):
        groups = _norm_groups(m.get("keywords"))
        hit = [f for f in risks if _matches(f"{f.title} {f.description} {f.attacker_path}", groups)
               and (not m.get("stride") or f.stride_category == m["stride"])]
        if not hit:
            sc.must_find_miss.append(m["id"])
            continue
        sc.must_find_hit.append(m["id"])
        if m.get("min_severity") and min(sev_rank(f.severity) for f in hit) > sev_rank(m["min_severity"]):
            sc.severity_low.append(f"{m['id']} (< {m['min_severity']})")
    for m in expected.get("must_not_find", []):
        groups = _norm_groups(m.get("keywords"))
        if any(_matches(f"{f.title} {f.description}", groups) for f in risks):
            sc.false_positives.append(m["id"])
    if result.enforced.decisions:
        worst = max(result.enforced.decisions, key=lambda d: _DECISION_RANK[d.decision])
        sc.decision_actual = worst.decision
    sc.decision_expected = expected.get("expected_decision", "")
    got = {g.gate_id: g.answer for g in result.enforced.gate_assessments}
    for gid, ans in (expected.get("gates") or {}).items():
        if got.get(gid) != ans:
            sc.gate_mismatches.append(f"{gid}: expected {ans}, got {got.get(gid)}")
    return sc


def run_case(case_dir: Path, default_profile: str, out_dir: str, client=None, quiet: bool = True) -> CaseScore:
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text()) or {}
    try:
        profile_path = expected.get("profile") or default_profile
        profile = load_profile(profile_path)
        ctx = (case_dir / "context.md").read_text() if (case_dir / "context.md").exists() else ""
        bundle = load_bundle(case_dir / "artifacts", context=ctx)
        repo = str(case_dir / "repo") if (case_dir / "repo").is_dir() else None
        llm = LLM(client=client, max_tokens=int(profile.get("max_tokens", 32000)))
        logs: list[str] = []
        opts = ReviewOptions(repo=repo, system_name=expected.get("system_name"), out_dir=out_dir,
                             log=(logs.append if quiet else print))
        result = run_review(bundle, profile, llm, opts)
        return score_case(case_dir.name, expected, result)
    except Exception as e:  # keep the suite running
        return CaseScore(case=case_dir.name, error=f"{type(e).__name__}: {e}")


def run_suite(cases_dir: str, profile: str, out_dir: str, only: list[str] | None = None,
              parallel: int = 2, client=None) -> list[CaseScore]:
    cases = sorted(p for p in Path(cases_dir).iterdir() if (p / "expected.yaml").exists())
    if only:
        cases = [c for c in cases if c.name in only]
    with ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        return list(pool.map(lambda c: run_case(c, profile, out_dir, client), cases))


def format_scores(scores: list[CaseScore]) -> str:
    lines = ["| Case | Pass | Recall | Sev low | False pos | Decision | Gates | Findings | Fixes |",
             "|---|---|---|---|---|---|---|---|---|"]
    for s in scores:
        if s.error:
            lines.append(f"| {s.case} | ERROR | | | | | | | {s.error[:80]} |")
            continue
        dec = "✓" if not s.decision_expected or s.decision_expected == s.decision_actual else \
            f"✗ {s.decision_actual}"
        lines.append(f"| {s.case} | {'✅' if s.passed else '❌'} | {s.recall:.0%} "
                     f"{('miss: ' + ', '.join(s.must_find_miss)) if s.must_find_miss else ''} | "
                     f"{', '.join(s.severity_low)} | {', '.join(s.false_positives)} | {dec} | "
                     f"{'; '.join(s.gate_mismatches) or '✓'} | {s.n_findings}"
                     f"{'/' + str(s.max_findings) if s.max_findings else ''} | {s.validator_fixes} |")
    passed = sum(s.passed for s in scores)
    lines.append(f"\n{passed}/{len(scores)} cases passed")
    return "\n".join(lines)


def scores_json(scores: list[CaseScore]) -> str:
    return json.dumps([{**s.__dict__, "recall": s.recall, "passed": s.passed} for s in scores], indent=1)

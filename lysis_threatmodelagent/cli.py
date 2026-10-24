"""Command-line interface.

  lysis review <artifacts> [--repo PATH] [--profile FILE] [--name NAME] [--context FILE|TEXT]
  lysis batch  <reviews_dir> [--parallel N]      # each subfolder = one review (artifacts/ [+ repo/])
  lysis eval   [--cases DIR] [--case NAME ...]
  lysis inspect <artifacts>                      # show what would be sent, no API calls
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import load_profile, render_gates, render_policy, render_standards
from .intake import load_bundle
from .llm import LLM
from .pipeline import ReviewOptions, run_review

DEFAULT_PROFILE = "profiles/default.yaml"


def _context_arg(val: str | None) -> str:
    if not val:
        return ""
    p = Path(val)
    return p.read_text(encoding="utf-8") if p.is_file() else val


def cmd_review(a) -> int:
    profile = load_profile(a.profile)
    bundle = load_bundle(a.artifacts, context=_context_arg(a.context), pdf_mode=a.pdf_mode)
    if not bundle.artifacts:
        print("no supported artifacts found", file=sys.stderr)
        return 2
    llm = LLM(max_tokens=int(profile.get("max_tokens", 32000)))
    res = run_review(bundle, profile, llm, ReviewOptions(
        repo=a.repo, system_name=a.name, skip_critique=a.skip_critique, out_dir=a.out,
        prior_names=a.prior or [], make_diagram=not a.no_diagram))
    risks = [f for f in res.enforced.export.findings if f.type == "Risk"]
    story = next((f for f in res.enforced.export.findings if f.type == "Story"), None)
    print()
    if story:
        print(story.description)
    diagram = res.run_dir / "threat-model.html"
    print(f"\n{len(risks)} findings | report: {res.run_dir / 'report.md'} | "
          f"tickets: {res.run_dir / 'findings.json'}"
          + (f" | diagram: {diagram}" if diagram.exists() else ""))
    return 0


def _one_batch(sub: Path, a) -> str:
    try:
        profile = load_profile(a.profile)
        art = sub / "artifacts" if (sub / "artifacts").is_dir() else sub
        ctx = (sub / "context.md").read_text() if (sub / "context.md").exists() else ""
        bundle = load_bundle(art, context=ctx, pdf_mode=a.pdf_mode)
        repo = str(sub / "repo") if (sub / "repo").is_dir() else None
        llm = LLM(max_tokens=int(profile.get("max_tokens", 32000)))
        res = run_review(bundle, profile, llm, ReviewOptions(
            repo=repo, out_dir=a.out, log=lambda m: print(f"[{sub.name}] {m}")))
        n = sum(f.type == "Risk" for f in res.enforced.export.findings)
        dec = "; ".join(f"{d.decision} ({d.scope})" for d in res.enforced.decisions)
        return f"{sub.name}: {n} findings, {dec} -> {res.run_dir}"
    except Exception as e:
        return f"{sub.name}: ERROR {type(e).__name__}: {e}"


def cmd_batch(a) -> int:
    subs = sorted(p for p in Path(a.reviews_dir).iterdir() if p.is_dir() and not p.name.startswith("."))
    with ThreadPoolExecutor(max_workers=a.parallel) as pool:
        results = list(pool.map(lambda s: _one_batch(s, a), subs))
    print("\n".join(["", "Batch summary:"] + results))
    return 0


def cmd_eval(a) -> int:
    from .evals import format_scores, run_suite, scores_json
    scores = run_suite(a.cases, a.profile, a.out, only=a.case or None, parallel=a.parallel)
    print(format_scores(scores))
    Path(a.out).mkdir(parents=True, exist_ok=True)
    (Path(a.out) / "eval_scores.json").write_text(scores_json(scores))
    return 0 if all(s.passed for s in scores) else 1


def cmd_inspect(a) -> int:
    profile = load_profile(a.profile)
    bundle = load_bundle(a.artifacts, context=_context_arg(a.context), pdf_mode=a.pdf_mode)
    print(bundle.manifest())
    sys_chars = len(render_policy(profile)) + len(render_standards(profile)) + len(render_gates(profile))
    print(f"\nstandards loaded: {sorted(profile.standard_names) or 'none'}")
    print(f"gates: {[g['id'] for g in profile.gates]}")
    est = bundle.estimated_tokens() + sys_chars // 4
    print(f"estimated input per pass: ~{est:,} tokens "
          f"(system ~{sys_chars // 4:,}, artifacts ~{bundle.estimated_tokens():,})")
    print(f"passes: 4 (+ code verification if --repo); after the first call per model, "
          f"the shared prefix is read from cache")
    if est > 350_000:
        print("WARNING: very large input. Consider --pdf-mode text, trimming artifacts, "
              "or splitting the review by service.")
    print(f"models: {json.dumps(profile.get('models'))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lysis", description="Lysis — AI threat model agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("review", help="run one review")
    r.add_argument("artifacts", help="folder (or single file) of review artifacts")
    r.add_argument("--repo", help="path to source repository for code verification")
    r.add_argument("--profile", default=DEFAULT_PROFILE)
    r.add_argument("--name", help="system name (otherwise taken from the artifacts)")
    r.add_argument("--context", help="additional context: a file path or inline text")
    r.add_argument("--skip-critique", action="store_true", help="faster/cheaper, lower quality")
    r.add_argument("--out", default="runs")
    r.add_argument("--pdf-mode", choices=["auto", "native", "text"], default="auto",
                   help="auto: native PDF if <=30 pages, else extracted text")
    r.add_argument("--prior", action="append", metavar="NAME",
                   help="artifact (sub)name to treat as a prior assessment to overlay/dedupe; "
                        "repeatable. Pentest-looking filenames are auto-detected anyway.")
    r.add_argument("--no-diagram", action="store_true", help="skip the interactive HTML diagram")
    r.set_defaults(fn=cmd_review)

    b = sub.add_parser("batch", help="run many reviews; each subfolder is one review")
    b.add_argument("reviews_dir")
    b.add_argument("--profile", default=DEFAULT_PROFILE)
    b.add_argument("--parallel", type=int, default=3)
    b.add_argument("--out", default="runs")
    b.add_argument("--pdf-mode", choices=["auto", "native", "text"], default="auto",
                   help="auto: native PDF if <=30 pages, else extracted text")
    b.set_defaults(fn=cmd_batch)

    e = sub.add_parser("eval", help="run the eval suite")
    e.add_argument("--cases", default="evals/cases")
    e.add_argument("--case", action="append", help="run only this case (repeatable)")
    e.add_argument("--profile", default=DEFAULT_PROFILE)
    e.add_argument("--parallel", type=int, default=2)
    e.add_argument("--out", default="runs/evals")
    e.set_defaults(fn=cmd_eval)

    i = sub.add_parser("inspect", help="show what would be sent (no API calls)")
    i.add_argument("artifacts")
    i.add_argument("--profile", default=DEFAULT_PROFILE)
    i.add_argument("--context")
    i.add_argument("--pdf-mode", choices=["auto", "native", "text"], default="auto",
                   help="auto: native PDF if <=30 pages, else extracted text")
    i.set_defaults(fn=cmd_inspect)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

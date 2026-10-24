"""Profile loading, standards pack loading, and prompt assembly."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_profile_dict(path: str | Path) -> dict:
    path = Path(path).resolve()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    parent = data.pop("extends", None)
    if parent:
        base = load_profile_dict(path.parent / parent)
        data = _deep_merge(base, data)
    data.setdefault("_path", str(path))
    return data


@dataclass
class Standard:
    name: str
    path: str
    text: str


@dataclass
class Profile:
    raw: dict
    base_dir: Path
    standards: list[Standard] = field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    @property
    def gates(self) -> list[dict]:
        siem = self.raw.get("siem", "the central SIEM")
        gates = []
        for g in self.raw.get("control_gates", []) or []:
            g = dict(g)
            for k in ("question", "remediation", "title", "attacker_path"):
                if isinstance(g.get(k), str):
                    g[k] = g[k].replace("{{siem}}", siem)
            gates.append(g)
        return gates

    @property
    def standard_names(self) -> set[str]:
        return {s.name for s in self.standards}

    def model_for(self, pass_name: str) -> str:
        return self.raw.get("models", {}).get(pass_name, "claude-opus-5-5")


def load_standards(dir_path: Path) -> list[Standard]:
    out: list[Standard] = []
    if not dir_path.is_dir():
        return out
    for p in sorted(dir_path.glob("*.md")):
        text = p.read_text(encoding="utf-8")
        first = next((ln for ln in text.splitlines() if ln.strip()), p.stem)
        name = first.lstrip("#").strip() or p.stem
        out.append(Standard(name=name, path=str(p), text=text))
    return out


def load_profile(path: str | Path, repo_root: Path | None = None) -> Profile:
    raw = load_profile_dict(path)
    profile_path = Path(raw["_path"])
    # standards dir is resolved relative to the project root (parent of profiles/), then profile dir
    candidates = []
    sdir = (raw.get("standards") or {}).get("dir")
    if sdir:
        candidates = [Path(sdir), profile_path.parent.parent / sdir, profile_path.parent / sdir]
        if repo_root:
            candidates.insert(0, repo_root / sdir)
    standards: list[Standard] = []
    for c in candidates:
        if c.is_dir():
            standards = load_standards(c)
            break
    return Profile(raw=raw, base_dir=profile_path.parent, standards=standards)


# ---------------------------------------------------------------- prompts

def prompt_text(name: str) -> str:
    return resources.files("lysis_threatmodelagent.prompts").joinpath(f"{name}.md").read_text(encoding="utf-8")


def render_policy(profile: Profile) -> str:
    text = prompt_text("policy")
    org_context = profile.get("org_context") or ""
    if org_context:
        org_context = "# ORGANIZATION CONTEXT\n" + org_context.strip()
    repl = {
        "{{org_name}}": profile.get("org_name", "the client"),
        "{{frameworks}}": profile.get("frameworks", ""),
        "{{critical_extra}}": profile.get("critical_extra", ""),
        "{{org_context}}": org_context,
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    text = text.strip()
    # Optional per-profile methodology additions, appended to the system prompt. This is how a user
    # tweaks the review without editing prompts/ — everything they customize stays in the profile.
    extra = (profile.get("extra_instructions") or "").strip()
    if extra:
        text = text + "\n\n# ADDITIONAL INSTRUCTIONS (from profile)\n" + extra
    return text


def render_standards(profile: Profile) -> str:
    if not profile.standards:
        return "# STANDARDS PACK\n(No standards attached for this review. Do not cite any standards.)"
    lines = ["# STANDARDS PACK", "Cite these ONLY by the exact names below.", ""]
    triggers = (profile.get("standards") or {}).get("triggers") or []
    if triggers:
        lines.append("## When each standard applies")
        for t in triggers:
            if t.get("name") in profile.standard_names:
                lines.append(f"- {t['name']}: {t.get('when', '')}")
        lines.append("")
    for s in profile.standards:
        lines.append(f"<standard name=\"{s.name}\">\n{s.text.strip()}\n</standard>")
    return "\n".join(lines)


def render_gates(profile: Profile) -> str:
    gates = profile.gates
    if not gates:
        return "# MANDATORY CONTROL GATES\n(None configured.)"
    lines = [
        "# MANDATORY CONTROL GATES",
        "Answer each Yes / No / Unknown with evidence from the input. \"Yes\" needs evidence;",
        "a \"Yes\" you cannot point to evidence for is treated as a gap.",
    ]
    for g in gates:
        lines.append(f"- {g['id']}: {g['question']}")
    return "\n".join(lines)

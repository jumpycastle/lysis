"""Read-only, path-sandboxed repository tools for the code-verification pass.

The model can only list, grep, and read files under the repo root. No writes, no execution,
no symlink escape, output size-capped. Also provides snippet verification used by enforce.py.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
from pathlib import Path

IGNORE_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__",
               ".terraform", ".next", "target", "bin", "obj", ".idea", ".vscode", "coverage"}
MAX_FILE_BYTES = 2_000_000
MAX_OUT_CHARS = 20_000


class RepoSandbox:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ValueError(f"repo not found: {root}")

    # ------------------------------------------------------------ safety
    def _resolve(self, rel: str) -> Path:
        rel = (rel or ".").lstrip("/")
        p = (self.root / rel).resolve()
        if p != self.root and self.root not in p.parents:
            raise PermissionError(f"path escapes repository: {rel}")
        return p

    def _iter_files(self):
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
            for f in filenames:
                p = Path(dirpath) / f
                if p.is_symlink():
                    continue
                yield p

    @staticmethod
    def _is_binary(p: Path) -> bool:
        try:
            with p.open("rb") as fh:
                return b"\0" in fh.read(4096)
        except OSError:
            return True

    # ------------------------------------------------------------ tools
    def repo_map(self, max_entries: int = 400) -> str:
        files = sorted(str(p.relative_to(self.root)) for p in self._iter_files())
        head = files[:max_entries]
        more = f"\n... and {len(files) - max_entries} more files" if len(files) > max_entries else ""
        return f"Repository file list ({len(files)} files):\n" + "\n".join(head) + more

    def list_dir(self, args: dict) -> str:
        p = self._resolve(args.get("path", "."))
        if not p.is_dir():
            return f"not a directory: {args.get('path')}"
        items = []
        for c in sorted(p.iterdir()):
            if c.name in IGNORE_DIRS or c.name.startswith(".") or c.is_symlink():
                continue
            items.append(c.name + ("/" if c.is_dir() else f"  ({c.stat().st_size} B)"))
        return "\n".join(items) or "(empty)"

    def glob(self, args: dict) -> str:
        pat = args.get("pattern", "*")
        hits = [str(p.relative_to(self.root)) for p in self._iter_files()
                if fnmatch.fnmatch(str(p.relative_to(self.root)), pat) or fnmatch.fnmatch(p.name, pat)]
        return "\n".join(sorted(hits)[:300]) or "(no matches)"

    def grep(self, args: dict) -> str:
        pattern = args.get("pattern", "")
        path_glob = args.get("path_glob") or ""
        ignore_case = bool(args.get("ignore_case", False))
        max_results = min(int(args.get("max_results", 80)), 300)
        if not pattern:
            return "error: pattern required"
        if shutil.which("rg"):
            cmd = ["rg", "--line-number", "--no-heading", "--color", "never", "--max-columns", "300",
                   "--max-filesize", "2M"]
            for d in IGNORE_DIRS:
                cmd += ["--glob", f"!{d}/"]
            if ignore_case:
                cmd.append("-i")
            if path_glob:
                cmd += ["--glob", path_glob]
            cmd += ["--regexp", pattern, "."]
            try:
                r = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired:
                return "error: search timed out; narrow the pattern or path_glob"
            if r.returncode == 2:
                return f"error: {r.stderr.strip()[:500]}"
            lines = [ln[2:] if ln.startswith("./") else ln for ln in r.stdout.splitlines()]
        else:
            try:
                rx = re.compile(pattern, re.I if ignore_case else 0)
            except re.error as e:
                return f"error: bad regex: {e}"
            lines = []
            for p in self._iter_files():
                rel = str(p.relative_to(self.root))
                if path_glob and not fnmatch.fnmatch(rel, path_glob):
                    continue
                if p.stat().st_size > MAX_FILE_BYTES or self._is_binary(p):
                    continue
                for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
                    if rx.search(ln):
                        lines.append(f"{rel}:{i}:{ln[:300]}")
        total = len(lines)
        out = "\n".join(lines[:max_results])
        if total > max_results:
            out += f"\n... {total - max_results} more matches (narrow the search)"
        return out[:MAX_OUT_CHARS] or "(no matches)"

    def read_file(self, args: dict) -> str:
        p = self._resolve(args.get("path", ""))
        if not p.is_file():
            return f"not a file: {args.get('path')}"
        if p.stat().st_size > MAX_FILE_BYTES or self._is_binary(p):
            return "refused: binary or too large"
        lines = p.read_text(errors="replace").splitlines()
        start = max(1, int(args.get("start_line", 1)))
        end = min(len(lines), int(args.get("end_line", start + 299)))
        body = "\n".join(f"{i:>6}  {lines[i - 1]}" for i in range(start, end + 1))
        tail = f"\n[showing lines {start}-{end} of {len(lines)}]"
        return (body[:MAX_OUT_CHARS] + tail) if body else f"(file has {len(lines)} lines)"

    # ------------------------------------------------------------ verification helper
    def snippet_matches(self, file: str, line_start: int, line_end: int, snippet: str) -> bool:
        """True if `snippet` (whitespace-normalized) appears in the file near the cited lines."""
        try:
            p = self._resolve(file)
        except PermissionError:
            return False
        if not p.is_file() or self._is_binary(p):
            return False
        lines = p.read_text(errors="replace").splitlines()
        if line_start < 1 or line_start > len(lines):
            return False
        lo = max(0, line_start - 4)
        hi = min(len(lines), max(line_end, line_start) + 3)
        window = _norm("\n".join(lines[lo:hi]))
        snip = _norm(snippet)
        return bool(snip) and snip in window

    # ------------------------------------------------------------ tool specs
    def tool_specs(self) -> list[dict]:
        return [
            {"name": "list_dir", "description": "List a directory in the repository.",
             "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "glob", "description": "Find files by glob pattern, e.g. '**/*.tf' or 'auth*.py'.",
             "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}},
                              "required": ["pattern"]}},
            {"name": "grep", "description": "Regex search across the repository. Returns path:line:text.",
             "input_schema": {"type": "object", "properties": {
                 "pattern": {"type": "string"},
                 "path_glob": {"type": "string", "description": "optional file glob filter, e.g. '*.py'"},
                 "ignore_case": {"type": "boolean"},
                 "max_results": {"type": "integer"}}, "required": ["pattern"]}},
            {"name": "read_file", "description": "Read a file with line numbers (max 300 lines per call).",
             "input_schema": {"type": "object", "properties": {
                 "path": {"type": "string"}, "start_line": {"type": "integer"},
                 "end_line": {"type": "integer"}}, "required": ["path"]}},
        ]

    def handlers(self) -> dict:
        return {"list_dir": self.list_dir, "glob": self.glob, "grep": self.grep,
                "read_file": self.read_file}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()

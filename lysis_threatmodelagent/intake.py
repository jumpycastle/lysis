"""Artifact intake: turn a folder of review artifacts into API content blocks.

Supported:
- text / markdown / code / config / IaC           -> text blocks
- .drawio / .xml (draw.io)                        -> parsed into a textual DFD (+ raw kept short)
- .mmd / .mermaid / .puml                         -> text (diagram-as-code is read exactly)
- .json (incl. OWASP Threat Dragon)               -> text
- .docx                                           -> extracted text
- .pdf                                            -> native PDF block (small PDFs) or extracted text (large)
- .pptx                                           -> slide text, tables, and speaker notes
- .png / .jpg / .jpeg / .gif / .webp              -> image blocks
Everything else is listed in the manifest as skipped.
"""
from __future__ import annotations

import base64
import hashlib
import html
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from pathlib import Path

TEXT_EXT = {
    ".md", ".txt", ".rst", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env.example",
    ".tf", ".tfvars", ".hcl", ".json", ".csv", ".sql", ".graphql", ".proto",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".cs", ".rb", ".php", ".rs",
    ".swift", ".scala", ".sh", ".ps1", ".dockerfile", ".mmd", ".mermaid", ".puml", ".bicep",
    ".html", ".htm",
}
IMAGE_EXT = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
             ".gif": "image/gif", ".webp": "image/webp"}
SPECIAL_NAMES = {"dockerfile", "makefile", "jenkinsfile", "procfile"}

MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_PDF_BYTES = 30 * 1024 * 1024
PDF_NATIVE_MAX_PAGES = 30   # larger PDFs go as text by default (cost); override with --pdf-mode native


@dataclass
class Artifact:
    name: str               # path relative to the artifact folder
    kind: str               # text | diagram | image | pdf | docx
    sha256: str
    bytes: int
    text: str = ""          # searchable text (for quote verification); may be empty for images
    pages: int = 0          # PDFs sent natively: page count (for token estimates)
    block: dict | None = None
    note: str = ""


@dataclass
class Bundle:
    root: str
    artifacts: list[Artifact] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    context_text: str = ""

    @property
    def text_chars(self) -> int:
        return sum(len(a.text) for a in self.artifacts if a.kind != "pdf")

    def estimated_tokens(self) -> int:
        """Rough input size of the artifact prefix: ~4 chars/token for text, ~2.5k tokens
        per natively-sent PDF page (text + page image), ~1.6k per image."""
        t = self.text_chars // 4 + len(self.context_text) // 4
        t += sum(a.pages * 2500 for a in self.artifacts if a.kind == "pdf")
        t += sum(1600 for a in self.artifacts if a.kind == "image")
        return t

    def manifest(self) -> str:
        lines = ["# ARTIFACT MANIFEST"]
        for a in self.artifacts:
            extra = f" — {a.note}" if a.note else ""
            lines.append(f"- {a.name} ({a.kind}, {a.bytes} bytes){extra}")
        for name, why in self.skipped:
            lines.append(f"- {name} (SKIPPED: {why})")
        return "\n".join(lines)

    def content_blocks(self) -> list[dict]:
        blocks: list[dict] = [{"type": "text", "text": self.manifest()}]
        if self.context_text:
            blocks.append({"type": "text",
                           "text": f"<additional_context>\n{self.context_text}\n</additional_context>"})
        for a in self.artifacts:
            if a.block is None:
                continue
            if a.kind in ("image", "pdf"):
                blocks.append({"type": "text", "text": f"<artifact name=\"{a.name}\" kind=\"{a.kind}\"/> follows:"})
            blocks.append(a.block)
        return blocks

    def searchable(self) -> dict[str, str]:
        return {a.name: a.text for a in self.artifacts if a.text}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strip_html(s: str) -> str:
    s = re.sub(r"<br\s*/?>", " ", s or "", flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def parse_drawio(xml_text: str) -> str:
    """Render a draw.io / diagrams.net file into a plain-text DFD listing."""
    root = ET.fromstring(xml_text)
    models: list[ET.Element] = []
    diagrams = root.findall(".//diagram") if root.tag != "mxGraphModel" else []
    if root.tag == "mxGraphModel":
        models.append(root)
    for d in diagrams:
        inner = d.find("mxGraphModel")
        if inner is not None:
            models.append(inner)
        elif d.text and d.text.strip():
            raw = base64.b64decode(d.text.strip())
            try:
                inflated = zlib.decompress(raw, -15).decode("utf-8")
            except zlib.error:
                inflated = raw.decode("utf-8", errors="replace")
            models.append(ET.fromstring(urllib.parse.unquote(inflated)))

    out: list[str] = []
    for i, m in enumerate(models, 1):
        cells = {c.get("id"): c for c in m.iter("mxCell")}
        nodes, edges, groups = [], [], []
        for cid, c in cells.items():
            label = _strip_html(c.get("value", ""))
            style = c.get("style", "") or ""
            if c.get("edge") == "1":
                src = _strip_html(cells.get(c.get("source"), ET.Element("x")).get("value", "")) or c.get("source") or "?"
                dst = _strip_html(cells.get(c.get("target"), ET.Element("x")).get("value", "")) or c.get("target") or "?"
                edges.append(f"  {src} -> {dst}" + (f"  [{label}]" if label else ""))
            elif c.get("vertex") == "1" and label:
                parent = cells.get(c.get("parent"))
                parent_label = _strip_html(parent.get("value", "")) if parent is not None else ""
                is_boundary = "dashed=1" in style or "swimlane" in style or "container=1" in style
                entry = f"  {label}" + (f"  (inside: {parent_label})" if parent_label else "")
                (groups if is_boundary else nodes).append(entry)
        out.append(f"Diagram page {i}:")
        if groups:
            out.append(" Boundaries/containers:")
            out.extend(groups)
        out.append(" Elements:")
        out.extend(nodes or ["  (none)"])
        out.append(" Flows:")
        out.extend(edges or ["  (none)"])
    return "\n".join(out)


def _docx_text(path: Path) -> str:
    import docx  # python-docx
    d = docx.Document(str(path))
    parts = [p.text for p in d.paragraphs if p.text.strip()]
    for t in d.tables:
        for row in t.rows:
            parts.append(" | ".join(c.text.strip() for c in row.cells))
    return "\n".join(parts)


def _pdf_pages_text(path: Path) -> tuple[int, str]:
    try:
        import warnings
        warnings.filterwarnings("ignore")
        from pypdf import PdfReader
        pages = PdfReader(str(path)).pages
        return len(pages), "\n\n".join(f"[page {i}]\n{p.extract_text() or ''}" for i, p in enumerate(pages, 1))
    except Exception:
        return 0, ""


def _pptx_text(path: Path) -> str:
    from pptx import Presentation
    prs = Presentation(str(path))
    out = []
    for i, slide in enumerate(prs.slides, 1):
        parts = []
        for shape in slide.shapes:
            if getattr(shape, "has_text_frame", False) and shape.text_frame.text.strip():
                parts.append(shape.text_frame.text.strip())
            if getattr(shape, "has_table", False):
                for row in shape.table.rows:
                    parts.append(" | ".join(c.text.strip() for c in row.cells))
            if shape.shape_type == 13:  # picture
                parts.append("[image on slide — not extracted; export the slide as PNG if it matters]")
        if slide.has_notes_slide and slide.notes_slide.notes_text_frame.text.strip():
            parts.append("Speaker notes: " + slide.notes_slide.notes_text_frame.text.strip())
        out.append(f"--- Slide {i} ---\n" + "\n".join(parts))
    return "\n\n".join(out)


def _text_block(name: str, text: str) -> dict:
    return {"type": "text", "text": f"<artifact name=\"{name}\">\n{text}\n</artifact>"}


def load_artifact(path: Path, rel: str, pdf_mode: str = "auto") -> Artifact | tuple[str, str]:
    data = path.read_bytes()
    sha, size = _sha(data), len(data)
    ext = path.suffix.lower()
    lname = path.name.lower()

    is_drawio_xml = ext == ".xml" and (b"<mxfile" in data[:500] or b"<mxGraphModel" in data[:5000])
    if ext == ".drawio" or is_drawio_xml:
        try:
            txt = parse_drawio(data.decode("utf-8"))
            return Artifact(rel, "diagram", sha, size, text=txt, block=_text_block(rel, txt),
                            note="draw.io parsed to elements/flows")
        except Exception as e:  # fall through to raw text
            txt = data.decode("utf-8", errors="replace")
            return Artifact(rel, "diagram", sha, size, text=txt, block=_text_block(rel, txt),
                            note=f"draw.io parse failed ({e}); raw XML")
    if ext in IMAGE_EXT:
        if size > MAX_IMAGE_BYTES:
            return (rel, f"image larger than {MAX_IMAGE_BYTES // 1024 // 1024} MB")
        block = {"type": "image", "source": {"type": "base64", "media_type": IMAGE_EXT[ext],
                                             "data": base64.b64encode(data).decode()}}
        return Artifact(rel, "image", sha, size, block=block, note="image (quotes unverifiable)")
    if ext == ".pdf":
        pages, txt = _pdf_pages_text(path)
        use_native = pdf_mode == "native" or (pdf_mode == "auto" and pages <= PDF_NATIVE_MAX_PAGES
                                              and size <= MAX_PDF_BYTES)
        if pdf_mode == "auto" and not use_native and len(txt.strip()) < 20 * max(pages, 1):
            use_native = pages <= 100 and size <= MAX_PDF_BYTES  # scanned PDF: text extraction failed
        if use_native:
            block = {"type": "document", "title": rel,
                     "source": {"type": "base64", "media_type": "application/pdf",
                                "data": base64.b64encode(data).decode()}}
            return Artifact(rel, "pdf", sha, size, text=txt, block=block, pages=pages,
                            note=f"{pages} pages, sent as native PDF (text + visuals)")
        return Artifact(rel, "pdf-text", sha, size, text=txt, block=_text_block(rel, txt),
                        note=f"{pages} pages, sent as extracted text (diagrams/images inside not seen)")
    if ext == ".pptx":
        txt = _pptx_text(path)
        return Artifact(rel, "pptx", sha, size, text=txt, block=_text_block(rel, txt),
                        note="slide text + notes (slide images not extracted)")
    if ext == ".docx":
        txt = _docx_text(path)
        return Artifact(rel, "docx", sha, size, text=txt, block=_text_block(rel, txt))
    if ext in TEXT_EXT or lname in SPECIAL_NAMES or lname.endswith(".env.example"):
        txt = data.decode("utf-8", errors="replace")
        kind = "diagram" if ext in (".mmd", ".mermaid", ".puml") else "text"
        return Artifact(rel, kind, sha, size, text=txt, block=_text_block(rel, txt))
    return (rel, f"unsupported type '{ext or path.name}'")


def load_bundle(folder: str | Path, context: str = "", pdf_mode: str = "auto") -> Bundle:
    """pdf_mode: auto (native if <= PDF_NATIVE_MAX_PAGES pages), native, or text."""
    root = Path(folder).resolve()
    b = Bundle(root=str(root), context_text=context.strip())
    if root.is_file():
        files = [root]
        base = root.parent
    else:
        files = sorted(p for p in root.rglob("*") if p.is_file() and not any(
            part.startswith(".") for part in p.relative_to(root).parts))
        base = root
    for p in files:
        rel = str(p.relative_to(base))
        res = load_artifact(p, rel, pdf_mode)
        if isinstance(res, Artifact):
            b.artifacts.append(res)
        else:
            b.skipped.append(res)
    return b

from __future__ import annotations

import json
import re
from dataclasses import asdict
from html.parser import HTMLParser
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.request import Request, urlopen

from .official_sources import OFFICIAL_SOURCES, OfficialSource


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self._skip_depth += 1
        if tag in {"p", "div", "li", "h1", "h2", "h3", "tr", "br"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self._skip_depth:
            self._skip_depth -= 1
        if tag in {"p", "li", "h1", "h2", "h3", "tr"}:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            text = data.strip()
            if text:
                self._parts.append(text)

    def text(self) -> str:
        raw = " ".join(self._parts)
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n\s*\n+", "\n", raw)
        return raw.strip()


def import_official_sources(
    raw_dir: Path = Path("data/raw"),
    processed_path: Path = Path("data/processed/documents.jsonl"),
    sources: tuple[OfficialSource, ...] = OFFICIAL_SOURCES,
) -> int:
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_path.parent.mkdir(parents=True, exist_ok=True)
    error_path = processed_path.with_name("import_errors.jsonl")

    imported = 0
    with processed_path.open("w", encoding="utf-8") as output, error_path.open("w", encoding="utf-8") as errors:
        for source in sources:
            try:
                payload = fetch_url(source.url)
            except Exception as exc:
                errors.write(
                    json.dumps(
                        {
                            "title": source.title,
                            "url": source.url,
                            "topic": source.topic,
                            "error": str(exc),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                continue
            suffix = ".pdf" if source.resource_type == "pdf" else ".html"
            raw_file = raw_dir / f"{source.slug}{suffix}"
            if source.resource_type == "pdf":
                raw_file.write_bytes(payload)
                text = extract_pdf_text(payload)
            else:
                html = payload.decode("utf-8", errors="replace")
                raw_file.write_text(html, encoding="utf-8")
                parser = VisibleTextParser()
                parser.feed(html)
                text = parser.text()
            if not text:
                continue
            record = {
                "id": source.slug,
                "text": text,
                "metadata": asdict(source) | {"raw_file": str(raw_file)},
            }
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
            imported += 1
    return imported


def fetch_url(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Off_WebSec_RAG/0.1 university project"})
    with urlopen(request, timeout=20) as response:
        return response.read()


    try:
        from pypdf import PdfReader
    except ImportError:
        return "PDF source downloaded. Install pypdf to extract searchable PDF text."
    with NamedTemporaryFile(suffix=".pdf", delete=False) as handle:
        handle.write(payload)
        temp_path = Path(handle.name)
    try:
        pages = [(page.extract_text() or "") for page in reader.pages]
        text = "\n".join(pages)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()
        temp_path.unlink(missing_ok=True)
    finally:
        reader = PdfReader(str(temp_path))



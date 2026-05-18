from __future__ import annotations

import json
import re
from dataclasses import asdict
from html.parser import HTMLParser
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import quote, unquote, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from .official_sources import OFFICIAL_SOURCES, OWASP_COMMUNITY_ATTACKS_INDEX_URL, OfficialSource


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "noscript", "svg", "button"}:
            self._skip_depth += 1
        if tag in {"p", "div", "li", "h1", "h2", "h3", "tr", "br"}:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg", "button"} and self._skip_depth:
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


class AttackLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._current_href = ""
        self._current_text: list[str] = []
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href", "")
        if href:
            self._current_href = str(href)
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href:
            text = data.strip()
            if text:
                self._current_text.append(text)

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._current_href:
            return
        text = " ".join(self._current_text).strip()
        if text:
            self.links.append((self._current_href, text))
        self._current_href = ""
        self._current_text = []


def import_official_sources(
    raw_dir: Path = Path("data/raw"),
    processed_path: Path = Path("data/processed/documents.jsonl"),
    sources: tuple[OfficialSource, ...] = OFFICIAL_SOURCES,
) -> int:
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_path.parent.mkdir(parents=True, exist_ok=True)
    error_path = processed_path.with_name("import_errors.jsonl")

    imported = 0
    expanded_sources = expand_sources(sources)
    with processed_path.open("w", encoding="utf-8") as output, error_path.open("w", encoding="utf-8") as errors:
        for source in expanded_sources:
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
                text = normalize_imported_text(parser.text())
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


def expand_sources(sources: tuple[OfficialSource, ...]) -> tuple[OfficialSource, ...]:
    expanded: list[OfficialSource] = list(sources)
    for source in sources:
        if source.url.rstrip("/") != OWASP_COMMUNITY_ATTACKS_INDEX_URL.rstrip("/"):
            continue
        try:
            html = fetch_url(source.url).decode("utf-8", errors="replace")
        except Exception:
            continue
        expanded.extend(discover_owasp_community_attack_sources(html, source.url))
    return dedupe_sources(expanded)


def discover_owasp_community_attack_sources(html: str, index_url: str = OWASP_COMMUNITY_ATTACKS_INDEX_URL) -> tuple[OfficialSource, ...]:
    parser = AttackLinkParser()
    parser.feed(html)
    sources: list[OfficialSource] = []
    seen: set[str] = set()
    for href, text in parser.links:
        url = sanitize_url(urljoin(index_url, href).split("#", 1)[0])
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        if parsed.netloc not in {"owasp.org", "www.owasp.org"}:
            continue
        if not path.startswith("/www-community/attacks/") or path == "/www-community/attacks":
            continue
        if url in seen:
            continue
        seen.add(url)
        title = normalize_attack_title(text, path)
        sources.append(
            OfficialSource(
                topic=infer_attack_topic(title, url),
                title=f"OWASP Community Attack: {title}",
                url=url,
                authority="OWASP",
            )
        )
    return tuple(sources)


def normalize_attack_title(text: str, path: str) -> str:
    title = re.sub(r"\s+", " ", text).strip(" -")
    if not title or len(title) < 3:
        title = unquote(path.rsplit("/", 1)[-1]).replace("_", " ").replace("-", " ")
    title = title.replace("¶", "").strip()
    return title


def infer_attack_topic(title: str, url: str) -> str:
    value = f"{title} {unquote(url)}".lower().replace("_", " ").replace("-", " ")
    topic_rules = (
        ("sql_injection", ("sql injection", "blind sql")),
        ("nosql_injection", ("nosql", "no sql")),
        ("ldap_injection", ("ldap injection",)),
        ("xpath_injection", ("xpath injection", "xpath")),
        ("csv_injection", ("csv injection", "formula injection")),
        ("xss", ("cross site scripting", "xss", "cross-site scripting")),
        ("dom_xss", ("dom based", "dom-based", "client side url redirect")),
        ("cors", ("cors", "cross origin resource sharing")),
        ("ssrf", ("server side request forgery", "ssrf")),
        ("csrf", ("csrf", "xsrf", "cross site request forgery")),
        ("xxe", ("xml external entity", "xxe")),
        ("ddos", ("denial of service", "dos", "ddos", "traffic flood", "amplification")),
        ("open_redirect", ("open redirect", "unvalidated redirect", "execution after redirect")),
        ("clickjacking", ("clickjacking", "qrljacking", "cross frame scripting", "ui redress")),
        ("path_traversal", ("path traversal", "directory traversal", "relative path traversal")),
        ("command_injection", ("command injection", "command execution")),
        ("code_injection", ("code injection", "eval injection", "function injection", "resource injection")),
        ("response_splitting", ("response splitting", "crlf")),
        ("log_injection", ("log injection", "log forging")),
        ("parameter_tampering", ("parameter tampering", "parameter delimiter", "parameter pollution")),
        ("reverse_tabnabbing", ("reverse tabnabbing", "tabnabbing")),
        ("information_disclosure", ("full path disclosure", "information disclosure", "data leakage")),
        ("session_management", ("session fixation", "session hijacking", "session prediction")),
        ("authentication", ("brute force", "password spraying", "credential stuffing")),
        ("access_control", ("forced browsing", "idor", "direct object reference", "authorization")),
        ("host_header", ("http headers", "http header", "ip spoofing via http headers")),
        ("web_cache_poisoning", ("cache poisoning",)),
        ("content_spoofing", ("content spoofing",)),
        ("web_llm_attacks", ("mcp tool poisoning", "llm")),
    )
    for topic, markers in topic_rules:
        if any(topic_marker_matches(value, marker) for marker in markers):
            return topic
    return "web_attack"


def sanitize_url(url: str) -> str:
    parsed = urlparse(url)
    path = quote(unquote(parsed.path), safe="/()_-")
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def topic_marker_matches(value: str, marker: str) -> bool:
    if len(marker) <= 4:
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", value))
    return marker in value


def dedupe_sources(sources: list[OfficialSource]) -> tuple[OfficialSource, ...]:
    deduped: list[OfficialSource] = []
    seen: set[str] = set()
    for source in sources:
        key = source.url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(source)
    return tuple(deduped)


def normalize_imported_text(text: str) -> str:
    text = text.replace("Â", " ")
    text = re.sub(r"\bFor full functionality of this site it is necessary to enable JavaScript\.\s*", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bSkip to content\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bEdit on GitHub\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bStore This website uses cookies.*?Accept x Store Donate Join\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bDonate Join\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bThank you for visiting OWASP\.org\..*?programmatically ported from its previous wiki page\.", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bThere.?s still some work to be done\.", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bThis is an example of a Project or Chapter Page\.", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bWatch Star The OWASP.*$", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def fetch_url(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Off_WebSec_RAG/0.1 university project"})
    with urlopen(request, timeout=20) as response:
        return response.read()


def extract_pdf_text(payload: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError:
        return "PDF source downloaded. Install pypdf to extract searchable PDF text."

    with NamedTemporaryFile(suffix=".pdf", delete=False) as handle:
        handle.write(payload)
        temp_path = Path(handle.name)
    try:
        reader = PdfReader(str(temp_path))
        pages = [(page.extract_text() or "") for page in reader.pages]
        text = "\n".join(pages)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()
    finally:
        temp_path.unlink(missing_ok=True)



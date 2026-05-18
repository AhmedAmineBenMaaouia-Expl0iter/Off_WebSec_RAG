from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .chunking import Chunk

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
STOPWORDS = {
    "a", "about", "an", "and", "are", "can", "corpus", "define", "describe",
    "do", "does", "explain", "for", "from", "how", "in", "is", "me", "of",
    "on", "or", "please", "tell", "the", "this", "to", "what", "why", "with",
    "attack", "attacks", "issue", "problem", "security", "vulnerability",
    "vulnerabilities", "web",
}

TOPIC_ALIASES: dict[str, tuple[str, ...]] = {
    "sql_injection": (
        "sql injection", "sqli", "sql inj", "database injection", "unsafe sql",
        "prepared statement", "prepared statements", "parameterized query",
        "parameterized queries", "query parameterization", "sqlinjection", "sqlii",
    ),
    "nosql_injection": (
        "nosql injection", "nosql", "no sql", "nosqli", "mongodb injection",
        "mongo injection", "query selector injection", "operator injection", "nosqlinjection",
    ),
    "ldap_injection": ("ldap injection", "ldap", "directory injection", "ldap query injection", "ldapinjection"),
    "xpath_injection": ("xpath injection", "xpath", "blind xpath injection", "xpathinjection"),
    "csv_injection": ("csv injection", "formula injection", "spreadsheet injection", "csvinjection"),
    "injection": ("injection", "code injection", "interpreter injection"),
    "xss": (
        "xss", "cross site scripting", "cross-site scripting", "cross scripting",
        "reflected xss", "stored xss", "client side script injection", "crosssitescripting",
    ),
    "dom_xss": ("dom xss", "dom based xss", "dom-based xss", "client side xss"),
    "dom_clobbering": ("dom clobbering", "dom clobber", "html clobbering"),
    "ssrf": (
        "ssrf", "server side request forgery", "server-side request forgery",
        "server request forgery", "metadata service", "internal service fetch", "serversiderequestforgery",
    ),
    "csrf": (
        "csrf", "xsrf", "cross site request forgery", "cross-site request forgery",
        "anti csrf", "csrf token", "crosssiterequestforgery",
    ),
    "xxe": ("xxe", "xml external entity", "external entity injection", "xml entity", "xmlexternalentity"),
    "ddos": (
        "dos",
        "ddos",
        "d d o s",
        "d o s",
        "distributed denial of service",
        "denial of service",
        "denialofservice",
        "dos attack",
        "service exhaustion",
        "resource exhaustion",
    ),
    "file_upload": ("file upload", "fileupload", "unrestricted file upload", "upload vulnerability", "malicious upload"),
    "path_traversal": (
        "path traversal", "pathtraversal", "directory traversal", "file path traversal", "lfi",
        "rfi", "local file inclusion", "remote file inclusion",
    ),
    "command_injection": ("command injection", "commandinjection", "os command injection", "shell injection", "rce command"),
    "code_injection": ("code injection", "eval injection", "dynamic code evaluation", "function injection", "resource injection"),
    "deserialization": ("deserialization", "untrusted deserialization", "insecure deserialization"),
    "authentication": (
        "authentication", "login", "password", "credential", "brute force",
        "credential stuffing", "password reset", "account takeover",
    ),
    "access_control": (
        "access control", "authorization", "idor", "bola", "broken access control",
        "authorization bypass", "object level authorization", "user controlled key",
    ),
    "broken_access_control": ("broken access control", "access control", "authorization"),
    "security_misconfiguration": ("security misconfiguration", "misconfiguration"),
    "session_management": ("session management", "session fixation", "cookie"),
    "api_security": ("api security", "rest security", "api", "api endpoint", "rest api"),
    "jwt": (
        "jwt", "json web token", "json web tokens", "token forgery",
        "algorithm confusion", "jwt none", "hs256", "rs256",
    ),
    "ssti": (
        "ssti", "server side template injection", "server-side template injection",
        "template injection", "jinja injection", "twig injection", "serversidetemplateinjection",
    ),
    "request_smuggling": (
        "request smuggling", "http request smuggling", "http desync",
        "desynchronization", "cl te", "te cl", "requestsmuggling",
    ),
    "web_cache_poisoning": (
        "web cache poisoning", "cache poisoning", "cache deception",
        "web cache deception", "cache key", "cachepoisoning", "webcachepoisoning",
    ),
    "web_cache_deception": ("web cache deception", "webcachedeception", "cache deception", "cache deception attack"),
    "graphql": ("graphql", "graphql api", "introspection", "graphql query"),
    "oauth": ("oauth", "oauth authentication", "oauth2", "openid connect", "oidc"),
    "cors": (
        "cors", "cross origin resource sharing", "cross-origin resource sharing",
        "access control allow origin", "acao", "origin header",
    ),
    "open_redirect": (
        "open redirect", "unvalidated redirect", "url redirect", "redirect vulnerability",
        "open forwarding", "unvalidated forwards", "unvalidated redirects",
        "unvalidated redirects and forwards", "openredirect", "open redirection",
    ),
    "clickjacking": ("clickjacking", "clickjack", "ui redress", "ui redressing", "iframe overlay", "frame busting"),
    "mass_assignment": ("mass assignment", "massassignment", "overposting", "autobinding", "object injection", "property binding"),
    "prototype_pollution": ("prototype pollution", "prototypepollution", "proto pollution", "__proto__", "constructor prototype"),
    "websocket_security": ("websocket", "websockets", "web socket", "ws security", "websocket hijacking"),
    "host_header": ("host header", "hostheader", "http host header", "host header injection", "password reset poisoning"),
    "response_splitting": ("response splitting", "http response splitting", "crlf injection", "crlf"),
    "log_injection": ("log injection", "log forging", "dialog forging", "lies in the loop", "hitl dialog"),
    "parameter_tampering": (
        "parameter tampering", "parameter pollution", "http parameter pollution",
        "parameter delimiter", "query parameter tampering",
    ),
    "reverse_tabnabbing": ("reverse tabnabbing", "tabnabbing", "target blank", "window opener"),
    "content_spoofing": ("content spoofing", "content injection", "text injection"),
    "race_condition": ("race condition", "race conditions", "limit overrun", "concurrency bug", "parallel requests"),
    "business_logic": ("business logic", "logic flaw", "logic flaws", "workflow bypass", "price manipulation"),
    "security_headers": ("security headers", "http headers", "hsts", "x frame options", "x content type options"),
    "content_security_policy": ("content security policy", "csp", "script-src", "frame-ancestors"),
    "xs_leaks": ("xs leaks", "xs-leaks", "cross site leaks", "cross-site leaks", "side channel web"),
    "ajax_security": ("ajax", "ajax security", "xmlhttprequest", "xhr", "client side api call"),
    "information_disclosure": (
        "information disclosure", "information exposure", "sensitive information",
        "error message", "verbose error", "stack trace", "debug information",
    ),
    "web_llm_attacks": ("web llm", "llm attack", "llm attacks", "prompt injection", "indirect prompt injection"),
    "web_attack": ("abuse of functionality", "binary planting", "buffer overflow", "format string attack"),
}


@dataclass(frozen=True)
class RetrievalResult:
    chunk: Chunk
    score: float


class BM25Index:
    """Small local BM25 index for the Simple RAG baseline."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.chunks: list[Chunk] = []
        self.document_frequency: dict[str, int] = {}
        self.tokenized_chunks: list[list[str]] = []
        self.doc_lengths: list[int] = []
        self.avgdl = 0.0

    def fit(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        self.tokenized_chunks = [tokenize(searchable_text(chunk)) for chunk in chunks]
        self.doc_lengths = [len(tokens) for tokens in self.tokenized_chunks]
        self.avgdl = sum(self.doc_lengths) / max(len(self.doc_lengths), 1)

        df: Counter[str] = Counter()
        for tokens in self.tokenized_chunks:
            df.update(set(tokens))
        self.document_frequency = dict(df)

    def search(self, query: str, top_k: int = 4) -> list[RetrievalResult]:
        query_topics = detect_topics(query)
        query_terms = expanded_query_terms(query, query_topics)
        if not query_terms:
            return []

        results: list[RetrievalResult] = []
        for chunk, tokens, doc_length in zip(self.chunks, self.tokenized_chunks, self.doc_lengths):
            if not query_topics and not has_enough_query_term_coverage(query_terms, tokens):
                continue
            score = self._bm25_score(query_terms, tokens, doc_length)
            score += metadata_boost(chunk, query_terms, query_topics)
            score += content_quality_adjustment(chunk, query_topics)
            score = apply_topic_guard(score, chunk, query_topics)
            if score >= minimum_score(query_topics):
                results.append(RetrievalResult(chunk=chunk, score=score))

        results.sort(key=lambda item: item.score, reverse=True)
        if query_topics and not any(chunk_topic(result.chunk) in query_topics for result in results[:top_k]):
            return []
        return results[:top_k]

    def save(self, path: Path = Path("storage/simple_index.json")) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "backend": "bm25",
            "k1": self.k1,
            "b": self.b,
            "document_frequency": self.document_frequency,
            "chunks": [asdict(chunk) for chunk in self.chunks],
            "tokenized_chunks": self.tokenized_chunks,
            "doc_lengths": self.doc_lengths,
            "avgdl": self.avgdl,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        save_chroma_snapshot(path.with_suffix("").parent / "chroma", self.chunks)

    @classmethod
    def load(cls, path: Path = Path("storage/simple_index.json")) -> "BM25Index":
        payload = json.loads(path.read_text(encoding="utf-8"))
        index = cls(k1=float(payload.get("k1", 1.5)), b=float(payload.get("b", 0.75)))
        index.document_frequency = {key: int(value) for key, value in payload.get("document_frequency", {}).items()}
        index.chunks = [Chunk(**item) for item in payload["chunks"]]
        index.tokenized_chunks = [list(tokens) for tokens in payload.get("tokenized_chunks", [])]
        if not index.tokenized_chunks:
            index.tokenized_chunks = [tokenize(searchable_text(chunk)) for chunk in index.chunks]
        index.doc_lengths = [int(value) for value in payload.get("doc_lengths", [])] or [len(tokens) for tokens in index.tokenized_chunks]
        index.avgdl = float(payload.get("avgdl", 0.0)) or sum(index.doc_lengths) / max(len(index.doc_lengths), 1)
        if not index.document_frequency:
            df: Counter[str] = Counter()
            for tokens in index.tokenized_chunks:
                df.update(set(tokens))
            index.document_frequency = dict(df)
        return index

    def _bm25_score(self, query_terms: list[str], tokens: list[str], doc_length: int) -> float:
        counts = Counter(tokens)
        total_docs = max(len(self.chunks), 1)
        score = 0.0
        for term in query_terms:
            frequency = counts.get(term, 0)
            if not frequency:
                continue
            df = self.document_frequency.get(term, 0)
            idf = math.log(1 + (total_docs - df + 0.5) / (df + 0.5))
            denominator = frequency + self.k1 * (1 - self.b + self.b * doc_length / max(self.avgdl, 1))
            score += idf * (frequency * (self.k1 + 1)) / denominator
        return score


def tokenize(text: str) -> list[str]:
    return [match.group(0).lower() for match in TOKEN_RE.finditer(text)]


def expanded_query_terms(query: str, topics: list[str]) -> list[str]:
    terms = [term for term in tokenize(query) if term not in STOPWORDS]
    for topic in topics:
        terms.extend(tokenize(topic.replace("_", " ")))
        for alias in TOPIC_ALIASES.get(topic, ()):
            terms.extend(tokenize(alias))
    return list(dict.fromkeys(terms))


def detect_topics(text: str) -> list[str]:
    normalized = " ".join(tokenize(text))
    padded = f" {normalized} "
    topics: list[str] = []
    for topic, aliases in TOPIC_ALIASES.items():
        for alias in aliases:
            alias_norm = " ".join(tokenize(alias))
            if len(alias_norm) <= 4:
                pattern = rf"(?<![a-z0-9]){re.escape(alias_norm)}(?![a-z0-9])"
                if re.search(pattern, normalized):
                    topics.append(topic)
                    break
            elif alias_norm in padded:
                topics.append(topic)
                break
    return reduce_overlapping_topics(topics)


def reduce_overlapping_topics(topics: list[str]) -> list[str]:
    reduced = list(dict.fromkeys(topics))
    specific_injections = {
        "sql_injection",
        "nosql_injection",
        "ldap_injection",
        "xpath_injection",
        "csv_injection",
        "command_injection",
        "code_injection",
        "ssti",
        "xxe",
    }
    if "injection" in reduced and any(topic in reduced for topic in specific_injections):
        reduced.remove("injection")
    if "nosql_injection" in reduced and "sql_injection" in reduced:
        reduced.remove("sql_injection")
    if "broken_access_control" in reduced and "access_control" in reduced:
        reduced.remove("broken_access_control")
    if "xss" in reduced and "dom_xss" in reduced:
        reduced.remove("xss")
    if "web_cache_poisoning" in reduced and "web_cache_deception" in reduced:
        reduced.remove("web_cache_poisoning")
    if "content_security_policy" in reduced and "security_headers" in reduced:
        reduced.remove("security_headers")
    return reduced


def metadata_text(chunk: Chunk) -> str:
    metadata = chunk.metadata
    return " ".join(str(metadata.get(key, "")) for key in ("title", "topic", "authority", "url", "document_id"))


def searchable_text(chunk: Chunk) -> str:
    return chunk.text


def metadata_boost(chunk: Chunk, query_terms: list[str], query_topics: list[str]) -> float:
    metadata_terms = set(tokenize(metadata_text(chunk)))
    overlap = len(set(query_terms) & metadata_terms)
    boost = min(overlap * 0.15, 0.8)
    topic = chunk_topic(chunk)
    if topic and topic in query_topics:
        boost += 1.2
    return boost


def content_quality_adjustment(chunk: Chunk, query_topics: list[str]) -> float:
    text = chunk.text.lower()
    title = str(chunk.metadata.get("title", "")).lower()
    adjustment = 0.0
    noisy_markers = (
        "home > cwe list",
        "id lookup:",
        "made with material for mkdocs",
        "©copyright",
        "creative commons attribution",
        "redirecting...",
        "references ¶",
        "related articles ¶",
        "tools and code used",
    )
    for marker in noisy_markers:
        if marker in text:
            adjustment -= 4.0
    if "table of contents" in text:
        adjustment -= 2.5
    if "owasp community attack" in title and (
        "store this website uses cookies" in text
        or "thank you for visiting owasp.org" in text
        or "needed to be programmatically ported" in text
    ):
        adjustment -= 1.8
    useful_markers = (
        "what is ",
        "definition",
        "description",
        "introduction",
        "attack vector",
        "vulnerability",
        "weakness",
        "denial of service",
        "availability",
        "successful dos attack",
        "rate limiting",
        "throttling",
        "limit total request",
        "resource exhaustion",
        "prevent",
        "mitigat",
    )
    if any(marker in text for marker in useful_markers):
        adjustment += 1.5
    if query_topics and any(alias in text for topic in query_topics for alias in TOPIC_ALIASES.get(topic, ())):
        adjustment += 1.0
    if "blind " in title and "blind" not in text[:80]:
        adjustment -= 0.6
    return adjustment


def chunk_topic(chunk: Chunk) -> str:
    return str(chunk.metadata.get("topic", ""))


def apply_topic_guard(score: float, chunk: Chunk, query_topics: list[str]) -> float:
    if not query_topics:
        return score
    topic = chunk_topic(chunk)
    if topic in query_topics:
        return score
    related = {
        "xss": {"dom_xss"},
        "dom_xss": {"xss"},
        "access_control": {"broken_access_control"},
        "broken_access_control": {"access_control"},
    }
    allowed = set(query_topics)
    for query_topic in query_topics:
        allowed.update(related.get(query_topic, set()))
    if topic in allowed:
        return score * 0.85
    return score * 0.08


def minimum_score(query_topics: list[str]) -> float:
    return 1.0 if query_topics else 1.8


def has_enough_query_term_coverage(query_terms: list[str], tokens: list[str]) -> bool:
    """Avoid answering unknown subjects from a single generic word match.

    A query like "quantum cryptography" should not be grounded by a web testing
    chunk that only happens to contain the word "cryptography".
    """
    terms = {term for term in query_terms if len(term) > 2}
    if not terms:
        return False
    matches = terms & set(tokens)
    if len(terms) == 1:
        return bool(matches)
    if len(terms) == 2:
        return len(matches) == 2
    return len(matches) >= max(2, math.ceil(len(terms) * 0.65))


def save_chroma_snapshot(path: Path, chunks: list[Chunk]) -> None:
    """Persist chunk metadata in ChromaDB when available.

    BM25 remains the retrieval algorithm required for this simple RAG baseline.
    ChromaDB is used as the vector database / indexed corpus store so the project
    includes a real vector DB component instead of only a local JSON file.
    """
    try:
        import chromadb
    except Exception:
        return

    path.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(path))
    try:
        try:
            client.delete_collection("web_attack_chunks")
        except Exception:
            pass
        collection = client.get_or_create_collection(name="web_attack_chunks", embedding_function=None)
        if chunks:
            collection.add(
                ids=[chunk.id for chunk in chunks],
                documents=[chunk.text for chunk in chunks],
                metadatas=[flatten_metadata(chunk.metadata) for chunk in chunks],
                embeddings=[[0.0] for _ in chunks],
            )
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
        clear_cache = getattr(client, "clear_system_cache", None)
        if callable(clear_cache):
            clear_cache()


def flatten_metadata(metadata: dict) -> dict:
    clean: dict[str, str | int | float | bool] = {}
    for key, value in metadata.items():
        if isinstance(value, (str, int, float, bool)):
            clean[key] = value
        elif value is not None:
            clean[key] = str(value)
    return clean


# Backward-compatible name for older CLI/web imports. The implementation is BM25.
TfidfVectorIndex = BM25Index

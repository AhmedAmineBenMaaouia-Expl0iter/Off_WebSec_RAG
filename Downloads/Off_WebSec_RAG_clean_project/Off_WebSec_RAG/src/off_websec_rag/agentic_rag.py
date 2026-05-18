from __future__ import annotations

import re
from dataclasses import dataclass

from .retrieval import BM25Index, RetrievalResult, detect_topics, reduce_overlapping_topics
from .simple_rag import (
    NOT_ENOUGH,
    best_sentence,
    clean_text,
    is_unsafe_operational_request,
    looks_defensive,
    looks_like_definition,
    looks_risk_or_impact,
    normalize_prompt_text,
    topic_label,
)


@dataclass(frozen=True)
class AgenticResponse:
    answer: str
    results: list[RetrievalResult]


@dataclass(frozen=True)
class ChainEvidence:
    topic: str
    results: list[RetrievalResult]


class AttackChainAgent:
    """Defensive agentic RAG assistant for web attack chain feasibility.

    The agent reasons over retrieved official-source chunks, but deliberately
    avoids payloads, exploit commands, and step-by-step attack execution.
    """

    def __init__(self, index: BM25Index) -> None:
        self.index = index

    def answer(self, question: str, top_k_per_topic: int = 4) -> AgenticResponse:
        normalized, corrected = normalize_prompt_text(question)
        topics = extract_chain_topics(normalized)
        unsafe = is_chain_abuse_request(question)

        if len(topics) < 2:
            return AgenticResponse(
                answer=not_supported_answer(question, normalized, topics, corrected),
                results=[],
            )

        evidence = [
            ChainEvidence(topic=topic, results=topic_results(self.index, topic, top_k_per_topic))
            for topic in topics[:6]
        ]
        supported = [item for item in evidence if item.results]
        all_results = merge_agent_results([result for item in supported for result in item.results])

        feasibility = assess_feasibility([item.topic for item in supported], topics)
        answer = format_chain_answer(
            question=question,
            normalized=normalized,
            corrected=corrected,
            topics=topics,
            supported=supported,
            missing=[item.topic for item in evidence if not item.results],
            feasibility=feasibility,
            unsafe=unsafe,
            results=all_results,
        )
        return AgenticResponse(answer=answer, results=all_results)


def extract_chain_topics(normalized_question: str) -> list[str]:
    topics = list(detect_topics(normalized_question))
    feature_markers = (
        ("file_upload", r"\b(upload|uploads|uploaded file|image upload|avatar upload|file handling)\b"),
        ("access_control", r"\b(admin panel|admin dashboard|idor|access control|authorization|permission|privilege|auth bypass)\b"),
        ("authentication", r"\b(login|signin|sign in|password reset|credential|account takeover|auth bypass|weak auth)\b"),
        ("session_management", r"\b(session|cookie|session fixation|session hijack)\b"),
        ("xss", r"\b(comment|comments|stored content|profile bio|user content)\b"),
        ("open_redirect", r"\b(redirect|callback url|return url)\b"),
        ("api_security", r"\b(api|rest endpoint|graphql endpoint)\b"),
    )
    for topic, pattern in feature_markers:
        if re.search(pattern, normalized_question) and topic not in topics:
            topics.append(topic)
    return reduce_overlapping_topics(topics)


def topic_results(index: BM25Index, topic: str, top_k: int) -> list[RetrievalResult]:
    query = chain_topic_query(topic)
    candidates = index.search(query, top_k=max(top_k * 4, 12))
    exact = [result for result in candidates if result.chunk.metadata.get("topic") == topic]
    if exact:
        return exact[:top_k]
    related = related_topics(topic)
    return [result for result in candidates if result.chunk.metadata.get("topic") in related][:top_k]


def chain_topic_query(topic: str) -> str:
    labels = {
        "sql_injection": "SQL injection definition risks parameterized queries prevention",
        "xss": "cross-site scripting definition output encoding content security policy prevention",
        "csrf": "cross-site request forgery csrf token same site origin referer prevention",
        "ssrf": "server-side request forgery internal request allowlist network segmentation prevention",
        "file_upload": "file upload vulnerability validation storage content type prevention",
        "access_control": "broken access control authorization idor privilege prevention",
        "authentication": "authentication vulnerability login credential brute force prevention",
        "session_management": "session management cookie session fixation hijacking prevention",
        "xxe": "xml external entity xxe secure parser external entity prevention",
        "open_redirect": "open redirect unvalidated redirect allowlist prevention",
        "path_traversal": "path traversal directory traversal file path validation prevention",
        "command_injection": "os command injection shell injection prevention",
        "request_smuggling": "http request smuggling desync prevention",
        "web_cache_poisoning": "web cache poisoning cache key prevention",
        "jwt": "json web token jwt algorithm confusion prevention",
    }
    return labels.get(topic, f"{topic_label([topic])} definition risk mitigation prevention")


def related_topics(topic: str) -> set[str]:
    related = {
        "access_control": {"broken_access_control"},
        "broken_access_control": {"access_control"},
        "xss": {"dom_xss"},
        "dom_xss": {"xss"},
        "authentication": {"session_management"},
        "session_management": {"authentication"},
    }
    return related.get(topic, set())


def assess_feasibility(supported_topics: list[str], requested_topics: list[str]) -> str:
    if len(supported_topics) < 2:
        return "not supported"
    if len(supported_topics) < len(requested_topics):
        return "weakly supported"
    pairs = {frozenset(pair) for pair in synergy_pairs()}
    supported_set = set(supported_topics)
    if any(pair <= supported_set for pair in pairs):
        return "plausible"
    return "weakly supported"


def synergy_pairs() -> tuple[tuple[str, str], ...]:
    return (
        ("sql_injection", "authentication"),
        ("sql_injection", "access_control"),
        ("sql_injection", "xss"),
        ("xss", "csrf"),
        ("xss", "session_management"),
        ("xss", "file_upload"),
        ("file_upload", "access_control"),
        ("file_upload", "xss"),
        ("ssrf", "xxe"),
        ("ssrf", "access_control"),
        ("xxe", "path_traversal"),
        ("open_redirect", "authentication"),
        ("jwt", "authentication"),
        ("request_smuggling", "web_cache_poisoning"),
        ("host_header", "web_cache_poisoning"),
    )


def format_chain_answer(
    question: str,
    normalized: str,
    corrected: bool,
    topics: list[str],
    supported: list[ChainEvidence],
    missing: list[str],
    feasibility: str,
    unsafe: bool,
    results: list[RetrievalResult],
) -> str:
    citation_map = citation_numbers(results)
    lines = [
        "OFF_WEBSEC_RAG - Agentic RAG - Attack Chain Feasibility",
        "",
        f"Question: {question.strip()}",
        "Agent intent: attack_chain_feasibility",
        f"Detected attacks: {', '.join(topic_label([topic]) for topic in topics)}",
        f"Feasibility: {feasibility}",
        f"Evidence status: grounded in {len(citation_map)} official source(s)",
    ]
    if corrected or normalized != question.strip().lower():
        lines.append(f"Interpreted as: {normalized}")

    if unsafe:
        lines.extend(
            [
                "",
                "Safety handling:",
                "- I cannot provide payloads, exploitation steps, commands, or instructions for real-world abuse.",
                "- The assessment below stays at a defensive, high-level architecture and mitigation level.",
            ]
        )

    lines.extend(
        [
            "",
            "Agent trace:",
            f"- detect_attacks -> {', '.join(topics)}",
            f"- search_corpus -> {len(results)} grounded chunks across {len(supported)} supported attack(s)",
            f"- assess_chain_feasibility -> {feasibility}",
            "- recommend_chain_breaks -> defensive controls only",
        ]
    )

    if missing:
        lines.append(f"- evidence_gap -> no grounded chunk for {', '.join(topic_label([topic]) for topic in missing)}")

    lines.extend(["", "Assessment:"])
    lines.extend(assessment_lines(feasibility, supported, missing, citation_map))

    if feasibility != "not supported":
        lines.extend(["", "Possible high-level chain:"])
        lines.extend(chain_narrative(supported, citation_map))
        lines.extend(["", "Required preconditions:"])
        lines.extend(precondition_lines(supported))
        lines.extend(["", "Defensive breakpoints:"])
        lines.extend(defense_lines(supported, citation_map))

    if corrected or len(topics) <= 2:
        lines.extend(
            [
                "",
                "Prompt quality note:",
                "- The agent accepted the messy/plain-English prompt and normalized it before retrieval.",
                '- For sharper results, ask for a chain with named attacks and the target context, for example: "Can SQLi, XSS, and file upload be chained in a blog app, and where would defenders break it?"',
            ]
        )

    lines.extend(["", "Official sources:"])
    if citation_map:
        for number, result in citation_map.values():
            lines.append(f"[{number}] {result.chunk.metadata.get('title', 'official source')}")
            lines.append(f"    {result.chunk.metadata.get('url', '')}")
    else:
        lines.append("- No grounded official source was strong enough for a chain assessment.")

    lines.extend(["", "Retrieved evidence:"])
    for result in unique_sources(results)[:8]:
        lines.append(f"- {result.chunk.metadata.get('title', 'official source')} | BM25 score {result.score:.3f}")

    return "\n".join(lines)


def not_supported_answer(question: str, normalized: str, topics: list[str], corrected: bool) -> str:
    lines = [
        "OFF_WEBSEC_RAG - Agentic RAG - Attack Chain Feasibility",
        "",
        f"Question: {question.strip()}",
        "Agent intent: attack_chain_feasibility",
        f"Detected attacks: {', '.join(topic_label([topic]) for topic in topics) if topics else 'none'}",
        "Feasibility: not supported",
        "Evidence status: insufficient for chain reasoning",
    ]
    if corrected or normalized != question.strip().lower():
        lines.append(f"Interpreted as: {normalized}")
    lines.extend(
        [
            "",
            "Assessment:",
            f"- {NOT_ENOUGH}",
            "- Attack-chain feasibility needs at least two clearly named web attacks or app features.",
            "",
            "Prompt quality note:",
            "- The prompt is too vague for agentic chain reasoning.",
            '- Ask something like: "Can SQLi, XSS, and file upload be chained in a blog app, and where would defenders break it?"',
            "",
            "Official sources:",
            "- No grounded official source was strong enough for a chain assessment.",
        ]
    )
    return "\n".join(lines)


def assessment_lines(
    feasibility: str,
    supported: list[ChainEvidence],
    missing: list[str],
    citation_map: dict[str, tuple[int, RetrievalResult]],
) -> list[str]:
    if feasibility == "not supported":
        return [f"- {NOT_ENOUGH}"]
    if feasibility == "plausible":
        first = "The requested attacks can form a plausible defensive attack-chain scenario, but only under specific application conditions."
    else:
        first = "The corpus supports some requested attacks, but the full chain is only weakly supported or missing evidence for at least one link."
    lines = [f"- {first}"]
    for item in supported[:6]:
        mapped = mapped_topic_summary_line(item, citation_map)
        if mapped:
            lines.append(mapped)
            continue
        definition = best_sentence("", item.results, [item.topic], looks_like_definition)
        if definition:
            lines.append(f"- {topic_label([item.topic])}: {with_citation(definition, citation_map)}")
    if missing:
        lines.append(f"- Missing evidence for: {', '.join(topic_label([topic]) for topic in missing)}.")
    return lines


def mapped_topic_summary_line(item: ChainEvidence, citation_map: dict[str, tuple[int, RetrievalResult]]) -> str:
    summaries = {
        "sql_injection": "can affect database queries and may influence stored data, identity data, or authorization decisions if the application trusts database output.",
        "xss": "can affect users in the browser when untrusted content is rendered without safe encoding or sanitization.",
        "csrf": "can abuse a trusted user's browser session for unintended state-changing actions when request protections are missing.",
        "ssrf": "can make the server issue unintended requests, which matters most when internal systems or metadata services are reachable.",
        "file_upload": "can become a chain link when uploaded content is accepted, stored, served, or processed unsafely.",
        "access_control": "can let a user reach objects or actions outside their intended permissions.",
        "authentication": "can affect login, credential, or account recovery flows and may amplify another web weakness.",
        "session_management": "can affect session identifiers and browser trust after a user authenticates.",
        "xxe": "can affect XML parsing behavior and server-side resource access when parser hardening is missing.",
        "open_redirect": "can support social-engineering or account-flow abuse if redirects are user controlled.",
        "path_traversal": "can affect filesystem access when user-controlled path input is not constrained.",
        "command_injection": "can affect server command execution when user input reaches shell-like execution paths.",
        "request_smuggling": "can affect how front-end and back-end servers parse the same HTTP request.",
        "web_cache_poisoning": "can affect cached responses when attacker-controlled inputs influence cache behavior.",
        "jwt": "can affect token trust when signatures, algorithms, or claims are not validated strictly.",
    }
    if item.topic not in summaries:
        return ""
    title = str(item.results[0].chunk.metadata.get("title", ""))
    citation = f" [{citation_map[title][0]}]" if title in citation_map else ""
    return f"- {topic_label([item.topic])}: {summaries[item.topic]}{citation}"


def chain_narrative(supported: list[ChainEvidence], citation_map: dict[str, tuple[int, RetrievalResult]]) -> list[str]:
    topics = [item.topic for item in supported]
    lines: list[str] = []
    if {"sql_injection", "xss"} <= set(topics):
        lines.append("- A database-facing weakness and browser-facing script weakness can be related if unsafe data later appears in rendered pages, but this remains conditional on application behavior.")
    if {"file_upload", "xss"} <= set(topics):
        lines.append("- Upload handling can become part of a browser-side chain if uploaded content is served back unsafely or without strict validation.")
    if {"xss", "csrf"} <= set(topics):
        lines.append("- Browser/session trust issues can reinforce each other when user actions and rendered content are not strongly controlled.")
    if {"ssrf", "xxe"} <= set(topics):
        lines.append("- Server-side request primitives can become related when XML parsing or outbound request behavior reaches internal systems.")
    if {"access_control", "authentication"} & set(topics):
        lines.append("- Identity and authorization weaknesses can turn an initial web bug into broader unauthorized access if server-side checks are missing.")
    if not lines:
        joined = " -> ".join(topic_label([topic]) for topic in topics[:4])
        lines.append(f"- Possible relationship to investigate defensively: {joined}. The corpus supports the components, but not a guaranteed sequence.")
    for item in supported[:2]:
        risk = best_sentence("", item.results, [item.topic], looks_risk_or_impact)
        if risk:
            lines.append(f"- Corpus risk signal: {with_citation(risk, citation_map)}")
    return lines[:5]


def precondition_lines(supported: list[ChainEvidence]) -> list[str]:
    topics = {item.topic for item in supported}
    lines = [
        "- The affected features must exist in the same application or trust boundary.",
        "- The output of one weakness must be reachable by the next weakness; otherwise the items are separate risks, not a chain.",
    ]
    if "sql_injection" in topics:
        lines.append("- SQLi only becomes a chain link if database impact can influence identity, stored content, or authorization decisions.")
    if "file_upload" in topics:
        lines.append("- File upload only becomes a chain link if uploaded files are accepted, stored, served, or processed unsafely.")
    if "ssrf" in topics:
        lines.append("- SSRF only becomes a chain link if the server can reach sensitive internal or metadata services.")
    if "xss" in topics:
        lines.append("- XSS only becomes a chain link if attacker-controlled content reaches another user's browser context.")
    return lines


def defense_lines(supported: list[ChainEvidence], citation_map: dict[str, tuple[int, RetrievalResult]]) -> list[str]:
    lines: list[str] = []
    for item in supported:
        mapped = mapped_defense_line(item, citation_map)
        if mapped:
            lines.append(mapped)
            continue
        defense = best_sentence("", item.results, [item.topic], looks_defensive)
        if defense:
            lines.append(f"- {topic_label([item.topic])}: {with_citation(defense, citation_map)}")
    if not lines:
        lines.append("- Apply input validation, output encoding, strict authorization checks, least privilege, secure configuration, logging, and monitoring at each chain link.")
    return lines[:6]


def mapped_defense_line(item: ChainEvidence, citation_map: dict[str, tuple[int, RetrievalResult]]) -> str:
    controls = {
        "sql_injection": "use parameterized queries or prepared statements, avoid dynamic string-built queries, and keep database privileges limited.",
        "xss": "use contextual output encoding, framework escaping, safe sanitization, and Content Security Policy as a secondary control.",
        "csrf": "use unpredictable CSRF tokens, SameSite cookies, and Origin/Referer validation for state-changing requests.",
        "ssrf": "validate destinations with allowlists, block sensitive internal ranges, segment networks, and restrict metadata-service access.",
        "file_upload": "allow-list file types, validate content, store uploads safely outside executable paths, rename server-side, and scan uploads.",
        "access_control": "enforce server-side authorization checks on every request, deny by default, and apply least privilege.",
        "authentication": "use MFA where appropriate, rate limiting, secure password reset flows, and monitoring for suspicious login behavior.",
        "session_management": "protect cookies with secure attributes, rotate session identifiers, and invalidate sessions after sensitive changes.",
        "xxe": "disable external entity processing and use hardened XML parser configurations.",
        "open_redirect": "avoid user-controlled redirect targets or restrict them with a strict allowlist.",
        "path_traversal": "normalize and validate paths, enforce allowlisted directories, and avoid direct user-controlled filesystem paths.",
        "command_injection": "avoid shell invocation with user input and use safe APIs plus strict input validation.",
        "request_smuggling": "normalize front-end/back-end HTTP parsing and reject ambiguous request framing.",
        "web_cache_poisoning": "control cache keys, avoid caching attacker-influenced responses, and validate unkeyed inputs.",
        "jwt": "validate algorithms explicitly, verify signatures, enforce claims, and avoid accepting unsigned or confused-token states.",
    }
    if item.topic not in controls:
        return ""
    number = preferred_citation_number(item, citation_map)
    citation = f" [{number}]" if number else ""
    return f"- {topic_label([item.topic])}: {controls[item.topic]}{citation}"


def preferred_citation_number(item: ChainEvidence, citation_map: dict[str, tuple[int, RetrievalResult]]) -> int | None:
    preferred_title_markers = {
        "sql_injection": ("sql injection prevention", "query parameterization"),
        "xss": ("cross site scripting prevention", "xss prevention"),
        "csrf": ("csrf prevention", "cross-site request forgery prevention"),
        "ssrf": ("server side request forgery prevention", "ssrf prevention"),
        "file_upload": ("file upload cheat sheet",),
        "access_control": ("authorization cheat sheet", "access control"),
        "authentication": ("authentication cheat sheet",),
        "session_management": ("session management cheat sheet",),
        "xxe": ("xml external entity prevention",),
        "open_redirect": ("unvalidated redirects", "open redirect"),
        "path_traversal": ("path traversal",),
        "command_injection": ("os command injection",),
        "request_smuggling": ("request smuggling",),
        "web_cache_poisoning": ("cache poisoning",),
        "jwt": ("json web token", "jwt"),
    }
    markers = preferred_title_markers.get(item.topic, ())
    for marker in markers:
        for result in item.results:
            title = str(result.chunk.metadata.get("title", ""))
            if marker in title.lower() and title in citation_map:
                return citation_map[title][0]
    if item.results:
        title = str(item.results[0].chunk.metadata.get("title", ""))
        if title in citation_map:
            return citation_map[title][0]
    return None


def with_citation(sentence: str, citation_map: dict[str, tuple[int, RetrievalResult]]) -> str:
    text, title = split_source_title(sentence)
    if title and title in citation_map:
        return f"{text} [{citation_map[title][0]}]"
    return sentence


def split_source_title(sentence: str) -> tuple[str, str]:
    match = re.search(r"\s+\(([^()]+)\)$", sentence.strip())
    if not match:
        return sentence, ""
    return sentence[: match.start()].strip(), match.group(1).strip()


def citation_numbers(results: list[RetrievalResult]) -> dict[str, tuple[int, RetrievalResult]]:
    citations: dict[str, tuple[int, RetrievalResult]] = {}
    for result in unique_sources(results):
        title = str(result.chunk.metadata.get("title", "official source"))
        if title not in citations:
            citations[title] = (len(citations) + 1, result)
    return citations


def unique_sources(results: list[RetrievalResult]) -> list[RetrievalResult]:
    unique: list[RetrievalResult] = []
    seen: set[str] = set()
    for result in results:
        key = f"{result.chunk.metadata.get('title')}:{result.chunk.metadata.get('url')}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
    return unique


def merge_agent_results(results: list[RetrievalResult]) -> list[RetrievalResult]:
    by_id: dict[str, RetrievalResult] = {}
    for result in results:
        existing = by_id.get(result.chunk.id)
        if existing is None or result.score > existing.score:
            by_id[result.chunk.id] = result
    return sorted(by_id.values(), key=lambda item: item.score, reverse=True)


def is_chain_abuse_request(question: str) -> bool:
    lower = question.lower()
    if is_unsafe_operational_request(question):
        return True
    return bool(re.search(r"\b(payload|payloads|exploit steps|step by step|weaponize|shell|reverse shell|commands?)\b", lower))

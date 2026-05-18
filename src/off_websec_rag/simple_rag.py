from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .retrieval import BM25Index, RetrievalResult, TOPIC_ALIASES, detect_topics, tokenize


NOT_ENOUGH = "I do not have enough evidence in the imported official web attack corpus to answer that."
STOPWORDS_FOR_PROMPTS = {
    "a", "about", "an", "and", "are", "can", "do", "does", "explain", "for",
    "from", "give", "how", "i", "is", "me", "please", "tell", "the", "to",
    "what", "whats", "with", "you",
}


@dataclass(frozen=True)
class RagResponse:
    answer: str
    results: list[RetrievalResult]


@dataclass(frozen=True)
class PromptAnalysis:
    original: str
    normalized: str
    retrieval_question: str
    topics: list[str]
    comparison_intent: bool
    issues: list[str]
    suggestion: str

    @property
    def needs_feedback(self) -> bool:
        return bool(self.issues)


class SimpleRag:
    def __init__(self, index: BM25Index) -> None:
        self.index = index

    def answer(self, question: str, top_k: int = 30) -> RagResponse:
        prompt = analyze_prompt(question)
        if not prompt.topics and prompt.needs_feedback:
            return RagResponse(answer=refusal_answer(prompt), results=[])
        abuse_request = is_unsafe_operational_request(question)
        safe_question = defensive_rewrite(prompt.retrieval_question) if abuse_request else prompt.retrieval_question
        results = self.index.search(safe_question, top_k=top_k)
        topics = ordered_detected_topics(safe_question)
        if is_comparison_request(safe_question, topics):
            results = merge_results(results, comparison_support_results(self.index, topics))

        grounded = grounded_results(safe_question, results)
        if not grounded:
            return RagResponse(answer=refusal_answer(prompt), results=[])

        bullets = answer_bullets(safe_question, grounded)
        if abuse_request:
            bullets.insert(0, "I cannot help with instructions for real-world abuse. Here is the defensive, corpus-grounded version.")
        answer = format_answer(question, safe_question, bullets, grounded, prompt, abuse_request)
        return RagResponse(answer=answer, results=grounded)


def analyze_prompt(question: str) -> PromptAnalysis:
    original = question.strip()
    normalized, corrected = normalize_prompt_text(original)
    topics = ordered_detected_topics(normalized)
    comparison_intent = is_comparison_request(normalized, topics)
    issues: list[str] = []

    content_terms = [
        term for term in tokenize(normalized)
        if term not in STOPWORDS_FOR_PROMPTS and len(term) > 1
    ]
    vague_reference = bool(re.search(r"\b(it|this|that|thing|stuff|help)\b", normalized, re.IGNORECASE))

    if not original:
        issues.append("The prompt is empty; name the web attack and the type of answer you need.")
    elif corrected:
        issues.append("I corrected spelling, shorthand, or informal wording before retrieval.")

    if topics:
        if comparison_intent:
            missing = "comparison"
        elif wants_defensive_answer(normalized):
            missing = "defensive guidance"
        elif is_definition_request(normalized, topics):
            missing = "definition"
        else:
            missing = ""
        if len(content_terms) <= 2 or not missing:
            issues.append("The prompt is too short or underspecified, so I expanded it into a clearer retrieval question.")
    elif not topics and (len(content_terms) < 2 or vague_reference):
        issues.append("The prompt is too vague for grounded retrieval; name the exact web attack from the indexed corpus.")

    retrieval_question = build_retrieval_question(normalized or original, topics, comparison_intent)
    suggestion = prompt_suggestion(topics, comparison_intent)
    return PromptAnalysis(
        original=original,
        normalized=normalized,
        retrieval_question=retrieval_question,
        topics=topics,
        comparison_intent=comparison_intent,
        issues=list(dict.fromkeys(issues)),
        suggestion=suggestion,
    )


def normalize_prompt_text(question: str) -> tuple[str, bool]:
    text = unicodedata.normalize("NFKD", question)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.lower()
    text = re.sub(r"[_/\\|]+", " ", text)
    text = re.sub(r"([a-z])[-]+([a-z])", r"\1 \2", text)
    corrected = False
    replacements = (
        (r"\bwhts\b|\bwhats\b|\bwat\b|\bwht\b", "what is"),
        (r"\bpls\b|\bplz\b", "please"),
        (r"\bdfrnce\b|\bdiffrence\b|\bdifrence\b|\bdiffernce\b|\bdeffrence\b", "difference"),
        (r"\bdeffensive\b|\bdefencive\b|\bdefnsive\b|\bdefnse\b", "defensive"),
        (r"\bmitigration\b|\bmitigationss\b", "mitigation"),
        (r"\bvulns?\b", "vulnerability"),
        (r"\bsql\s*inj(?:ection|eciton|ction)?\b", "sql injection"),
        (r"\bsqlinj(?:ection|eciton|ction)?\b", "sql injection"),
        (r"\bsqlii\b", "sqli"),
        (r"\bcross\s*site\s*scriping\b|\bcross\s*xss\b", "cross site scripting"),
        (r"\bserver\s*side\s*req(?:uest)?\s*forgery\b", "server side request forgery"),
    )
    for pattern, replacement in replacements:
        text, count = re.subn(pattern, replacement, text)
        corrected = corrected or count > 0
    text = re.sub(r"[^a-z0-9+#.]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text, corrected


def build_retrieval_question(question: str, topics: list[str], comparison_intent: bool) -> str:
    if not topics:
        return question
    if comparison_intent and len(topics) >= 2:
        labels = [topic_label([topic]) for topic in topics[:3]]
        return "Compare " + " and ".join(labels) + "."
    if wants_defensive_answer(question):
        return f"How can defenders prevent or mitigate {topic_label(topics)}?"
    if is_definition_request(question, topics):
        return f"What is {topic_label(topics)}?"
    return f"What is {topic_label(topics)} and how can defenders prevent or mitigate it?"


def wants_defensive_answer(question: str) -> bool:
    return bool(re.search(r"\b(prevent|defen[cs]ive|defen[cs]e|mitigat|protect|respond|avoid|fix|secure|hardening)\b", question, re.IGNORECASE))


def prompt_suggestion(topics: list[str], comparison_intent: bool) -> str:
    if comparison_intent and len(topics) >= 2:
        return f'ask: "Compare {topic_label([topics[0]])} and {topic_label([topics[1]])}, including risks and defenses."'
    if topics:
        return f'ask: "What is {topic_label(topics)} and how do defenders prevent or mitigate it?"'
    return 'name the exact web attack and ask for a definition, risks, defenses, or a comparison.'


def refusal_answer(prompt: PromptAnalysis) -> str:
    if not prompt.needs_feedback:
        return NOT_ENOUGH
    lines = [NOT_ENOUGH, "", "Prompt quality note:"]
    lines.extend(f"- {issue}" for issue in prompt.issues)
    lines.append(f"- To get a sharper answer, {prompt.suggestion}")
    return "\n".join(lines)


def grounded_results(question: str, results: list[RetrievalResult]) -> list[RetrievalResult]:
    topics = detect_topics(question)
    if topics:
        filtered = [result for result in results if result.chunk.metadata.get("topic") in topics]
        if filtered:
            return filtered
        return []
    return [result for result in results if result.score >= 1.8]


def comparison_support_results(index: BM25Index, topics: list[str]) -> list[RetrievalResult]:
    results: list[RetrievalResult] = []
    for topic in topics[:3]:
        query = topic_defense_query(topic)
        for result in index.search(query, top_k=18):
            if result.chunk.metadata.get("topic") == topic:
                results.append(result)
    return results


def topic_defense_query(topic: str) -> str:
    special_queries = {
        "csrf": "CSRF tokens SameSite cookie Origin Referer Fetch Metadata defense",
        "ssrf": "SSRF input validation allowlist network segmentation block metadata services defense",
        "sql_injection": "SQL injection parameterized queries prepared statements least privilege defense",
        "xss": "XSS output encoding content security policy sanitization defense",
        "xxe": "XXE disable external entities secure XML parser defense",
        "open_redirect": "open redirect allowlist redirect target validation defense",
    }
    return special_queries.get(topic, f"{topic_label([topic])} prevention mitigation defense")


def merge_results(primary: list[RetrievalResult], extra: list[RetrievalResult]) -> list[RetrievalResult]:
    merged: dict[str, RetrievalResult] = {}
    for result in [*primary, *extra]:
        existing = merged.get(result.chunk.id)
        if existing is None or result.score > existing.score:
            merged[result.chunk.id] = result
    return sorted(merged.values(), key=lambda item: item.score, reverse=True)


def answer_bullets(question: str, results: list[RetrievalResult]) -> list[str]:
    topics = ordered_detected_topics(question)
    question_terms = {term for term in tokenize(question) if len(term) > 2}
    if is_comparison_request(question, topics):
        compared = comparison_answer(question, results, topics)
        if compared:
            return compared

    wants_definition = is_definition_request(question, topics)
    wants_defense = bool(re.search(r"\b(prevent|defen[cs]e|mitigat|protect|respond|avoid|fix|secure)\b", question, re.IGNORECASE))

    if wants_definition or wants_defense:
        structured = structured_definition_answer(question, results, topics)
        if structured:
            return structured

    candidates: list[tuple[float, str]] = []
    for result in results:
        title = result.chunk.metadata.get("title", "official source")
        for sentence in split_sentences(clean_text(result.chunk.text)):
            sentence = polish_sentence(sentence)
            if not useful_sentence(sentence):
                continue
            sentence_terms = set(tokenize(sentence))
            overlap = len(question_terms & sentence_terms)
            score = overlap + min(result.score, 6) / 6
            if result.chunk.metadata.get("topic") in topics:
                score += 3.0
            if wants_definition and looks_like_definition(sentence, topics):
                score += 7.0
            if wants_definition and looks_defensive(sentence) and not looks_like_definition(sentence, topics):
                score -= 2.0
            if wants_defense and looks_defensive(sentence):
                score += 3.0
                score += predicate_quality_bonus(sentence, looks_defensive)
            score += source_quality_bonus(title)
            if score > 0:
                candidates.append((score, f"{sentence} ({title})"))

    candidates.sort(key=lambda item: item[0], reverse=True)
    selected: list[str] = []
    max_bullets = 4 if wants_defense else 2 if wants_definition else 3
    for _, sentence in candidates:
        compact = sentence.strip()
        if compact not in selected:
            selected.append(compact)
        if len(selected) >= max_bullets:
            break
    if selected:
        return selected

    fallback = clean_text(results[0].chunk.text)
    return [fallback[:420].strip()]


def is_definition_request(question: str, topics: list[str]) -> bool:
    if re.search(r"\b(what is|what are|define|explain|overview)\b", question, re.IGNORECASE):
        return True
    content_terms = [term for term in tokenize(question) if term not in {"a", "an", "the"}]
    return bool(topics and len(content_terms) <= 3)


def is_comparison_request(question: str, topics: list[str]) -> bool:
    if len(topics) < 2:
        return False
    normalized = " ".join(tokenize(question))
    comparison_words = r"\b(compare|comparison|difference|diffrence|differnce|different|diffrent|distinguish|between|versus|vs|v)\b"
    if re.search(comparison_words, normalized, re.IGNORECASE):
        return True
    return bool(re.search(r"\b(and|or)\b", normalized, re.IGNORECASE))


def is_unsafe_operational_request(question: str) -> bool:
    lower = question.lower()
    request_words = r"\b(how\s+(do|can|to)|show me|give me|steps?|commands?|payload|script|launch)\b"
    abuse_words = (
        r"\b(hack|attack|exploit|weaponize|steal|dump|bypass|exfiltrate|take down|crash|flood|botnet|launch|pwn)\b"
    )
    return bool(re.search(request_words, lower) and re.search(abuse_words, lower))


def defensive_rewrite(question: str) -> str:
    topics = detect_topics(question)
    if topics:
        return f"What is {topic_label(topics)} and how can defenders prevent or mitigate it?"
    return "How can defenders understand and mitigate this web security risk?"


def comparison_answer(question: str, results: list[RetrievalResult], topics: list[str]) -> list[str]:
    lines: list[str] = []
    ordered_topics = ordered_detected_topics(question) or topics
    core = core_difference_line(question, results, ordered_topics[:3])
    if core:
        lines.append(core)
    for topic in ordered_topics[:3]:
        topic_results = [result for result in results if result.chunk.metadata.get("topic") == topic]
        if not topic_results:
            continue
        definition = best_sentence(question, topic_results, [topic], looks_like_definition)
        defense = best_sentence(question, topic_results, [topic], looks_defensive)
        if definition:
            lines.append(f"{topic_label([topic])}: {definition}")
        if defense and defense != definition:
            lines.append(f"{topic_label([topic])} defensive note: {defense}")
    return lines[:6]


def core_difference_line(question: str, results: list[RetrievalResult], topics: list[str]) -> str:
    if len(topics) < 2:
        return ""
    pair = set(topics[:2])
    if pair == {"csrf", "ssrf"}:
        csrf_ref = best_sentence(question, [r for r in results if r.chunk.metadata.get("topic") == "csrf"], ["csrf"], looks_like_definition)
        ssrf_ref = best_sentence(question, [r for r in results if r.chunk.metadata.get("topic") == "ssrf"], ["ssrf"], looks_like_definition)
        refs = " ".join(f"({title})" for title in cited_titles([csrf_ref, ssrf_ref]))
        return (
            "Core difference: CSRF abuses a trusted user's browser/session to send unwanted actions to a web application; "
            f"SSRF abuses the server-side application itself to make unintended requests to internal or external systems. {refs}"
        ).strip()

    cited: list[str] = []
    parts: list[str] = []
    for topic in topics[:2]:
        topic_results = [result for result in results if result.chunk.metadata.get("topic") == topic]
        definition = best_sentence(question, topic_results, [topic], looks_like_definition)
        if not definition:
            continue
        text, title = split_trailing_title(definition)
        cited.append(title)
        parts.append(f"{topic_label([topic])}: {text}")
    if len(parts) < 2:
        return ""
    refs = " ".join(f"({title})" for title in cited if title)
    return f"Core difference: {' | '.join(parts)} {refs}".strip()


def format_answer(
    question: str,
    safe_question: str,
    bullets: list[str],
    results: list[RetrievalResult],
    prompt: PromptAnalysis | None = None,
    safety_rewritten: bool = False,
) -> str:
    topics = ordered_detected_topics(safe_question)
    citations = citation_entries(results, "\n".join(bullets))
    citation_lookup = {title: number for number, title, _ in citations}
    sections = organize_answer_sections(bullets, citation_lookup)

    lines = [
        "OFF_WEBSEC_RAG - Grounded Simple RAG Answer",
        "",
        f"Question: {question.strip()}",
        f"Detected topic: {topic_summary(topics) if topics else 'General web attack corpus match'}",
        f"Evidence status: grounded in {len(citations)} official source(s)",
    ]
    if prompt and prompt.retrieval_question != prompt.original and not safety_rewritten:
        lines.append(f"Interpreted as: {safe_question}")
    if safety_rewritten:
        lines.append(f"Safety rewrite: {safe_question}")

    if prompt and prompt.needs_feedback:
        lines.extend(["", "Prompt quality note:"])
        lines.extend(f"- {issue}" for issue in prompt.issues)
        lines.append(f"- To get a sharper answer, {prompt.suggestion}")

    if sections["safety"]:
        lines.extend(["", "Safety handling:"])
        lines.extend(f"- {item}" for item in sections["safety"])

    if sections["direct"]:
        lines.extend(["", "Direct answer:"])
        lines.extend(f"- {item}" for item in sections["direct"])

    if sections["impact"]:
        lines.extend(["", "Why it matters:"])
        lines.extend(f"- {item}" for item in sections["impact"])

    if sections["defense"]:
        lines.extend(["", "Defensive guidance:"])
        lines.extend(f"- {item}" for item in sections["defense"])

    if sections["extra"]:
        lines.extend(["", "Additional corpus evidence:"])
        lines.extend(f"- {item}" for item in sections["extra"])

    lines.extend(["", "Official sources:"])
    for number, title, url in citations:
        lines.append(f"[{number}] {title}")
        lines.append(f"    {url}")

    lines.extend(["", "Retrieved evidence:"])
    for result in unique_result_sources(results)[:5]:
        title = result.chunk.metadata.get("title", "official source")
        lines.append(f"- {title} | BM25 score {result.score:.3f}")

    return "\n".join(lines)


def organize_answer_sections(bullets: list[str], citation_lookup: dict[str, int]) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {"safety": [], "direct": [], "impact": [], "defense": [], "extra": []}
    for bullet in bullets:
        item = apply_citation_markers(bullet, citation_lookup)
        lower = item.lower()
        if lower.startswith("i cannot help"):
            sections["safety"].append(item)
        elif lower.startswith("why it matters:"):
            sections["impact"].append(item.split(":", 1)[1].strip())
        elif lower.startswith("defensive takeaway:"):
            sections["defense"].append(item.split(":", 1)[1].strip())
        elif " defensive note:" in lower:
            topic, detail = item.split(" defensive note:", 1)
            sections["defense"].append(f"{topic}: {detail.strip()}")
        elif ":" in item and len(item.split(":", 1)[0]) <= 80:
            topic, detail = item.split(":", 1)
            sections["direct"].append(f"{topic}: {detail.strip()}")
        else:
            sections["extra"].append(item)
    return sections


def citation_entries(results: list[RetrievalResult], answer_text: str) -> list[tuple[int, str, str]]:
    matching: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for result in results:
        title = str(result.chunk.metadata.get("title", result.chunk.metadata.get("document_id", "source")))
        url = str(result.chunk.metadata.get("url", ""))
        if answer_text and title not in answer_text:
            continue
        key = f"{title}:{url}"
        if key in seen:
            continue
        seen.add(key)
        matching.append((answer_text.find(title), title, url))
    if matching:
        matching.sort(key=lambda item: item[0])
        return [(index + 1, title, url) for index, (_, title, url) in enumerate(matching)]
    entries: list[tuple[int, str, str]] = []
    for result in unique_result_sources(results)[:3]:
        title = str(result.chunk.metadata.get("title", result.chunk.metadata.get("document_id", "source")))
        url = str(result.chunk.metadata.get("url", ""))
        entries.append((len(entries) + 1, title, url))
    return entries


def apply_citation_markers(text: str, citation_lookup: dict[str, int]) -> str:
    for title, number in sorted(citation_lookup.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(f" ({title})", f" [{number}]")
    return text


def split_trailing_title(text: str) -> tuple[str, str]:
    match = re.search(r"\s+\(([^()]+)\)$", text.strip())
    if not match:
        return text.strip(), ""
    return text[: match.start()].strip(), match.group(1).strip()


def cited_titles(items: list[str]) -> list[str]:
    titles: list[str] = []
    for item in items:
        _, title = split_trailing_title(item)
        if title and title not in titles:
            titles.append(title)
    return titles


def ordered_detected_topics(question: str) -> list[str]:
    topics = detect_topics(question)
    if len(topics) < 2:
        return topics
    normalized = f" {' '.join(tokenize(question))} "

    def position(topic: str) -> int:
        positions: list[int] = []
        aliases = [topic.replace("_", " "), *TOPIC_ALIASES.get(topic, ())]
        for alias in aliases:
            alias_norm = " ".join(tokenize(alias))
            if not alias_norm:
                continue
            found = normalized.find(f" {alias_norm} ")
            if found >= 0:
                positions.append(found)
        return min(positions) if positions else 10_000 + topics.index(topic)

    return sorted(topics, key=position)


def unique_result_sources(results: list[RetrievalResult]) -> list[RetrievalResult]:
    unique: list[RetrievalResult] = []
    seen: set[str] = set()
    for result in results:
        metadata = result.chunk.metadata
        key = f"{metadata.get('title')}:{metadata.get('url')}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
    return unique


def structured_definition_answer(question: str, results: list[RetrievalResult], topics: list[str]) -> list[str]:
    definition = best_sentence(question, results, topics, looks_like_definition)
    risk = best_sentence(question, results, topics, looks_risk_or_impact)
    defense = best_sentence(question, results, topics, looks_defensive)

    lines: list[str] = []
    if definition:
        lines.append(f"{topic_label(topics)}: {definition}")
    if risk and risk != definition:
        lines.append(f"Why it matters: {risk}")
    if defense and defense not in {definition, risk}:
        lines.append(f"Defensive takeaway: {defense}")
    return lines[:3]


def best_sentence(question: str, results: list[RetrievalResult], topics: list[str], predicate) -> str:
    question_terms = {term for term in tokenize(question) if len(term) > 2}
    candidates: list[tuple[float, str]] = []
    for result in results:
        title = result.chunk.metadata.get("title", "official source")
        for sentence in split_sentences(clean_text(result.chunk.text)):
            sentence = polish_sentence(sentence)
            if not useful_sentence(sentence) or not predicate(sentence, topics):
                continue
            sentence_terms = set(tokenize(sentence))
            score = len(question_terms & sentence_terms) + source_quality_bonus(title) + min(result.score, 6) / 6
            if result.chunk.metadata.get("topic") in topics:
                score += 3.0
            if predicate is looks_like_definition:
                score += 5.0
                if not re.search(r"\b(second[- ]order|blind|stored|reflected|dom[- ]based)\b", question, re.IGNORECASE):
                    if re.search(r"\b(second[- ]order|blind|stored|reflected|dom[- ]based)\b", sentence, re.IGNORECASE):
                        score -= 8.0
            if predicate is looks_defensive and not re.search(r"\b(aws|cloud|metadata|imds)\b", question, re.IGNORECASE):
                if re.search(r"\b(imdsv2|aws)\b", sentence, re.IGNORECASE):
                    score -= 5.0
            score += predicate_quality_bonus(sentence, predicate)
            candidates.append((score, f"{sentence} ({title})"))
    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[0], reverse=True)
    if predicate is looks_defensive and candidates[0][0] < 4.0:
        return ""
    return candidates[0][1]


def source_lines(results: list[RetrievalResult], answer_text: str = "") -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for result in results:
        title = result.chunk.metadata.get("title", result.chunk.metadata.get("document_id", "source"))
        if answer_text and str(title) not in answer_text:
            continue
        url = result.chunk.metadata.get("url", "")
        key = f"{title}:{url}"
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- {title}: {url}")
    if not lines and answer_text:
        return source_lines(results)
    return lines


def split_sentences(text: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", text.replace("\n", " ")).strip()
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+", normalized) if part.strip()]


def clean_text(text: str) -> str:
    text = text.replace("�", " ")
    text = text.replace("¶", ". ")
    text = text.replace("•", ". ")
    text = re.sub(r"\bSkip to content\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bInitializing search\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bOWASP Cheat Sheet Series\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bContext\s+", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bOverview of a\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bStore This website uses cookies.*?Accept x Store Donate Join\b", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bThank you for visiting OWASP\.org\..*?programmatically ported from its previous wiki page\.", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bThere.?s still some work to be done\.", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bThis is an example of a Project or Chapter Page\.", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\bWatch Star The OWASP.*$", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def polish_sentence(sentence: str) -> str:
    sentence = re.sub(r"^.*?\b(Cross-site scripting \(also known as XSS\) is a web security vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(Filter your inputs with\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(HTTP response splitting occurs when\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(CSV Injection, also known as Formula Injection, occurs when\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(To reliably prevent formula execution\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(XPath is a type of query language\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(Blind XPath Injection attacks can be used\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^Description\s+", "", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(NoSQL injection is a vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(SQL injection is a web security vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(Prototype pollution is a JavaScript vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(Cross-site scripting is a web security vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(Clickjacking is an interface-based attack\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(Server-side request forgery is a web security vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(XML external entity injection is a web security vulnerability\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"^.*?\b(To prevent HTTP Host header attacks\b)", r"\1", sentence, flags=re.IGNORECASE)
    sentence = re.sub(
        r"^.*?\b(misconfigurations and flawed business logic can expose websites to a variety of attacks via the HTTP Host header\b)",
        r"HTTP Host header attacks happen when \1",
        sentence,
        flags=re.IGNORECASE,
    )
    sentence = re.sub(
        r"^.*?\b(Safe use of redirects and forwards can be done in a number of ways\b)",
        r"\1",
        sentence,
        flags=re.IGNORECASE,
    )
    sentence = re.sub(r"^Impact Details.*?Scope:\s*Availability\s*", "", sentence, flags=re.IGNORECASE)
    sentence = re.sub(
        r"^Potential Mitigations Phase\(s\) Mitigation Architecture and Design\s*",
        "",
        sentence,
        flags=re.IGNORECASE,
    )
    sentence = re.sub(r"^\(resource exhaustion\)\s*", "", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"\s+", " ", sentence)
    return sentence.strip(" -")


def useful_sentence(sentence: str) -> bool:
    if len(sentence) < 45 or len(sentence) > 420:
        return False
    lower = sentence.lower()
    noisy = (
        "cookiename",
        "headername",
        "interface ",
        "function ",
        "const ",
        "let ",
        "full production example",
        "provide advices",
        "semgrep",
        "sources:",
        "edit on github",
        "license",
        "theoretical",
        "home > cwe list",
        "id lookup",
        "common weakness enumeration a community-developed list",
        "references ¶",
        "related articles ¶",
        "tools and code used",
        "defense option",
        "safe prepared statement",
        "other examples of safe",
        "hibernate query language",
        "oledbparameter",
        "preparedstatement",
        "resultset",
        "getparameter",
        "http:/",
        "https://",
        "www.",
        "cve-",
        "faq",
        "url validated",
        "anatomy of a typical",
        "though stored procedures are not always",
        "notes relationship",
        "if you need examples",
        "this cheat sheet will focus",
        "will not explain how to perform",
        "this cheat sheet will help",
        "createquery",
        "unsafehqlquery",
        "safehqlquery",
        "setparameter",
        "select account_balance",
        "string query",
        "will define what",
        "see large-scale-systems",
        "learning how to prevent",
        "see the owasp",
        "related articles",
        "alternate terms",
        "common consequences",
        "this table specifies",
        "view all",
        "academy home",
        "dashboard learning paths",
        "all labs",
        "all topics",
        "labs ",
        "read more",
        "mystery labs",
        "leaderboard",
        "interview -",
        "support center",
        "lets you use your browser",
        "burp suite",
        "clickbandit",
        "proof of concept",
        "write a single line of html",
        "constructing an attack",
        "exploiting vulnerabilities",
        "supply an arbitrary host header",
        "imagine the user-submitted url",
        "exploitability as full ssrf might be limited",
        "cia triad",
        "how to find and exploit",
        "construct and perform",
        "using burp to exploit",
        "applicable platform",
        "great deal of developer discipline",
        "store donate join",
        "this website uses cookies",
        "accept x",
        "thank you for visiting owasp",
        "programmatically ported",
        "project or chapter page",
        "still some work to be done",
        "owasp foundation http response",
        "input escaped output",
        "it indicates the relationship",
        "sec-fetch-site",
        "fetch-metadata",
        "related threat agents",
        "related attacks",
        "related vulnerabilities",
        "related controls",
        "category:",
        "watch star",
        "community links",
        "corporate supporters",
        "become a corporate supporter",
        "owasp foundation works",
        "notes:",
        "not limited to the http protocol",
    )
    if any(item in lower for item in noisy):
        return False
    if sentence.endswith("?") or re.search(r"\bwhat is\b.+\?$", lower):
        return False
    if re.search(r"\b(a|an|the|and|or|on|in|to|with|by|from|as|of|for)$", lower):
        return False
    if sentence and sentence[0].islower():
        return False
    if sentence.strip().startswith(('"', "'")):
        return False
    if any(mark in sentence for mark in ("{", "}", "=>", "://localhost", "//")):
        return False
    return True


def looks_like_definition(sentence: str, topics: list[str]) -> bool:
    lower = f" {sentence.lower()} "
    aliases = topic_aliases(topics)
    if topics and not any(alias in lower for alias in aliases):
        return False
    if re.search(r"\b(is|are)\s+(a|an|the)?\s*(attack|vulnerability|weakness|technique|vector|flaw)", lower):
        return True
    definition_markers = (
        " what is ",
        " attackers can use ",
        " can read sensitive ",
        "result is denial of service",
        " is a vulnerability",
        " is a web security vulnerability",
        " are possible when ",
        " possible when ",
        "successful dos attack hinders",
        "successful denial of service attack hinders",
        "hinders the availability",
        "prevents normal users",
        " happens when ",
        " occurs when ",
        " allows ",
        " lets an application ",
        " abuses ",
        " make a target system perform ",
        " attack vector",
        " is an interface-based attack",
        " is a vulnerability where",
        " host header attacks happen when ",
        " can expose websites to a variety of attacks via the http host header",
        " interpreted as sql instead of ordinary user data",
        " when input is not properly sanitized",
    )
    return any(marker in lower for marker in definition_markers)


def looks_defensive(sentence: str, topics: list[str] | None = None) -> bool:
    lower = sentence.lower()
    if "prevent valid users" in lower or "prevent new connections" in lower:
        return False
    if "is due to an input validation problem" in lower or "should not be used as prevention guidance" in lower:
        return False
    if "not limited to the http protocol" in lower:
        return False
    if "mitigations may fail" in lower or "previously escaped formulas may become active" in lower:
        return False
    if "alternate terms" in lower or "common consequences" in lower or "this table specifies" in lower:
        return False
    if "bypass" in lower and "protection" in lower:
        return False
    defensive_terms = (
        "prevent",
        "mitigat",
        "defense",
        "defensive",
        "defend",
        "protect",
        "avoid",
        "encode",
        "limit",
        "throttl",
        "rate limit",
        "capacity",
        "caching",
        "allow list",
        "block",
        "blocking requests",
        "drop all connections",
        "parameterized",
        "prepared statement",
        "least privilege",
        "same-site",
        "csp",
    )
    defensive_patterns = (
        r"\binput validation\b",
        r"\bvalidate (it|input|the host|the supplied|the url|the value)\b",
        r"\breject(ing)?\b",
        r"\bwhitelist\b",
        r"\ballow-list(ing)?\b",
        r"\bx-frame-options\b",
        r"\bcontent security policy\b",
    )
    return any(term in lower for term in defensive_terms) or any(re.search(pattern, lower) for pattern in defensive_patterns)


def looks_risk_or_impact(sentence: str, topics: list[str]) -> bool:
    lower = f" {sentence.lower()} "
    impact_terms = (
        "can read sensitive",
        "modify database",
        "execute administration",
        "recover the content",
        "without the victim",
        "internal/external network",
        "outbound requests",
        "unauthorized",
        "prevent valid users",
        "prevents normal users",
        "slow down",
        "crash",
        "availability",
        "render the entire system inaccessible",
        "bypass authentication",
        "extract or edit data",
        "execute code on the server",
        "cause a denial of service",
    )
    if "ddos" in topics and any(term in lower for term in impact_terms):
        return True
    aliases = topic_aliases(topics)
    if topics and not any(alias in lower for alias in aliases):
        return False
    return any(term in lower for term in impact_terms)


def predicate_quality_bonus(sentence: str, predicate) -> float:
    lower = sentence.lower()
    if predicate is looks_defensive:
        bonus = 0.0
        strong_defense = (
            "to avoid",
            "prevent malicious",
            "prepared statements",
            "parameterized queries",
            "always distinguish between code and data",
            "cannot change the intent",
            "force the developer",
            "allow-list",
            "allowlist",
            "input validation",
            "limit the amount",
            "tracking the rate",
            "blocking requests",
            "rate limiting",
            "throttl",
            "capacity",
            "network segmentation",
            "blocking access",
            "same-site",
            "content security policy",
            "x-frame-options",
            "preventing xss vulnerabilities",
            "html-encode",
            "output encoding",
            "filter input",
            "encode your output",
            "prefix any cell",
            "wrap each cell",
            "escape every double quote",
            "avoid using redirects",
            "do not allow the url as user input",
            "mapped server-side",
            "whitelist of permitted domains",
            "rejecting or redirecting any requests",
            "avoid using the host header",
            "manually specified in a configuration file",
            "csrf token",
            "same-site cookie",
            "samesite",
            "origin header",
        )
        if any(term in lower for term in strong_defense):
            bonus += 4.0
        weak_explanation = (
            "see the",
            "examples of",
            "this cheat sheet",
            "will focus",
            "will not explain",
            "generally, developers like",
            "alternate terms",
            "common consequences",
            "read more",
            "view all",
        "bypass authentication or protection mechanisms",
        "request initiator",
    )
        if any(term in lower for term in weak_explanation):
            bonus -= 6.0
        return bonus
    if predicate is looks_like_definition:
        bonus = 0.0
        strong_definition = (
            "is a vulnerability where",
            "is a web security vulnerability",
            "is an interface-based attack",
            "host header attacks happen when",
            "are possible when",
            "occurs when",
            "happens when",
            "attackers can use",
            "is an attack vector",
        )
        if any(term in lower for term in strong_definition):
            bonus += 5.0
        weak_definition = (
            "types of",
            "two different types",
            "view all",
            "read more",
            "this section",
            "constructing an attack",
            "labs",
        )
        if any(term in lower for term in weak_definition):
            bonus -= 6.0
        return bonus
    return 0.0


def topic_label(topics: list[str]) -> str:
    labels = {
        "sql_injection": "SQL injection (SQLi)",
        "xss": "Cross-site scripting (XSS)",
        "dom_xss": "DOM-based XSS",
        "ssrf": "Server-side request forgery (SSRF)",
        "csrf": "Cross-site request forgery (CSRF)",
        "xxe": "XML external entity (XXE)",
        "ddos": "Denial of service / distributed denial of service (DoS/DDoS)",
        "nosql_injection": "NoSQL injection",
        "ldap_injection": "LDAP injection",
        "xpath_injection": "XPath injection",
        "csv_injection": "CSV/formula injection",
        "code_injection": "Code injection",
        "dom_clobbering": "DOM clobbering",
        "open_redirect": "Open redirect",
        "clickjacking": "Clickjacking",
        "mass_assignment": "Mass assignment",
        "prototype_pollution": "Prototype pollution",
        "websocket_security": "WebSocket security",
        "host_header": "HTTP Host header attack",
        "response_splitting": "HTTP response splitting",
        "log_injection": "Log injection",
        "parameter_tampering": "Parameter tampering",
        "reverse_tabnabbing": "Reverse tabnabbing",
        "content_spoofing": "Content spoofing",
        "race_condition": "Race condition",
        "business_logic": "Business logic vulnerability",
        "security_headers": "HTTP security headers",
        "content_security_policy": "Content Security Policy (CSP)",
        "xs_leaks": "Cross-site leaks (XS-Leaks)",
        "ajax_security": "AJAX security",
        "information_disclosure": "Information disclosure",
        "web_cache_deception": "Web cache deception",
        "web_llm_attacks": "Web LLM attacks",
        "jwt": "JSON Web Token (JWT) security",
        "ssti": "Server-side template injection (SSTI)",
        "request_smuggling": "HTTP request smuggling",
        "web_cache_poisoning": "Web cache poisoning",
        "graphql": "GraphQL security",
        "oauth": "OAuth security",
        "cors": "CORS misconfiguration",
        "file_upload": "File upload vulnerability",
        "path_traversal": "Path traversal",
        "command_injection": "OS command injection",
        "deserialization": "Insecure deserialization",
        "authentication": "Authentication vulnerability",
        "access_control": "Access control vulnerability",
    }
    return labels.get(topics[0], topics[0].replace("_", " ").title()) if topics else "Answer"


def topic_summary(topics: list[str]) -> str:
    if not topics:
        return "General web attack corpus match"
    return " + ".join(topic_label([topic]) for topic in topics)


def topic_aliases(topics: list[str]) -> list[str]:
    aliases: list[str] = []
    for topic in topics:
        aliases.append(topic.replace("_", " "))
        aliases.extend(TOPIC_ALIASES.get(topic, ()))
    return [alias.lower() for alias in aliases]


def source_quality_bonus(title: object) -> float:
    lower = str(title).lower()
    if "portswigger" in lower:
        return 1.0
    if "cheat sheet" in lower:
        return 0.8
    if "cwe" in lower:
        return 0.35
    if "testing guide" in lower:
        return -1.0
    return 0.0

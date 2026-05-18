from __future__ import annotations

from dataclasses import dataclass

from .retrieval import RetrievalResult, TfidfVectorIndex, tokenize


@dataclass(frozen=True)
class RagResponse:
    answer: str
    results: list[RetrievalResult]


class SimpleRag:
    def __init__(self, index: TfidfVectorIndex) -> None:
        self.index = index

    def answer(self, question: str, top_k: int = 4) -> RagResponse:
        results = self.index.search(question, top_k=top_k)
        if not results:
            return RagResponse(
                answer="I do not have enough evidence in the imported official web attack corpus to answer that.",
                results=[],
            )

        query_terms = set(tokenize(question))
        sentences: list[tuple[int, str]] = []
        for result in results:
            for sentence in split_sentences(result.chunk.text):
                score = len(query_terms & set(tokenize(sentence)))
                if score:
                    sentences.append((score, sentence))
        sentences.sort(key=lambda item: item[0], reverse=True)
        selected = []
        for _, sentence in sentences:
            if sentence not in selected:
                selected.append(sentence)
            if len(selected) >= 4:
                break
        if not selected:
            selected = [results[0].chunk.text[:600]]

        citations = []
        for result in results:
            title = result.chunk.metadata.get("title", result.chunk.metadata.get("document_id", "source"))
            url = result.chunk.metadata.get("url", "")
            citations.append(f"- {title}: {url}")
        answer = " ".join(selected) + "\n\nSources:\n" + "\n".join(dict.fromkeys(citations))
        return RagResponse(answer=answer, results=results)


def split_sentences(text: str) -> list[str]:
    normalized = text.replace("\n", " ")
    parts = []
    current = []
    for token in normalized.split():
        current.append(token)
        if token.endswith((".", "?", "!")):
            parts.append(" ".join(current).strip())
            current = []
    if current:
        parts.append(" ".join(current).strip())
    return [part for part in parts if part]

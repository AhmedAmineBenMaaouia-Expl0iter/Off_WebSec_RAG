from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .chunking import Chunk

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


@dataclass(frozen=True)
class RetrievalResult:
    chunk: Chunk
    score: float


class TfidfVectorIndex:
    def __init__(self) -> None:
        self.chunks: list[Chunk] = []
        self.idf: dict[str, float] = {}
        self.vectors: list[dict[str, float]] = []

    def fit(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        document_frequency: Counter[str] = Counter()
        tokenized = [tokenize(chunk.text) for chunk in chunks]
        for tokens in tokenized:
            document_frequency.update(set(tokens))
        total = max(len(chunks), 1)
        self.idf = {
            term: math.log((1 + total) / (1 + frequency)) + 1
            for term, frequency in document_frequency.items()
        }
        self.vectors = [self._vector(tokens) for tokens in tokenized]

    def search(self, query: str, top_k: int = 4) -> list[RetrievalResult]:
        query_vector = self._vector(tokenize(query))
        results: list[RetrievalResult] = []
        for chunk, vector in zip(self.chunks, self.vectors):
            score = cosine(query_vector, vector)
            if score > 0:
                results.append(RetrievalResult(chunk=chunk, score=score))
        results.sort(key=lambda item: item.score, reverse=True)
        return results[:top_k]

    def save(self, path: Path = Path("storage/simple_index.json")) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "idf": self.idf,
            "chunks": [asdict(chunk) for chunk in self.chunks],
            "vectors": self.vectors,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path = Path("storage/simple_index.json")) -> "TfidfVectorIndex":
        payload = json.loads(path.read_text(encoding="utf-8"))
        index = cls()
        index.idf = {key: float(value) for key, value in payload["idf"].items()}
        index.chunks = [Chunk(**item) for item in payload["chunks"]]
        index.vectors = [{key: float(value) for key, value in vector.items()} for vector in payload["vectors"]]
        return index

    def _vector(self, tokens: list[str]) -> dict[str, float]:
        counts = Counter(tokens)
        total = max(sum(counts.values()), 1)
        vector = {
            term: (count / total) * self.idf.get(term, 1.0)
            for term, count in counts.items()
        }
        norm = math.sqrt(sum(value * value for value in vector.values())) or 1.0
        return {term: value / norm for term, value in vector.items()}


def tokenize(text: str) -> list[str]:
    return [match.group(0).lower() for match in TOKEN_RE.finditer(text)]


def cosine(left: dict[str, float], right: dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    if len(left) > len(right):
        left, right = right, left
    return sum(value * right.get(term, 0.0) for term, value in left.items())

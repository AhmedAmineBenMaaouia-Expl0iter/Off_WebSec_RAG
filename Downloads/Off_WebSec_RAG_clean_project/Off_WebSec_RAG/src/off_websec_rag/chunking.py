from __future__ import annotations

from dataclasses import dataclass

from .documents import Document


@dataclass(frozen=True)
class Chunk:
    id: str
    text: str
    metadata: dict


def chunk_documents(documents: list[Document], chunk_words: int = 220, overlap_words: int = 40) -> list[Chunk]:
    chunks: list[Chunk] = []
    for document in documents:
        words = document.text.split()
        if not words:
            continue
        step = max(chunk_words - overlap_words, 1)
        for index, start in enumerate(range(0, len(words), step)):
            part = words[start : start + chunk_words]
            if not part:
                continue
            chunks.append(
                Chunk(
                    id=f"{document.id}::{index}",
                    text=" ".join(part),
                    metadata={
                        **document.metadata,
                        "document_id": document.id,
                        "chunk_index": index,
                        "word_count": len(part),
                    },
                )
            )
            if start + chunk_words >= len(words):
                break
    return chunks

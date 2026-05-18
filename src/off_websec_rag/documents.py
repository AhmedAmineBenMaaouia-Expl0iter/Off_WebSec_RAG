from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Document:
    id: str
    text: str
    metadata: dict


def load_documents(path: Path = Path("data/processed/documents.jsonl")) -> list[Document]:
    documents: list[Document] = []
    if not path.exists():
        return documents
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        documents.append(Document(id=item["id"], text=item["text"], metadata=item.get("metadata", {})))
    return documents

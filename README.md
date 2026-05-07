# Off_WebSec_RAG

Simple RAG for official web attack resources.

This repository is intentionally limited to the professor's required scope:

- Simple RAG only.
- One cybersecurity data type: web attacks.
- Official imported sources only.
- Web interface included.
- Real Git commits from each group member.

## Team Responsibilities

| Member | Technical ownership | Expected branch |
| --- | --- | --- |
| Ahmed Amine Ben Maaouia | Repository structure, CLI entrypoint, web interface, integration README | `ahmed/web-interface` |
| Sadok Mahdi Jeridi | Official OWASP/MITRE source list, downloader, HTML cleaner, raw and processed corpus | `sadok/official-corpus-import` |
| Hiba Hedfi | Chunking, local TF-IDF retrieval, Simple RAG answer generation, tests | `hiba/simple-rag-engine` |

## Project Pipeline

```text
Official OWASP/MITRE pages
        |
        v
Sadok: import and clean official corpus
        |
        v
Hiba: chunk + embed + local vector retrieval
        |
        v
Ahmed: web interface + CLI integration
```

## Current State

Ahmed's base structure and web interface shell are present. The project becomes runnable after Sadok merges the corpus import module and Hiba merges the Simple RAG engine.

## Commands After All Parts Are Merged

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .

python -m off_websec_rag.cli import-sources
python -m off_websec_rag.cli ingest
python -m off_websec_rag.cli ask "What is SQL injection?"
python -m off_websec_rag.cli web
```

Open:

```text
http://127.0.0.1:5000
```

## Forbidden For This Validation

Do not add MCP, agentic RAG, improved RAG modes, multiple mode selectors, manually written Markdown corpus files, or non-web-attack topics.

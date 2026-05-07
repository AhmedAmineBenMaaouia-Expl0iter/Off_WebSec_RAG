from __future__ import annotations

import argparse
from pathlib import Path


DEFAULT_DOCUMENTS = Path("data/processed/documents.jsonl")
DEFAULT_INDEX = Path("storage/simple_index.json")


def main() -> int:
    parser = argparse.ArgumentParser(prog="off-websec-rag")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("import-sources", help="Import official OWASP/MITRE web attack sources")
    subcommands.add_parser("ingest", help="Build the local Simple RAG index")

    ask = subcommands.add_parser("ask", help="Ask the Simple RAG system")
    ask.add_argument("question")

    web = subcommands.add_parser("web", help="Run the web interface")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()

    if args.command == "import-sources":
        from .importer import import_official_sources

        count = import_official_sources(processed_path=DEFAULT_DOCUMENTS)
        print(f"Imported {count} official web attack sources into {DEFAULT_DOCUMENTS}")
        return 0

    if args.command == "ingest":
        from .chunking import chunk_documents
        from .documents import load_documents
        from .retrieval import TfidfVectorIndex

        documents = load_documents(DEFAULT_DOCUMENTS)
        chunks = chunk_documents(documents)
        index = TfidfVectorIndex()
        index.fit(chunks)
        index.save(DEFAULT_INDEX)
        print(f"Indexed {len(chunks)} chunks from {len(documents)} official documents into {DEFAULT_INDEX}")
        return 0

    if args.command == "ask":
        from .retrieval import TfidfVectorIndex
        from .simple_rag import SimpleRag

        response = SimpleRag(TfidfVectorIndex.load(DEFAULT_INDEX)).answer(args.question)
        print(response.answer)
        return 0

    if args.command == "web":
        from web.app import run

        run(host=args.host, port=args.port)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

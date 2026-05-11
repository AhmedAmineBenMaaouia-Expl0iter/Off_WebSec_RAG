from __future__ import annotations

from pathlib import Path

from flask import Flask, render_template, request


INDEX_PATH = Path("storage/simple_index.json")


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/", methods=["GET", "POST"])
    def home():
        question = ""
        answer = ""
        results = []
        index_ready = INDEX_PATH.exists()
        status = "Index armed." if index_ready else "Index offline. Waiting for corpus import and Simple RAG engine merge."

        if request.method == "POST":
            question = request.form.get("question", "").strip()
            if not index_ready:
                status = "Index not found. After all team parts are merged, run import-sources then ingest."
            elif question:
                try:
                    from off_websec_rag.retrieval import TfidfVectorIndex
                    from off_websec_rag.simple_rag import SimpleRag

                    response = SimpleRag(TfidfVectorIndex.load(INDEX_PATH)).answer(question)
                    answer = response.answer
                    results = response.results
                    status = "Answer generated from the local Simple RAG index."
                except ImportError as exc:
                    status = f"RAG engine module not merged yet: {exc}"

        return render_template(
            "index.html",
            question=question,
            answer=answer,
            results=results,
            status=status,
            index_ready=index_ready,
        )

    return app


def run(host: str = "127.0.0.1", port: int = 5000) -> None:
    create_app().run(host=host, port=port, debug=True)


if __name__ == "__main__":
    run()

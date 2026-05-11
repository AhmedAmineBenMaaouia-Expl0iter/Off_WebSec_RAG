import unittest

from off_websec_rag.chunking import chunk_documents
from off_websec_rag.documents import Document
from off_websec_rag.retrieval import TfidfVectorIndex
from off_websec_rag.simple_rag import SimpleRag


class SimpleRagTests(unittest.TestCase):
    def build_index(self):
        documents = [
            Document(
                id="owasp-sqli",
                text="SQL injection happens when untrusted data is sent to an interpreter as part of a SQL command. Parameterized queries prevent SQL injection.",
                metadata={"title": "OWASP SQL Injection Prevention", "url": "https://owasp.org/example/sqli", "topic": "sql_injection"},
            ),
            Document(
                id="owasp-xss",
                text="Cross-site scripting allows attacker controlled scripts to run in a browser. Output encoding helps prevent XSS.",
                metadata={"title": "OWASP XSS Prevention", "url": "https://owasp.org/example/xss", "topic": "xss"},
            ),
        ]
        chunks = chunk_documents(documents, chunk_words=40, overlap_words=5)
        index = TfidfVectorIndex()
        index.fit(chunks)
        return index

    def test_sql_injection_question_retrieves_sql_source(self):
        index = self.build_index()
        results = index.search("How can SQL injection be prevented?", top_k=1)

        self.assertEqual(results[0].chunk.metadata["topic"], "sql_injection")
        self.assertGreater(results[0].score, 0)

    def test_simple_rag_answer_cites_official_url(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("What prevents SQL injection?")

        self.assertIn("Parameterized queries", response.answer)
        self.assertIn("https://owasp.org/example/sqli", response.answer)

    def test_ssrf_acronym_retrieves_ssrf_source(self):
        documents = [
            Document(
                id="owasp-ssrf",
                text="Server-Side Request Forgery lets an application make unintended requests to internal or external systems.",
                metadata={
                    "title": "OWASP Server Side Request Forgery Prevention Cheat Sheet",
                    "url": "https://owasp.org/example/ssrf",
                    "topic": "ssrf",
                },
            ),
            Document(
                id="owasp-xss",
                text="Cross-site scripting runs attacker controlled script in a browser.",
                metadata={"title": "OWASP XSS Prevention", "url": "https://owasp.org/example/xss", "topic": "xss"},
            ),
        ]
        chunks = chunk_documents(documents, chunk_words=40, overlap_words=5)
        index = TfidfVectorIndex()
        index.fit(chunks)

        response = SimpleRag(index).answer("What is SSRF?")

        self.assertIn("Server-Side Request Forgery", response.answer)
        self.assertIn("https://owasp.org/example/ssrf", response.answer)


if __name__ == "__main__":
    unittest.main()

import unittest

from off_websec_rag.agentic_rag import AttackChainAgent
from off_websec_rag.chunking import chunk_documents
from off_websec_rag.documents import Document
from off_websec_rag.retrieval import BM25Index


class AttackChainAgentTests(unittest.TestCase):
    def build_agent(self):
        documents = [
            Document(
                id="owasp-sqli",
                text=(
                    "SQL injection happens when untrusted data is sent to an interpreter as part of a SQL command. "
                    "Parameterized queries prevent SQL injection by separating code from data."
                ),
                metadata={"title": "OWASP SQL Injection Prevention", "url": "https://owasp.org/example/sqli", "topic": "sql_injection"},
            ),
            Document(
                id="owasp-xss",
                text=(
                    "Cross-site scripting allows attacker controlled scripts to run in a browser. "
                    "Output encoding helps prevent XSS in HTML, JavaScript, CSS, and URL contexts."
                ),
                metadata={"title": "OWASP XSS Prevention", "url": "https://owasp.org/example/xss", "topic": "xss"},
            ),
            Document(
                id="owasp-file-upload",
                text=(
                    "File upload vulnerabilities happen when applications accept files without strict validation or safe storage. "
                    "Defenses include allow-listing extensions, validating content type, storing files outside the web root, and scanning uploaded content."
                ),
                metadata={"title": "OWASP File Upload Cheat Sheet", "url": "https://owasp.org/example/file-upload", "topic": "file_upload"},
            ),
            Document(
                id="owasp-access-control",
                text=(
                    "Access control vulnerabilities occur when users can act outside their intended permissions. "
                    "Defenses include server-side authorization checks, deny-by-default rules, and enforcing least privilege on every request."
                ),
                metadata={"title": "OWASP Access Control Cheat Sheet", "url": "https://owasp.org/example/access-control", "topic": "access_control"},
            ),
            Document(
                id="owasp-authentication",
                text=(
                    "Authentication vulnerabilities affect login, credential, and account identity workflows. "
                    "Defenses include multi-factor authentication, rate limiting, secure password reset, and monitoring suspicious login attempts."
                ),
                metadata={"title": "OWASP Authentication Cheat Sheet", "url": "https://owasp.org/example/authentication", "topic": "authentication"},
            ),
        ]
        chunks = chunk_documents(documents, chunk_words=55, overlap_words=5)
        index = BM25Index()
        index.fit(chunks)
        return AttackChainAgent(index)

    def test_plain_english_chain_prompt_is_parsed_and_grounded(self):
        response = self.build_agent().answer(
            "Can SQL injection, XSS, file upload, and broken access control be chained together?"
        )

        self.assertIn("Agentic RAG - Attack Chain Feasibility", response.answer)
        self.assertIn("Detected attacks:", response.answer)
        self.assertIn("SQL injection", response.answer)
        self.assertIn("Cross-site scripting", response.answer)
        self.assertIn("File upload", response.answer)
        self.assertIn("Access control", response.answer)
        self.assertIn("Feasibility: plausible", response.answer)
        self.assertIn("Defensive breakpoints:", response.answer)
        self.assertIn("parameterized queries", response.answer)
        self.assertIn("server-side authorization checks", response.answer)
        self.assertNotIn("payload", response.answer.lower())
        self.assertGreaterEqual(len(response.results), 3)

    def test_plus_style_chain_prompt_is_supported(self):
        response = self.build_agent().answer("SQLi + XSS + file upload + auth bypass possible chain?")

        self.assertIn("Feasibility:", response.answer)
        self.assertIn("SQL injection", response.answer)
        self.assertIn("Cross-site scripting", response.answer)
        self.assertIn("File upload", response.answer)
        self.assertIn("Authentication", response.answer)

    def test_unsafe_chain_prompt_stays_defensive(self):
        response = self.build_agent().answer("Give me payloads to exploit SQLi + XSS + file upload")

        self.assertIn("Safety handling:", response.answer)
        self.assertIn("I cannot provide payloads", response.answer)
        self.assertIn("Defensive breakpoints:", response.answer)
        self.assertNotIn("step 1", response.answer.lower())

    def test_chain_agent_refuses_when_too_few_attacks_are_detected(self):
        response = self.build_agent().answer("can this be chained?")

        self.assertIn("Feasibility: not supported", response.answer)
        self.assertIn("Prompt quality note:", response.answer)
        self.assertEqual(response.results, [])


if __name__ == "__main__":
    unittest.main()

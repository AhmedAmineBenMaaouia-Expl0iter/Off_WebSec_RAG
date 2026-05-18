import tempfile
import unittest
from pathlib import Path

from off_websec_rag.chunking import chunk_documents
from off_websec_rag.documents import Document
from off_websec_rag.retrieval import BM25Index, detect_topics
from off_websec_rag.simple_rag import NOT_ENOUGH, SimpleRag


class SimpleRagTests(unittest.TestCase):
    def build_index(self):
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
                id="owasp-ssrf",
                text=(
                    "Server-Side Request Forgery lets an application make unintended requests to internal or external systems. "
                    "SSRF defenses include allow lists, URL validation, network segmentation, and blocking access to metadata services."
                ),
                metadata={
                    "title": "OWASP Server Side Request Forgery Prevention Cheat Sheet",
                    "url": "https://owasp.org/example/ssrf",
                    "topic": "ssrf",
                },
            ),
            Document(
                id="portswigger-csrf",
                text=(
                    "Cross-site request forgery is a web security vulnerability that allows an attacker to induce users "
                    "to perform actions that they do not intend to perform. Client-side CSRF is due to an input validation "
                    "problem and should not be used as prevention guidance. CSRF tokens help defend against forged requests."
                ),
                metadata={
                    "title": "PortSwigger Cross-site Request Forgery",
                    "url": "https://portswigger.net/example/csrf",
                    "topic": "csrf",
                },
            ),
            Document(
                id="owasp-ddos",
                text=(
                    "A denial of service attack prevents normal users from accessing a web application by exhausting resources. "
                    "DDoS defenses include rate limiting, throttling, monitoring, capacity planning, and upstream filtering."
                ),
                metadata={
                    "title": "OWASP Denial of Service Cheat Sheet",
                    "url": "https://owasp.org/example/dos",
                    "topic": "ddos",
                },
            ),
            Document(
                id="portswigger-nosql",
                text=(
                    "NoSQL injection occurs when an application includes untrusted user input in a NoSQL database query. "
                    "Defenses include strict input validation, safe query construction, and avoiding direct user-controlled operators."
                ),
                metadata={"title": "PortSwigger NoSQL Injection", "url": "https://portswigger.net/example/nosql", "topic": "nosql_injection"},
            ),
            Document(
                id="owasp-open-redirect",
                text=(
                    "An open redirect occurs when an application redirects users to a URL controlled by user input. "
                    "Defenses include allow-listing redirect targets and avoiding unvalidated redirect parameters."
                ),
                metadata={"title": "OWASP Unvalidated Redirects and Forwards Cheat Sheet", "url": "https://owasp.org/example/redirect", "topic": "open_redirect"},
            ),
            Document(
                id="portswigger-clickjacking",
                text=(
                    "Clickjacking is an interface-based attack in which a user is tricked into clicking actionable content "
                    "on a hidden website by clicking decoy content. X-Frame-Options and Content Security Policy help prevent framing."
                ),
                metadata={"title": "PortSwigger Clickjacking", "url": "https://portswigger.net/example/clickjacking", "topic": "clickjacking"},
            ),
            Document(
                id="portswigger-host-header",
                text=(
                    "HTTP Host header attacks happen when misconfigurations and flawed business logic expose websites to attacks "
                    "through the HTTP Host header. Defenses include validating the Host header against a whitelist of permitted domains."
                ),
                metadata={"title": "PortSwigger HTTP Host Header Attacks", "url": "https://portswigger.net/example/host-header", "topic": "host_header"},
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
        return index

    def test_sql_injection_question_retrieves_sql_source(self):
        index = self.build_index()
        results = index.search("How can SQL injection be prevented?", top_k=1)

        self.assertEqual(results[0].chunk.metadata["topic"], "sql_injection")
        self.assertGreater(results[0].score, 1)

    def test_simple_rag_answer_cites_official_url(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("What prevents SQL injection?")

        self.assertIn("Parameterized queries", response.answer)
        self.assertIn("https://owasp.org/example/sqli", response.answer)

    def test_answer_template_is_structured_with_numbered_sources(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("SQL injection")

        self.assertIn("OFF_WEBSEC_RAG - Grounded Simple RAG Answer", response.answer)
        self.assertIn("Detected topic: SQL injection", response.answer)
        self.assertIn("Direct answer:", response.answer)
        self.assertIn("Official sources:", response.answer)
        self.assertIn("Retrieved evidence:", response.answer)
        self.assertRegex(response.answer, r"\[1\] .+")

    def test_misspelled_difference_question_triggers_comparison(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("whats the diffrence between CSRF and SSRF")

        self.assertIn("Core difference", response.answer)
        self.assertIn("Cross-site request forgery", response.answer)
        self.assertIn("Server-Side Request Forgery", response.answer)
        self.assertIn("CSRF tokens", response.answer)
        self.assertIn("network segmentation", response.answer)
        self.assertNotIn("Additional corpus evidence", response.answer)

    def test_short_sqli_query_returns_explanation_not_code(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("SQLi")

        self.assertIn("SQL injection", response.answer)
        self.assertIn("Prompt quality note:", response.answer)
        self.assertNotIn("createQuery", response.answer)
        self.assertNotIn("unsafeHQLQuery", response.answer)

    def test_messy_prompt_is_interpreted_before_retrieval(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("pls sqli deffensive???")

        self.assertIn("Interpreted as:", response.answer)
        self.assertIn("Prompt quality note:", response.answer)
        self.assertIn("Parameterized queries", response.answer)
        self.assertIn("https://owasp.org/example/sqli", response.answer)

    def test_vague_prompt_refuses_and_coaches_user(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("help me with it pls??")

        self.assertTrue(response.answer.startswith(NOT_ENOUGH))
        self.assertIn("Prompt quality note:", response.answer)
        self.assertIn("name the exact web attack", response.answer)
        self.assertEqual(response.results, [])

    def test_badly_spelled_comparison_is_rewritten_and_grounded(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("whts dfrnce csrf ssrf plz")

        self.assertIn("Interpreted as:", response.answer)
        self.assertIn("Core difference", response.answer)
        self.assertIn("CSRF tokens", response.answer)
        self.assertIn("network segmentation", response.answer)

    def test_unsafe_operational_prompt_is_rewritten_defensively(self):
        rag = SimpleRag(self.build_index())
        response = rag.answer("How do I hack a bank with SQLi?")

        self.assertIn("cannot help with instructions", response.answer)
        self.assertIn("Parameterized queries", response.answer)
        self.assertNotIn("exploit", response.answer.lower())

    def test_ssrf_acronym_retrieves_ssrf_source(self):
        response = SimpleRag(self.build_index()).answer("What is SSRF?")

        self.assertIn("Server-Side Request Forgery", response.answer)
        self.assertIn("https://owasp.org/example/ssrf", response.answer)
        self.assertEqual(response.results[0].chunk.metadata["topic"], "ssrf")

    def test_ddos_acronym_retrieves_denial_of_service_source(self):
        response = SimpleRag(self.build_index()).answer("DDOS")

        self.assertIn("denial of service", response.answer.lower())
        self.assertIn("https://owasp.org/example/dos", response.answer)
        self.assertEqual(response.results[0].chunk.metadata["topic"], "ddos")

    def test_dos_acronym_retrieves_denial_of_service_source(self):
        response = SimpleRag(self.build_index()).answer("DOS")

        self.assertIn("denial of service", response.answer.lower())
        self.assertIn("https://owasp.org/example/dos", response.answer)
        self.assertEqual(response.results[0].chunk.metadata["topic"], "ddos")

    def test_messy_topic_detection(self):
        self.assertEqual(detect_topics("pls explain sqli"), ["sql_injection"])
        self.assertEqual(detect_topics("DOS"), ["ddos"])
        self.assertEqual(detect_topics("no sql injection?"), ["nosql_injection"])
        self.assertEqual(detect_topics("open redirect bug"), ["open_redirect"])
        self.assertEqual(detect_topics("host header issue"), ["host_header"])
        self.assertEqual(detect_topics("hostheader issue"), ["host_header"])
        self.assertEqual(detect_topics("sqlinjection"), ["sql_injection"])
        self.assertEqual(detect_topics("openredirect"), ["open_redirect"])
        self.assertEqual(detect_topics("CSP bypass"), ["content_security_policy"])
        self.assertEqual(detect_topics("verbose error information disclosure"), ["information_disclosure"])
        self.assertEqual(detect_topics("xpath injection"), ["xpath_injection"])
        self.assertEqual(detect_topics("csv formula injection"), ["csv_injection"])
        self.assertEqual(detect_topics("http response splitting"), ["response_splitting"])
        self.assertEqual(detect_topics("reverse tabnabbing"), ["reverse_tabnabbing"])

    def test_modern_web_attack_topics_retrieve_correct_sources(self):
        rag = SimpleRag(self.build_index())

        nosql = rag.answer("no sql injection")
        self.assertIn("NoSQL injection", nosql.answer)
        self.assertIn("https://portswigger.net/example/nosql", nosql.answer)
        self.assertEqual(nosql.results[0].chunk.metadata["topic"], "nosql_injection")

        redirect = rag.answer("open redirect")
        self.assertIn("open redirect", redirect.answer.lower())
        self.assertIn("https://owasp.org/example/redirect", redirect.answer)
        self.assertEqual(redirect.results[0].chunk.metadata["topic"], "open_redirect")

    def test_answer_generation_avoids_navigation_and_lab_noise(self):
        rag = SimpleRag(self.build_index())

        clickjacking = rag.answer("clickjacking")
        self.assertIn("interface-based attack", clickjacking.answer)
        self.assertNotIn("View all", clickjacking.answer)
        self.assertNotIn("labs", clickjacking.answer.lower())

        host_header = rag.answer("host header")
        self.assertIn("HTTP Host header attacks happen", host_header.answer)
        self.assertIn("whitelist", host_header.answer)
        self.assertNotIn("Read more", host_header.answer)

    def test_unrelated_question_refuses(self):
        response = SimpleRag(self.build_index()).answer("What is quantum cryptography?")

        self.assertEqual(response.answer, NOT_ENOUGH)
        self.assertEqual(response.results, [])

    def test_unknown_phrase_does_not_match_one_generic_word(self):
        documents = [
            Document(
                id="owasp-auth",
                text="Cryptography is often used in authentication systems, but this source only discusses web login protections.",
                metadata={"title": "OWASP Authentication Cheat Sheet", "url": "https://owasp.org/example/auth", "topic": "authentication"},
            )
        ]
        index = BM25Index()
        index.fit(chunk_documents(documents, chunk_words=40, overlap_words=0))
        response = SimpleRag(index).answer("What is quantum cryptography?")

        self.assertEqual(response.answer, NOT_ENOUGH)
        self.assertEqual(response.results, [])

    def test_bm25_index_persists_backend(self):
        index = self.build_index()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bm25_index.json"
            index.save(path)
            self.assertTrue((Path(tmp) / "chroma").exists())
            restored = BM25Index.load(path)

        self.assertIsInstance(restored, BM25Index)
        self.assertEqual(restored.search("SSRF", top_k=1)[0].chunk.metadata["topic"], "ssrf")


if __name__ == "__main__":
    unittest.main()

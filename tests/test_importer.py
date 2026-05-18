import unittest

from off_websec_rag.documents import Document
from off_websec_rag.importer import VisibleTextParser, discover_owasp_community_attack_sources, sanitize_url
from off_websec_rag.official_sources import OFFICIAL_SOURCES, OfficialSource


class OfficialSourceTests(unittest.TestCase):
    def test_official_source_creation(self):
        source = OfficialSource(
            topic="test",
            title="Test Source",
            url="https://example.com",
            authority="TEST",
        )

        self.assertEqual(source.topic, "test")
        self.assertEqual(source.title, "Test Source")
        self.assertEqual(source.resource_type, "html")

    def test_official_source_slug(self):
        source = OfficialSource(
            topic="test",
            title="OWASP SQL Injection Prevention",
            url="https://example.com",
            authority="OWASP",
        )

        self.assertEqual(source.slug, "owasp-sql-injection-prevention")

    def test_expanded_official_sources_cover_web_attack_range(self):
        topics = {source.topic for source in OFFICIAL_SOURCES}

        self.assertIn("sql_injection", topics)
        self.assertIn("xss", topics)
        self.assertIn("ssrf", topics)
        self.assertIn("csrf", topics)
        self.assertIn("xxe", topics)
        self.assertIn("path_traversal", topics)
        self.assertIn("file_upload", topics)
        self.assertIn("command_injection", topics)
        self.assertIn("web_testing", topics)
        self.assertIn("content_security_policy", topics)
        self.assertIn("xs_leaks", topics)
        self.assertIn("web_cache_deception", topics)
        self.assertIn("information_disclosure", topics)
        self.assertGreaterEqual(len(OFFICIAL_SOURCES), 85)

    def test_pdf_source_is_configured(self):
        pdf_sources = [source for source in OFFICIAL_SOURCES if source.resource_type == "pdf"]

        self.assertTrue(pdf_sources)
        self.assertTrue(any("Testing Guide" in source.title for source in pdf_sources))

    def test_all_sources_have_required_fields(self):
        for source in OFFICIAL_SOURCES:
            self.assertTrue(source.topic)
            self.assertTrue(source.title)
            self.assertTrue(source.url.startswith("https://"))
            self.assertTrue(source.authority)


class VisibleTextParserTests(unittest.TestCase):
    def test_parse_simple_html(self):
        parser = VisibleTextParser()
        parser.feed("<p>Hello World</p>")

        self.assertIn("Hello World", parser.text())

    def test_ignore_script_tags(self):
        parser = VisibleTextParser()
        parser.feed("<p>Visible</p><script>alert('hidden')</script>")
        text = parser.text()

        self.assertIn("Visible", text)
        self.assertNotIn("hidden", text)


class OwaspCommunityAttackDiscoveryTests(unittest.TestCase):
    def test_discovers_attack_links_from_index_html(self):
        html = """
        <a href="/www-community/attacks/Blind_SQL_Injection">Blind SQL Injection</a>
        <a href="/www-community/attacks/XPATH_Injection">XPATH Injection</a>
        <a href="/www-community/pages/About">About</a>
        """

        sources = discover_owasp_community_attack_sources(html)

        self.assertEqual(len(sources), 2)
        self.assertEqual(sources[0].topic, "sql_injection")
        self.assertEqual(sources[1].topic, "xpath_injection")
        self.assertTrue(sources[0].url.startswith("https://owasp.org/www-community/attacks/"))

    def test_sanitize_url_encodes_spaces_without_breaking_owasp_paths(self):
        url = sanitize_url("https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval Injection")

        self.assertIn("Eval%20Injection", url)


class DocumentTests(unittest.TestCase):
    def test_document_creation(self):
        doc = Document(
            id="test-doc",
            text="Test content",
            metadata={"source": "official"},
        )

        self.assertEqual(doc.id, "test-doc")
        self.assertEqual(doc.text, "Test content")
        self.assertEqual(doc.metadata["source"], "official")
if __name__ == "__main__":
    unittest.main()


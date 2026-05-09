import pytest
from off_websec_rag.importer import import_official_sources, VisibleTextParser
from off_websec_rag.official_sources import OfficialSource, OFFICIAL_SOURCES
from off_websec_rag.documents import Document, load_documents


class TestOfficialSource:
    def test_official_source_creation(self):
        """Test creating an OfficialSource"""
        source = OfficialSource(
            topic="test",
            title="Test Source",
            url="https://example.com",
            authority="TEST"
        )
        assert source.topic == "test"
        assert source.title == "Test Source"

    def test_official_source_slug(self):
        """Test slug generation"""
        source = OfficialSource(
            topic="test",
            title="OWASP SQL Injection Prevention",
            url="https://example.com",
            authority="OWASP"
        )
        assert source.slug == "owasp-sql-injection-prevention"


class TestVisibleTextParser:
    def test_parse_simple_html(self):
        """Test parsing simple HTML"""
        parser = VisibleTextParser()
        parser.feed("<p>Hello World</p>")
        assert "Hello World" in parser.text()

    def test_ignore_script_tags(self):
        """Test that script content is ignored"""
        parser = VisibleTextParser()
        parser.feed("<p>Visible</p><script>alert('hidden')</script>")
        text = parser.text()
        assert "Visible" in text
        assert "hidden" not in text


class TestDocument:
    def test_document_creation(self):
        """Test creating a Document"""
        doc = Document(
            id="test-doc",
            text="Test content",
            metadata={"source": "official"}
        )
        assert doc.id == "test-doc"
        assert doc.text == "Test content"
        assert doc.metadata["source"] == "official"


class TestOfficialSources:
    def test_official_sources_not_empty(self):
        """Test that OFFICIAL_SOURCES is populated"""
        assert len(OFFICIAL_SOURCES) > 0

    def test_all_sources_have_required_fields(self):
        """Test that all sources have required fields"""
        for source in OFFICIAL_SOURCES:
            assert source.topic
            assert source.title
            assert source.url
            assert source.authority

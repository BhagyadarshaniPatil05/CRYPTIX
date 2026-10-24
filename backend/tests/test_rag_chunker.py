import pytest
from app.rag.document_loader import CybersecurityDocument
from app.rag.chunker import CybersecurityChunker, DocumentChunk


def test_chunker_section_preservation_and_indices():
    """12, 13, 16, & 19. Test that section headings are preserved and indices are deterministic."""
    doc = CybersecurityDocument(
        source="MITRE_ATTACK",
        source_type="MITRE",
        source_version="15.1",
        trust_level="AUTHORITATIVE",
        title="Dynamic Code Loading",
        technique_id="T1407",
        content=(
            "Overview:\nAdversaries may dynamically load obfuscated code.\n\n"
            "Detection:\nMonitor process executions and DexClassLoader usage.\n\n"
            "Mitigations:\nRestrict dynamic loading permissions."
        ),
        content_hash="hash123",
    )
    chunker = CybersecurityChunker(max_chunk_chars=500)
    chunks = chunker.chunk_document(doc)

    assert len(chunks) == 3
    assert chunks[0].chunk_index == 0
    assert chunks[0].section_title == "Overview"
    assert "dynamically load" in chunks[0].content

    assert chunks[1].chunk_index == 1
    assert chunks[1].section_title == "Detection"
    assert "DexClassLoader" in chunks[1].content

    assert chunks[2].chunk_index == 2
    assert chunks[2].section_title == "Mitigations"


def test_chunker_long_section_splitting():
    """14 & 15. Test that sections exceeding max_chunk_chars split into non-empty sub-chunks."""
    long_para1 = "Sentence one. " * 30  # ~420 chars
    long_para2 = "Sentence two. " * 30  # ~420 chars

    doc = CybersecurityDocument(
        source="MITRE_ATTACK",
        source_type="MITRE",
        source_version="15.1",
        trust_level="AUTHORITATIVE",
        title="Long Technique",
        technique_id="T1437",
        content=f"{long_para1}\n\n{long_para2}",
        content_hash="hash_long",
    )
    chunker = CybersecurityChunker(max_chunk_chars=500)
    chunks = chunker.chunk_document(doc)

    assert len(chunks) >= 2
    for chunk in chunks:
        assert len(chunk.content) <= 500
        assert len(chunk.content.strip()) > 0


def test_chunker_preserves_technique_and_cve_ids():
    """17 & 18. Test that technique_id and cve_id are preserved across all chunks."""
    doc = CybersecurityDocument(
        source="NVD",
        source_type="NVD",
        source_version="1.0",
        trust_level="AUTHORITATIVE",
        title="Android Vulnerability",
        technique_id="T1437.001",
        cve_id="CVE-2024-9999",
        content="Description:\nCritical Android IPC vulnerability CVE-2024-9999.",
        content_hash="hash_cve",
    )
    chunker = CybersecurityChunker()
    chunks = chunker.chunk_document(doc)

    assert len(chunks) == 1
    assert chunks[0].technique_id == "T1437.001"
    assert chunks[0].cve_id == "CVE-2024-9999"


def test_chunker_empty_document_handling():
    """Test handling of empty or whitespace-only document content."""
    doc = CybersecurityDocument(
        source="TEST",
        source_type="UNKNOWN",
        source_version="1.0",
        trust_level="UNKNOWN",
        title="Empty Doc",
        content="   ",
        content_hash="hash_empty",
    )
    chunker = CybersecurityChunker()
    chunks = chunker.chunk_document(doc)
    assert len(chunks) == 0

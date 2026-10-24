import pytest
from app.rag.query_builder import RAGQueryBuilder, StructuredRetrievalQuery


def test_query_builder_basic_question():
    """1. Test building query from a basic user question."""
    builder = RAGQueryBuilder()
    query = builder.build_query(question="What makes this APK suspicious?")
    
    assert query.user_question == "What makes this APK suspicious?"
    assert len(query.keywords) > 0
    assert "suspicious" in query.keywords
    assert query.technique_ids == []
    assert query.cve_ids == []


def test_query_builder_technique_and_subtechnique_extraction():
    """2 & 4. Test extraction of MITRE technique IDs and sub-techniques."""
    builder = RAGQueryBuilder()
    query = builder.build_query(
        question="Explain T1412 SMS control and sub-technique T1437.001 web protocols."
    )
    
    assert "T1412" in query.technique_ids
    assert "T1437.001" in query.technique_ids
    assert len(query.technique_ids) == 2


def test_query_builder_cve_extraction():
    """3. Test extraction of CVE identifiers."""
    builder = RAGQueryBuilder()
    query = builder.build_query(
        question="Is this sample exploiting CVE-2024-12345 or CVE-2023-9999?"
    )
    
    assert "CVE-2024-12345" in query.cve_ids
    assert "CVE-2023-9999" in query.cve_ids


def test_query_builder_apk_evidence_and_static_labeling():
    """5 & 7. Test inclusion of APK evidence with static capability labeling."""
    builder = RAGQueryBuilder()
    query = builder.build_query(
        question="Analyze SMS behavior",
        apk_evidence=[
            "Static DEX analysis identified DexClassLoader API capability",
            "Manifest permission grant: SEND_SMS",
        ],
        malware_dna="DNA-HASH-12345",
    )
    
    assert len(query.apk_evidence) == 2
    assert "DexClassLoader" in query.raw_context_text
    assert "SEND_SMS" in query.raw_context_text
    assert "DNA-HASH-12345" in query.raw_context_text


def test_query_builder_empty_input():
    """6. Test handling of empty input safely."""
    builder = RAGQueryBuilder()
    query = builder.build_query(question="")
    
    assert query.user_question == ""
    assert query.technique_ids == []
    assert query.cve_ids == []
    assert query.keywords == []

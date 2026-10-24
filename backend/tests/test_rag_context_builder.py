import pytest
from app.rag.query_builder import StructuredRetrievalQuery
from app.rag.retriever import RetrievalResultItem
from app.rag.context_builder import RAGContextBuilder, GroundedContext


def test_context_builder_structures_and_labels():
    """1, 2, 5, 6, 7, & 8. Test building structured context with clear section dividers."""
    query = StructuredRetrievalQuery(
        user_question="What does suspicious SMS behavior indicate?",
        technique_ids=["T1412"],
        cve_ids=["CVE-2024-1234"],
        keywords=["sms", "behavior"],
        apk_evidence=["Static DEX analysis identified DexClassLoader API capability"],
        malware_dna="DNA-HASH-9999",
        threat_memory="KNOWN_EXACT sample match",
        global_threat_intel="VirusTotal 15/70 detections",
    )

    retrieved = [
        RetrievalResultItem(
            document_id=1,
            chunk_id=10,
            content="Adversaries may intercept SMS messages.",
            title="SMS Control",
            source="MITRE_ATTACK_MOBILE",
            source_type="MITRE",
            source_version="15.1",
            trust_level="AUTHORITATIVE",
            publisher="MITRE",
            url="https://attack.mitre.org/techniques/T1412/",
            technique_id="T1412",
            final_score=0.53,
            retrieval_reasons=["Exact technique_id match (T1412)"],
        )
    ]

    builder = RAGContextBuilder()
    context = builder.build_context(query=query, retrieved_results=retrieved)

    assert "=== SYSTEM INSTRUCTIONS ===" in context.full_prompt_text
    assert "=== USER QUESTION ===" in context.full_prompt_text
    assert "=== APK EVIDENCE ===" in context.full_prompt_text
    assert "=== MITRE ANALYSIS ===" in context.full_prompt_text
    assert "=== MALWARE DNA ===" in context.full_prompt_text
    assert "=== THREAT MEMORY ===" in context.full_prompt_text
    assert "=== GLOBAL THREAT INTELLIGENCE ===" in context.full_prompt_text
    assert "=== RETRIEVED CYBERSECURITY KNOWLEDGE ===" in context.full_prompt_text

    assert "T1412" in context.mitre_analysis_section
    assert "DNA-HASH-9999" in context.malware_dna_section
    assert "KNOWN_EXACT" in context.threat_memory_section
    assert "VirusTotal" in context.global_threat_intel_section


def test_context_builder_provenance_and_static_boundary():
    """3 & 4. Test that provenance metadata and static capability phrasing are preserved."""
    query = StructuredRetrievalQuery(
        user_question="Explain SMS capabilities",
        apk_evidence=["Static DEX analysis identified DexClassLoader API capability"],
    )
    retrieved = [
        RetrievalResultItem(
            document_id=1,
            chunk_id=10,
            content="SMS interception content.",
            title="SMS Control",
            source="MITRE_ATTACK_MOBILE",
            source_type="MITRE",
            source_version="15.1",
            trust_level="AUTHORITATIVE",
            technique_id="T1412",
            final_score=0.53,
        )
    ]

    builder = RAGContextBuilder()
    context = builder.build_context(query=query, retrieved_results=retrieved)

    # Static boundary phrasing
    assert "STATIC ANALYSIS BOUNDARY" in context.full_prompt_text or "Static capabilities" in context.apk_evidence_section
    # Provenance
    assert "Source: MITRE_ATTACK_MOBILE" in context.retrieved_knowledge_section
    assert "Version: 15.1" in context.retrieved_knowledge_section


def test_context_builder_missing_sections_and_empty_context():
    """9 & 10. Test handling of missing sections and empty context."""
    query = StructuredRetrievalQuery(user_question="Generic query")
    builder = RAGContextBuilder()
    context = builder.build_context(query=query, retrieved_results=[])

    assert "No specific static APK evidence" in context.apk_evidence_section
    assert "No relevant cybersecurity domain knowledge" in context.retrieved_knowledge_section


def test_context_builder_truncation_limits():
    """11 & 12. Test character truncation limits and warning generation."""
    query = StructuredRetrievalQuery(user_question="Long query")
    retrieved = [
        RetrievalResultItem(
            document_id=1,
            chunk_id=i,
            content="Extremely long text content " * 100,
            title=f"Doc {i}",
            source="TEST",
            source_type="MITRE",
            source_version="15.1",
            trust_level="AUTHORITATIVE",
            final_score=0.5,
        )
        for i in range(10)
    ]

    builder = RAGContextBuilder(max_chunks=5, max_total_chars=1000)
    context = builder.build_context(query=query, retrieved_results=retrieved)

    assert len(context.full_prompt_text) <= 1200
    assert any("truncated" in w.lower() for w in context.context_warnings)

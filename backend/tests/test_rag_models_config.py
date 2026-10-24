import pytest
from app.rag.config import (
    SourceType,
    TrustLevel,
    GroundingState,
    MITRE_MOBILE_PINNED_VERSION,
    EXACT_ID_MATCH_WEIGHT,
    SEMANTIC_RELEVANCE_WEIGHT,
    TRUST_LEVEL_MULTIPLIERS,
)
from app.models.rag import RagDocument, RagChunk, RagQueryLog
from app.config.settings import settings


def test_rag_config_constants():
    """Verify pinned MITRE version, grounding states, source types, and ranking weights."""
    assert MITRE_MOBILE_PINNED_VERSION == "15.1"
    assert SourceType.MITRE.value == "MITRE"
    assert SourceType.PROJECT_INVESTIGATION.value == "PROJECT_INVESTIGATION"

    assert TrustLevel.AUTHORITATIVE.value == "AUTHORITATIVE"
    assert TRUST_LEVEL_MULTIPLIERS[TrustLevel.AUTHORITATIVE] == 1.0
    assert TRUST_LEVEL_MULTIPLIERS[TrustLevel.UNKNOWN] == 0.50

    assert GroundingState.SUPPORTED.value == "SUPPORTED"
    assert GroundingState.PARTIALLY_SUPPORTED.value == "PARTIALLY_SUPPORTED"
    assert GroundingState.INSUFFICIENT_EVIDENCE.value == "INSUFFICIENT_EVIDENCE"

    # Relevance weights must sum to <= 1.0
    total_weight = EXACT_ID_MATCH_WEIGHT + SEMANTIC_RELEVANCE_WEIGHT
    assert total_weight == 0.70
    # Exact ID + Semantic relevance must dominate trust and freshness
    assert EXACT_ID_MATCH_WEIGHT >= 0.35
    assert SEMANTIC_RELEVANCE_WEIGHT >= 0.35


def test_rag_settings():
    """Verify RAG configuration settings."""
    assert settings.RAG_ENABLED is True
    assert settings.RAG_VECTOR_STORE in ("sqlite", "faiss", "pgvector")
    assert settings.RAG_EMBEDDING_PROVIDER in ("tfidf", "sentence_transformers", "mock")
    assert settings.RAG_LLM_PROVIDER in ("mock", "openai", "custom")
    assert settings.RAG_TOP_K >= 1


def test_rag_sqlalchemy_models_instantiation():
    """Verify instantiation of RagDocument, RagChunk, and RagQueryLog models."""
    doc = RagDocument(
        source="MITRE_ATTACK",
        source_type=SourceType.MITRE.value,
        source_version=MITRE_MOBILE_PINNED_VERSION,
        trust_level=TrustLevel.AUTHORITATIVE.value,
        title="Dynamic Code Loading",
        technique_id="T1407",
        content_hash="abc123hash",
    )
    assert doc.source == "MITRE_ATTACK"
    assert doc.source_version == "15.1"
    assert doc.trust_level == "AUTHORITATIVE"
    assert doc.technique_id == "T1407"

    chunk = RagChunk(
        chunk_index=0,
        section_title="Description",
        content="Adversaries may dynamically load code...",
        technique_id="T1407",
    )
    assert chunk.technique_id == "T1407"
    assert chunk.section_title == "Description"

    query_log = RagQueryLog(
        question="Why is this high risk?",
        grounding_state=GroundingState.SUPPORTED.value,
        llm_provider="mock",
        latency_ms=12.5,
    )
    assert query_log.grounding_state == "SUPPORTED"
    assert query_log.latency_ms == 12.5

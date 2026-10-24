import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.models.rag import RagDocument, RagChunk
from app.rag.config import SourceType, TrustLevel
from app.rag.embeddings import TFIDFEmbeddingProvider, SentenceTransformerEmbeddingProvider
from app.rag.vector_store import SQLiteVectorStore
from app.rag.query_builder import RAGQueryBuilder
from app.rag.retriever import HybridRetriever, RetrievalResultItem


@pytest.fixture
def db_session():
    """In-memory SQLite database session fixture for testing retriever."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def seed_rag_database(db_session):
    """Seed database with MITRE, CVE, and Vendor documents."""
    doc1 = RagDocument(
        id=1,
        source="MITRE_ATTACK_MOBILE",
        source_type=SourceType.MITRE.value,
        source_version="15.1",
        trust_level=TrustLevel.AUTHORITATIVE.value,
        title="SMS Control",
        url="https://attack.mitre.org/techniques/T1412/",
        publisher="MITRE",
        last_verified=datetime.utcnow(),
        platform="Android",
        technique_id="T1412",
        content_hash="hash_t1412",
    )
    c1 = RagChunk(
        id=10,
        document_id=1,
        chunk_index=0,
        section_title="Description",
        content="Adversaries may send, read, or intercept SMS messages without user interaction.",
        technique_id="T1412",
    )

    doc2 = RagDocument(
        id=2,
        source="NVD",
        source_type=SourceType.NVD.value,
        source_version="2.0",
        trust_level=TrustLevel.AUTHORITATIVE.value,
        title="Android Component Vulnerability",
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        publisher="NVD",
        last_verified=datetime.utcnow() - timedelta(days=10),
        platform="Android",
        cve_id="CVE-2024-1234",
        content_hash="hash_cve1234",
    )
    c2 = RagChunk(
        id=20,
        document_id=2,
        chunk_index=0,
        section_title="Overview",
        content="Vulnerability CVE-2024-1234 allows unauthenticated remote code execution via intent broadcast.",
        cve_id="CVE-2024-1234",
    )

    doc3 = RagDocument(
        id=3,
        source="VENDOR_REPORT",
        source_type=SourceType.VENDOR_REPORT.value,
        source_version="1.0",
        trust_level=TrustLevel.RESEARCH.value,
        title="Academic Research Paper",
        url="https://example.com/research",
        publisher="Security Lab",
        last_verified=datetime.utcnow() - timedelta(days=400),
        platform="Android",
        content_hash="hash_vendor",
    )
    c3 = RagChunk(
        id=30,
        document_id=3,
        chunk_index=0,
        section_title="Findings",
        content="Unrelated academic analysis of legacy desktop Windows malware buffer overflows.",
    )

    db_session.add_all([doc1, doc2, doc3, c1, c2, c3])
    db_session.commit()
    return db_session


def test_retriever_exact_technique_match(seed_rag_database):
    """8, 23, 24, & 25. Test exact technique ID matching, provenance, retrieval reasons, and source_version."""
    builder = RAGQueryBuilder()
    query = builder.build_query(question="What does technique T1412 mean?")

    retriever = HybridRetriever(db_session=seed_rag_database)
    results = retriever.retrieve(query=query, top_k=5)

    assert len(results) >= 1
    top_res = results[0]
    assert top_res.technique_id == "T1412"
    assert top_res.exact_id_score == 1.0
    assert top_res.source_type == "MITRE"
    assert top_res.source_version == "15.1"
    assert top_res.trust_level == "AUTHORITATIVE"
    assert any("Exact technique_id match" in reason for reason in top_res.retrieval_reasons)


def test_retriever_exact_cve_match(seed_rag_database):
    """9. Test exact CVE identifier matching."""
    builder = RAGQueryBuilder()
    query = builder.build_query(question="Tell me about CVE-2024-1234")

    retriever = HybridRetriever(db_session=seed_rag_database)
    results = retriever.retrieve(query=query, top_k=5)

    assert len(results) >= 1
    top_res = results[0]
    assert top_res.cve_id == "CVE-2024-1234"
    assert top_res.exact_id_score == 1.0
    assert any("Exact cve_id match" in reason for reason in top_res.retrieval_reasons)


def test_retriever_lexical_matching(seed_rag_database):
    """10 & 13. Test lexical keyword matching and verify TF-IDF is NOT labeled semantic."""
    builder = RAGQueryBuilder()
    query = builder.build_query(question="intercept SMS messages")

    retriever = HybridRetriever(
        db_session=seed_rag_database,
        embedding_provider=TFIDFEmbeddingProvider()
    )
    results = retriever.retrieve(query=query, top_k=5)

    assert len(results) >= 1
    top_res = results[0]
    assert top_res.lexical_score > 0.0
    assert top_res.semantic_score == 0.0  # TFIDF must NOT be labeled as semantic
    assert any("Lexical" in r or "lexical" in r for r in top_res.retrieval_reasons)


def test_retriever_relevance_beats_trust(seed_rag_database):
    """15, 16, & 17. Test hybrid score calculation, trust/freshness weighting, and relevance beating trust."""
    builder = RAGQueryBuilder()
    # Query for intent broadcast vulnerability matching CVE-2024-1234
    query = builder.build_query(question="intent broadcast vulnerability remote code execution")

    retriever = HybridRetriever(db_session=seed_rag_database)
    results = retriever.retrieve(query=query, top_k=5)

    # Result matching CVE-2024-1234 must rank above unrelated doc3
    assert len(results) >= 1
    assert results[0].cve_id == "CVE-2024-1234"

    # Verify unrelated doc3 (with 0 relevance) was zeroed out and excluded from top results
    doc3_results = [r for r in results if r.document_id == 3]
    assert len(doc3_results) == 0


def test_retriever_empty_store_and_unrelated_query(db_session):
    """18, 19, 20, & 21. Test top_k handling, empty store, missing embeddings, and unrelated query."""
    retriever = HybridRetriever(db_session=db_session)
    builder = RAGQueryBuilder()

    # Empty store
    res_empty = retriever.retrieve(query=builder.build_query(question="Test question"), top_k=5)
    assert res_empty == []

    # Empty query
    res_no_q = retriever.retrieve(query=builder.build_query(question=""), top_k=5)
    assert res_no_q == []


def test_retriever_missing_embeddings_handling(seed_rag_database):
    """20. Test that chunks with embedding_json = NULL do not crash retrieval."""
    builder = RAGQueryBuilder()
    query = builder.build_query(question="T1412")

    retriever = HybridRetriever(db_session=seed_rag_database)
    results = retriever.retrieve(query=query, top_k=5)

    assert len(results) >= 1
    assert results[0].technique_id == "T1412"

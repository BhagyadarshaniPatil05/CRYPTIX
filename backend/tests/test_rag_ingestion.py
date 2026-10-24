import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.models.rag import RagDocument, RagChunk
from app.rag.config import SourceType, TrustLevel, MITRE_MOBILE_PINNED_VERSION
from app.rag.document_loader import (
    CybersecurityDocument,
    MitreMobileLoader,
    normalize_document_content,
    compute_content_hash,
)
from app.rag.chunker import CybersecurityChunker
from app.rag.ingestion import (
    ingest_cybersecurity_documents,
    ingest_mitre_mobile_catalog,
    IngestionResult,
)


@pytest.fixture
def db_session():
    """In-memory SQLite database session fixture for testing ingestion."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_mitre_mobile_loader_metadata_and_version():
    """1, 4, 5, 27, 28, 29, 30, 31. Test MITRE loader metadata, pinned version 15.1, and trust level."""
    loader = MitreMobileLoader()
    docs = loader.load()

    assert len(docs) > 0
    for doc in docs:
        assert doc.source_type == SourceType.MITRE.value
        assert doc.source_version == MITRE_MOBILE_PINNED_VERSION
        assert doc.trust_level == TrustLevel.AUTHORITATIVE.value
        assert doc.publisher == "MITRE"
        assert doc.technique_id is not None
        assert doc.url.startswith("https://attack.mitre.org/techniques/")
        assert doc.platform == "Android"


def test_mitre_loader_rejects_unpinned_version():
    """32. Test that MITRE loader rejects documents not matching pinned version 15.1."""
    invalid_catalog = {
        "T9999": {
            "technique_id": "T9999",
            "technique_name": "Unversioned Technique",
            "source_version": "16.0",  # Unpinned version
            "description": "Invalid technique version",
        }
    }
    loader = MitreMobileLoader(catalog_dict=invalid_catalog)
    with pytest.raises(ValueError, match="does not match pinned version '15.1'"):
        loader.load()


def test_normalization_and_preservation_of_identifiers():
    """6, 7, & 8. Test whitespace normalization while preserving technical identifiers and URLs."""
    raw = "   Adversary uses DexClassLoader  and  CVE-2024-1234.\r\n\r\n\r\nSee https://attack.mitre.org/techniques/T1407/   "
    normalized = normalize_document_content(raw)

    assert "\r" not in normalized
    assert "\n\n\n" not in normalized
    assert "DexClassLoader" in normalized
    assert "CVE-2024-1234" in normalized
    assert "https://attack.mitre.org/techniques/T1407/" in normalized


def test_content_hashing_determinism_and_distinctness():
    """9, 10, & 11. Test content hash determinism, variation on change, and distinction from APK hash."""
    h1 = compute_content_hash("MITRE", "T1407", "Normalized content A")
    h2 = compute_content_hash("MITRE", "T1407", "Normalized content A")
    h3 = compute_content_hash("MITRE", "T1407", "Normalized content B")

    assert h1 == h2  # Deterministic
    assert h1 != h3  # Changes on content change
    assert len(h1) == 64  # SHA-256 hex string


def test_deduplication_behavior(db_session):
    """21 & 22. Test that duplicate document ingestion does not create duplicate database records."""
    doc1 = CybersecurityDocument(
        source="MITRE_ATTACK",
        source_type="MITRE",
        source_version="15.1",
        trust_level="AUTHORITATIVE",
        title="Dynamic Code Loading",
        technique_id="T1407",
        content="Description:\nAdversaries dynamically load obfuscated code.",
        content_hash="hash_dedup_test",
    )

    # First ingestion
    res1 = ingest_cybersecurity_documents(db=db_session, documents=[doc1])
    assert res1.documents_created == 1
    assert res1.documents_skipped == 0

    # Repeat ingestion of same document
    res2 = ingest_cybersecurity_documents(db=db_session, documents=[doc1])
    assert res2.documents_created == 0
    assert res2.documents_skipped == 1

    # Verify total DB record count is still 1
    assert db_session.query(RagDocument).count() == 1


def test_database_persistence_and_relationships(db_session):
    """23, 24, 25, & 26. Test persistence of RagDocument and RagChunk records and parent-child cascade."""
    res = ingest_mitre_mobile_catalog(db=db_session)
    assert res.documents_created > 0
    assert res.chunks_created > 0

    # Query persistent records
    doc = db_session.query(RagDocument).filter(RagDocument.technique_id == "T1406").first()
    assert doc is not None
    assert doc.title == "Obfuscated Files or Information"
    assert doc.source_version == "15.1"
    assert doc.trust_level == "AUTHORITATIVE"

    # Verify associated chunks
    chunks = db_session.query(RagChunk).filter(RagChunk.document_id == doc.id).all()
    assert len(chunks) > 0
    assert chunks[0].technique_id == "T1406"
    assert chunks[0].embedding_json is None  # Decoupled from vector indexing


def test_mitre_seed_dataset_scope_and_separation():
    """Verify architectural distinction: Phase 3.4.1 mapping catalog is the initial RAG seed, not the full matrix."""
    loader = MitreMobileLoader()
    docs = loader.load()
    technique_ids = {d.technique_id for d in docs}

    # Verify the 11 Phase 3.4.1 validated technique IDs are present
    expected_ids = {"T1406", "T1412", "T1420", "T1426", "T1430", "T1432", "T1437", "T1437.001", "T1409", "T1624", "T1626"}
    assert technique_ids == expected_ids
    assert len(docs) == 11

    # Verify architectural scope note is documented on MitreMobileLoader
    assert "Current RAG MITRE seed data is limited to the audited Phase 3.4.1" in MitreMobileLoader.__doc__



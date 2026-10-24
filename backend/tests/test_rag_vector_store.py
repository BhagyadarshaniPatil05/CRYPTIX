import pytest
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.models.rag import RagDocument, RagChunk
from app.rag.config import SourceType, TrustLevel
from app.rag.embeddings import TFIDFEmbeddingProvider
from app.rag.vector_store import (
    VectorRecord,
    SQLiteVectorStore,
    get_vector_store,
)


@pytest.fixture
def db_session():
    """In-memory SQLite database session fixture for testing vector store."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_sqlite_vector_store_add_and_count(db_session):
    """13 & 19. Test adding a single vector record and counting."""
    store = SQLiteVectorStore(db_session=db_session)
    assert store.count() == 0

    record = VectorRecord(
        chunk_id=1,
        document_id=10,
        embedding=np.array([0.1, 0.2, 0.3], dtype=np.float32),
        metadata={"section_title": "Detection", "technique_id": "T1407"}
    )
    store.add(record)
    assert store.count() == 1


def test_sqlite_vector_store_add_many(db_session):
    """14. Test adding multiple vector records in batch."""
    store = SQLiteVectorStore(db_session=db_session)
    records = [
        VectorRecord(chunk_id=1, document_id=10, embedding=np.array([1.0, 0.0], dtype=np.float32)),
        VectorRecord(chunk_id=2, document_id=10, embedding=np.array([0.0, 1.0], dtype=np.float32)),
        VectorRecord(chunk_id=3, document_id=11, embedding=np.array([0.7, 0.7], dtype=np.float32)),
    ]
    store.add_many(records)
    assert store.count() == 3


def test_sqlite_vector_store_search_similarity_and_ranking(db_session):
    """15, 16, & 17. Test search ranking, top-K filtering, and metadata preservation."""
    store = SQLiteVectorStore(db_session=db_session)
    
    # Create doc
    doc = RagDocument(
        id=10,
        source="MITRE_ATTACK",
        source_type=SourceType.MITRE.value,
        title="Dynamic Code Loading",
        trust_level=TrustLevel.AUTHORITATIVE.value,
        content_hash="hash123",
    )
    db_session.add(doc)
    db_session.commit()

    # Exact match vector vs distant vector
    r1 = VectorRecord(chunk_id=1, document_id=10, embedding=np.array([1.0, 0.0, 0.0], dtype=np.float32), metadata={"technique_id": "T1407"})
    r2 = VectorRecord(chunk_id=2, document_id=10, embedding=np.array([0.0, 1.0, 0.0], dtype=np.float32), metadata={"technique_id": "T1437"})
    r3 = VectorRecord(chunk_id=3, document_id=10, embedding=np.array([0.9, 0.1, 0.0], dtype=np.float32), metadata={"technique_id": "T1407"})
    store.add_many([r1, r2, r3])

    query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    results = store.search(query_embedding=query_vec, top_k=2)

    assert len(results) == 2
    # Highest similarity should be chunk_id=1 (score ~ 1.0)
    assert results[0].chunk_id == 1
    assert results[0].similarity_score > 0.99
    assert results[0].metadata["technique_id"] == "T1407"
    assert results[0].metadata["title"] == "Dynamic Code Loading"

    # Second highest similarity should be chunk_id=3
    assert results[1].chunk_id == 3


def test_sqlite_vector_store_delete_and_clear(db_session):
    """18 & 20. Test deleting vector record and clearing store."""
    store = SQLiteVectorStore(db_session=db_session)
    records = [
        VectorRecord(chunk_id=1, document_id=10, embedding=np.array([1.0, 0.0], dtype=np.float32)),
        VectorRecord(chunk_id=2, document_id=10, embedding=np.array([0.0, 1.0], dtype=np.float32)),
    ]
    store.add_many(records)
    assert store.count() == 2

    # Delete chunk_id 1
    deleted = store.delete(1)
    assert deleted is True
    assert store.count() == 1

    # Clear all
    store.clear()
    assert store.count() == 0


def test_sqlite_vector_store_zero_vector_and_empty_store_search(db_session):
    """21 & 22. Test zero-vector search safety and empty store search."""
    store = SQLiteVectorStore(db_session=db_session)

    # Empty store search
    q_vec = np.array([1.0, 0.0], dtype=np.float32)
    results = store.search(query_embedding=q_vec, top_k=5)
    assert len(results) == 0

    # Zero vector search safety
    r1 = VectorRecord(chunk_id=1, document_id=10, embedding=np.array([0.0, 0.0], dtype=np.float32))
    store.add(r1)

    zero_q = np.array([0.0, 0.0], dtype=np.float32)
    results_zero = store.search(query_embedding=zero_q, top_k=5)
    assert len(results_zero) == 1
    assert results_zero[0].similarity_score == 0.0


def test_end_to_end_embedding_to_vector_store(db_session):
    """23, 24, & 25. Test complete embedding -> vector store -> similarity search workflow."""
    embedder = TFIDFEmbeddingProvider(max_features=32)
    corpus = [
        "Android malware T1407 dynamic code loading DexClassLoader",
        "SMS Trojan SMS_RECEIVED permission escalation",
        "Network communication HttpURLConnection socket T1437.001",
    ]
    embedder.fit(corpus)

    store = SQLiteVectorStore(db_session=db_session)

    # Create document
    doc = RagDocument(
        id=1,
        source="MITRE_ATTACK",
        source_type=SourceType.MITRE.value,
        title="MITRE Mobile v15.1 Catalog",
        content_hash="catalog123",
    )
    db_session.add(doc)
    db_session.commit()

    # Embed and add chunks
    records = []
    for idx, text in enumerate(corpus, start=1):
        vec = embedder.embed_text(text)
        records.append(VectorRecord(
            chunk_id=idx,
            document_id=1,
            embedding=vec,
            metadata={"content": text, "index": idx}
        ))
    store.add_many(records)
    assert store.count() == 3

    # Query for dynamic code loading
    query_text = "dynamic code loading DexClassLoader"
    query_vec = embedder.embed_text(query_text)

    search_results = store.search(query_embedding=query_vec, top_k=3)
    assert len(search_results) == 3

    # Top result MUST be chunk 1 (dynamic code loading)
    assert search_results[0].chunk_id == 1
    assert "DexClassLoader" in search_results[0].metadata["content"]

    # Unrelated chunk (SMS Trojan) must rank lower
    chunk_1_score = search_results[0].similarity_score
    unrelated_score = [r.similarity_score for r in search_results if r.chunk_id == 2][0]
    assert chunk_1_score > unrelated_score


def test_factory_vector_store(db_session):
    """Test get_vector_store factory function."""
    store = get_vector_store("sqlite", db_session=db_session)
    assert isinstance(store, SQLiteVectorStore)

    with pytest.raises(ValueError, match="db_session is required"):
        get_vector_store("sqlite", db_session=None)

    with pytest.raises(ValueError, match="Unknown or unsupported vector store"):
        get_vector_store("pgvector", db_session=db_session)

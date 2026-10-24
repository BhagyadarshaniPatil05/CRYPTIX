"""
Phase 3.5.2 — Vector Store Abstraction and SQLite MVP Vector Store Implementation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import json
from typing import List, Dict, Any, Optional
import numpy as np
from sqlalchemy.orm import Session

from app.models.rag import RagChunk


@dataclass
class VectorRecord:
    chunk_id: int
    document_id: int
    embedding: np.ndarray
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VectorSearchResult:
    chunk_id: int
    document_id: int
    similarity_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseVectorStore(ABC):
    """Abstract Base Class for Vector Stores (e.g. SQLite, FAISS, pgvector)."""

    @abstractmethod
    def add(self, record: VectorRecord) -> None:
        """Add a single vector record."""
        pass

    @abstractmethod
    def add_many(self, records: List[VectorRecord]) -> None:
        """Add a batch of vector records."""
        pass

    @abstractmethod
    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
        metadata_filters: Optional[Dict[str, Any]] = None
    ) -> List[VectorSearchResult]:
        """Search for top_k most similar vector records matching optional filters."""
        pass

    @abstractmethod
    def delete(self, chunk_id: int) -> bool:
        """Delete a vector record by chunk_id."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Return total number of stored vector records."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored vector records."""
        pass


class SQLiteVectorStore(BaseVectorStore):
    """
    SQLite Vector Store Implementation for Local MVP.

    Stores vector embeddings as JSON serialized strings in the database (RagChunk.embedding_json).
    Performs in-memory numpy cosine similarity calculation over candidate records for top-K ranking.
    Provides a zero-dependency local MVP vector store while preserving the BaseVectorStore abstraction.
    """

    def __init__(self, db_session: Session):
        self.db = db_session

    def add(self, record: VectorRecord) -> None:
        self.add_many([record])

    def add_many(self, records: List[VectorRecord]) -> None:
        if not records:
            return

        for rec in records:
            chunk = self.db.query(RagChunk).filter(RagChunk.id == rec.chunk_id).first()
            emb_list = rec.embedding.tolist() if isinstance(rec.embedding, np.ndarray) else list(rec.embedding)
            emb_json = json.dumps(emb_list)

            if chunk:
                chunk.embedding_json = emb_json
            else:
                chunk = RagChunk(
                    id=rec.chunk_id,
                    document_id=rec.document_id,
                    content=rec.metadata.get("content", ""),
                    section_title=rec.metadata.get("section_title"),
                    technique_id=rec.metadata.get("technique_id"),
                    cve_id=rec.metadata.get("cve_id"),
                    embedding_json=emb_json,
                )
                self.db.add(chunk)

        self.db.commit()

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
        metadata_filters: Optional[Dict[str, Any]] = None
    ) -> List[VectorSearchResult]:
        if query_embedding is None or len(query_embedding) == 0:
            return []

        q_vec = np.asarray(query_embedding, dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)

        query = self.db.query(RagChunk).filter(RagChunk.embedding_json.isnot(None))

        # Apply metadata filters if provided
        if metadata_filters:
            if "technique_id" in metadata_filters and metadata_filters["technique_id"]:
                query = query.filter(RagChunk.technique_id == metadata_filters["technique_id"])
            if "cve_id" in metadata_filters and metadata_filters["cve_id"]:
                query = query.filter(RagChunk.cve_id == metadata_filters["cve_id"])
            if "document_id" in metadata_filters and metadata_filters["document_id"]:
                query = query.filter(RagChunk.document_id == metadata_filters["document_id"])

        chunks = query.all()
        if not chunks:
            return []

        results: List[VectorSearchResult] = []

        for chunk in chunks:
            if not chunk.embedding_json:
                continue

            try:
                emb_list = json.loads(chunk.embedding_json)
                c_vec = np.asarray(emb_list, dtype=np.float32)

                # Skip vector dimension mismatch
                if c_vec.shape != q_vec.shape:
                    continue

                c_norm = np.linalg.norm(c_vec)
                if q_norm > 0 and c_norm > 0:
                    sim = float(np.dot(q_vec, c_vec) / (q_norm * c_norm))
                else:
                    sim = 0.0

                meta = {
                    "section_title": chunk.section_title,
                    "technique_id": chunk.technique_id,
                    "cve_id": chunk.cve_id,
                    "content": chunk.content,
                }
                if chunk.document:
                    meta.update({
                        "source": chunk.document.source,
                        "source_type": chunk.document.source_type,
                        "title": chunk.document.title,
                        "url": chunk.document.url,
                        "trust_level": chunk.document.trust_level,
                    })

                results.append(VectorSearchResult(
                    chunk_id=chunk.id,
                    document_id=chunk.document_id,
                    similarity_score=sim,
                    metadata=meta,
                ))
            except Exception:
                continue

        # Sort descending by similarity score
        results.sort(key=lambda r: r.similarity_score, reverse=True)
        return results[:top_k]

    def delete(self, chunk_id: int) -> bool:
        chunk = self.db.query(RagChunk).filter(RagChunk.id == chunk_id).first()
        if not chunk:
            return False

        chunk.embedding_json = None
        self.db.commit()
        return True

    def count(self) -> int:
        return self.db.query(RagChunk).filter(RagChunk.embedding_json.isnot(None)).count()

    def clear(self) -> None:
        chunks = self.db.query(RagChunk).filter(RagChunk.embedding_json.isnot(None)).all()
        for chunk in chunks:
            chunk.embedding_json = None
        self.db.commit()


def get_vector_store(store_type: str = "sqlite", db_session: Optional[Session] = None) -> BaseVectorStore:
    """Factory function for instantiating vector stores."""
    store_clean = (store_type or "sqlite").lower().strip()
    if store_clean in ("sqlite", "local"):
        if db_session is None:
            raise ValueError("db_session is required for SQLiteVectorStore.")
        return SQLiteVectorStore(db_session=db_session)
    else:
        raise ValueError(f"Unknown or unsupported vector store: '{store_type}'. Supported for MVP: 'sqlite'.")

"""
Phase 3.5.3 — RAG Document Ingestion & Database Persistence Service.
"""

from dataclasses import dataclass
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.rag import RagDocument, RagChunk
from app.rag.document_loader import CybersecurityDocument, MitreMobileLoader
from app.rag.chunker import CybersecurityChunker


@dataclass
class IngestionResult:
    documents_processed: int
    documents_created: int
    documents_skipped: int
    chunks_created: int
    chunks_skipped: int


def ingest_cybersecurity_documents(
    db: Session,
    documents: List[CybersecurityDocument],
    chunker: Optional[CybersecurityChunker] = None
) -> IngestionResult:
    """
    Persist normalized CybersecurityDocument records and section-aware RagChunk records to database.

    Deduplicates documents based on unique content_hash.
    Leaves RagChunk.embedding_json NULL to decouple document ingestion from vector indexing.
    """
    if chunker is None:
        chunker = CybersecurityChunker()

    docs_processed = 0
    docs_created = 0
    docs_skipped = 0
    chunks_created = 0
    chunks_skipped = 0

    for doc in documents:
        docs_processed += 1

        # Deduplication check by SHA-256 content_hash
        existing_doc = db.query(RagDocument).filter(RagDocument.content_hash == doc.content_hash).first()
        if existing_doc:
            docs_skipped += 1
            chunks_skipped += db.query(RagChunk).filter(RagChunk.document_id == existing_doc.id).count()
            continue

        # Create new RagDocument
        db_doc = RagDocument(
            source=doc.source,
            source_type=doc.source_type,
            source_version=doc.source_version,
            trust_level=doc.trust_level,
            title=doc.title,
            url=doc.url,
            publisher=doc.publisher,
            published_at=doc.published_at,
            updated_at=doc.updated_at,
            last_verified=doc.last_verified,
            platform=doc.platform,
            technique_id=doc.technique_id,
            cve_id=doc.cve_id,
            content_hash=doc.content_hash,
        )
        db.add(db_doc)
        db.flush()  # Obtain db_doc.id
        docs_created += 1

        # Chunk document content
        parsed_chunks = chunker.chunk_document(doc)

        for chunk_data in parsed_chunks:
            db_chunk = RagChunk(
                document_id=db_doc.id,
                chunk_index=chunk_data.chunk_index,
                section_title=chunk_data.section_title,
                content=chunk_data.content,
                technique_id=chunk_data.technique_id,
                cve_id=chunk_data.cve_id,
                embedding_json=None,  # Decoupled from vector embedding generation
            )
            db.add(db_chunk)
            chunks_created += 1

    db.commit()

    return IngestionResult(
        documents_processed=docs_processed,
        documents_created=docs_created,
        documents_skipped=docs_skipped,
        chunks_created=chunks_created,
        chunks_skipped=chunks_skipped,
    )


def ingest_mitre_mobile_catalog(db: Session) -> IngestionResult:
    """
    Convenience function to load and ingest the pinned MITRE ATT&CK Mobile v15.1 catalog into the database.
    """
    loader = MitreMobileLoader()
    docs = loader.load()
    chunker = CybersecurityChunker(max_chunk_chars=1500)
    return ingest_cybersecurity_documents(db=db, documents=docs, chunker=chunker)

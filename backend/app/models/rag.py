from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class RagDocument(Base):
    __tablename__ = "rag_documents"

    id = Column(Integer, primary_key=True, index=True)

    source = Column(String(100), nullable=False, index=True)  # e.g., MITRE_ATTACK, NVD, CISA
    source_type = Column(String(50), nullable=False, index=True)  # e.g., MITRE, NVD, CISA, ANDROID_DOCS, VENDOR_REPORT, PROJECT_INVESTIGATION
    source_version = Column(String(50), nullable=True, default="15.1")
    trust_level = Column(String(30), nullable=False, default="AUTHORITATIVE", index=True)  # AUTHORITATIVE, TRUSTED_VENDOR, RESEARCH, UNKNOWN

    title = Column(String(255), nullable=False)
    url = Column(String(500), nullable=True)
    publisher = Column(String(100), nullable=True)

    published_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    last_verified = Column(DateTime, nullable=True)
    collection_timestamp = Column(DateTime, default=datetime.utcnow)

    platform = Column(String(50), nullable=True, default="Android", index=True)
    technique_id = Column(String(50), nullable=True, index=True)  # e.g. T1407
    cve_id = Column(String(50), nullable=True, index=True)        # e.g. CVE-2024-1234
    content_hash = Column(String(64), nullable=False, unique=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    chunks = relationship("RagChunk", back_populates="document", cascade="all, delete-orphan")


class RagChunk(Base):
    __tablename__ = "rag_chunks"

    id = Column(Integer, primary_key=True, index=True)

    document_id = Column(
        Integer,
        ForeignKey("rag_documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    chunk_index = Column(Integer, nullable=False, default=0)
    section_title = Column(String(255), nullable=True)
    content = Column(Text, nullable=False)

    embedding_json = Column(Text, nullable=True)        # Vector embedding array stored as JSON
    lexical_tokens_json = Column(Text, nullable=True)   # Token frequencies for TF-IDF lexical fallback

    technique_id = Column(String(50), nullable=True, index=True)
    cve_id = Column(String(50), nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    document = relationship("RagDocument", back_populates="chunks")


class RagQueryLog(Base):
    __tablename__ = "rag_query_logs"

    id = Column(Integer, primary_key=True, index=True)

    apk_id = Column(
        Integer,
        ForeignKey("apk_metadata.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    question = Column(Text, nullable=False)
    retrieved_chunk_ids_json = Column(Text, nullable=True)
    grounding_state = Column(String(30), nullable=False, default="SUPPORTED")
    llm_provider = Column(String(50), nullable=True)
    latency_ms = Column(Float, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    apk = relationship("APKMetadata")

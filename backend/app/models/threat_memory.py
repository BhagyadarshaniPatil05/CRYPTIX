from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class ThreatMemory(Base):
    __tablename__ = "threat_memory"

    id = Column(Integer, primary_key=True, index=True)

    apk_id = Column(
        Integer,
        ForeignKey("apk_metadata.id"),
        nullable=False,
        unique=True,
        index=True
    )

    sha256 = Column(String, nullable=False, index=True)

    dna_hash = Column(String(68), nullable=True, index=True)

    status = Column(String, nullable=False, index=True, default="NEW_SAMPLE")

    matched_apk_id = Column(
        Integer,
        ForeignKey("apk_metadata.id"),
        nullable=True
    )

    similarity_score = Column(Float, nullable=True)

    historical_risk_score = Column(Integer, nullable=True)

    historical_threat_level = Column(String, nullable=True)

    historical_family = Column(String, nullable=True)

    digital_twin_id = Column(Integer, nullable=True)

    match_explanation_json = Column(Text, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    apk = relationship("APKMetadata", foreign_keys=[apk_id])
    matched_apk = relationship("APKMetadata", foreign_keys=[matched_apk_id])

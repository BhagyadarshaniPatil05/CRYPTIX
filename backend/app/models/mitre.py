from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id = Column(Integer, primary_key=True, index=True)

    apk_id = Column(
        Integer,
        ForeignKey("apk_metadata.id"),
        nullable=False,
        index=True
    )

    technique_id = Column(String(50), nullable=False, index=True)

    technique_name = Column(String(255), nullable=False)

    tactic = Column(String(100), nullable=False, index=True)

    evidence_type = Column(String(50), nullable=False)

    evidence_reference = Column(String(255), nullable=False)

    evidence_summary = Column(Text, nullable=True)

    confidence = Column(String(20), nullable=False, default="MEDIUM")

    rule_id = Column(String(50), nullable=False)

    attack_version = Column(String(20), nullable=False, default="Mobile v15.1")

    created_at = Column(DateTime, default=datetime.utcnow)

    apk = relationship("APKMetadata")

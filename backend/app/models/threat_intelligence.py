from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"

    id = Column(Integer, primary_key=True, index=True)

    apk_id = Column(
        Integer,
        ForeignKey("apk_metadata.id"),
        nullable=False,
        index=True
    )

    provider = Column(String(50), nullable=False, index=True)

    indicator_type = Column(String(50), nullable=False, index=True)

    indicator_value = Column(String(255), nullable=False, index=True)

    status = Column(String(50), nullable=False, default="NOT_CONFIGURED")

    found = Column(Boolean, default=False)

    normalized_result_json = Column(Text, nullable=False, default="{}")

    raw_metadata_json = Column(Text, nullable=True)

    cached = Column(Boolean, default=False)

    queried_at = Column(DateTime, default=datetime.utcnow)

    expires_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    apk = relationship("APKMetadata")

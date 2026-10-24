from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class DigitalTwin(Base):
    __tablename__ = "digital_twins"

    id = Column(Integer, primary_key=True, index=True)

    # Link the Digital Twin to the original APK
    apk_id = Column(
        Integer,
        ForeignKey("apk_metadata.id"),
        nullable=False,
        unique=True
    )

    package_name = Column(String, nullable=False)
    app_name = Column(String, nullable=True)

    current_version = Column(Integer, default=1)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Relationship with APK
    apk = relationship("APKMetadata")

    # All historical states of this Digital Twin
    versions = relationship(
        "DigitalTwinVersion",
        back_populates="digital_twin",
        cascade="all, delete-orphan"
    )


class DigitalTwinVersion(Base):
    __tablename__ = "digital_twin_versions"

    id = Column(Integer, primary_key=True, index=True)

    digital_twin_id = Column(
        Integer,
        ForeignKey("digital_twins.id"),
        nullable=False
    )

    version_number = Column(Integer, nullable=False)

    # APK security state
    package_name = Column(String, nullable=False)
    app_name = Column(String, nullable=True)

    version_name = Column(String, nullable=True)
    version_code = Column(String, nullable=True)

    # Complete Digital Twin state
    permissions = Column(JSON, nullable=False, default=list)

    dangerous_permissions = Column(
        JSON,
        nullable=False,
        default=list
    )

    exported_components = Column(
        JSON,
        nullable=False,
        default=dict
    )

    intent_filters = Column(
        JSON,
        nullable=False,
        default=list
    )

    certificate = Column(
        JSON,
        nullable=False,
        default=dict
    )

    indicators = Column(
        JSON,
        nullable=False,
        default=dict
    )

    behaviors = Column(
        JSON,
        nullable=False,
        default=list
    )

    dex_findings = Column(
        JSON,
        nullable=False,
        default=list
    )

    yara_matches = Column(
        JSON,
        nullable=False,
        default=list
    )

    risk_score = Column(
        Integer,
        nullable=False
    )

    risk_level = Column(
        String,
        nullable=False
    )

    threat_level = Column(
        String,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    # Relationship back to DigitalTwin
    digital_twin = relationship(
        "DigitalTwin",
        back_populates="versions"
    )
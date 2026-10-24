from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinVersion
)


def get_security_timeline(
    db: Session,
    twin_id: int
):
    versions = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number
        )
        .all()
    )

    return [
        {
            "version": v.version_number,
            "risk_score": v.risk_score,
            "risk_level": v.risk_level,
            "threat_level": v.threat_level,
            "created_at": v.created_at
        }
        for v in versions
    ]
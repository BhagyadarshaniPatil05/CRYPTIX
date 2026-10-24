from sqlalchemy.orm import Session

from app.models.digital_twin import DigitalTwinVersion


def get_risk_graph(
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
            "version": version.version_number,
            "risk_score": version.risk_score,
            "risk_level": version.risk_level,
            "threat_level": version.threat_level
        }
        for version in versions
    ]
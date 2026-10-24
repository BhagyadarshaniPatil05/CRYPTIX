from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwin,
    DigitalTwinVersion
)


def get_twin_summary(
    db: Session,
    twin_id: int
):
    twin = (
        db.query(DigitalTwin)
        .filter(DigitalTwin.id == twin_id)
        .first()
    )

    if not twin:
        return {
            "error": "Twin not found"
        }

    latest = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .first()
    )

    total_versions = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .count()
    )

    return {
        "digital_twin_id": twin.id,
        "package_name": twin.package_name,
        "app_name": twin.app_name,
        "total_versions": total_versions,
        "latest_risk_score": latest.risk_score,
        "latest_risk_level": latest.risk_level,
        "latest_threat_level": latest.threat_level
    }
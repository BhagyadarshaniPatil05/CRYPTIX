from sqlalchemy.orm import Session

from app.models.digital_twin import DigitalTwinVersion


def get_twin_analytics(
    db: Session,
    twin_id: int
):
    versions = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .all()
    )

    if not versions:
        return {
            "error": "No versions found"
        }

    scores = [
        version.risk_score
        for version in versions
    ]

    return {
        "total_versions": len(scores),
        "average_risk_score":
            round(sum(scores) / len(scores), 2),

        "highest_risk_score":
            max(scores),

        "lowest_risk_score":
            min(scores),

        "latest_risk_score":
            scores[-1]
    }
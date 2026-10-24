from sqlalchemy.orm import Session

from app.models.apk import APKMetadata
from app.models.digital_twin import (
    DigitalTwin,
    DigitalTwinVersion
)


def get_dashboard_metrics(db: Session):

    total_apks = db.query(
        APKMetadata
    ).count()

    twins = db.query(
        DigitalTwin
    ).all()

    high_risk = 0
    medium_risk = 0
    low_risk = 0

    risk_scores = []

    for twin in twins:

        latest = (
            db.query(DigitalTwinVersion)
            .filter(
                DigitalTwinVersion.digital_twin_id
                == twin.id
            )
            .order_by(
                DigitalTwinVersion.version_number.desc()
            )
            .first()
        )

        if not latest:
            continue

        risk_scores.append(
            latest.risk_score
        )

        if latest.risk_level == "High":
            high_risk += 1

        elif latest.risk_level == "Medium":
            medium_risk += 1

        elif latest.risk_level == "Low":
            low_risk += 1

    avg_risk = 0

    if risk_scores:
        avg_risk = round(
            sum(risk_scores) / len(risk_scores),
            2
        )

    return {
        "total_apks": total_apks,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "average_risk_score": avg_risk
    }
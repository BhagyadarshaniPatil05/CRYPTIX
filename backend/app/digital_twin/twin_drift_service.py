from sqlalchemy.orm import Session

from app.models.digital_twin import DigitalTwinVersion


def detect_drift(
    db: Session,
    twin_id: int
):
    versions = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .limit(2)
        .all()
    )

    if len(versions) < 2:
        return {
            "status": "Not enough versions",
            "message": "At least 2 versions are required."
        }

    latest = versions[0]
    previous = versions[1]

    old_permissions = set(previous.permissions)
    new_permissions_set = set(latest.permissions)

    old_behaviors = {
        item.get("api")
        for item in previous.behaviors
    }

    new_behaviors_set = {
        item.get("api")
        for item in latest.behaviors
    }

    risk_change = (
        latest.risk_score
        - previous.risk_score
    )

    added_permissions = list(
        new_permissions_set - old_permissions
    )

    removed_permissions = list(
        old_permissions - new_permissions_set
    )

    added_behaviors = list(
        new_behaviors_set - old_behaviors
    )

    removed_behaviors = list(
        old_behaviors - new_behaviors_set
    )

    status = "Stable"

    if risk_change > 0:
        status = "Risk Increased"

    elif risk_change < 0:
        status = "Risk Reduced"

    return {
        "status": status,

        "previous_version":
        previous.version_number,

        "current_version":
        latest.version_number,

        "risk_change":
        risk_change,

        "old_risk":
        previous.risk_score,

        "new_risk":
        latest.risk_score,

        "new_permissions":
        added_permissions,

        "removed_permissions":
        removed_permissions,

        "new_behaviors":
        added_behaviors,

        "removed_behaviors":
        removed_behaviors
    }
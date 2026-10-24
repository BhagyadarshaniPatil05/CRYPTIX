from collections import Counter

from app.models.digital_twin import (
    DigitalTwin,
    DigitalTwinVersion
)


def get_top_permissions(db):

    twins = db.query(
        DigitalTwin
    ).all()

    counter = Counter()

    for twin in twins:

        latest_version = (
            db.query(DigitalTwinVersion)
            .filter(
                DigitalTwinVersion.digital_twin_id == twin.id
            )
            .order_by(
                DigitalTwinVersion.version_number.desc()
            )
            .first()
        )

        if not latest_version:
            continue

        for permission in (
            latest_version.dangerous_permissions or []
        ):

            counter[
                permission["permission"]
            ] += 1

    return [
        {
            "permission": permission,
            "count": count
        }
        for permission, count
        in counter.most_common(10)
    ]

def get_risk_distribution(db):

    twins = db.query(
        DigitalTwin
    ).all()

    high = 0
    medium = 0
    low = 0

    for twin in twins:

        latest_version = (
            db.query(DigitalTwinVersion)
            .filter(
                DigitalTwinVersion.digital_twin_id == twin.id
            )
            .order_by(
                DigitalTwinVersion.version_number.desc()
            )
            .first()
        )

        if not latest_version:
            continue

        if latest_version.risk_level == "High":
            high += 1

        elif latest_version.risk_level == "Medium":
            medium += 1

        elif latest_version.risk_level == "Low":
            low += 1

    return {
        "High": high,
        "Medium": medium,
        "Low": low
    }

def get_threat_levels(db):

    twins = db.query(
        DigitalTwin
    ).all()

    counter = Counter()

    for twin in twins:

        latest_version = (
            db.query(DigitalTwinVersion)
            .filter(
                DigitalTwinVersion.digital_twin_id == twin.id
            )
            .order_by(
                DigitalTwinVersion.version_number.desc()
            )
            .first()
        )

        if not latest_version:
            continue

        counter[
            latest_version.threat_level
        ] += 1

    return dict(counter)

def get_recent_analyses(db):

    versions = (
        db.query(
            DigitalTwinVersion
        )
        .order_by(
            DigitalTwinVersion.created_at.desc()
        )
        .limit(10)
        .all()
    )

    return [
        {
            "package_name":
                version.package_name,

            "digital_twin_id":
                version.digital_twin_id,

            "apk_id":
                version.digital_twin.apk_id if version.digital_twin else None,

            "risk_score":
                version.risk_score,

            "risk_level":
                version.risk_level,

            "threat_level":
                version.threat_level,

            "created_at":
                version.created_at
        }
        for version in versions
    ]
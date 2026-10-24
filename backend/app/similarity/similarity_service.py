from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwinVersion
)


def jaccard_score(list_a, list_b):

    set_a = set(list_a)
    set_b = set(list_b)

    if not set_a and not set_b:
        return 100

    union = len(set_a | set_b)

    if union == 0:
        return 0

    intersection = len(set_a & set_b)

    return (intersection / union) * 100


def calculate_similarity(
    target,
    candidate
):

    permission_score = jaccard_score(
        target.permissions,
        candidate.permissions
    )

    dangerous_a = [
        p["permission"]
        for p in (
            target.dangerous_permissions or []
        )
    ]

    dangerous_b = [
        p["permission"]
        for p in (
            candidate.dangerous_permissions or []
        )
    ]

    dangerous_score = jaccard_score(
        dangerous_a,
        dangerous_b
    )

    behavior_a = [
        b["api"]
        for b in (
            target.behaviors or []
        )
    ]

    behavior_b = [
        b["api"]
        for b in (
            candidate.behaviors or []
        )
    ]

    behavior_score = jaccard_score(
        behavior_a,
        behavior_b
    )

    threat_score = (
        100
        if target.threat_level ==
           candidate.threat_level
        else 0
    )

    final_score = (
        permission_score * 0.40
        + dangerous_score * 0.20
        + behavior_score * 0.20
        + threat_score * 0.20
    )

    return round(final_score, 2)


def find_similar_apks(
    db: Session,
    twin_id: int
):

    target = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id
            == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .first()
    )

    if not target:
        return []

    all_versions = (
        db.query(DigitalTwinVersion)
        .all()
    )

    # Keep latest version of each twin
    latest_versions = {}

    for version in all_versions:

        current_twin_id = (
            version.digital_twin_id
        )

        if (
            current_twin_id
            not in latest_versions
        ):

            latest_versions[
                current_twin_id
            ] = version

        elif (
            version.version_number >
            latest_versions[
                current_twin_id
            ].version_number
        ):

            latest_versions[
                current_twin_id
            ] = version

    results = []

    for version in latest_versions.values():

        if (
            version.digital_twin_id
            == twin_id
        ):
            continue

        score = calculate_similarity(
            target,
            version
        )

        if score >= 80:
            relationship = "Highly Similar"

        elif score >= 50:
            relationship = "Moderately Similar"

        elif score >= 20:
            relationship = "Weakly Similar"

        else:
            relationship = "Unrelated"

        results.append(
            {
                "package_name":
                    version.package_name,

                "digital_twin_id":
                    version.digital_twin_id,

                "similarity_score":
                    score,

                "relationship":
                    relationship,

                "risk_level":
                    version.risk_level
            }
        )

    results.sort(
        key=lambda x: x["similarity_score"],
        reverse=True
    )

    return results[:10]
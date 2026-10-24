from app.models.digital_twin import (
    DigitalTwinVersion
)


def detect_drift(
    old_version: DigitalTwinVersion,
    new_version: DigitalTwinVersion
):
    """
    Detect security drift between
    two Digital Twin versions.
    """

    changes = []

    # -------------------------
    # Permission Drift
    # -------------------------
    old_permissions = set(
        old_version.permissions or []
    )

    new_permissions = set(
        new_version.permissions or []
    )

    added_permissions = (
        new_permissions - old_permissions
    )

    removed_permissions = (
        old_permissions - new_permissions
    )

    for permission in added_permissions:
        changes.append(
            f"New permission: {permission}"
        )

    for permission in removed_permissions:
        changes.append(
            f"Removed permission: {permission}"
        )

    # -------------------------
    # Risk Score Drift
    # -------------------------
    if (
        new_version.risk_score
        > old_version.risk_score
    ):
        changes.append(
            f"Risk score increased "
            f"{old_version.risk_score}"
            f" -> "
            f"{new_version.risk_score}"
        )

    elif (
        new_version.risk_score
        < old_version.risk_score
    ):
        changes.append(
            f"Risk score decreased "
            f"{old_version.risk_score}"
            f" -> "
            f"{new_version.risk_score}"
        )

    # -------------------------
    # Threat Level Drift
    # -------------------------
    if (
        old_version.threat_level
        != new_version.threat_level
    ):
        changes.append(
            f"Threat level changed "
            f"{old_version.threat_level}"
            f" -> "
            f"{new_version.threat_level}"
        )

    return {
        "drift_detected": len(changes) > 0,
        "changes": changes
    }
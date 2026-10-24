def compare_versions(
    old_version,
    new_version
):
    old_permissions = set(
        old_version.permissions or []
    )

    new_permissions = set(
        new_version.permissions or []
    )

    old_behaviors = {
        b.get("api", str(b))
        for b in (old_version.behaviors or [])
    }

    new_behaviors = {
        b.get("api", str(b))
        for b in (new_version.behaviors or [])
    }

    return {
        "from_version": old_version.version_number,
        "to_version": new_version.version_number,

        "risk_score_old": old_version.risk_score,
        "risk_score_new": new_version.risk_score,

        "risk_score_change":
            new_version.risk_score
            - old_version.risk_score,

        "threat_level_old":
            old_version.threat_level,

        "threat_level_new":
            new_version.threat_level,

        "new_permissions":
            list(
                new_permissions
                - old_permissions
            ),

        "removed_permissions":
            list(
                old_permissions
                - new_permissions
            ),

        "new_behaviors":
            list(
                new_behaviors
                - old_behaviors
            ),

        "removed_behaviors":
            list(
                old_behaviors
                - new_behaviors
            )
    }
def generate_recommendations(
    version
):

    recommendations = []

    dangerous_permissions = (
        version.dangerous_permissions
        or []
    )

    for permission in (
        dangerous_permissions
    ):

        permission_name = (
            permission.get(
                "permission",
                ""
            )
        )

        if (
            "SEND_SMS"
            in permission_name
        ):

            recommendations.append(
                {
                    "issue":
                        "Dangerous SMS Permission",

                    "severity":
                        "Critical",

                    "recommendation":
                        "Remove SEND_SMS permission if not required"
                }
            )

        elif (
            "READ_PHONE_STATE"
            in permission_name
        ):

            recommendations.append(
                {
                    "issue":
                        "Phone State Access",

                    "severity":
                        "Medium",

                    "recommendation":
                        "Limit access to device information"
                }
            )

    exported = (
        version.exported_components
        or {}
    )

    activities = (
        exported.get(
            "activities",
            []
        )
    )

    if activities:

        recommendations.append(
            {
                "issue":
                    "Exported Activity Detected",

                "severity":
                    "Medium",

                "recommendation":
                    "Restrict exported activities where possible"
            }
        )

    behaviors = (
        version.behaviors
        or []
    )

    for behavior in behaviors:

        api = (
            behavior.get(
                "api",
                ""
            )
        )

        if api == "su":

            recommendations.append(
                {
                    "issue":
                        "Root Access Attempt",

                    "severity":
                        "Critical",

                    "recommendation":
                        "Investigate root access behavior immediately"
                }
            )

    return recommendations
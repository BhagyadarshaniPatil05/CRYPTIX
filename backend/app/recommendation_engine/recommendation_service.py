def generate_recommendations(version):

    recommendations = []

    permissions = (
        version.permissions or []
    )

    behaviors = (
        version.behaviors or []
    )

    dangerous_permissions = (
        version.dangerous_permissions or []
    )

    # SEND_SMS

    if (
        "android.permission.SEND_SMS"
        in permissions
    ):
        recommendations.append(
            {
                "severity": "Critical",
                "issue":
                    "SEND_SMS permission detected",
                "recommendation":
                    "Remove SEND_SMS permission unless absolutely required."
            }
        )

    # WRITE_EXTERNAL_STORAGE

    if (
        "android.permission.WRITE_EXTERNAL_STORAGE"
        in permissions
    ):
        recommendations.append(
            {
                "severity": "Medium",
                "issue":
                    "External storage access",
                "recommendation":
                    "Use scoped storage whenever possible."
            }
        )

    # INTERNET

    if (
        "android.permission.INTERNET"
        in permissions
    ):
        recommendations.append(
            {
                "severity": "Low",
                "issue":
                    "Internet communication enabled",
                "recommendation":
                    "Validate all remote endpoints and use HTTPS."
            }
        )

    # Root behavior

    for behavior in behaviors:

        if (
            behavior.get("api")
            == "su"
        ):
            recommendations.append(
                {
                    "severity": "Critical",
                    "issue":
                        "Root access attempt detected",
                    "recommendation":
                        "Investigate possible privilege escalation behavior."
                }
            )

    # Exported Activities

    exported = (
        version.exported_components
        or {}
    )

    activities = (
        exported.get("activities", [])
    )

    if len(activities) > 0:

        recommendations.append(
            {
                "severity": "Medium",
                "issue":
                    "Exported activities detected",
                "recommendation":
                    "Review exported activities and restrict access where possible."
            }
        )

    return recommendations
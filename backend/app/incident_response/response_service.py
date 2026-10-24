def generate_incident_response(version):

    actions = []

    severity = "Low"

    permissions = (
        version.permissions or []
    )

    behaviors = (
        version.behaviors or []
    )

    risk_score = (
        version.risk_score or 0
    )

    # High-risk indicators

    if (
        "android.permission.SEND_SMS"
        in permissions
    ):

        severity = "Critical"

        actions.append(
            "Block APK deployment immediately"
        )

        actions.append(
            "Review SMS-related functionality"
        )

    # Root access behavior

    for behavior in behaviors:

        if (
            behavior.get("api")
            == "su"
        ):

            severity = "Critical"

            actions.append(
                "Investigate root access attempts"
            )

            actions.append(
                "Perform malware sandbox analysis"
            )

    # Medium-risk APK

    if (
        risk_score >= 20
        and severity != "Critical"
    ):

        severity = "Medium"

        actions.append(
            "Perform manual security review"
        )

        actions.append(
            "Review permissions and components"
        )

    # Low-risk APK

    if not actions:

        actions.append(
            "Continue monitoring"
        )

        actions.append(
            "No immediate action required"
        )

    return {
        "incident_severity":
            severity,

        "recommended_actions":
            actions
    }
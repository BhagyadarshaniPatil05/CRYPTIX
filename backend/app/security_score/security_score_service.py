def calculate_security_score(version):

    score = 100

    permissions = (
        version.permissions or []
    )

    behaviors = (
        version.behaviors or []
    )

    exported = (
        version.exported_components or {}
    )

    activities = (
        exported.get("activities", [])
    )

    # Critical permissions

    if (
        "android.permission.SEND_SMS"
        in permissions
    ):
        score -= 30

    if (
        "android.permission.READ_PHONE_STATE"
        in permissions
    ):
        score -= 10

    if (
        "android.permission.WRITE_EXTERNAL_STORAGE"
        in permissions
    ):
        score -= 10

    if (
        "android.permission.INTERNET"
        in permissions
    ):
        score -= 5

    # Dangerous behaviors

    for behavior in behaviors:

        if (
            behavior.get("api")
            == "su"
        ):
            score -= 30

    # Exported activities

    if len(activities) > 0:
        score -= 10

    # Keep score between 0 and 100

    score = max(0, min(score, 100))

    # Grade

    if score >= 90:
        grade = "A"
        status = "Very Safe"

    elif score >= 75:
        grade = "B"
        status = "Mostly Safe"

    elif score >= 60:
        grade = "C"
        status = "Moderate Risk"

    elif score >= 40:
        grade = "D"
        status = "Unsafe"

    else:
        grade = "F"
        status = "Critical Risk"

    return {
        "security_score": score,
        "grade": grade,
        "status": status
    }
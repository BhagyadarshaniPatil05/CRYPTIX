SEVERITY_SCORES = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3
}


def calculate_risk_score(
    dangerous_permissions,
    behaviors=None,
    yara_matches=None
):
    """
    Calculate overall risk score from dangerous permissions,
    suspicious behaviors, and YARA matches.
    """

    score = 0

    # -----------------------------
    # Score from permissions
    # -----------------------------
    for permission in dangerous_permissions:
        severity = permission["severity"]
        score += SEVERITY_SCORES.get(severity, 0)

    # -----------------------------
    # Score from suspicious behaviors
    # -----------------------------
    if behaviors:
        for behavior in behaviors:
            severity = behavior["severity"]
            score += SEVERITY_SCORES.get(severity, 0)

    # -----------------------------
    # Score from YARA matches
    # -----------------------------
    if yara_matches:
        for match in yara_matches:
            # YARA currently returns rule, namespace and tags.
            # Severity will be added to the YARA result later.
            severity = match.get("severity", "Low")
            score += SEVERITY_SCORES.get(severity, 0)

    # -----------------------------
    # Determine risk level
    # -----------------------------
    if score >= 70:
        risk_level = "Critical"

    elif score >= 40:
        risk_level = "High"

    elif score >= 20:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {
        "risk_score": score,
        "risk_level": risk_level
    }
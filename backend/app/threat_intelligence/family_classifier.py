def classify_family(
    permissions,
    behaviors,
    indicators
):

    reasons = []

    permission_names = set(
        permissions or []
    )

    behavior_names = {
        b.get("api", "")
        for b in (behaviors or [])
    }

    # SMS Trojan
    if (
        "android.permission.SEND_SMS"
        in permission_names
    ):
        reasons.append(
            "SEND_SMS permission detected"
        )

        return {
            "family": "SMS Trojan",
            "confidence": "High",
            "reasons": reasons
        }

    # Root Malware
    if "su" in behavior_names:

        reasons.append(
            "Root access attempt detected"
        )

        return {
            "family": "Root Malware",
            "confidence": "High",
            "reasons": reasons
        }

    # Network Spyware
    if (
        "android.permission.INTERNET"
        in permission_names
    ):

        reasons.append(
            "Internet communication capability"
        )

        return {
            "family": "Network-enabled Application",
            "confidence": "Low",
            "reasons": reasons
        }

    return {
        "family": "Unknown",
        "confidence": "Low",
        "reasons": [
            "No malware family indicators detected"
        ]
    }
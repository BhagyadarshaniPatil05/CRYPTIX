from app.models.digital_twin import (
    DigitalTwinVersion
)


def calculate_twin_health(version):

    risk_score = (
        version.risk_score or 0
    )

    health_score = max(
        0,
        100 - risk_score
    )

    if health_score >= 90:
        health_status = "Excellent"

    elif health_score >= 75:
        health_status = "Good"

    elif health_score >= 50:
        health_status = "Fair"

    elif health_score >= 25:
        health_status = "Poor"

    else:
        health_status = "Critical"

    return {
        "health_score": health_score,
        "health_status": health_status
    }


def get_health_trend(versions):

    if len(versions) < 2:

        return "Insufficient Data"

    previous = (
        versions[-2].risk_score
    )

    current = (
        versions[-1].risk_score
    )

    if current > previous:
        return "Degrading"

    elif current < previous:
        return "Improving"

    else:
        return "Stable"
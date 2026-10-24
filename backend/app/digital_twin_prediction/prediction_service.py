from app.models.digital_twin import (
    DigitalTwinVersion
)


def predict_future_risk(
    versions
):

    if len(versions) < 2:

        latest = versions[-1]

        return {
            "current_risk":
                latest.risk_score,

            "predicted_risk":
                latest.risk_score,

            "trend":
                "Insufficient Data"
        }

    previous = (
        versions[-2].risk_score
    )

    current = (
        versions[-1].risk_score
    )

    change = (
        current - previous
    )

    predicted = (
        current + change
    )

    predicted = max(
        0,
        min(100, predicted)
    )

    if change > 0:
        trend = "Increasing"

    elif change < 0:
        trend = "Decreasing"

    else:
        trend = "Stable"

    return {
        "current_risk":
            current,

        "predicted_risk":
            predicted,

        "trend":
            trend
    }
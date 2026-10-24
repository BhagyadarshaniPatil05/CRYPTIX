from app.digital_twin_health.health_service import (
    calculate_twin_health,
    get_health_trend
)

from app.digital_twin_prediction.prediction_service import (
    predict_future_risk
)

from app.digital_twin_events.event_service import (
    get_twin_events
)

from app.digital_twin_lifecycle.lifecycle_service import (
    get_lifecycle_status
)


def build_twin_dashboard(
    twin
):

    latest = max(
        twin.versions,
        key=lambda x: x.version_number
    )

    lifecycle = (
        get_lifecycle_status(
            twin
        )
    )

    health = (
        calculate_twin_health(
            latest
        )
    )

    trend = (
        get_health_trend(
            twin.versions
        )
    )

    prediction = (
        predict_future_risk(
            twin.versions
        )
    )

    events = (
        get_twin_events(
            twin
        )
    )

    return {

        "twin_id":
            twin.id,

        "package_name":
            twin.package_name,

        "current_version":
            latest.version_number,

        "risk_score":
            latest.risk_score,

        "risk_level":
            latest.risk_level,

        "threat_level":
            latest.threat_level,

        "health":
            health,

        "health_trend":
            trend,

        "prediction":
            prediction,

        "lifecycle":
            lifecycle,

        "recent_events":
            events[-5:]
    }
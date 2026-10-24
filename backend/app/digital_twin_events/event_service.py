from app.models.digital_twin import (
    DigitalTwin
)


def get_twin_events(twin):

    events = []

    events.append(
        {
            "event":
                "Twin Created",

            "timestamp":
                twin.created_at
        }
    )

    for version in twin.versions:

        events.append(
            {
                "event":
                    f"Version {version.version_number} Created",

                "timestamp":
                    version.created_at,

                "risk_score":
                    version.risk_score,

                "risk_level":
                    version.risk_level,

                "threat_level":
                    version.threat_level
            }
        )

    events.sort(
        key=lambda x:
        x["timestamp"]
    )

    return events
def get_risk_trend(versions):

    if not versions:
        return []

    trend = []

    for version in versions:

        trend.append(
            {
                "version":
                    version.version_number,

                "risk_score":
                    version.risk_score,

                "risk_level":
                    version.risk_level,

                "threat_level":
                    version.threat_level,

                "created_at":
                    version.created_at
            }
        )

    return trend
from app.security_score.security_score_service import (
    calculate_security_score
)

from app.recommendation_engine.recommendation_service import (
    generate_recommendations
)

from app.incident_response.response_service import (
    generate_incident_response
)


def generate_executive_summary(version):

    security = calculate_security_score(
        version
    )

    recommendations = (
        generate_recommendations(
            version
        )
    )

    incident = (
        generate_incident_response(
            version
        )
    )

    summary = (
        f"APK '{version.package_name}' "
        f"has a risk level of "
        f"{version.risk_level} and "
        f"threat level of "
        f"{version.threat_level}. "
        f"The application received "
        f"a security score of "
        f"{security['security_score']}/100 "
        f"with grade "
        f"{security['grade']}. "
        f"{len(recommendations)} security "
        f"recommendations were generated. "
        f"Incident severity is "
        f"{incident['incident_severity']}."
    )

    return {
        "package_name":
            version.package_name,

        "risk_level":
            version.risk_level,

        "threat_level":
            version.threat_level,

        "security_score":
            security["security_score"],

        "grade":
            security["grade"],

        "incident_severity":
            incident["incident_severity"],

        "recommendation_count":
            len(recommendations),

        "summary":
            summary
    }
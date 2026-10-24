from app.digital_twin.twin_models import DigitalTwinState


def create_digital_twin(analysis_result: dict):
    """
    Create a Digital Twin from the APK analysis result.
    """

    threat_assessment = analysis_result.get(
        "threat_assessment",
        {}
    )

    twin = DigitalTwinState(
        package_name=analysis_result["package_name"],
        app_name=analysis_result["app_name"],

        version_name=analysis_result["version_name"],
        version_code=analysis_result["version_code"],

        permissions=analysis_result["permissions"],

        dangerous_permissions=analysis_result[
            "dangerous_permissions"
        ],

        exported_components=analysis_result[
            "exported_components"
        ],

        intent_filters=analysis_result[
            "intent_filters"
        ],

        certificate=analysis_result[
            "certificate"
        ],

        indicators=analysis_result[
            "indicators"
        ],

        behaviors=analysis_result[
            "behaviors"
        ],

        dex_findings=analysis_result.get(
            "dex_findings",
            []
        ),

        yara_matches=analysis_result.get(
            "yara_matches",
            []
        ),

        risk_score=analysis_result["risk_score"],

        risk_level=analysis_result["risk_level"],

        threat_level=threat_assessment.get(
            "threat_level",
            analysis_result["risk_level"]
        )
    )

    return twin
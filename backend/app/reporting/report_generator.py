from datetime import datetime


def generate_report(analysis_result: dict):
    """
    Generate a structured security report.
    """

    report = {
        "generated_at": datetime.utcnow().isoformat(),

        "executive_summary": {
            "package_name": analysis_result.get("package_name"),
            "app_name": analysis_result.get("app_name"),
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level"),
            "threat_level": analysis_result.get("threat_assessment", {}).get("threat_level", "Low"),
            "apk_id": analysis_result.get("apk_id"),
            "digital_twin_id": analysis_result.get("digital_twin_id"),
            "digital_twin_version": analysis_result.get("digital_twin_version"),
            "sha256": analysis_result.get("sha256"),
            "file_name": analysis_result.get("file_name"),
            "file_size": analysis_result.get("file_size"),
            "min_sdk": analysis_result.get("min_sdk"),
            "target_sdk": analysis_result.get("target_sdk"),
            "version_name": analysis_result.get("version_name"),
            "version_code": analysis_result.get("version_code")
        },

        "permissions_analysis":
            analysis_result["dangerous_permissions"],

        "exported_components":
            analysis_result["exported_components"],

        "intent_filters":
            analysis_result["intent_filters"],

        "certificate_analysis":
            analysis_result["certificate"],

        "indicator_analysis":
            analysis_result["indicators"],

        "behavior_analysis":
            analysis_result["behaviors"],

        "dex_analysis":
            analysis_result["dex_findings"],

        "yara_analysis":
            analysis_result["yara_matches"],

        "threat_assessment":
            analysis_result["threat_assessment"]
    }

    return report
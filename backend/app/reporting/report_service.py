from sqlalchemy.orm import Session

from app.database.crud import get_apk_by_id
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion
from app.services.analysis_service import (
    analyze_uploaded_apk
)
from app.reporting.report_generator import (
    generate_report
)


def generate_apk_report(
    db: Session,
    apk_id: int
):
    """
    Idempotent report generation.

    If a Digital Twin & Version record exists for this APK, reconstruct the
    analysis result from DB state without re-running full static analysis or
    creating a new Digital Twin version.

    If no Digital Twin exists yet, analyze the APK and store Version 1.
    """
    apk = get_apk_by_id(db, apk_id)
    if not apk:
        return None

    # Check for existing Digital Twin and versions
    digital_twin = (
        db.query(DigitalTwin)
        .filter(DigitalTwin.apk_id == apk_id)
        .first()
    )

    if digital_twin and digital_twin.versions:
        # Get the latest version by version_number
        latest_version = sorted(
            digital_twin.versions,
            key=lambda v: v.version_number,
            reverse=True
        )[0]

        analysis = {
            "apk_id": apk.id,
            "package_name": latest_version.package_name or apk.package_name,
            "app_name": latest_version.app_name or apk.file_name,
            "version_name": latest_version.version_name or apk.version,
            "version_code": latest_version.version_code or "1",
            "min_sdk": getattr(apk, "min_sdk", "Unknown"),
            "target_sdk": getattr(apk, "target_sdk", "Unknown"),
            "sha256": apk.sha256,
            "file_name": apk.file_name,
            "file_size": apk.file_size,
            "digital_twin_id": digital_twin.id,
            "digital_twin_version": latest_version.version_number,
            "risk_score": latest_version.risk_score,
            "risk_level": latest_version.risk_level,
            "dangerous_permissions": latest_version.dangerous_permissions or [],
            "exported_components": latest_version.exported_components or {"activities": [], "services": [], "receivers": [], "providers": []},
            "intent_filters": latest_version.intent_filters or [],
            "certificate": latest_version.certificate or {},
            "indicators": latest_version.indicators or {},
            "behaviors": latest_version.behaviors or [],
            "dex_findings": latest_version.dex_findings or [],
            "yara_matches": latest_version.yara_matches or [],
            "threat_assessment": {
                "threat_level": latest_version.threat_level,
                "summary": f"Threat Level: {latest_version.threat_level}. Risk Score: {latest_version.risk_score}/100.",
                "key_findings": latest_version.behaviors or []
            }
        }
        return generate_report(analysis)

    # Fallback: If no Digital Twin exists yet, analyze now
    analysis = analyze_uploaded_apk(db, apk_id)
    if not analysis:
        return None

    return generate_report(analysis)
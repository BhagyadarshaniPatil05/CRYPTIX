from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwin,
    DigitalTwinVersion
)
from app.models.apk import APKMetadata
from app.digital_twin.twin_models import DigitalTwinState


def save_digital_twin(
    db: Session,
    apk: APKMetadata,
    twin: DigitalTwinState
):
    """
    Create or update a persistent Digital Twin.

    If this APK does not have a Digital Twin yet:
        - Create DigitalTwin
        - Create Version 1

    If the Digital Twin already exists:
        - Create the next version
        - Update current_version
    """

    # ----------------------------------------
    # Check whether Digital Twin already exists
    # ----------------------------------------
    digital_twin = (
        db.query(DigitalTwin)
        .filter(DigitalTwin.apk_id == apk.id)
        .first()
    )

    # ========================================
    # CREATE NEW DIGITAL TWIN
    # ========================================
    if digital_twin is None:

        digital_twin = DigitalTwin(
            apk_id=apk.id,
            package_name=twin.package_name,
            app_name=twin.app_name,
            current_version=1
        )

        db.add(digital_twin)
        db.flush()

        version_number = 1

    # ========================================
    # CREATE NEW VERSION
    # ========================================
    else:

        version_number = digital_twin.current_version + 1

        digital_twin.current_version = version_number
        digital_twin.package_name = twin.package_name
        digital_twin.app_name = twin.app_name

    # ----------------------------------------
    # Store Digital Twin State
    # ----------------------------------------
    twin_version = DigitalTwinVersion(
        digital_twin_id=digital_twin.id,

        version_number=version_number,

        package_name=twin.package_name,
        app_name=twin.app_name,

        version_name=twin.version_name,
        version_code=twin.version_code,

        permissions=twin.permissions,

        dangerous_permissions=twin.dangerous_permissions,

        exported_components=twin.exported_components,

        intent_filters=twin.intent_filters,

        certificate=twin.certificate,

        indicators=twin.indicators,

        behaviors=twin.behaviors,

        dex_findings=twin.dex_findings,

        yara_matches=twin.yara_matches,

        risk_score=twin.risk_score,

        risk_level=twin.risk_level,

        threat_level=twin.threat_level
    )

    db.add(twin_version)

    # ----------------------------------------
    # Save everything
    # ----------------------------------------
    db.commit()

    # Refresh objects from database
    db.refresh(digital_twin)
    db.refresh(twin_version)

    return digital_twin, twin_version
from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.threat_intelligence.family_classifier import (
    classify_family
)


def hunt_high_risk(db):

    versions = (
        db.query(DigitalTwinVersion)
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .all()
    )

    latest_versions = {}

    for version in versions:

        twin_id = version.digital_twin_id

        if twin_id not in latest_versions:

            latest_versions[twin_id] = version

    results = []

    for version in latest_versions.values():

        if version.risk_level == "High":

            results.append(
                {
                    "package_name":
                        version.package_name,

                    "digital_twin_id":
                        version.digital_twin_id,

                    "version":
                        version.version_number,

                    "risk_score":
                        version.risk_score,

                    "risk_level":
                        version.risk_level,

                    "threat_level":
                        version.threat_level
                }
            )

    return results


def hunt_sms(db):

    versions = (
        db.query(DigitalTwinVersion)
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .all()
    )

    latest_versions = {}

    for version in versions:

        twin_id = version.digital_twin_id

        if twin_id not in latest_versions:
            latest_versions[twin_id] = version

    results = []

    for version in latest_versions.values():

        permissions = (
            version.permissions or []
        )

        if (
            "android.permission.SEND_SMS"
            in permissions
        ):

            results.append(
                {
                    "package_name":
                        version.package_name,

                    "digital_twin_id":
                        version.digital_twin_id,

                    "version":
                        version.version_number,

                    "risk_score":
                        version.risk_score,

                    "risk_level":
                        version.risk_level,

                    "threat_level":
                        version.threat_level
                }
            )

    return results


def hunt_root(db):

    versions = (
        db.query(DigitalTwinVersion)
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .all()
    )

    latest_versions = {}

    for version in versions:

        twin_id = version.digital_twin_id

        if twin_id not in latest_versions:
            latest_versions[twin_id] = version

    results = []

    for version in latest_versions.values():

        behaviors = (
            version.behaviors or []
        )

        for behavior in behaviors:

            if (
                behavior.get("api")
                == "su"
            ):

                results.append(
                    {
                        "package_name":
                            version.package_name,

                        "digital_twin_id":
                            version.digital_twin_id,

                        "version":
                            version.version_number,

                        "risk_score":
                            version.risk_score,

                        "risk_level":
                            version.risk_level,

                        "threat_level":
                            version.threat_level
                    }
                )

                break

    return results


def hunt_family(
    db,
    family_name
):

    versions = (
        db.query(DigitalTwinVersion)
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .all()
    )

    latest_versions = {}

    for version in versions:

        twin_id = version.digital_twin_id

        if twin_id not in latest_versions:
            latest_versions[twin_id] = version

    results = []

    family_name = (
        family_name.lower()
    )

    for version in latest_versions.values():

        family_result = classify_family(
            version.permissions,
            version.behaviors,
            version.indicators
        )

        detected_family = (
            family_result["family"]
            .lower()
        )

        if (
            detected_family
            ==
            family_name.lower()
        ):

            results.append(
                {
                    "package_name":
                        version.package_name,

                    "digital_twin_id":
                        version.digital_twin_id,

                    "version":
                        version.version_number,

                    "family":
                        family_result["family"],

                    "confidence":
                        family_result["confidence"],

                    "risk_level":
                        version.risk_level,

                    "threat_level":
                        version.threat_level
                }
            )

    return results
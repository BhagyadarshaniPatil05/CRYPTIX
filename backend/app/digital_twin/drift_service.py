from sqlalchemy.orm import Session

from app.digital_twin.twin_repository import (
    get_latest_version,
    get_all_versions
)

from app.digital_twin.drift_detector import (
    detect_drift
)


def get_drift_report(
    db: Session,
    twin_id: int
):
    """
    Compare the last two versions
    of a Digital Twin.
    """

    versions = get_all_versions(
        db,
        twin_id
    )

    if len(versions) < 2:
        return None

    old_version = versions[-2]
    new_version = versions[-1]

    return detect_drift(
        old_version,
        new_version
    )
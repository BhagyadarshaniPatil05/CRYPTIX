from sqlalchemy.orm import Session

from app.digital_twin.twin_repository import (
    get_twin_by_id,
    get_all_twins,
    get_latest_version,
    get_all_versions,
    get_version_by_number
)

from app.digital_twin.twin_diff_engine import (
    compare_versions
)

def fetch_twin(
    db: Session,
    twin_id: int
):
    return get_twin_by_id(db, twin_id)


def fetch_all_twins(
    db: Session
):
    return get_all_twins(db)


def fetch_latest_version(
    db: Session,
    twin_id: int
):
    return get_latest_version(db, twin_id)


def fetch_versions(
    db: Session,
    twin_id: int
):
    return get_all_versions(db, twin_id)


def compare_twin_versions(
    db: Session,
    twin_id: int,
    old_version: int,
    new_version: int
):
    v1 = get_version_by_number(
        db,
        twin_id,
        old_version
    )

    v2 = get_version_by_number(
        db,
        twin_id,
        new_version
    )

    if not v1 or not v2:
        return None

    return compare_versions(
        v1,
        v2
    )
from sqlalchemy.orm import Session

from app.models.digital_twin import (
    DigitalTwin,
    DigitalTwinVersion
)


def get_twin_by_id(
    db: Session,
    twin_id: int
):
    return (
        db.query(DigitalTwin)
        .filter(DigitalTwin.id == twin_id)
        .first()
    )


def get_all_twins(
    db: Session
):
    return (
        db.query(DigitalTwin)
        .order_by(DigitalTwin.id.desc())
        .all()
    )


def get_latest_version(
    db: Session,
    twin_id: int
):
    return (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .first()
    )


def get_all_versions(
    db: Session,
    twin_id: int
):
    return (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.asc()
        )
        .all()
    )


def get_version_by_number(
    db: Session,
    twin_id: int,
    version_number: int
):
    return (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id
            == twin_id
        )
        .filter(
            DigitalTwinVersion.version_number
            == version_number
        )
        .first()
    )
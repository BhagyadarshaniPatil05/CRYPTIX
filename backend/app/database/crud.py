from sqlalchemy.orm import Session
from app.models.apk import APKMetadata


def get_apk_by_hash(db: Session, sha256: str):
    return db.query(APKMetadata).filter(
        APKMetadata.sha256 == sha256
    ).first()


def get_apk_by_id(db: Session, apk_id: int):
    """
    Get APK metadata using its database ID.
    """
    return db.query(APKMetadata).filter(
        APKMetadata.id == apk_id
    ).first()


def create_apk(
    db: Session,
    file_name: str,
    sha256: str,
    file_size: int,
    file_path: str,
):
    apk = APKMetadata(
        file_name=file_name,
        sha256=sha256,
        file_size=file_size,
        file_path=file_path,
        status="uploaded"
    )

    db.add(apk)
    db.commit()
    db.refresh(apk)

    return apk
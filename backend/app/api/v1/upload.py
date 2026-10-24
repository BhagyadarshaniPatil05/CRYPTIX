from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from pathlib import Path

from app.database.session import get_db
from app.database.crud import create_apk, get_apk_by_hash
from app.services.upload_service import save_apk_by_hash, validate_apk
from app.utils.hash_utils import generate_sha256_from_file_object
from app.schemas.apk_schema import APKUploadResponse
from app.core.logger import logger

router = APIRouter()


@router.post(
    "/upload",
    response_model=APKUploadResponse
)
async def upload_apk(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    # 1. Validate file extension and ZIP magic header container format
    is_valid, error_msg = validate_apk(file)
    if not is_valid:
        logger.warning(f"Invalid file upload attempt: {file.filename} - {error_msg}")
        raise HTTPException(
            status_code=400,
            detail=error_msg
        )

    logger.info(f"APK container validation successful: {file.filename}")

    # 2. Generate SHA-256 directly from request stream BEFORE saving to disk
    sha256 = generate_sha256_from_file_object(file.file)
    logger.info(f"Pre-storage SHA-256 generated: {sha256} for {file.filename}")

    # 3. Check local database for duplicate exact-file hash BEFORE persisting to disk
    existing = get_apk_by_hash(db, sha256)
    if existing:
        logger.warning(f"Duplicate APK detected: {file.filename} (SHA256: {sha256})")
        raise HTTPException(
            status_code=409,
            detail="APK already exists."
        )

    # 4. Save file permanently under unique SHA-256 filename to prevent collision/overwrites
    file_path = save_apk_by_hash(file, sha256)
    file_size = Path(file_path).stat().st_size
    logger.info(f"APK permanently stored at: {file_path}")

    # 5. Store metadata in local database
    apk = create_apk(
        db=db,
        file_name=file.filename,
        sha256=sha256,
        file_size=file_size,
        file_path=file_path,
    )

    logger.info(f"Metadata stored in database. ID={apk.id}")
    logger.info(f"Upload completed successfully: {file.filename}")

    return {
        "message": "APK uploaded successfully",
        "id": apk.id,
        "filename": apk.file_name,
        "sha256": apk.sha256,
        "size": apk.file_size,
        "status": apk.status,
    }
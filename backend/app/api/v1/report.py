from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from fastapi.responses import StreamingResponse

from app.reporting.report_pdf_service import (
    generate_apk_pdf
)

from app.reporting.report_service import (
    generate_apk_report
)

router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)


@router.get("/{apk_id}")
def get_report(
    apk_id: int,
    db: Session = Depends(get_db)
):
    report = generate_apk_report(
        db,
        apk_id
    )

    if not report:
        raise HTTPException(
            status_code=404,
            detail="APK not found"
        )

    return report


@router.get("/{apk_id}/pdf")
def download_pdf(
    apk_id: int,
    db: Session = Depends(get_db)
):
    pdf = generate_apk_pdf(
        db,
        apk_id
    )

    if not pdf:
        raise HTTPException(
            status_code=404,
            detail="APK not found"
        )

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            f"attachment; filename=cryptix_report_{apk_id}.pdf"
        }
    )
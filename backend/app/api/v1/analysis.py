from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.analysis_service import analyze_uploaded_apk
from app.schemas.analysis_schema import APKAnalysisResponse

router = APIRouter(
    prefix="/analysis",
    tags=["APK Analysis"]
)


@router.post(
    "/{apk_id}",
    response_model=APKAnalysisResponse
)
def analyze(
    apk_id: int,
    db: Session = Depends(get_db)
):
    result = analyze_uploaded_apk(db, apk_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="APK not found."
        )

    return result
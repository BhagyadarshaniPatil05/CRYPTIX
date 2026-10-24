from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.threat_memory.memory_service import (
    get_threat_memory_by_apk_id,
    get_historical_matches,
)

router = APIRouter(prefix="/threat-memory", tags=["Threat Memory"])


@router.get("/{apk_id}")
def get_threat_memory_for_apk(apk_id: int, db: Session = Depends(get_db)):
    """
    Fetch Threat Memory evaluation decision, status, best match, similar historical samples, and explainable evidence.
    """
    memory = get_threat_memory_by_apk_id(db=db, apk_id=apk_id)
    if not memory:
        raise HTTPException(
            status_code=404,
            detail=f"Threat Memory not found for APK {apk_id}. Ensure sample exists in database."
        )
    return memory


@router.get("/{apk_id}/matches")
def get_historical_threat_matches(
    apk_id: int,
    limit: int = Query(default=5, ge=1, le=50),
    db: Session = Depends(get_db)
):
    """
    Fetch top N historical threat matches for an APK sample.
    """
    matches = get_historical_matches(db=db, apk_id=apk_id, limit=limit)
    return {
        "apk_id": apk_id,
        "historical_matches_count": len(matches),
        "historical_matches": matches
    }

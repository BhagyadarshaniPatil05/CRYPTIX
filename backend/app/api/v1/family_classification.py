from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.threat_intelligence.family_classifier import (
    classify_family
)

router = APIRouter(
    prefix="/family",
    tags=["Malware Family Classification"]
)


@router.get("/{twin_id}")
def classify_apk_family(
    twin_id: int,
    db: Session = Depends(get_db)
):

    version = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id
            == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.desc()
        )
        .first()
    )

    if not version:
        raise HTTPException(
            status_code=404,
            detail="Twin not found"
        )

    return classify_family(
        version.permissions,
        version.behaviors,
        version.indicators
    )
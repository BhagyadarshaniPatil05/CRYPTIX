from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.executive_summary.summary_service import (
    generate_executive_summary
)

router = APIRouter(
    prefix="/executive-summary",
    tags=["Executive Summary"]
)


@router.get("/{twin_id}")
def get_executive_summary(
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

    return generate_executive_summary(
        version
    )
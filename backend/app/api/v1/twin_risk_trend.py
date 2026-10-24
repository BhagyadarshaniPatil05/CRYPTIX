from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwin,
    DigitalTwinVersion
)

from app.digital_twin_analytics.risk_trend_service import (
    get_risk_trend
)

router = APIRouter(
    prefix="/twin-risk-trend",
    tags=["Twin Analytics"]
)


@router.get("/{twin_id}")
def twin_risk_trend(
    twin_id: int,
    db: Session = Depends(get_db)
):

    twin = (
        db.query(DigitalTwin)
        .filter(
            DigitalTwin.id == twin_id
        )
        .first()
    )

    if not twin:
        raise HTTPException(
            status_code=404,
            detail="Twin not found"
        )

    versions = (
        db.query(DigitalTwinVersion)
        .filter(
            DigitalTwinVersion.digital_twin_id
            == twin_id
        )
        .order_by(
            DigitalTwinVersion.version_number.asc()
        )
        .all()
    )

    return {
        "digital_twin_id":
            twin.id,

        "package_name":
            twin.package_name,

        "trend":
            get_risk_trend(
                versions
            )
    }
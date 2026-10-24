from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.digital_twin_health.health_service import (
    calculate_twin_health,
    get_health_trend
)

router = APIRouter(
    prefix="/twin-health",
    tags=["Twin Health"]
)


@router.get("/{twin_id}")
def get_twin_health(
    twin_id: int,
    db: Session = Depends(get_db)
):

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

    if not versions:
        raise HTTPException(
            status_code=404,
            detail="Twin not found"
        )

    latest = versions[-1]

    health = (
        calculate_twin_health(
            latest
        )
    )

    trend = (
        get_health_trend(
            versions
        )
    )

    return {
        "digital_twin_id":
            twin_id,

        "package_name":
            latest.package_name,

        **health,

        "trend":
            trend,

        "current_version":
            latest.version_number
    }
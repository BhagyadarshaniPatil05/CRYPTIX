from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.recommendation_engine.recommendation_service import (
    generate_recommendations
)

router = APIRouter(
    prefix="/recommendation",
    tags=["Security Recommendations"]
)


@router.get("/{twin_id}")
def get_recommendations(
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

    return {
        "package_name":
            version.package_name,

        "risk_level":
            version.risk_level,

        "threat_level":
            version.threat_level,

        "recommendations":
            generate_recommendations(version)
    }
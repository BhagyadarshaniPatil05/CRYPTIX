from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.digital_twin_recommendations.recommendation_service import (
    generate_recommendations
)

router = APIRouter(
    prefix="/twin-recommendations",
    tags=["Twin Recommendations"]
)


@router.get("/{twin_id}")
def twin_recommendations(
    twin_id: int,
    db: Session = Depends(get_db)
):

    latest_version = (
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

    if not latest_version:

        raise HTTPException(
            status_code=404,
            detail="Twin not found"
        )

    return {
        "digital_twin_id":
            twin_id,

        "package_name":
            latest_version.package_name,

        "risk_score":
            latest_version.risk_score,

        "recommendations":
            generate_recommendations(
                latest_version
            )
    }
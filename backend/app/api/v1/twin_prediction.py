from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.digital_twin_prediction.prediction_service import (
    predict_future_risk
)

router = APIRouter(
    prefix="/twin-prediction",
    tags=["Twin Prediction"]
)


@router.get("/{twin_id}")
def twin_prediction(
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

    prediction = (
        predict_future_risk(
            versions
        )
    )

    latest = versions[-1]

    return {
        "digital_twin_id":
            twin_id,

        "package_name":
            latest.package_name,

        **prediction
    }
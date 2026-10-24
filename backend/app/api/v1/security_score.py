from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.security_score.security_score_service import (
    calculate_security_score
)

router = APIRouter(
    prefix="/security-score",
    tags=["Security Score"]
)


@router.get("/{twin_id}")
def get_security_score(
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

    result = calculate_security_score(
        version
    )

    return {
        "package_name":
            version.package_name,

        "digital_twin_id":
            version.digital_twin_id,

        **result
    }
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwinVersion
)

from app.incident_response.response_service import (
    generate_incident_response
)

router = APIRouter(
    prefix="/incident-response",
    tags=["Incident Response"]
)


@router.get("/{twin_id}")
def get_incident_response(
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

    response = generate_incident_response(
        version
    )

    return {
        "package_name":
            version.package_name,

        "digital_twin_id":
            version.digital_twin_id,

        **response
    }
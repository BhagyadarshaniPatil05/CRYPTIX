from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwin
)

from app.digital_twin_dashboard.dashboard_service import (
    build_twin_dashboard
)

router = APIRouter(
    prefix="/twin-dashboard",
    tags=["Twin Dashboard"]
)


@router.get("/{twin_id}")
def twin_dashboard(
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

    return build_twin_dashboard(
        twin
    )
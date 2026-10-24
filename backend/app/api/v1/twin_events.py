from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.models.digital_twin import (
    DigitalTwin
)

from app.digital_twin_events.event_service import (
    get_twin_events
)

router = APIRouter(
    prefix="/twin-events",
    tags=["Twin Events"]
)


@router.get("/{twin_id}")
def twin_events(
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

    return get_twin_events(
        twin
    )
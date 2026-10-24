from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.dashboard.dashboard_service import (
    get_dashboard_metrics
)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)


@router.get("/metrics")
def dashboard_metrics(
    db: Session = Depends(get_db)
):
    return get_dashboard_metrics(db)
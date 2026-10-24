from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.dashboard.threat_intelligence_service import (
    get_top_permissions,
    get_risk_distribution,
    get_threat_levels,
    get_recent_analyses
)

router = APIRouter(
    prefix="/threat-dashboard",
    tags=["Threat Intelligence"]
)


@router.get("/top-permissions")
def top_permissions(
    db: Session = Depends(get_db)
):
    return get_top_permissions(db)


@router.get("/risk-distribution")
def risk_distribution(
    db: Session = Depends(get_db)
):
    return get_risk_distribution(db)


@router.get("/threat-levels")
def threat_levels(
    db: Session = Depends(get_db)
):
    return get_threat_levels(db)


@router.get("/recent-analyses")
def recent_analyses(
    db: Session = Depends(get_db)
):
    return get_recent_analyses(db)
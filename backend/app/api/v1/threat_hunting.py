from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.threat_hunting.hunt_service import (
    hunt_high_risk,
    hunt_sms,
    hunt_root,
    hunt_family
)

router = APIRouter(
    prefix="/hunt",
    tags=["Threat Hunting"]
)


@router.get("/high-risk")
def get_high_risk(
    db: Session = Depends(get_db)
):
    return hunt_high_risk(db)


@router.get("/sms")
def get_sms(
    db: Session = Depends(get_db)
):
    return hunt_sms(db)


@router.get("/root")
def get_root(
    db: Session = Depends(get_db)
):
    return hunt_root(db)


@router.get("/family/{family_name}")
def get_family(
    family_name: str,
    db: Session = Depends(get_db)
):
    return hunt_family(
        db,
        family_name
    )
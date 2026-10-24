from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.session import get_db

from app.digital_twin.twin_query_service import (
    fetch_twin,
    fetch_all_twins,
    fetch_latest_version,
    fetch_versions,
    compare_twin_versions
)

from app.digital_twin.twin_timeline_service import (
    get_risk_timeline
)

from app.digital_twin.twin_drift_service import (
    detect_drift
)

from app.digital_twin.twin_summary_service import (
    get_twin_summary
)

from app.digital_twin.twin_analytics_service import (
    get_twin_analytics
)

from app.digital_twin.twin_graph_service import (
    get_risk_graph
)

from app.digital_twin.drift_service import (
    get_drift_report
)

from app.digital_twin.timeline_service import (
    get_security_timeline
)

router = APIRouter(
    prefix="/twins",
    tags=["Digital Twin"]
)

# -------------------------
# Endpoint 0: List All Twins
# -------------------------
@router.get("")
def get_all_digital_twins(
    db: Session = Depends(get_db)
):
    return fetch_all_twins(db)


# -------------------------
# Endpoint 1
# -------------------------
@router.get("/{twin_id}")
def get_twin(
    twin_id: int,
    db: Session = Depends(get_db)
):
    twin = fetch_twin(
        db,
        twin_id
    )

    if not twin:
        raise HTTPException(
            status_code=404,
            detail="Twin not found"
        )

    return twin


# -------------------------
# Endpoint 2
# -------------------------
@router.get("/{twin_id}/latest")
def get_latest(
    twin_id: int,
    db: Session = Depends(get_db)
):
    version = fetch_latest_version(
        db,
        twin_id
    )

    if not version:
        raise HTTPException(
            status_code=404,
            detail="Version not found"
        )

    return version


# -------------------------
# Endpoint 3
# -------------------------
@router.get("/{twin_id}/versions")
def get_versions(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return fetch_versions(
        db,
        twin_id
    )


# -------------------------
# Endpoint 4
# -------------------------
@router.get(
    "/{twin_id}/compare/{old_version}/{new_version}"
)
def compare_versions_endpoint(
    twin_id: int,
    old_version: int,
    new_version: int,
    db: Session = Depends(get_db)
):
    result = compare_twin_versions(
        db,
        twin_id,
        old_version,
        new_version
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Version not found"
        )

    return result


# -------------------------
# Endpoint 5: Timeline
# -------------------------
@router.get("/{twin_id}/timeline")
def risk_timeline(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return get_risk_timeline(
        db,
        twin_id
    )


# -------------------------
# Endpoint 6: Drift Metrics
# -------------------------
@router.get("/{twin_id}/drift")
def get_drift(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return detect_drift(
        db,
        twin_id
    )


# -------------------------
# Endpoint 7: Summary
# -------------------------
@router.get("/{twin_id}/summary")
def summary(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return get_twin_summary(
        db,
        twin_id
    )


# -------------------------
# Endpoint 8: Analytics
# -------------------------
@router.get("/{twin_id}/analytics")
def analytics(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return get_twin_analytics(
        db,
        twin_id
    )


# -------------------------
# Endpoint 9: Risk Graph
# -------------------------
@router.get("/{twin_id}/risk-graph")
def risk_graph(
    twin_id: int,
    db: Session = Depends(get_db)
):
    return get_risk_graph(
        db,
        twin_id
    )


# -------------------------
# Endpoint 10: Drift Text Report
# -------------------------
@router.get("/{twin_id}/drift/report")
def get_drift_report_endpoint(
    twin_id: int,
    db: Session = Depends(get_db)
):
    report = get_drift_report(
        db,
        twin_id
    )

    if not report:
        raise HTTPException(
            status_code=404,
            detail="Need at least 2 versions"
        )

    return report
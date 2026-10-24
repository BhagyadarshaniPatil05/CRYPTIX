"""
API Router for MITRE ATT&CK for Mobile and IOC Intelligence Mapping.
Provides endpoints for retrieving evidence-backed technique mappings, tactic breakdowns,
and correlated IOC threat intelligence.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, List, Any

from app.database.session import get_db
from app.database.crud import get_apk_by_id
from app.mitre.service import get_mitre_mappings_by_apk
from app.mitre.catalog import get_technique, ATTACK_VERSION, ATTACK_DOMAIN
from app.threat_intelligence.service import get_threat_intelligence_by_apk

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK for Mobile"])


@router.get("/{apk_id}")
def get_mitre_mappings_for_apk(apk_id: int, db: Session = Depends(get_db)):
    """
    Fetch all evidence-backed MITRE Mobile ATT&CK technique mappings for an APK sample.
    """
    apk = get_apk_by_id(db, apk_id)
    if not apk:
        raise HTTPException(
            status_code=404,
            detail=f"APK sample with ID {apk_id} not found."
        )

    mappings = get_mitre_mappings_by_apk(db=db, apk_id=apk_id)

    formatted_mappings = []
    tactics_summary: Dict[str, int] = {}
    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for m in mappings:
        tech_meta = get_technique(m.technique_id) or {}

        # Increment tactic summary
        tactic_name = m.tactic or "Other"
        tactics_summary[tactic_name] = tactics_summary.get(tactic_name, 0) + 1

        # Increment confidence count
        conf = (m.confidence or "MEDIUM").upper()
        if conf in confidence_counts:
            confidence_counts[conf] += 1

        formatted_mappings.append({
            "id": m.id,
            "apk_id": m.apk_id,
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tactic": m.tactic,
            "evidence_type": m.evidence_type,
            "evidence_reference": m.evidence_reference,
            "evidence_summary": m.evidence_summary,
            "confidence": m.confidence,
            "rule_id": m.rule_id,
            "attack_version": m.attack_version or ATTACK_VERSION,
            "official_url": tech_meta.get("url"),
            "description": tech_meta.get("description"),
        })

    return {
        "apk_id": apk_id,
        "sha256": apk.sha256,
        "attack_domain": ATTACK_DOMAIN,
        "attack_version": ATTACK_VERSION,
        "total_mappings": len(formatted_mappings),
        "confidence_counts": confidence_counts,
        "tactics_summary": tactics_summary,
        "mappings": formatted_mappings,
    }


@router.get("/{apk_id}/tactics")
def get_mitre_tactics_for_apk(apk_id: int, db: Session = Depends(get_db)):
    """
    Fetch MITRE Mobile ATT&CK technique mappings grouped by tactic category.
    """
    apk = get_apk_by_id(db, apk_id)
    if not apk:
        raise HTTPException(
            status_code=404,
            detail=f"APK sample with ID {apk_id} not found."
        )

    mappings = get_mitre_mappings_by_apk(db=db, apk_id=apk_id)

    tactics_map: Dict[str, List[Any]] = {}

    for m in mappings:
        tactic_name = m.tactic or "Other"
        if tactic_name not in tactics_map:
            tactics_map[tactic_name] = []

        tech_meta = get_technique(m.technique_id) or {}

        tactics_map[tactic_name].append({
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "confidence": m.confidence,
            "evidence_reference": m.evidence_reference,
            "evidence_summary": m.evidence_summary,
            "official_url": tech_meta.get("url"),
        })

    return {
        "apk_id": apk_id,
        "sha256": apk.sha256,
        "total_tactics": len(tactics_map),
        "tactics": tactics_map,
    }


@router.get("/{apk_id}/iocs")
def get_mitre_ioc_correlation(apk_id: int, db: Session = Depends(get_db)):
    """
    Fetch normalized IOC intelligence correlation linking extracted indicators to MITRE techniques and external TI.
    """
    apk = get_apk_by_id(db, apk_id)
    if not apk:
        raise HTTPException(
            status_code=404,
            detail=f"APK sample with ID {apk_id} not found."
        )

    mappings = get_mitre_mappings_by_apk(db=db, apk_id=apk_id)
    ti_records = get_threat_intelligence_by_apk(db=db, apk_id=apk_id)

    ioc_mappings = [m for m in mappings if m.evidence_type == "IOC_INDICATOR"]

    ti_summary = []
    for r in ti_records:
        ti_summary.append({
            "provider": r.provider,
            "indicator_type": r.indicator_type,
            "indicator_value": r.indicator_value,
            "status": r.status,
            "found": r.found,
        })

    return {
        "apk_id": apk_id,
        "sha256": apk.sha256,
        "ioc_technique_mappings_count": len(ioc_mappings),
        "ioc_technique_mappings": [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "indicator_reference": m.evidence_reference,
                "confidence": m.confidence,
            }
            for m in ioc_mappings
        ],
        "threat_intelligence_records": ti_summary,
    }

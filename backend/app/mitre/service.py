"""
Database persistence and retrieval service for MITRE ATT&CK technique mappings.
Handles sample mapping evaluation, DB transactional storage, and forensic querying.
"""
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.database.crud import get_apk_by_id
from app.models.mitre import MitreMapping
from app.mitre.mapping_engine import map_evidence_to_mitre

logger = logging.getLogger("cryptix.mitre.service")


def evaluate_and_store_mitre_mappings(
    db: Session,
    apk_id: int,
    analysis_results: Optional[Dict[str, Any]] = None,
) -> List[MitreMapping]:
    """
    Evaluates evidence-backed MITRE ATT&CK technique mappings for an analyzed sample and persists them in DB.
    """
    saved_records = []

    apk = get_apk_by_id(db, apk_id)
    if not apk:
        logger.warning(f"APK {apk_id} not found for MITRE ATT&CK mapping evaluation.")
        return saved_records

    # Clear prior mappings for this APK if re-analyzing
    try:
        db.query(MitreMapping).filter(MitreMapping.apk_id == apk_id).delete()
        db.commit()
    except Exception as e:
        logger.error(f"Error clearing previous MITRE mappings for APK {apk_id}: {str(e)}")
        db.rollback()

    if not analysis_results:
        logger.info(f"No analysis results provided for MITRE mapping of APK {apk_id}.")
        return saved_records

    candidate_mappings = map_evidence_to_mitre(analysis_results)

    for cand in candidate_mappings:
        rec = MitreMapping(
            apk_id=apk_id,
            technique_id=cand["technique_id"],
            technique_name=cand["technique_name"],
            tactic=cand["tactic"],
            evidence_type=cand["evidence_type"],
            evidence_reference=cand["evidence_reference"],
            evidence_summary=cand["evidence_summary"],
            confidence=cand["confidence"],
            rule_id=cand["rule_id"],
            attack_version=cand["attack_version"],
        )
        db.add(rec)
        saved_records.append(rec)

    try:
        db.commit()
        for rec in saved_records:
            db.refresh(rec)
    except Exception as e:
        logger.error(f"Failed to commit MITRE mappings for APK {apk_id}: {str(e)}")
        db.rollback()
        return []

    return saved_records


def get_mitre_mappings_by_apk(db: Session, apk_id: int) -> List[MitreMapping]:
    """
    Retrieve all persisted MITRE ATT&CK technique mappings for a given APK ID.
    """
    return (
        db.query(MitreMapping)
        .filter(MitreMapping.apk_id == apk_id)
        .order_by(MitreMapping.tactic.asc(), MitreMapping.technique_id.asc())
        .all()
    )

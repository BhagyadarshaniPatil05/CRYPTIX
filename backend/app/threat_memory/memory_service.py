"""
High-level service orchestrating Threat Memory evaluation, DB persistence, and query API retrieval.
"""
import json
import logging
from sqlalchemy.orm import Session

from app.models.threat_memory import ThreatMemory
from app.models.apk import APKMetadata
from app.threat_memory.decision_engine import evaluate_threat_memory
from app.threat_memory.config import STATUS_ERROR

logger = logging.getLogger("cryptix.threat_memory")


def evaluate_and_store_threat_memory(db: Session, apk_id: int) -> ThreatMemory:
    """
    Evaluates Threat Memory for an APK sample, persists or updates the ThreatMemory DB record,
    and returns the saved model instance.
    """
    decision = evaluate_threat_memory(db=db, apk_id=apk_id)

    status = decision.get("status", STATUS_ERROR)
    sha256 = decision.get("sha256", "")
    dna_hash = decision.get("dna_hash")

    best_match = decision.get("best_match") or {}
    matched_apk_id = best_match.get("apk_id")
    similarity_score = best_match.get("similarity_score")
    historical_risk_score = best_match.get("risk_score")
    historical_threat_level = best_match.get("threat_level")
    digital_twin_id = best_match.get("digital_twin_id")

    explanation_json = json.dumps(decision.get("explanation", {}), sort_keys=True)

    record = db.query(ThreatMemory).filter(ThreatMemory.apk_id == apk_id).first()

    if record:
        record.sha256 = sha256
        record.dna_hash = dna_hash
        record.status = status
        record.matched_apk_id = matched_apk_id
        record.similarity_score = similarity_score
        record.historical_risk_score = historical_risk_score
        record.historical_threat_level = historical_threat_level
        record.digital_twin_id = digital_twin_id
        record.match_explanation_json = explanation_json
    else:
        record = ThreatMemory(
            apk_id=apk_id,
            sha256=sha256,
            dna_hash=dna_hash,
            status=status,
            matched_apk_id=matched_apk_id,
            similarity_score=similarity_score,
            historical_risk_score=historical_risk_score,
            historical_threat_level=historical_threat_level,
            digital_twin_id=digital_twin_id,
            match_explanation_json=explanation_json,
        )
        db.add(record)

    db.commit()
    db.refresh(record)
    logger.info(f"Threat Memory evaluated for APK {apk_id}: Status={status}, Match={matched_apk_id}")
    return record


def get_threat_memory_by_apk_id(db: Session, apk_id: int) -> dict:
    """
    Fetches stored Threat Memory record for an APK ID. If missing, runs evaluation and stores it.
    Returns serialized dictionary payload for API consumption.
    """
    record = db.query(ThreatMemory).filter(ThreatMemory.apk_id == apk_id).first()

    if not record:
        apk = db.query(APKMetadata).filter(APKMetadata.id == apk_id).first()
        if not apk:
            return None
        record = evaluate_and_store_threat_memory(db=db, apk_id=apk_id)

    try:
        explanation = json.loads(record.match_explanation_json)
    except Exception:
        explanation = {}

    # Query full decision to populate live similar samples array
    live_decision = evaluate_threat_memory(db=db, apk_id=apk_id)

    return {
        "id": record.id,
        "apk_id": record.apk_id,
        "sha256": record.sha256,
        "dna_hash": record.dna_hash,
        "status": record.status,
        "exact_match": record.status == "KNOWN_EXACT",
        "best_match": live_decision.get("best_match"),
        "similar_samples": live_decision.get("similar_samples", []),
        "explanation": explanation,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def get_historical_matches(db: Session, apk_id: int, limit: int = 5) -> list:
    """
    Retrieves top N historical matches for an APK ID from Threat Memory.
    """
    memory = get_threat_memory_by_apk_id(db=db, apk_id=apk_id)
    if not memory:
        return []
    similar = memory.get("similar_samples", [])
    return similar[:limit]

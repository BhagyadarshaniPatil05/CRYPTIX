"""
Threat Memory decision engine implementing the 4-level explainable decision hierarchy:
Level 1: KNOWN_EXACT (Exact SHA-256 binary match)
Level 2: HIGH_SIMILARITY (Malware DNA Jaccard similarity >= 65%)
Level 3: RELATED_SAMPLE (Malware DNA Jaccard similarity >= 35%)
Level 4: NEW_SAMPLE (No matching historical sample in local corpus)
"""
import logging
import json
from sqlalchemy.orm import Session

from app.models.apk import APKMetadata
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion
from app.models.malware_dna import MalwareDNA
from app.threat_memory.config import (
    HIGH_SIMILARITY_THRESHOLD,
    RELATED_SAMPLE_THRESHOLD,
    STATUS_KNOWN_EXACT,
    STATUS_HIGH_SIMILARITY,
    STATUS_RELATED_SAMPLE,
    STATUS_NEW_SAMPLE,
    STATUS_ERROR,
)
from app.malware_dna.dna_service import find_similar_samples, compare_dna

logger = logging.getLogger("cryptix.threat_memory")


def evaluate_threat_memory(db: Session, apk_id: int) -> dict:
    """
    Evaluates an APK sample against local historical records using the decision tree hierarchy.
    Returns structured decision payload with status, match references, and explainable evidence.
    """
    try:
        target_apk = db.query(APKMetadata).filter(APKMetadata.id == apk_id).first()
        if not target_apk:
            return {
                "status": STATUS_ERROR,
                "error_detail": f"Target APK ID {apk_id} not found in database.",
                "exact_match": False,
                "best_match": None,
                "similar_samples": [],
                "explanation": {"summary": "Target APK not found in database."}
            }

        target_sha256 = target_apk.sha256
        target_dna = db.query(MalwareDNA).filter(MalwareDNA.apk_id == apk_id).first()
        target_dna_hash = target_dna.dna_hash if target_dna else None

        # Helper to fetch prior historical posture metrics (Twin ID, Risk Score, Threat Level)
        def fetch_sample_history_metrics(matched_id: int):
            twin = db.query(DigitalTwin).filter(DigitalTwin.apk_id == matched_id).first()
            twin_id = twin.id if twin else None
            risk_score = None
            threat_level = None

            if twin:
                latest = db.query(DigitalTwinVersion).filter(
                    DigitalTwinVersion.digital_twin_id == twin.id
                ).order_by(DigitalTwinVersion.version_number.desc()).first()
                if latest:
                    risk_score = latest.risk_score
                    threat_level = latest.threat_level

            return {
                "digital_twin_id": twin_id,
                "risk_score": risk_score,
                "threat_level": threat_level,
            }
        # -------------------------------------------------------------
        # LEVEL 1 — EXACT SHA-256 MATCH LOOKUP
        # -------------------------------------------------------------
        exact_prior = db.query(APKMetadata).filter(
            APKMetadata.sha256 == target_sha256,
            APKMetadata.id != apk_id
        ).order_by(APKMetadata.id.asc()).first()

        if exact_prior:
            history = fetch_sample_history_metrics(exact_prior.id)
            prior_dna = db.query(MalwareDNA).filter(MalwareDNA.apk_id == exact_prior.id).first()

            explanation = {
                "summary": "Exact binary previously analyzed in local corpus.",
                "match_type": STATUS_KNOWN_EXACT,
                "reason": f"Exact file SHA-256 match found: {target_sha256}",
                "matched_sample_id": exact_prior.id,
                "matched_file_name": exact_prior.file_name,
                "matched_package_name": exact_prior.package_name,
                "historical_risk_score": history["risk_score"],
                "historical_threat_level": history["threat_level"],
                "shared_features": ["exact_file_sha256_binary_match"],
                "differing_features": []
            }

            best_match = {
                "apk_id": exact_prior.id,
                "file_name": exact_prior.file_name,
                "package_name": exact_prior.package_name,
                "sha256": exact_prior.sha256,
                "dna_hash": prior_dna.dna_hash if prior_dna else None,
                "similarity_score": 100.0,
                "match_classification": STATUS_KNOWN_EXACT,
                "digital_twin_id": history["digital_twin_id"],
                "risk_score": history["risk_score"],
                "threat_level": history["threat_level"],
            }

            return {
                "apk_id": apk_id,
                "sha256": target_sha256,
                "dna_hash": target_dna_hash,
                "status": STATUS_KNOWN_EXACT,
                "exact_match": True,
                "best_match": best_match,
                "similar_samples": [best_match],
                "explanation": explanation
            }

        # -------------------------------------------------------------
        # LEVEL 2 & 3 — MALWARE DNA SIMILARITY LOOKUP
        # -------------------------------------------------------------
        if target_dna:
            similar_list = find_similar_samples(
                db=db,
                apk_id=apk_id,
                limit=5,
                min_threshold=RELATED_SAMPLE_THRESHOLD
            )

            if similar_list:
                top_match = similar_list[0]
                top_score = top_match["similarity_score"]
                matched_id = top_match["apk_id"]

                history = fetch_sample_history_metrics(matched_id)
                comp = compare_dna(db, apk_id, matched_id)

                if top_score >= HIGH_SIMILARITY_THRESHOLD:
                    decision_status = STATUS_HIGH_SIMILARITY
                    narrative = f"High Malware DNA similarity ({top_score:.1f}%) detected with historical sample APK #{matched_id}."
                else:
                    decision_status = STATUS_RELATED_SAMPLE
                    narrative = f"Related capability overlap ({top_score:.1f}%) detected with historical sample APK #{matched_id}."

                # Enrich similar list items with twin ID and prior risk
                enriched_similar = []
                for item in similar_list:
                    item_hist = fetch_sample_history_metrics(item["apk_id"])
                    item["digital_twin_id"] = item_hist["digital_twin_id"]
                    item["risk_score"] = item_hist["risk_score"]
                    item["threat_level"] = item_hist["threat_level"]
                    enriched_similar.append(item)

                explanation = {
                    "summary": narrative,
                    "match_type": decision_status,
                    "reason": f"Malware DNA Jaccard score {top_score:.1f}% vs APK #{matched_id}",
                    "matched_sample_id": matched_id,
                    "matched_file_name": top_match["file_name"],
                    "matched_package_name": top_match["package_name"],
                    "historical_risk_score": history["risk_score"],
                    "historical_threat_level": history["threat_level"],
                    "shared_features_count": comp["shared_features_count"] if comp else 0,
                    "shared_features": comp["shared_features"] if comp else [],
                    "differing_features_sample_a": comp["differing_features_sample_a"] if comp else [],
                    "differing_features_sample_b": comp["differing_features_sample_b"] if comp else []
                }

                best_match = enriched_similar[0]

                return {
                    "apk_id": apk_id,
                    "sha256": target_sha256,
                    "dna_hash": target_dna_hash,
                    "status": decision_status,
                    "exact_match": False,
                    "best_match": best_match,
                    "similar_samples": enriched_similar,
                    "explanation": explanation
                }

        # -------------------------------------------------------------
        # LEVEL 4 — NEW SAMPLE (No prior exact SHA or DNA match >= 35%)
        # -------------------------------------------------------------
        explanation = {
            "summary": "NEW TO LOCAL THREAT MEMORY: No matching historical sample found in local corpus.",
            "match_type": STATUS_NEW_SAMPLE,
            "reason": "Neither exact SHA-256 nor Malware DNA similarity >= 35.0% found in local database.",
            "analyst_notice": "NEW_SAMPLE indicates the file is unseen in local Threat Memory. It does NOT imply the sample is safe, benign, or globally unknown.",
            "shared_features": [],
            "differing_features": []
        }

        return {
            "apk_id": apk_id,
            "sha256": target_sha256,
            "dna_hash": target_dna_hash,
            "status": STATUS_NEW_SAMPLE,
            "exact_match": False,
            "best_match": None,
            "similar_samples": [],
            "explanation": explanation
        }

    except Exception as e:
        logger.error(f"Threat Memory decision engine exception for APK {apk_id}: {str(e)}")
        safe_sha256 = ""
        safe_dna_hash = None
        try:
            if 'target_apk' in locals() and target_apk:
                safe_sha256 = target_apk.sha256
            if 'target_dna' in locals() and target_dna:
                safe_dna_hash = target_dna.dna_hash
        except Exception:
            pass

        return {
            "apk_id": apk_id,
            "sha256": safe_sha256,
            "dna_hash": safe_dna_hash,
            "status": STATUS_ERROR,
            "exact_match": False,
            "best_match": None,
            "similar_samples": [],
            "explanation": {
                "summary": "Threat Memory evaluation encountered a database or processing error.",
                "match_type": STATUS_ERROR,
                "error_detail": str(e)
            }
        }

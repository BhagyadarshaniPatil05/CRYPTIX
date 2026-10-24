"""
API Router for Global Threat Intelligence Integration.
Provides endpoints for retrieving provider reputation findings, indicator intelligence,
and provider configuration statuses for analyzed samples.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.crud import get_apk_by_id
from app.threat_intelligence.service import get_threat_intelligence_by_apk
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.otx import OTXProvider
from app.threat_intelligence.config import (
    PROVIDER_VIRUSTOTAL,
    PROVIDER_ABUSEIPDB,
    PROVIDER_OTX,
)

router = APIRouter(prefix="/threat-intelligence", tags=["Global Threat Intelligence"])


@router.get("/{apk_id}")
def get_threat_intelligence_for_apk(apk_id: int, db: Session = Depends(get_db)):
    """
    Fetch all Threat Intelligence provider lookup records for a specified APK sample.
    """
    apk = get_apk_by_id(db, apk_id)
    if not apk:
        raise HTTPException(
            status_code=404,
            detail=f"APK sample with ID {apk_id} not found."
        )

    records = get_threat_intelligence_by_apk(db=db, apk_id=apk_id)

    formatted_records = []
    for r in records:
        norm_result = {}
        if r.normalized_result_json:
            try:
                norm_result = json.loads(r.normalized_result_json)
            except Exception:
                norm_result = {}

        raw_meta = None
        if r.raw_metadata_json:
            try:
                raw_meta = json.loads(r.raw_metadata_json)
            except Exception:
                raw_meta = None

        formatted_records.append({
            "id": r.id,
            "apk_id": r.apk_id,
            "provider": r.provider,
            "indicator_type": r.indicator_type,
            "indicator_value": r.indicator_value,
            "status": r.status,
            "found": r.found,
            "normalized_result": norm_result,
            "raw_metadata": raw_meta,
            "cached": r.cached,
            "queried_at": r.queried_at.isoformat() if r.queried_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        })

    vt_provider = VirusTotalProvider()
    abuse_provider = AbuseIPDBProvider()
    otx_provider = OTXProvider()

    provider_statuses = {
        PROVIDER_VIRUSTOTAL: {
            "is_configured": vt_provider.is_configured(),
            "enabled": vt_provider.is_configured(),
        },
        PROVIDER_ABUSEIPDB: {
            "is_configured": abuse_provider.is_configured(),
            "enabled": abuse_provider.is_configured(),
        },
        PROVIDER_OTX: {
            "is_configured": otx_provider.is_configured(),
            "enabled": otx_provider.is_configured(),
        },
    }

    return {
        "apk_id": apk_id,
        "sha256": apk.sha256,
        "total_records": len(formatted_records),
        "providers_config": provider_statuses,
        "records": formatted_records,
    }


@router.get("/{apk_id}/summary")
def get_threat_intelligence_summary(apk_id: int, db: Session = Depends(get_db)):
    """
    Fetch a high-level Threat Intelligence status and threat detection summary for an APK sample.
    """
    apk = get_apk_by_id(db, apk_id)
    if not apk:
        raise HTTPException(
            status_code=404,
            detail=f"APK sample with ID {apk_id} not found."
        )

    records = get_threat_intelligence_by_apk(db=db, apk_id=apk_id)

    vt_found = any(r.provider == PROVIDER_VIRUSTOTAL and r.found for r in records)
    abuse_found = any(r.provider == PROVIDER_ABUSEIPDB and r.found for r in records)
    otx_found = any(r.provider == PROVIDER_OTX and r.found for r in records)

    return {
        "apk_id": apk_id,
        "sha256": apk.sha256,
        "total_ti_records": len(records),
        "threats_detected": {
            "virustotal": vt_found,
            "abuseipdb": abuse_found,
            "otx": otx_found,
        },
    }

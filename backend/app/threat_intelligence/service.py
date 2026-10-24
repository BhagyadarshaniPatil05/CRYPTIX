"""
Threat Intelligence Orchestration Service.
Coordinates hash-first lookups and IOC reputation queries across providers,
leveraging DB-backed caching and strict fail-safe isolation.
"""
import json
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.database.crud import get_apk_by_id
from app.models.threat_intelligence import ThreatIntelligence
from app.threat_intelligence.config import (
    PROVIDER_VIRUSTOTAL,
    PROVIDER_ABUSEIPDB,
    PROVIDER_OTX,
    IND_TYPE_HASH,
    IND_TYPE_IP,
    IND_TYPE_URL,
    IND_TYPE_DOMAIN,
)
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.otx import OTXProvider
from app.threat_intelligence.cache_service import get_cached_ti, save_ti_result

logger = logging.getLogger("cryptix.threat_intelligence.service")


def enrich_sample_threat_intelligence(
    db: Session,
    apk_id: int,
    analysis_results: Optional[Dict[str, Any]] = None,
) -> List[ThreatIntelligence]:
    """
    Orchestrates external threat intelligence enrichment for an analyzed sample.
    """
    saved_records = []

    apk = get_apk_by_id(db, apk_id)
    if not apk:
        logger.warning(f"APK {apk_id} not found for Threat Intelligence enrichment.")
        return saved_records

    sha256_hash = apk.sha256

    vt_provider = VirusTotalProvider()
    abuse_provider = AbuseIPDBProvider()
    otx_provider = OTXProvider()

    max_indicators = getattr(settings, "MAX_INDICATORS_PER_PROVIDER", 5)

    # -------------------------------------------------------------
    # 1. VirusTotal File Hash Lookup (Hash-First Privacy Rule)
    # -------------------------------------------------------------
    try:
        cached_vt = get_cached_ti(db, PROVIDER_VIRUSTOTAL, IND_TYPE_HASH, sha256_hash)
        if cached_vt:
            vt_result = {
                "provider": PROVIDER_VIRUSTOTAL,
                "indicator": sha256_hash,
                "indicator_type": IND_TYPE_HASH,
                "status": cached_vt.status,
                "found": cached_vt.found,
                "reputation": json.loads(cached_vt.normalized_result_json) if cached_vt.normalized_result_json else {},
                "raw_metadata": json.loads(cached_vt.raw_metadata_json) if cached_vt.raw_metadata_json else None,
            }
            rec = save_ti_result(db, apk_id, vt_result, is_cached_hit=True)
            saved_records.append(rec)
        else:
            vt_result = vt_provider.lookup_indicator(sha256_hash, IND_TYPE_HASH)
            rec = save_ti_result(db, apk_id, vt_result, is_cached_hit=False)
            saved_records.append(rec)
    except Exception as e:
        logger.error(f"Error in VirusTotal lookup for APK {apk_id}: {str(e)}")

    # -------------------------------------------------------------
    # 2. AbuseIPDB Extracted IP Reputation Lookups
    # -------------------------------------------------------------
    extracted_ips = []
    if analysis_results and isinstance(analysis_results, dict):
        indicators = analysis_results.get("indicators", {})
        if isinstance(indicators, dict):
            extracted_ips = indicators.get("ip_addresses", []) or []

    # Limit extracted IPs
    ips_to_query = extracted_ips[:max_indicators]

    for ip_addr in ips_to_query:
        if not ip_addr or not isinstance(ip_addr, str):
            continue
        ip_clean = ip_addr.strip()
        try:
            cached_ip = get_cached_ti(db, PROVIDER_ABUSEIPDB, IND_TYPE_IP, ip_clean)
            if cached_ip:
                ip_result = {
                    "provider": PROVIDER_ABUSEIPDB,
                    "indicator": ip_clean,
                    "indicator_type": IND_TYPE_IP,
                    "status": cached_ip.status,
                    "found": cached_ip.found,
                    "reputation": json.loads(cached_ip.normalized_result_json) if cached_ip.normalized_result_json else {},
                    "raw_metadata": json.loads(cached_ip.raw_metadata_json) if cached_ip.raw_metadata_json else None,
                }
                rec = save_ti_result(db, apk_id, ip_result, is_cached_hit=True)
                saved_records.append(rec)
            else:
                ip_result = abuse_provider.lookup_indicator(ip_clean, IND_TYPE_IP)
                rec = save_ti_result(db, apk_id, ip_result, is_cached_hit=False)
                saved_records.append(rec)
        except Exception as e:
            logger.error(f"Error in AbuseIPDB lookup for IP {ip_clean} (APK {apk_id}): {str(e)}")

    # -------------------------------------------------------------
    # 3. AlienVault OTX Indicator Lookups (Hash primary)
    # -------------------------------------------------------------
    try:
        cached_otx = get_cached_ti(db, PROVIDER_OTX, IND_TYPE_HASH, sha256_hash)
        if cached_otx:
            otx_result = {
                "provider": PROVIDER_OTX,
                "indicator": sha256_hash,
                "indicator_type": IND_TYPE_HASH,
                "status": cached_otx.status,
                "found": cached_otx.found,
                "reputation": json.loads(cached_otx.normalized_result_json) if cached_otx.normalized_result_json else {},
                "raw_metadata": json.loads(cached_otx.raw_metadata_json) if cached_otx.raw_metadata_json else None,
            }
            rec = save_ti_result(db, apk_id, otx_result, is_cached_hit=True)
            saved_records.append(rec)
        else:
            otx_result = otx_provider.lookup_indicator(sha256_hash, IND_TYPE_HASH)
            rec = save_ti_result(db, apk_id, otx_result, is_cached_hit=False)
            saved_records.append(rec)
    except Exception as e:
        logger.error(f"Error in AlienVault OTX lookup for APK {apk_id}: {str(e)}")

    return saved_records


def get_threat_intelligence_by_apk(db: Session, apk_id: int) -> List[ThreatIntelligence]:
    """
    Retrieve all persisted Threat Intelligence records for a given APK ID.
    """
    return (
        db.query(ThreatIntelligence)
        .filter(ThreatIntelligence.apk_id == apk_id)
        .order_by(ThreatIntelligence.created_at.desc())
        .all()
    )

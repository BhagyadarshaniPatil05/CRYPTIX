"""
Database-backed Cache Service for Threat Intelligence queries.
Manages TTL-based lookup and persistence of TI provider responses.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.models.threat_intelligence import ThreatIntelligence

logger = logging.getLogger("cryptix.threat_intelligence.cache_service")


def get_cached_ti(
    db: Session,
    provider: str,
    indicator_type: str,
    indicator_value: str,
) -> Optional[ThreatIntelligence]:
    """
    Look up valid unexpired TI query cache entry in DB.
    """
    try:
        now = datetime.utcnow()
        record = (
            db.query(ThreatIntelligence)
            .filter(
                ThreatIntelligence.provider == provider,
                ThreatIntelligence.indicator_type == indicator_type,
                ThreatIntelligence.indicator_value == indicator_value,
            )
            .order_by(ThreatIntelligence.created_at.desc())
            .first()
        )

        if record:
            # Check expiration if expires_at is set
            if record.expires_at and record.expires_at < now:
                logger.debug(f"Cache expired for {provider}:{indicator_type}:{indicator_value}")
                return None
            return record
    except Exception as e:
        logger.error(f"Error reading TI cache: {str(e)}")

    return None


def save_ti_result(
    db: Session,
    apk_id: int,
    result: Dict[str, Any],
    is_cached_hit: bool = False,
) -> ThreatIntelligence:
    """
    Persist or refresh a Threat Intelligence query result in DB.
    """
    provider = result.get("provider", "unknown")
    indicator_type = result.get("indicator_type", "unknown")
    indicator_value = result.get("indicator", "")
    status = result.get("status", "ERROR")
    found = result.get("found", False)
    reputation = result.get("reputation", {})
    raw_metadata = result.get("raw_metadata")

    now = datetime.utcnow()
    ttl_hours = getattr(settings, "TI_CACHE_TTL_HOURS", 24)
    expires_at = now + timedelta(hours=ttl_hours)

    normalized_json = json.dumps(reputation) if isinstance(reputation, dict) else str(reputation)
    raw_metadata_json = json.dumps(raw_metadata) if raw_metadata is not None else None

    ti_record = ThreatIntelligence(
        apk_id=apk_id,
        provider=provider,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        status=status,
        found=found,
        normalized_result_json=normalized_json,
        raw_metadata_json=raw_metadata_json,
        cached=is_cached_hit,
        queried_at=now,
        expires_at=expires_at,
        created_at=now,
    )

    db.add(ti_record)
    db.commit()
    db.refresh(ti_record)

    return ti_record

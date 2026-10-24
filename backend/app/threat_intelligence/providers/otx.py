"""
AlienVault OTX v1 Threat Intelligence Provider Adapter.
Executes indicator lookups (GET /api/v1/indicators/{section}/{indicator}/general).
Supports hash, IPv4, domain, and URL indicator types.
"""
import logging
import httpx

from app.config.settings import settings
from app.threat_intelligence.base import ThreatIntelligenceProvider
from app.threat_intelligence.config import (
    PROVIDER_OTX,
    IND_TYPE_HASH,
    IND_TYPE_IP,
    IND_TYPE_DOMAIN,
    IND_TYPE_URL,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_NOT_CONFIGURED,
    STATUS_DISABLED,
    STATUS_RATE_LIMITED,
    STATUS_TIMEOUT,
    STATUS_UNAUTHORIZED,
    STATUS_FORBIDDEN,
    STATUS_ERROR,
)

logger = logging.getLogger("cryptix.threat_intelligence.otx")

OTX_SECTION_MAP = {
    IND_TYPE_HASH: "file",
    IND_TYPE_IP: "IPv4",
    IND_TYPE_DOMAIN: "domain",
    IND_TYPE_URL: "url",
}


class OTXProvider(ThreatIntelligenceProvider):
    @property
    def provider_name(self) -> str:
        return PROVIDER_OTX

    @property
    def supported_indicator_types(self) -> list:
        return [IND_TYPE_HASH, IND_TYPE_IP, IND_TYPE_DOMAIN, IND_TYPE_URL]

    def is_configured(self) -> bool:
        return bool(settings.OTX_ENABLED and settings.OTX_API_KEY and settings.OTX_API_KEY.strip())

    def lookup_indicator(self, indicator: str, indicator_type: str = IND_TYPE_HASH) -> dict:
        result = {
            "provider": self.provider_name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": STATUS_NOT_CONFIGURED,
            "found": False,
            "reputation": {},
            "raw_metadata": None,
            "error_detail": None,
        }

        if not settings.OTX_ENABLED:
            result["status"] = STATUS_DISABLED
            result["error_detail"] = "AlienVault OTX provider is disabled in settings."
            return result

        if not self.is_configured():
            result["status"] = STATUS_NOT_CONFIGURED
            result["error_detail"] = "AlienVault OTX API key is not configured."
            return result

        section = OTX_SECTION_MAP.get(indicator_type)
        if not section:
            result["status"] = STATUS_ERROR
            result["error_detail"] = f"Unsupported indicator type '{indicator_type}' for AlienVault OTX adapter."
            return result

        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general"
        headers = {
            "X-OTX-API-KEY": settings.OTX_API_KEY.strip(),
            "Accept": "application/json",
        }

        try:
            with httpx.Client(timeout=settings.OTX_TIMEOUT_SECONDS) as client:
                response = client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                pulses = pulse_info.get("pulses", [])

                pulse_names = [p.get("name") for p in pulses if p.get("name")][:5]
                tags_set = set()
                for p in pulses:
                    for t in p.get("tags", []):
                        tags_set.add(t)

                result["status"] = STATUS_SUCCESS
                result["found"] = pulse_count > 0
                result["reputation"] = {
                    "pulse_count": pulse_count,
                    "pulse_names": pulse_names,
                    "tags": list(tags_set)[:10],
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                }
                result["raw_metadata"] = {
                    "sections_available": data.get("sections", []),
                    "pulse_summary": [
                        {
                            "id": p.get("id"),
                            "name": p.get("name"),
                            "author": p.get("author_name"),
                            "created": p.get("created"),
                        }
                        for p in pulses[:5]
                    ],
                }
            elif response.status_code == 404:
                result["status"] = STATUS_NOT_FOUND
                result["found"] = False
                result["error_detail"] = "Indicator record not found in AlienVault OTX database."
            elif response.status_code in (401, 403):
                result["status"] = STATUS_UNAUTHORIZED if response.status_code == 401 else STATUS_FORBIDDEN
                result["error_detail"] = f"Authentication failure ({response.status_code}) for AlienVault OTX API key."
            elif response.status_code == 429:
                result["status"] = STATUS_RATE_LIMITED
                result["error_detail"] = "AlienVault OTX API rate limit reached."
            else:
                result["status"] = STATUS_ERROR
                result["error_detail"] = f"AlienVault OTX HTTP status code: {response.status_code}"

        except httpx.TimeoutException:
            logger.warning(f"AlienVault OTX lookup timeout for indicator {indicator}")
            result["status"] = STATUS_TIMEOUT
            result["error_detail"] = "AlienVault OTX API request timed out."
        except Exception as e:
            logger.error(f"AlienVault OTX lookup exception for indicator {indicator}: {str(e)}")
            result["status"] = STATUS_ERROR
            result["error_detail"] = str(e)

        return result

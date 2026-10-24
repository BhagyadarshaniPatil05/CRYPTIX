"""
VirusTotal v3 Hash Threat Intelligence Provider Adapter.
Executes hash-first lookups (GET /api/v3/files/{sha256}).
NEVER uploads raw APK binary files.
"""
import logging
import httpx

from app.config.settings import settings
from app.threat_intelligence.base import ThreatIntelligenceProvider
from app.threat_intelligence.config import (
    PROVIDER_VIRUSTOTAL,
    IND_TYPE_HASH,
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

logger = logging.getLogger("cryptix.threat_intelligence.virustotal")


class VirusTotalProvider(ThreatIntelligenceProvider):
    @property
    def provider_name(self) -> str:
        return PROVIDER_VIRUSTOTAL

    @property
    def supported_indicator_types(self) -> list:
        return [IND_TYPE_HASH]

    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_ENABLED and settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip())

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

        if not settings.VIRUSTOTAL_ENABLED:
            result["status"] = STATUS_DISABLED
            result["error_detail"] = "VirusTotal provider is disabled in settings."
            return result

        if not self.is_configured():
            result["status"] = STATUS_NOT_CONFIGURED
            result["error_detail"] = "VirusTotal API key is not configured."
            return result

        if indicator_type != IND_TYPE_HASH:
            result["status"] = STATUS_ERROR
            result["error_detail"] = f"Unsupported indicator type '{indicator_type}' for VirusTotal adapter."
            return result

        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY.strip(),
            "Accept": "application/json",
        }

        try:
            with httpx.Client(timeout=settings.VIRUSTOTAL_TIMEOUT_SECONDS) as client:
                response = client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                total_engines = sum(stats.values()) if stats else 0

                result["status"] = STATUS_SUCCESS
                result["found"] = True
                result["reputation"] = {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                    "total_engines": total_engines,
                    "permalink": f"https://www.virustotal.com/gui/file/{indicator}",
                    "meaningful_name": attributes.get("meaningful_name") or attributes.get("type_description"),
                    "reputation_score": attributes.get("reputation", 0),
                }
                result["raw_metadata"] = {
                    "type_description": attributes.get("type_description"),
                    "tags": attributes.get("tags", [])[:10],
                    "last_analysis_date": attributes.get("last_analysis_date"),
                }
            elif response.status_code == 404:
                result["status"] = STATUS_NOT_FOUND
                result["found"] = False
                result["error_detail"] = "Hash record not found in VirusTotal database."
            elif response.status_code == 401:
                result["status"] = STATUS_UNAUTHORIZED
                result["error_detail"] = "Invalid or unauthorized VirusTotal API key."
            elif response.status_code == 403:
                result["status"] = STATUS_FORBIDDEN
                result["error_detail"] = "Access forbidden by VirusTotal API."
            elif response.status_code == 429:
                result["status"] = STATUS_RATE_LIMITED
                result["error_detail"] = "VirusTotal API rate limit reached."
            else:
                result["status"] = STATUS_ERROR
                result["error_detail"] = f"VirusTotal HTTP status code: {response.status_code}"

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal lookup timeout for hash {indicator}")
            result["status"] = STATUS_TIMEOUT
            result["error_detail"] = "VirusTotal API request timed out."
        except Exception as e:
            logger.error(f"VirusTotal lookup exception for hash {indicator}: {str(e)}")
            result["status"] = STATUS_ERROR
            result["error_detail"] = str(e)

        return result

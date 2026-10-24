"""
AbuseIPDB v2 Threat Intelligence Provider Adapter.
Executes IP reputation lookups (GET /api/v2/check).
Filters out private/loopback IPs prior to remote requests.
"""
import ipaddress
import logging
import httpx

from app.config.settings import settings
from app.threat_intelligence.base import ThreatIntelligenceProvider
from app.threat_intelligence.config import (
    PROVIDER_ABUSEIPDB,
    IND_TYPE_IP,
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

logger = logging.getLogger("cryptix.threat_intelligence.abuseipdb")


class AbuseIPDBProvider(ThreatIntelligenceProvider):
    @property
    def provider_name(self) -> str:
        return PROVIDER_ABUSEIPDB

    @property
    def supported_indicator_types(self) -> list:
        return [IND_TYPE_IP]

    def is_configured(self) -> bool:
        return bool(settings.ABUSEIPDB_ENABLED and settings.ABUSEIPDB_API_KEY and settings.ABUSEIPDB_API_KEY.strip())

    @staticmethod
    def is_private_or_invalid_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except ValueError:
            return True

    def lookup_indicator(self, indicator: str, indicator_type: str = IND_TYPE_IP) -> dict:
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

        if not settings.ABUSEIPDB_ENABLED:
            result["status"] = STATUS_DISABLED
            result["error_detail"] = "AbuseIPDB provider is disabled in settings."
            return result

        if not self.is_configured():
            result["status"] = STATUS_NOT_CONFIGURED
            result["error_detail"] = "AbuseIPDB API key is not configured."
            return result

        if indicator_type != IND_TYPE_IP:
            result["status"] = STATUS_ERROR
            result["error_detail"] = f"Unsupported indicator type '{indicator_type}' for AbuseIPDB adapter."
            return result

        if self.is_private_or_invalid_ip(indicator):
            result["status"] = STATUS_NOT_FOUND
            result["found"] = False
            result["error_detail"] = f"Skipped private, loopback, or invalid IP address: '{indicator}'"
            return result

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": indicator,
            "maxAgeInDays": "90",
            "verbose": "",
        }
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY.strip(),
            "Accept": "application/json",
        }

        try:
            with httpx.Client(timeout=settings.ABUSEIPDB_TIMEOUT_SECONDS) as client:
                response = client.get(url, params=params, headers=headers)

            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)

                found_flag = abuse_score > 0 or total_reports > 0

                result["status"] = STATUS_SUCCESS
                result["found"] = found_flag
                result["reputation"] = {
                    "ip_address": data.get("ipAddress", indicator),
                    "abuse_confidence_score": abuse_score,
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": total_reports,
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                }
                result["raw_metadata"] = {
                    "hostnames": data.get("hostnames", [])[:5],
                    "country_name": data.get("countryName"),
                }
            elif response.status_code == 404:
                result["status"] = STATUS_NOT_FOUND
                result["found"] = False
                result["error_detail"] = "IP address record not found in AbuseIPDB database."
            elif response.status_code in (401, 403):
                result["status"] = STATUS_UNAUTHORIZED if response.status_code == 401 else STATUS_FORBIDDEN
                result["error_detail"] = f"Authentication failure ({response.status_code}) for AbuseIPDB API key."
            elif response.status_code == 429:
                result["status"] = STATUS_RATE_LIMITED
                result["error_detail"] = "AbuseIPDB API rate limit reached."
            else:
                result["status"] = STATUS_ERROR
                result["error_detail"] = f"AbuseIPDB HTTP status code: {response.status_code}"

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB lookup timeout for IP {indicator}")
            result["status"] = STATUS_TIMEOUT
            result["error_detail"] = "AbuseIPDB API request timed out."
        except Exception as e:
            logger.error(f"AbuseIPDB lookup exception for IP {indicator}: {str(e)}")
            result["status"] = STATUS_ERROR
            result["error_detail"] = str(e)

        return result

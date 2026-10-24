"""
Abstract base class for Threat Intelligence Provider adapters.
"""
from abc import ABC, abstractmethod


class ThreatIntelligenceProvider(ABC):
    """
    Abstract interface for Threat Intelligence Provider adapters.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique provider identifier (e.g. 'virustotal', 'abuseipdb', 'otx')."""
        pass

    @property
    @abstractmethod
    def supported_indicator_types(self) -> list:
        """List of supported indicator types (e.g. ['hash'], ['ip'])."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if provider is enabled and required credentials/keys are present."""
        pass

    @abstractmethod
    def lookup_indicator(self, indicator: str, indicator_type: str) -> dict:
        """
        Queries the external threat intelligence API for the given indicator.
        Returns normalized dictionary payload:
        {
            "provider": str,
            "indicator": str,
            "indicator_type": str,
            "status": str,  # SUCCESS, NOT_FOUND, NOT_CONFIGURED, RATE_LIMITED, etc.
            "found": bool,
            "reputation": dict,
            "raw_metadata": dict/None,
            "error_detail": str/None,
        }
        """
        pass

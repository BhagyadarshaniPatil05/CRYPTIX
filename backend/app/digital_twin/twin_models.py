from pydantic import BaseModel
from typing import List, Dict, Any


class DigitalTwinState(BaseModel):
    """
    Represents the current security state of an APK.
    """

    package_name: str
    app_name: str

    version_name: str
    version_code: str

    permissions: List[str]
    dangerous_permissions: List[Dict[str, Any]]

    exported_components: Dict[str, Any]
    intent_filters: List[Dict[str, Any]]

    certificate: Dict[str, Any]

    indicators: Dict[str, Any]
    behaviors: List[Dict[str, Any]]

    dex_findings: List[Dict[str, Any]]
    yara_matches: List[Dict[str, Any]]

    risk_score: int
    risk_level: str

    threat_level: str
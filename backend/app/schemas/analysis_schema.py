from pydantic import BaseModel
from typing import List, Dict, Any


class DangerousPermission(BaseModel):
    permission: str
    severity: str
    reason: str


class ExportedComponent(BaseModel):
    name: str
    exported: bool


class ExportedComponents(BaseModel):
    activities: List[ExportedComponent]
    services: List[ExportedComponent]
    receivers: List[ExportedComponent]
    providers: List[ExportedComponent]


class IntentFilter(BaseModel):
    activity: str
    actions: List[str]
    categories: List[str]


class Certificate(BaseModel):
    issuer: str
    subject: str
    serial_number: str


class CertificateResponse(BaseModel):
    certificate_count: int
    certificates: List[Certificate]


class Indicators(BaseModel):
    urls: List[str]
    ip_addresses: List[str]
    emails: List[str]
    firebase_urls: List[str]
    api_keys: List[str]
    base64_strings: List[str]
    bitcoin_addresses: List[str]


class Behavior(BaseModel):
    api: str
    severity: str
    reason: str


class YaraMatch(BaseModel):
    rule: str
    namespace: str
    tags: List[str]
    severity: str


class ThreatAssessment(BaseModel):
    threat_level: str
    confidence: str
    summary: str
    key_findings: List[str]
    recommended_actions: List[str]


class DexFinding(BaseModel):
    api: str
    category: str
    severity: str
    reason: str


class DigitalTwinState(BaseModel):
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


class APKAnalysisResponse(BaseModel):
    package_name: str
    app_name: str
    version_name: str
    version_code: str

    min_sdk: str
    target_sdk: str

    permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]

    exported_components: ExportedComponents

    intent_filters: List[IntentFilter]

    certificate: CertificateResponse

    indicators: Indicators

    behaviors: List[Behavior]

    yara_matches: List[YaraMatch]

    threat_assessment: ThreatAssessment

    dex_findings: List[DexFinding]

    digital_twin: DigitalTwinState

    # Digital Twin Persistence Fields
    digital_twin_id: int | None = None
    digital_twin_version: int | None = None

    dangerous_permissions: List[DangerousPermission]

    risk_score: int
    risk_level: str
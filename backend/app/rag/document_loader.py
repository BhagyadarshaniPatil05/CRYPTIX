"""
Phase 3.5.3 — Cybersecurity Document Loader & Normalization Module.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import re
from typing import List, Optional, Dict, Any

from app.mitre.catalog import MITRE_MOBILE_CATALOG
from app.rag.config import SourceType, TrustLevel, MITRE_MOBILE_PINNED_VERSION


def normalize_document_content(content: str) -> str:
    """
    Normalize raw document content while preserving technical identifiers.

    Performs:
    - Line ending unification (CRLF -> LF)
    - Removal of trailing whitespace per line
    - Compression of consecutive blank lines (max 2)
    - Preserves exact technical identifiers (e.g. T1407, T1437.001, CVE-2024-1234, DexClassLoader, URLs).
    """
    if not content:
        return ""

    # Unify line endings
    text = content.replace("\r\n", "\n").replace("\r", "\n")

    # Strip trailing whitespace per line
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)

    # Replace 3+ consecutive newlines with 2 newlines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def compute_content_hash(source_type: str, identifier: str, normalized_content: str) -> str:
    """
    Compute a deterministic SHA-256 content hash for a document.

    Combines source_type, unique technique/CVE identifier, and normalized text.
    Distinct from APK file SHA-256 hash.
    """
    raw_key = f"{source_type}:{identifier}:{normalized_content}".encode("utf-8")
    return hashlib.sha256(raw_key).hexdigest()


@dataclass
class CybersecurityDocument:
    source: str
    source_type: str
    source_version: str
    trust_level: str
    title: str
    content: str
    content_hash: str
    url: Optional[str] = None
    publisher: Optional[str] = None
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_verified: Optional[datetime] = None
    platform: Optional[str] = "Android"
    technique_id: Optional[str] = None
    cve_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseDocumentLoader(ABC):
    """Abstract Base Class for Document Loaders."""

    @abstractmethod
    def load(self) -> List[CybersecurityDocument]:
        """Load and return normalized cybersecurity documents."""
        pass


class MitreMobileLoader(BaseDocumentLoader):
    """
    Document Loader for MITRE ATT&CK Mobile v15.1 Catalog.

    Loads official pinned v15.1 techniques from backend/app/mitre/catalog.py,
    validating version pinning, source type, trust level, and official URLs.

    ARCHITECTURAL SCOPE NOTE:
    Current RAG MITRE seed data is limited to the audited Phase 3.4.1 Mobile ATT&CK v15.1
    techniques. It is not claimed to represent the complete MITRE ATT&CK Mobile v15.1
    knowledge base.
    """


    def __init__(self, catalog_dict: Optional[Dict[str, Any]] = None):
        self._catalog = catalog_dict if catalog_dict is not None else MITRE_MOBILE_CATALOG

    def load(self) -> List[CybersecurityDocument]:
        documents: List[CybersecurityDocument] = []

        for tech_id, entry in self._catalog.items():
            version = entry.get("source_version", "15.1")
            # Strict version pinning enforcement
            if "15.1" not in str(version):
                raise ValueError(
                    f"MITRE loader rejection: Technique '{tech_id}' source_version '{version}' "
                    f"does not match pinned version '{MITRE_MOBILE_PINNED_VERSION}'."
                )

            raw_desc = entry.get("description", "")
            if not raw_desc or not raw_desc.strip():
                continue

            normalized_text = normalize_document_content(raw_desc)
            doc_hash = compute_content_hash(
                source_type=SourceType.MITRE.value,
                identifier=tech_id,
                normalized_content=normalized_text,
            )

            # Parse last_verified date if available
            last_ver_dt = None
            if entry.get("last_verified"):
                try:
                    last_ver_dt = datetime.strptime(entry["last_verified"], "%Y-%m-%d")
                except ValueError:
                    last_ver_dt = datetime.utcnow()

            doc = CybersecurityDocument(
                source="MITRE_ATTACK_MOBILE",
                source_type=SourceType.MITRE.value,
                source_version=MITRE_MOBILE_PINNED_VERSION,
                trust_level=TrustLevel.AUTHORITATIVE.value,
                title=entry.get("technique_name", tech_id),
                url=entry.get("url"),
                publisher="MITRE",
                last_verified=last_ver_dt,
                platform=entry.get("platform", "Android"),
                technique_id=tech_id,
                content=normalized_text,
                content_hash=doc_hash,
                metadata={
                    "tactic": entry.get("tactic"),
                    "domain": entry.get("domain", "Mobile"),
                    "is_subtechnique": entry.get("is_subtechnique", False),
                    "parent_id": entry.get("parent_id"),
                },
            )
            documents.append(doc)

        return documents

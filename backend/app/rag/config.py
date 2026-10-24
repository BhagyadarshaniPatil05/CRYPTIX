"""
Phase 3.5 — Cybersecurity RAG System Configuration & Constants.
"""

from enum import Enum


class SourceType(str, Enum):
    MITRE = "MITRE"
    NVD = "NVD"
    CISA = "CISA"
    ANDROID_DOCS = "ANDROID_DOCS"
    VENDOR_REPORT = "VENDOR_REPORT"
    PROJECT_INVESTIGATION = "PROJECT_INVESTIGATION"
    UNKNOWN = "UNKNOWN"


class TrustLevel(str, Enum):
    AUTHORITATIVE = "AUTHORITATIVE"  # MITRE, NVD, CISA, Android Official Docs
    TRUSTED_VENDOR = "TRUSTED_VENDOR"  # Google, Mandiant, Palo Alto, Microsoft, etc.
    RESEARCH = "RESEARCH"  # Academic papers, security blogs
    UNKNOWN = "UNKNOWN"  # Unverified sources


class GroundingState(str, Enum):
    SUPPORTED = "SUPPORTED"  # Evidence directly supports answer claims
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"  # Some claims are grounded, others contextual
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # Grounding evidence unavailable or sparse


# Pinned knowledge metadata versions
MITRE_MOBILE_PINNED_VERSION = "15.1"

# Retrieval Ranking Weights (Relevance > Trust)
EXACT_ID_MATCH_WEIGHT = 0.35
SEMANTIC_RELEVANCE_WEIGHT = 0.35
LEXICAL_MATCH_WEIGHT = 0.15
SOURCE_TRUST_WEIGHT = 0.10
FRESHNESS_WEIGHT = 0.05

# Trust Level Multipliers for ranking
TRUST_LEVEL_MULTIPLIERS = {
    TrustLevel.AUTHORITATIVE: 1.0,
    TrustLevel.TRUSTED_VENDOR: 0.85,
    TrustLevel.RESEARCH: 0.70,
    TrustLevel.UNKNOWN: 0.50,
}

# RAG Search Defaults
DEFAULT_TOP_K = 5
MAX_TOP_K = 20
MIN_SIMILARITY_SCORE = 0.20

"""
Phase 3.5.4 — APK-Aware Query Builder Module.
Converts user questions and optional static analysis findings into structured retrieval queries.
"""

from dataclasses import dataclass, field
import re
from typing import List, Optional, Dict, Any


@dataclass
class StructuredRetrievalQuery:
    user_question: str
    technique_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    apk_evidence: List[str] = field(default_factory=list)
    malware_dna: Optional[str] = None
    threat_memory: Optional[str] = None
    global_threat_intel: Optional[str] = None
    raw_context_text: str = ""


class RAGQueryBuilder:
    """
    Query Builder for constructing evidence-grounded RAG retrieval queries.
    
    Extracts MITRE technique IDs (e.g. T1412, T1437.001), CVE IDs (e.g. CVE-2024-1234),
    and cybersecurity keywords from user input and APK investigation context.
    Strictly preserves static capability language to avoid asserting unconfirmed runtime behavior.
    """

    TECHNIQUE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    # Standard cybersecurity stop words to filter from keyword extraction
    STOP_WORDS = {
        "what", "why", "how", "this", "that", "from", "with", "have", "does", "is", "are",
        "the", "and", "for", "in", "of", "to", "a", "an", "or", "on", "it", "be", "by", "as"
    }

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract normalized cybersecurity keywords from text string."""
        if not text:
            return []
        tokens = re.findall(r"\b[a-zA-Z0-9_\-\.]+\b", text.lower())
        keywords = []
        for t in tokens:
            if t not in self.STOP_WORDS and len(t) > 2 and not t.isdigit():
                keywords.append(t)
        return list(dict.fromkeys(keywords))  # Deduplicate preserving order

    def build_query(
        self,
        question: str,
        apk_evidence: Optional[List[str]] = None,
        technique_ids: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        malware_dna: Optional[str] = None,
        threat_memory: Optional[str] = None,
        global_threat_intel: Optional[str] = None,
    ) -> StructuredRetrievalQuery:
        """
        Construct a StructuredRetrievalQuery object from user question and optional APK context.
        """
        clean_question = (question or "").strip()
        evidence_list = apk_evidence or []

        # Extract technique IDs from question and explicit parameters
        found_techs = set(t.upper() for t in self.TECHNIQUE_REGEX.findall(clean_question))
        if technique_ids:
            found_techs.update(t.upper() for t in technique_ids)
        # Also check evidence strings for technique IDs
        for ev in evidence_list:
            found_techs.update(t.upper() for t in self.TECHNIQUE_REGEX.findall(ev))

        # Extract CVE IDs from question and explicit parameters
        found_cves = set(c.upper() for c in self.CVE_REGEX.findall(clean_question))
        if cve_ids:
            found_cves.update(c.upper() for c in cve_ids)
        for ev in evidence_list:
            found_cves.update(c.upper() for c in self.CVE_REGEX.findall(ev))

        # Extract keywords
        combined_text_for_keywords = f"{clean_question} {' '.join(evidence_list)}"
        keywords = self._extract_keywords(combined_text_for_keywords)

        # Build raw_context_text for vector embedding
        context_parts = []
        if clean_question:
            context_parts.append(f"Question: {clean_question}")
        if found_techs:
            context_parts.append(f"Techniques: {', '.join(sorted(found_techs))}")
        if found_cves:
            context_parts.append(f"CVEs: {', '.join(sorted(found_cves))}")
        if evidence_list:
            context_parts.append(f"Static Capabilities: {'; '.join(evidence_list)}")
        if malware_dna:
            context_parts.append(f"DNA Pattern: {malware_dna}")

        raw_context = "\n".join(context_parts) if context_parts else clean_question

        return StructuredRetrievalQuery(
            user_question=clean_question,
            technique_ids=sorted(list(found_techs)),
            cve_ids=sorted(list(found_cves)),
            keywords=keywords,
            apk_evidence=evidence_list,
            malware_dna=malware_dna,
            threat_memory=threat_memory,
            global_threat_intel=global_threat_intel,
            raw_context_text=raw_context,
        )

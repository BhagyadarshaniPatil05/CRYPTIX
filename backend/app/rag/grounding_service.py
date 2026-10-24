"""
Phase 3.5.5 — Deterministic Grounding Validation Service Module.
Performs evidence consistency checks over LLM responses to enforce grounding states:
SUPPORTED, PARTIALLY_SUPPORTED, INSUFFICIENT_EVIDENCE.
"""

from dataclasses import dataclass, field
import re
from typing import List, Dict, Any, Optional

from app.rag.config import GroundingState
from app.rag.context_builder import GroundedContext
from app.rag.llm_provider import LLMGenerationResponse


@dataclass
class GroundingResult:
    state: GroundingState
    supported_claims: List[str] = field(default_factory=list)
    unsupported_claims: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    evidence_references: List[str] = field(default_factory=list)


@dataclass
class GroundedResponse:
    answer: str
    grounding_state: str
    grounding_result: GroundingResult
    provenance_chunks: List[Dict[str, Any]] = field(default_factory=list)
    provider: str = "mock"
    model: str = "mock-offline-v1"
    latency_ms: float = 0.0


class GroundingValidationService:
    """
    Deterministic Grounding Validation Service.
    
    Evaluates LLM responses against GroundedContext to detect:
    1. Static capability -> confirmed runtime action overstatements.
    2. Absolute malware verdicts unsupported by deterministic risk engine.
    3. Unsupported technique IDs or CVE identifiers not present in context.
    4. Missing provenance or citation warnings.
    5. Insufficient evidence states.

    IMPORTANT: This service performs deterministic consistency checks; it is NOT a black-box AI classifier.
    """

    # Regex patterns for detecting technique IDs and CVEs
    TECHNIQUE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
    CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    # Overstatement phrase patterns that convert static findings to confirmed runtime execution
    OVERSTATEMENT_PATTERNS = [
        re.compile(r"\bdefinitely (?:intercepted|stole|executed|transmitted|exfiltrated)\b", re.IGNORECASE),
        re.compile(r"\bconfirmed (?:malware|trojan|ransomware|exploitation)\b", re.IGNORECASE),
        re.compile(r"\b100%\s*(?:malicious|trojan)\b", re.IGNORECASE),
        re.compile(r"\bproved to (?:steal|intercept|spy)\b", re.IGNORECASE),
    ]

    def validate_grounding(
        self,
        context: GroundedContext,
        llm_response: LLMGenerationResponse
    ) -> GroundedResponse:
        """
        Validate an LLMGenerationResponse against a GroundedContext and return a GroundedResponse.
        """
        supported_claims = []
        unsupported_claims = []
        warnings = []
        evidence_refs = []

        answer_text = llm_response.answer or ""

        # 1. Extract provenance references from retrieved items
        provenance_chunks = []
        context_tech_ids = set()
        context_cve_ids = set()

        if context.retrieved_items:
            for item in context.retrieved_items:
                ref_dict = {
                    "document_id": item.document_id,
                    "chunk_id": item.chunk_id,
                    "source": item.source,
                    "source_type": item.source_type,
                    "source_version": item.source_version,
                    "trust_level": item.trust_level,
                    "title": item.title,
                    "url": item.url,
                    "section_title": item.section_title,
                    "technique_id": item.technique_id,
                    "cve_id": item.cve_id,
                    "retrieval_score": item.final_score,
                }
                provenance_chunks.append(ref_dict)

                if item.technique_id:
                    context_tech_ids.add(item.technique_id.upper())
                    evidence_refs.append(f"Technique: {item.technique_id}")
                if item.cve_id:
                    context_cve_ids.add(item.cve_id.upper())
                    evidence_refs.append(f"CVE: {item.cve_id}")

        # Check for empty context / no retrieval / no evidence
        has_retrieved_knowledge = bool(context.retrieved_items)
        has_apk_evidence = "No specific static APK evidence" not in context.apk_evidence_section

        if not has_retrieved_knowledge and not has_apk_evidence:
            warnings.append("Both retrieved knowledge and APK evidence are absent.")
            g_result = GroundingResult(
                state=GroundingState.INSUFFICIENT_EVIDENCE,
                supported_claims=supported_claims,
                unsupported_claims=["No evidence or domain knowledge available in context."],
                warnings=warnings,
                evidence_references=evidence_refs,
            )
            return GroundedResponse(
                answer=answer_text,
                grounding_state=GroundingState.INSUFFICIENT_EVIDENCE.value,
                grounding_result=g_result,
                provenance_chunks=provenance_chunks,
                provider=llm_response.provider,
                model=llm_response.model,
                latency_ms=llm_response.latency_ms,
            )

        # 2. Check Overstatement Patterns (Static capability -> runtime claim)
        for pat in self.OVERSTATEMENT_PATTERNS:
            match = pat.search(answer_text)
            if match:
                unsupported_claims.append(f"Overstatement detected: '{match.group(0)}' asserts confirmed runtime execution.")
                warnings.append("Answer converts static capability into confirmed runtime behavior.")

        # 3. Check technique IDs in answer vs context
        answer_tech_ids = set(t.upper() for t in self.TECHNIQUE_REGEX.findall(answer_text))
        for t_id in answer_tech_ids:
            if t_id not in context_tech_ids and t_id not in context.full_prompt_text.upper():
                unsupported_claims.append(f"Technique ID '{t_id}' in answer was not present in context.")
                warnings.append(f"Unsupported technique ID '{t_id}'.")
            else:
                supported_claims.append(f"Technique ID '{t_id}' is supported by context.")

        # 4. Check CVE IDs in answer vs context
        answer_cve_ids = set(c.upper() for c in self.CVE_REGEX.findall(answer_text))
        for c_id in answer_cve_ids:
            if c_id not in context_cve_ids and c_id not in context.full_prompt_text.upper():
                unsupported_claims.append(f"CVE '{c_id}' in answer was not present in context.")
                warnings.append(f"Unsupported CVE '{c_id}'.")
            else:
                supported_claims.append(f"CVE '{c_id}' is supported by context.")

        # 5. Check capability preservation wording
        if "Static Analysis Boundary Notice" in answer_text or "static capability" in answer_text.lower() or "candidate" in answer_text.lower():
            supported_claims.append("Answer explicitly respects static analysis boundary phrasing.")

        # Determine Final Grounding State
        if unsupported_claims:
            if supported_claims:
                final_state = GroundingState.PARTIALLY_SUPPORTED
            else:
                final_state = GroundingState.INSUFFICIENT_EVIDENCE
        elif not has_retrieved_knowledge:
            final_state = GroundingState.PARTIALLY_SUPPORTED
            warnings.append("Retrieved domain knowledge chunks were empty; answer relies solely on static evidence.")
        else:
            final_state = GroundingState.SUPPORTED

        g_result = GroundingResult(
            state=final_state,
            supported_claims=supported_claims,
            unsupported_claims=unsupported_claims,
            warnings=warnings,
            evidence_references=evidence_refs,
        )

        return GroundedResponse(
            answer=answer_text,
            grounding_state=final_state.value,
            grounding_result=g_result,
            provenance_chunks=provenance_chunks,
            provider=llm_response.provider,
            model=llm_response.model,
            latency_ms=llm_response.latency_ms,
        )

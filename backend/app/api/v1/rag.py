"""
API Router for Phase 3.5.6 — Cybersecurity RAG REST API.
Exposes health, retrieval, and grounded question endpoints reusing existing RAG services.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session
import json
from typing import List, Dict, Any, Optional

from app.config.settings import settings
from app.database.session import get_db
from app.rag.config import GroundingState, DEFAULT_TOP_K, MAX_TOP_K
from app.rag.query_builder import RAGQueryBuilder
from app.rag.retriever import HybridRetriever, RetrievalResultItem
from app.rag.context_builder import RAGContextBuilder
from app.rag.llm_provider import get_llm_provider, LLMGenerationResponse
from app.rag.grounding_service import GroundingValidationService
from app.models.rag import RagQueryLog
from app.core.logger import logger

router = APIRouter(prefix="/rag", tags=["Cybersecurity RAG Engine"])


# ---------------------------------------------------------------------
# Pydantic Schemas with extra="forbid" (Rejects unknown/override fields)
# ---------------------------------------------------------------------

class RAGHealthResponse(BaseModel):
    status: str
    rag_enabled: bool
    vector_store: str
    embedding_provider: str
    llm_provider: str
    llm_model: str
    llm_configured: bool


class RAGRetrievalResultItemSchema(BaseModel):
    document_id: int
    chunk_id: int
    source: str
    source_type: str
    source_version: str
    publisher: Optional[str] = None
    title: str
    url: Optional[str] = None
    section_title: Optional[str] = None
    technique_id: Optional[str] = None
    cve_id: Optional[str] = None
    content: str
    retrieval_score: float
    retrieval_reasons: List[str]
    exact_id_score: float
    semantic_score: float
    lexical_score: float
    trust_score: float
    freshness_score: float


class RAGRetrieveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(..., min_length=1, max_length=4000, description="Cybersecurity inquiry")
    technique_ids: Optional[List[str]] = Field(default_factory=list)
    cve_ids: Optional[List[str]] = Field(default_factory=list)
    apk_evidence: Optional[List[str]] = Field(default_factory=list)
    malware_dna_context: Optional[List[str]] = Field(default_factory=list)
    threat_memory_context: Optional[List[str]] = Field(default_factory=list)
    global_ti_context: Optional[List[str]] = Field(default_factory=list)
    top_k: Optional[int] = Field(default=DEFAULT_TOP_K, ge=1, le=MAX_TOP_K)


class RAGRetrieveResponse(BaseModel):
    question: str
    query_techniques: List[str]
    query_cves: List[str]
    retrieved_count: int
    results: List[RAGRetrievalResultItemSchema]


class RAGAskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(..., min_length=1, max_length=4000, description="Cybersecurity question")
    apk_id: Optional[int] = None
    technique_ids: Optional[List[str]] = Field(default_factory=list)
    cve_ids: Optional[List[str]] = Field(default_factory=list)
    apk_evidence: Optional[List[str]] = Field(default_factory=list)
    mitre_analysis: Optional[List[str]] = Field(default_factory=list)
    malware_dna_context: Optional[List[str]] = Field(default_factory=list)
    threat_memory_context: Optional[List[str]] = Field(default_factory=list)
    global_ti_context: Optional[List[str]] = Field(default_factory=list)
    top_k: Optional[int] = Field(default=DEFAULT_TOP_K, ge=1, le=MAX_TOP_K)


class GroundingDetailSchema(BaseModel):
    state: str
    supported_claims: List[str]
    unsupported_claims: List[str]
    warnings: List[str]
    evidence_references: List[str]


class RAGAskResponse(BaseModel):
    answer: str
    grounding: GroundingDetailSchema
    provenance: List[RAGRetrievalResultItemSchema]
    provider: str
    model: str
    latency_ms: float


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def _check_rag_enabled():
    """Raise HTTP 503 if RAG is disabled in configuration."""
    if not settings.RAG_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cybersecurity RAG system is currently disabled."
        )


def _format_result_item(item: RetrievalResultItem) -> RAGRetrievalResultItemSchema:
    return RAGRetrievalResultItemSchema(
        document_id=item.document_id,
        chunk_id=item.chunk_id,
        source=item.source,
        source_type=item.source_type,
        source_version=item.source_version,
        publisher=item.publisher,
        title=item.title,
        url=item.url,
        section_title=item.section_title,
        technique_id=item.technique_id,
        cve_id=item.cve_id,
        content=item.content,
        retrieval_score=round(item.final_score, 4),
        retrieval_reasons=item.retrieval_reasons,
        exact_id_score=round(item.exact_id_score, 4),
        semantic_score=round(item.semantic_score, 4),
        lexical_score=round(item.lexical_score, 4),
        trust_score=round(item.trust_score, 4),
        freshness_score=round(item.freshness_score, 4),
    )


def _safe_log_query(
    db: Session,
    question: str,
    apk_id: Optional[int],
    retrieved_chunk_ids: List[int],
    grounding_state: str,
    provider: str,
    latency_ms: float
):
    """
    Safely persist query log to RagQueryLog table.
    Wrapped in isolated try/except so DB failure never breaks the RAG API response.
    Never stores secrets, API keys, or raw binaries.
    """
    try:
        query_log = RagQueryLog(
            apk_id=apk_id,
            question=question[:1000],  # Truncate to 1000 chars for logging
            retrieved_chunk_ids_json=json.dumps(retrieved_chunk_ids),
            grounding_state=grounding_state,
            llm_provider=provider,
            latency_ms=latency_ms,
        )
        db.add(query_log)
        db.commit()
    except Exception as ex:
        logger.warning(f"Failed to record RagQueryLog entry: {ex}")
        db.rollback()


# ---------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------

@router.get("/health", response_model=RAGHealthResponse)
def get_rag_health():
    """
    RAG Health and Status Endpoint.
    Callable even when RAG is disabled (reports status='disabled').
    Never exposes API keys or provider secrets.
    """
    is_enabled = settings.RAG_ENABLED
    llm_provider = settings.RAG_LLM_PROVIDER
    has_api_key = bool(settings.RAG_LLM_API_KEY and settings.RAG_LLM_API_KEY.strip())
    is_configured = has_api_key or llm_provider in ("mock", "offline", "test")

    return RAGHealthResponse(
        status="ok" if is_enabled else "disabled",
        rag_enabled=is_enabled,
        vector_store=settings.RAG_VECTOR_STORE,
        embedding_provider=settings.RAG_EMBEDDING_PROVIDER,
        llm_provider=llm_provider,
        llm_model=settings.RAG_LLM_MODEL,
        llm_configured=is_configured,
    )


@router.post("/retrieve", response_model=RAGRetrieveResponse)
def retrieve_knowledge(
    req: RAGRetrieveRequest,
    db: Session = Depends(get_db)
):
    """
    Retrieve Cybersecurity Knowledge without LLM Generation.
    Executes Query Builder and Hybrid Retriever over the vector database.
    """
    _check_rag_enabled()

    if not req.question.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Question string cannot be empty or whitespace only."
        )

    try:
        combined_evidence = (req.apk_evidence or [])
        dna_str = "; ".join(req.malware_dna_context) if req.malware_dna_context else None
        mem_str = "; ".join(req.threat_memory_context) if req.threat_memory_context else None
        gti_str = "; ".join(req.global_ti_context) if req.global_ti_context else None

        # 1. Query Builder
        q_builder = RAGQueryBuilder()
        query = q_builder.build_query(
            question=req.question,
            apk_evidence=combined_evidence,
            technique_ids=req.technique_ids,
            cve_ids=req.cve_ids,
            malware_dna=dna_str,
            threat_memory=mem_str,
            global_threat_intel=gti_str,
        )


        # 2. Hybrid Retriever
        retriever = HybridRetriever(db_session=db)
        retrieved_items = retriever.retrieve(query=query, top_k=req.top_k or DEFAULT_TOP_K)

        formatted_results = [_format_result_item(item) for item in retrieved_items]

        return RAGRetrieveResponse(
            question=query.user_question,
            query_techniques=query.technique_ids,
            query_cves=query.cve_ids,
            retrieved_count=len(formatted_results),
            results=formatted_results,
        )
    except HTTPException:
        raise
    except Exception as ex:
        logger.error(f"Error during RAG retrieval: {ex}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during knowledge retrieval."
        )


@router.post("/ask", response_model=RAGAskResponse)
def ask_grounded_question(
    req: RAGAskRequest,
    db: Session = Depends(get_db)
):
    """
    Run Grounded RAG Question Execution:
    Request -> QueryBuilder -> HybridRetriever -> ContextBuilder -> LLMProvider -> GroundingService -> Response.
    """
    _check_rag_enabled()

    if not req.question.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Question string cannot be empty or whitespace only."
        )

    try:
        combined_evidence = (req.apk_evidence or []) + (req.mitre_analysis or [])
        dna_str = "; ".join(req.malware_dna_context) if req.malware_dna_context else None
        mem_str = "; ".join(req.threat_memory_context) if req.threat_memory_context else None
        gti_str = "; ".join(req.global_ti_context) if req.global_ti_context else None

        # 1. Query Builder
        q_builder = RAGQueryBuilder()
        query = q_builder.build_query(
            question=req.question,
            apk_evidence=combined_evidence,
            technique_ids=req.technique_ids,
            cve_ids=req.cve_ids,
            malware_dna=dna_str,
            threat_memory=mem_str,
            global_threat_intel=gti_str,
        )


        # 2. Hybrid Retriever
        retriever = HybridRetriever(db_session=db)
        retrieved_items = retriever.retrieve(query=query, top_k=req.top_k or DEFAULT_TOP_K)

        # 3. Context Builder
        c_builder = RAGContextBuilder()
        context = c_builder.build_context(query=query, retrieved_results=retrieved_items)

        # 4. LLM Generation
        llm = get_llm_provider()
        llm_response = llm.generate(context)

        # 5. Grounding Validation Service
        validator = GroundingValidationService()
        grounded_res = validator.validate_grounding(context=context, llm_response=llm_response)

        formatted_provenance = [_format_result_item(item) for item in retrieved_items]

        # 6. Log Query to RagQueryLog safely
        chunk_ids = [item.chunk_id for item in retrieved_items]
        _safe_log_query(
            db=db,
            question=req.question,
            apk_id=req.apk_id,
            retrieved_chunk_ids=chunk_ids,
            grounding_state=grounded_res.grounding_state,
            provider=llm_response.provider,
            latency_ms=llm_response.latency_ms,
        )

        grounding_detail = GroundingDetailSchema(
            state=grounded_res.grounding_state,
            supported_claims=grounded_res.grounding_result.supported_claims,
            unsupported_claims=grounded_res.grounding_result.unsupported_claims,
            warnings=grounded_res.grounding_result.warnings,
            evidence_references=grounded_res.grounding_result.evidence_references,
        )

        return RAGAskResponse(
            answer=grounded_res.answer,
            grounding=grounding_detail,
            provenance=formatted_provenance,
            provider=grounded_res.provider,
            model=grounded_res.model,
            latency_ms=grounded_res.latency_ms,
        )

    except HTTPException:
        raise
    except Exception as ex:
        logger.error(f"Error during RAG ask execution: {ex}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during RAG question processing."
        )

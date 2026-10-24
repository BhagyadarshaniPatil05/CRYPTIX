"""
Phase 3.5.4 — Hybrid Retriever Module.
Combines Exact Identifier Matching, Lexical Keyword Search, Semantic Vector Search,
Source Trust Weighting, and Freshness Signals into an explainable ranking score.
"""

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import List, Optional, Dict, Any, Set
import numpy as np
from sqlalchemy.orm import Session

from app.models.rag import RagDocument, RagChunk
from app.rag.config import (
    TrustLevel,
    EXACT_ID_MATCH_WEIGHT,
    SEMANTIC_RELEVANCE_WEIGHT,
    LEXICAL_MATCH_WEIGHT,
    SOURCE_TRUST_WEIGHT,
    FRESHNESS_WEIGHT,
    TRUST_LEVEL_MULTIPLIERS,
    DEFAULT_TOP_K,
    MAX_TOP_K,
)
from app.rag.embeddings import (
    BaseEmbeddingProvider,
    SentenceTransformerEmbeddingProvider,
    TFIDFEmbeddingProvider,
    get_embedding_provider,
)
from app.rag.vector_store import (
    BaseVectorStore,
    SQLiteVectorStore,
    VectorRecord,
    VectorSearchResult,
    get_vector_store,
)
from app.rag.query_builder import StructuredRetrievalQuery


@dataclass
class RetrievalResultItem:
    document_id: int
    chunk_id: int
    content: str
    title: str
    source: str
    source_type: str
    source_version: str
    trust_level: str
    publisher: Optional[str] = None
    url: Optional[str] = None
    section_title: Optional[str] = None
    technique_id: Optional[str] = None
    cve_id: Optional[str] = None

    exact_id_score: float = 0.0
    semantic_score: float = 0.0
    lexical_score: float = 0.0
    trust_score: float = 0.0
    freshness_score: float = 0.0
    final_score: float = 0.0

    retrieval_reasons: List[str] = field(default_factory=list)


class HybridRetriever:
    """
    Hybrid Retrieval Engine combining:
    1. Exact Identifier Matching (technique_id, cve_id)
    2. Lexical Keyword Matching (TF-IDF / token overlap)
    3. Semantic Vector Search (SentenceTransformer if available)
    4. Source Trust & Freshness Score Weighting

    Produces explainable, deterministic, ranked top-K retrieval result items.
    """

    def __init__(
        self,
        db_session: Session,
        vector_store: Optional[BaseVectorStore] = None,
        embedding_provider: Optional[BaseEmbeddingProvider] = None,
    ):
        self.db = db_session
        self.vector_store = vector_store or SQLiteVectorStore(db_session=db_session)
        self.embedding_provider = embedding_provider or TFIDFEmbeddingProvider()

    def _compute_freshness_score(self, doc: RagDocument) -> float:
        """Compute freshness score (0.0 to 1.0) based on document verification timestamp."""
        ref_dt = doc.last_verified or doc.published_at or doc.collection_timestamp
        if not ref_dt:
            return 0.70  # Neutral fallback

        age_days = (datetime.utcnow() - ref_dt).days
        if age_days <= 30:
            return 1.0
        elif age_days <= 180:
            return 0.90
        elif age_days <= 365:
            return 0.80
        elif age_days <= 730:
            return 0.70
        else:
            return 0.50

    def _compute_lexical_score(self, query: StructuredRetrievalQuery, chunk_content: str, section_title: Optional[str]) -> float:
        """Compute keyword token overlap ratio (0.0 to 1.0) between query and chunk content."""
        if not query.keywords:
            return 0.0

        full_chunk_text = f"{section_title or ''} {chunk_content}".lower()
        chunk_tokens = set(full_chunk_text.split())
        if not chunk_tokens:
            return 0.0

        matched_count = sum(1 for kw in query.keywords if kw.lower() in full_chunk_text)
        return min(1.0, float(matched_count) / float(len(query.keywords)))

    def retrieve(
        self,
        query: StructuredRetrievalQuery,
        top_k: int = DEFAULT_TOP_K
    ) -> List[RetrievalResultItem]:
        """
        Execute hybrid retrieval pipeline and return ranked top_k RetrievalResultItem records.
        """
        if not query or (not query.user_question and not query.technique_ids and not query.cve_ids and not query.keywords):
            return []

        effective_top_k = min(max(1, top_k), MAX_TOP_K)
        all_chunks = self.db.query(RagChunk).all()
        if not all_chunks:
            return []

        # Map chunks by ID
        chunk_map: Dict[int, RagChunk] = {c.id: c for c in all_chunks}
        candidate_scores: Dict[int, Dict[str, Any]] = {}

        # ---------------------------------------------------------------
        # PASS 1: Exact Identifier Matching (technique_id, cve_id)
        # ---------------------------------------------------------------
        query_techs = set(t.upper() for t in query.technique_ids)
        query_cves = set(c.upper() for c in query.cve_ids)

        for chunk_id, chunk in chunk_map.items():
            candidate_scores[chunk_id] = {
                "exact_id_score": 0.0,
                "semantic_score": 0.0,
                "lexical_score": 0.0,
                "reasons": [],
            }

            tech_match = chunk.technique_id and chunk.technique_id.upper() in query_techs
            cve_match = chunk.cve_id and chunk.cve_id.upper() in query_cves

            if tech_match or cve_match:
                candidate_scores[chunk_id]["exact_id_score"] = 1.0
                if tech_match:
                    candidate_scores[chunk_id]["reasons"].append(f"Exact technique_id match ({chunk.technique_id})")
                if cve_match:
                    candidate_scores[chunk_id]["reasons"].append(f"Exact cve_id match ({chunk.cve_id})")

        # ---------------------------------------------------------------
        # PASS 2: Lexical Keyword Search
        # ---------------------------------------------------------------
        for chunk_id, chunk in chunk_map.items():
            lex_score = self._compute_lexical_score(query, chunk.content, chunk.section_title)
            if lex_score > 0.0:
                candidate_scores[chunk_id]["lexical_score"] = max(candidate_scores[chunk_id]["lexical_score"], lex_score)
                if lex_score >= 0.20:
                    candidate_scores[chunk_id]["reasons"].append(f"Lexical keyword match (score: {lex_score:.2f})")

        # ---------------------------------------------------------------
        # PASS 3: Semantic Vector Search
        # ---------------------------------------------------------------
        is_semantic_provider = isinstance(self.embedding_provider, SentenceTransformerEmbeddingProvider) and self.embedding_provider.is_available

        if query.raw_context_text or query.user_question:
            search_text = query.raw_context_text or query.user_question
            q_emb = self.embedding_provider.embed_text(search_text)

            # Perform vector similarity search
            vector_results = self.vector_store.search(query_embedding=q_emb, top_k=len(all_chunks))
            for v_res in vector_results:
                if v_res.chunk_id in candidate_scores and v_res.similarity_score > 0.0:
                    if is_semantic_provider:
                        candidate_scores[v_res.chunk_id]["semantic_score"] = v_res.similarity_score
                        if v_res.similarity_score >= 0.25:
                            candidate_scores[v_res.chunk_id]["reasons"].append(
                                f"Semantic similarity match ({v_res.similarity_score:.2f})"
                            )
                    else:
                        # TF-IDF lexical provider: accumulate under lexical_score, NOT semantic
                        old_lex = candidate_scores[v_res.chunk_id]["lexical_score"]
                        candidate_scores[v_res.chunk_id]["lexical_score"] = max(old_lex, v_res.similarity_score)

        if not is_semantic_provider:
            # Explicit reason for semantic fallback
            for cid in candidate_scores:
                if candidate_scores[cid]["lexical_score"] > 0.0:
                    candidate_scores[cid]["reasons"].append("Semantic model unavailable; vectorized lexical fallback applied")

        # ---------------------------------------------------------------
        # PASS 4: Score Fusion, Trust & Freshness Signals
        # ---------------------------------------------------------------
        results: List[RetrievalResultItem] = []

        for chunk_id, scores in candidate_scores.items():
            chunk = chunk_map[chunk_id]
            doc = chunk.document
            if not doc:
                continue

            exact_s = scores["exact_id_score"]
            sem_s = scores["semantic_score"]
            lex_s = scores["lexical_score"]
            reasons = list(dict.fromkeys(scores["reasons"]))  # Deduplicate reasons preserving order

            # Relevance Safety Check: If chunk has zero relevance to query, skip it
            if exact_s == 0.0 and sem_s == 0.0 and lex_s == 0.0:
                continue

            # Compute trust & freshness scores
            t_level = doc.trust_level or TrustLevel.UNKNOWN.value
            trust_s = TRUST_LEVEL_MULTIPLIERS.get(t_level, 0.50)
            fresh_s = self._compute_freshness_score(doc)

            if trust_s >= 0.85:
                reasons.append(f"High-trust source ({doc.source_type} / {t_level})")

            # Final Score Calculation
            final_s = (
                (EXACT_ID_MATCH_WEIGHT * exact_s)
                + (SEMANTIC_RELEVANCE_WEIGHT * sem_s)
                + (LEXICAL_MATCH_WEIGHT * lex_s)
                + (SOURCE_TRUST_WEIGHT * trust_s)
                + (FRESHNESS_WEIGHT * fresh_s)
            )

            item = RetrievalResultItem(
                document_id=doc.id,
                chunk_id=chunk.id,
                content=chunk.content,
                title=doc.title,
                source=doc.source,
                source_type=doc.source_type,
                source_version=doc.source_version or "15.1",
                trust_level=t_level,
                publisher=doc.publisher,
                url=doc.url,
                section_title=chunk.section_title,
                technique_id=chunk.technique_id or doc.technique_id,
                cve_id=chunk.cve_id or doc.cve_id,
                exact_id_score=round(exact_s, 4),
                semantic_score=round(sem_s, 4),
                lexical_score=round(lex_s, 4),
                trust_score=round(trust_s, 4),
                freshness_score=round(fresh_s, 4),
                final_score=round(final_s, 4),
                retrieval_reasons=reasons,
            )
            results.append(item)

        # Sort descending by final_score
        results.sort(key=lambda r: r.final_score, reverse=True)
        return results[:effective_top_k]

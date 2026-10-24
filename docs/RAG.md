# Cybersecurity RAG Engine Architecture (GARUD-AI / CRYPTIX)

## Overview

The Cybersecurity Retrieval-Augmented Generation (RAG) system provides evidence-grounded domain knowledge for Android APK threat investigations.

```
                              Cybersecurity Knowledge Sources
                               (MITRE Mobile, CVE, CISA, Vendor)
                                              │
                                              ▼
                                    Document Ingestion
                                              │
                                              ▼
                                   Cybersecurity Chunker
                                  (Section-Aware Boundaries)
                                              │
                                              ▼
                                   Embedding Provider
                          (SentenceTransformers / TF-IDF Vector)
                                              │
                                              ▼
                                     Vector Store
                             (SQLite / In-Memory Index)
                                              │
APK Evidence ─────────────────────────────────┤
(Static, MITRE, DNA, Intel)                   ▼
                                     APK Query Builder
                                              │
                                              ▼
                                     Hybrid Retriever
                          (Exact ID + Semantic Cosine + Trust)
                                              │
                                              ▼
                                   Labeled Context Builder
                                              │
                                              ▼
                                    Grounded LLM Provider
                                  (Mock / OpenAI-Compatible)
                                              │
                                              ▼
                                   Cited Response & Source UI
```

---

## Core Guarantees & Principles

1. **RAG provides KNOWLEDGE. Static analysis provides EVIDENCE.**
2. **RAG is optional and non-blocking**: The core APK analysis pipeline operates cleanly regardless of whether RAG is enabled, offline, keyless, or errored.
3. **Static findings are capabilities, not confirmed runtime actions**: Findings are labeled as *"static capability"*, *"static evidence"*, *"candidate technique"*, or *"potential behavior"*.
4. **Primary Source of Truth**: GARUD-AI's deterministic engines remain the sole authority for sample-specific risk scoring and malware verdicts. RAG acts as an intelligence assistant that explains and contextualizes findings.

---

## Vector Store & Embedding Architecture (Sub-phase 3.5.2)

### 1. Embedding Provider Abstraction (`BaseEmbeddingProvider`)

* **Semantic Embedding Provider (`SentenceTransformerEmbeddingProvider`)**:
  - Uses `sentence-transformers` (`all-MiniLM-L6-v2`, 384 dimensions).
  - Uses **lazy model loading**: Models are not downloaded on application startup or during testing.
  - Fails gracefully if `sentence-transformers` is missing or model loading fails.

* **Lexical Keyword Fallback (`TFIDFEmbeddingProvider`)**:
  - Provides a **Lexical Keyword Vector Representation** using term frequency - inverse document frequency over ingested text.
  - **IMPORTANT**: Classified strictly as a lexical fallback, NOT a semantic model.
  - Operates 100% offline using `numpy` without internet access or external API keys.

* **Factory (`get_embedding_provider`)**: Instantiates the configured provider based on `RAG_EMBEDDING_PROVIDER` settings.

### 2. Vector Store Abstraction (`BaseVectorStore`)

* **Local MVP Implementation (`SQLiteVectorStore`)**:
  - Stores float vector arrays as JSON strings in `RagChunk.embedding_json`.
  - Calculates cosine similarity dynamically using `numpy` dot products and L2 norms.
  - Ranks results descending by similarity score and returns top-K records matching optional metadata filters.
  - Handles zero vectors, empty stores, and vector dimension mismatches safely.

* **Future Extension Path**: The `BaseVectorStore` interface (`add`, `add_many`, `search`, `delete`, `count`, `clear`) allows pluggable replacement with production databases like **FAISS** or **pgvector** without modifying the RAG service layer.

---

## Document Ingestion & Cybersecurity Chunker Architecture (Sub-phase 3.5.3)

### 1. Document Loader & Normalization (`MitreMobileLoader`, `normalize_document_content`)
- **Pinned Knowledge Versioning**: Ingests official MITRE ATT&CK Mobile v15.1 catalog (`source_version="15.1"`), strictly pinned for reproducibility. Rejects unpinned or newer unverified MITRE data.
- **Content Normalization**: Normalizes whitespace, unifies line endings, and preserves technical identifiers (`T1407.001`, `CVE-2024-XXXX`, `DexClassLoader`, official URLs).
- **Deterministic SHA-256 Hashing**: Computes SHA-256 `content_hash` over `source_type:identifier:normalized_content` to prevent duplicate ingestion. Distinct from APK file SHA-256 hashes.

### 2. Section-Aware Cybersecurity Chunker (`CybersecurityChunker`)
- **Logical Section Boundaries**: Preserves cybersecurity headings (`Overview`, `Description`, `Detection`, `Procedure Examples`, `Mitigations`).
- **Configurable Chunk Sizing**: Target max chunk size defaults to 1500 characters (~300 words). Splits long sections cleanly at paragraph/sentence boundaries without breaking technical IDs.
- **Provenance Preservation**: Each `RagChunk` maintains `document_id`, `chunk_index`, `section_title`, `technique_id`, `cve_id`, and parent `RagDocument` provenance.

### 3. Database Persistence & Decoupling (`ingest_cybersecurity_documents`)
- **Deduplication**: Checks database for matching `content_hash` before insertion; skips duplicates cleanly.
- **Decoupled Embedding Pipeline**: `RagChunk.embedding_json` remains `NULL` during document ingestion, allowing document storage to remain strictly independent from vector indexing and re-embedding.

---

## Current MITRE Knowledge Coverage & Architectural Scope

> **IMPORTANT SCOPE NOTICE**:
> - **Pinned Version**: MITRE ATT&CK Mobile is strictly pinned to **v15.1**.
> - **Initial Seed Dataset**: Current RAG seed data is loaded from the audited Phase 3.4.1 catalog, containing **11 validated techniques** (`T1406`, `T1412`, `T1420`, `T1426`, `T1430`, `T1432`, `T1437`, `T1437.001`, `T1409`, `T1624`, `T1626`).
> - **Not the Complete Matrix**: This dataset is an initial seed and is **NOT** claimed to represent the entire Mobile ATT&CK v15.1 matrix.
> - **Future Full Corpus Ingestion**: A future ingestion task can import the full Mobile ATT&CK matrix (~100+ techniques). Any future dataset must be versioned (`source_version="15.1"`) and audited prior to ingestion.

### Architectural Separation: Mapping Rules vs. RAG Knowledge

```
Phase 3.4.1 (Static Mapping Engine):
Static Evidence (DEX/Manifest) ──► Mapping Rules ──► Sample-Specific ATT&CK Candidates

Phase 3.5 (Cybersecurity RAG Engine):
Domain Knowledge (MITRE v15.1) ──► RagDocument/RagChunk ──► External Knowledge Context
```

- **MITRE Mapping Output** represents sample-specific evidence and static candidate capabilities.
- **MITRE RAG Knowledge Documents** represent external domain knowledge used to explain and contextualize evidence.
- The two systems are strictly decoupled and do not overwrite each other.

---

## Query Builder & Hybrid Retriever Architecture (Sub-phase 3.5.4)

### 1. APK-Aware Query Builder (`RAGQueryBuilder`, `StructuredRetrievalQuery`)
- **Structured Extraction**: Extracts MITRE technique IDs (`T1412`, `T1437.001`), CVE IDs (`CVE-2024-1234`), and normalized cybersecurity keywords from user input and APK evidence.
- **Static Evidence Boundary**: Formats static findings strictly using capability language (*"Static DEX finding"*, *"Static permission grant"*) to prevent converting static indicators into unconfirmed runtime actions.

### 2. Explainable Hybrid Retriever (`HybridRetriever`, `RetrievalResultItem`)
- **Pass 1: Exact Identifier Match**: Strongly prioritizes exact `technique_id` or `cve_id` matches (`exact_id_score = 1.0`).
- **Pass 2: Lexical Keyword Match**: Computes token overlap ratio between query keywords and chunk text (`lexical_score`).
- **Pass 3: Semantic Vector Match**: Computes vector cosine similarity when `SentenceTransformer` is available. If provider is `TFIDF`, assigns score under `lexical_score` and logs fallback reason.
- **Pass 4: Source Trust & Freshness Signals**: Weights source authority (`AUTHORITATIVE` = 1.0, `TRUSTED_VENDOR` = 0.85, `RESEARCH` = 0.70) and verification age decay.

### 3. Explainable Ranking Formula
$$\text{Score} = (0.35 \times \text{ExactID}) + (0.35 \times \text{Semantic}) + (0.15 \times \text{Lexical}) + (0.10 \times \text{Trust}) + (0.05 \times \text{Freshness})$$

> **RELEVANCE SAFETY RULE**: Trust score never overrides zero relevance. If exact, semantic, and lexical scores are all zero, the chunk is excluded.

### 4. Retrieval Confidence vs. Answer Grounding Separation
- Retrieval returns `retrieval_reasons` (e.g. `"Exact technique_id match (T1412)"`, `"High-trust source (MITRE / AUTHORITATIVE)"`).
- Explicit grounding states (`SUPPORTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`) are calculated by the GroundingValidationService.

---

## Context Builder & Grounded LLM Layer Architecture (Sub-phase 3.5.5)

### 1. Security-Bounded Context Builder (`RAGContextBuilder`, `GroundedContext`)
- **Labeled Section Boundaries**: Constructs context prompts with explicit dividers:
  - `=== SYSTEM INSTRUCTIONS ===`
  - `=== USER QUESTION ===`
  - `=== APK EVIDENCE ===`
  - `=== MITRE ANALYSIS ===`
  - `=== MALWARE DNA ===`
  - `=== THREAT MEMORY ===`
  - `=== GLOBAL THREAT INTELLIGENCE ===`
  - `=== RETRIEVED CYBERSECURITY KNOWLEDGE ===`
- **Prompt Injection Defense**: Instructs the LLM that data within `=== APK EVIDENCE ===` and `=== RETRIEVED CYBERSECURITY KNOWLEDGE ===` represents untrusted DATA, not instructions. Prompt injection attempts like `"ignore previous instructions"` are ignored.
- **Static Analysis Boundary**: Formats static findings strictly using capability language (*"Static DEX finding"*, *"Static permission grant"*) to prevent converting static capabilities into confirmed runtime execution claims.
- **Provenance Transparency**: Every retrieved chunk includes full provenance metadata (`Source`, `Version`, `Technique`, `CVE`, `Trust Level`, `Retrieval Score`, `Retrieval Reasons`).

### 2. Pluggable LLM Provider Abstraction (`BaseLLMProvider`, `MockLLMProvider`, `OpenAILikeLLMProvider`)
- **Offline / Keyless Mode**: `MockLLMProvider` operates 100% offline without network calls or API keys, producing conservative, evidence-grounded summary responses incorporating citations and capability notices.
- **HTTP API Integration**: `OpenAILikeLLMProvider` uses `httpx` for OpenAI / Gemini / Ollama compatible endpoints. Falls back safely if API keys are unconfigured or request fails.

### 3. Deterministic Grounding Validation Service (`GroundingValidationService`, `GroundedResponse`)
- **Grounding States**:
  - `SUPPORTED`: Response claims are directly supported by context evidence and retrieved knowledge.
  - `PARTIALLY_SUPPORTED`: Answer contains cautious inference or relies solely on static evidence without domain knowledge retrieval.
  - `INSUFFICIENT_EVIDENCE`: Evidence or retrieved knowledge is absent or insufficient to answer.
- **Deterministic Consistency Checks**:
  1. Detects static capability -> confirmed runtime execution overstatements.
  2. Detects absolute malware verdicts unsupported by the deterministic risk engine.
  3. Detects unsupported technique IDs or CVE identifiers not present in context.
  4. Verifies citation and provenance references.

> **PRIMARY RISK ENGINE PROTECTION**: Grounding states measure factual support of AI explanations. Grounding states do NOT alter or overwrite deterministic risk scores, MITRE mapping candidate rules, or malware verdicts.

---

## Cybersecurity RAG REST API Specification (Sub-phase 3.5.6)

### Endpoints Overview

| Method | Endpoint | Purpose | Scope / Behavior |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/rag/health` | RAG System Health & Provider Status | Callable even when RAG is disabled (`status="disabled"`). Never leaks secrets/API keys. |
| `POST` | `/api/v1/rag/retrieve` | Knowledge Retrieval without LLM | Runs Query Builder + Hybrid Retriever. Returns scored chunks with full provenance details. Rejects unknown request fields (`extra="forbid"`). |
| `POST` | `/api/v1/rag/ask` | Grounded Cybersecurity Inquiry | Runs full pipeline: Request $\rightarrow$ QueryBuilder $\rightarrow$ HybridRetriever $\rightarrow$ ContextBuilder $\rightarrow$ LLMProvider $\rightarrow$ GroundingService $\rightarrow$ Response. Logs query safely to `RagQueryLog`. |

### Security & Input Validation Controls

1. **Pydantic Model Strictness (`extra="forbid"`)**:
   - `RAGRetrieveRequest` and `RAGAskRequest` configure `extra = "forbid"` via Pydantic v2 `ConfigDict`.
   - Attempts to pass override or risk fields (`risk_score`, `override_verdict`, `malware_verdict`, `classification`) are rejected immediately with **HTTP 422 Unprocessable Entity**.

2. **Secret Safety**:
   - `GET /api/v1/rag/health` reports provider status, vector store type, embedding provider, and safe `llm_configured: bool`.
   - API keys are **never** returned in API responses or logged in files.

3. **Query Logging Resilience (`RagQueryLog`)**:
   - `POST /api/v1/rag/ask` logs questions, chunk IDs, grounding states, providers, and latency to `RagQueryLog`.
   - Logging logic is wrapped in an isolated exception handler so database logging errors will **never** cause the primary RAG response to fail.

4. **RAG Disabled Mode Handling**:
   - `GET /api/v1/rag/health` remains accessible when `RAG_ENABLED=False`, returning `status="disabled"`, `rag_enabled=false`.
   - `POST /api/v1/rag/retrieve` and `POST /api/v1/rag/ask` return **HTTP 503 Service Unavailable** when `RAG_ENABLED=False`.

5. **100% Offline Capability**:
   - When `RAG_LLM_PROVIDER=mock`, endpoints execute completely offline with zero external network dependencies or external API calls.






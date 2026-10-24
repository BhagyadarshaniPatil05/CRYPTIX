# GARUD-AI / CRYPTIX CYBERSECURITY RAG ARCHITECTURE
**Technical Specification & Subsystem Architecture Document**

---

## 1. Executive Problem Statement & Core Value Proposition

### A. The Cybersecurity Explanation Gap
In Android malware analysis and security operations centers (SOC), automated tools generate high volumes of raw static findings (e.g., extracted permissions, DEX bytecode API signatures, YARA rules, X.509 certificate metadata). However:
1. **Raw Findings Lack Explanation**: An analyst seeing `android.permission.RECEIVE_SMS` alongside `Landroid/telephony/SmsManager;->sendTextMessage` needs immediate domain explanation of the underlying attack technique (e.g., MITRE ATT&CK Mobile `T1412` - SMS Control) and recommended containment steps.
2. **Generic LLMs Fail in Specialized Security**: Standard public LLMs are prone to hallucinating non-existent CVEs or techniques, exposing internal secrets, or overstating static findings into unconfirmed runtime verdicts.
3. **Static Analysis Cannot Provide Context**: Static analyzer modules provide exact sample evidence, but cannot provide general threat intelligence context, ATT&CK framework mitigations, or explainable reasoning over domain knowledge.

### B. What RAG Solves in GARUD-AI
The **Cybersecurity RAG (Retrieval-Augmented Generation)** subsystem bridges raw static findings and domain intelligence by retrieving authoritative, section-aware cybersecurity knowledge chunks (pinned MITRE ATT&CK Mobile v15.1 seed dataset) and grounding LLM-generated explanations strictly within retrieved context.

RAG does **not** replace sample analysis; it serves as an **on-demand analyst intelligence assistant**.

---

## 2. Subsystem Architecture & End-to-End Flow

### Pipeline Sequence Diagram

```
Analyst Query / APK Findings
             │
             ▼
    ┌─────────────────┐
    │  Query Builder  │  ──► Extracts IDs (T1412, CVE-2024-XXXX), normalizes keywords
    └─────────────────┘
             │
             ▼
    ┌─────────────────┐
    │ HybridRetriever │  ──► 4-Pass Score Fusion (Exact ID, Semantic, Lexical, Trust, Freshness)
    └─────────────────┘
             │
             ▼
    ┌─────────────────┐
    │ Context Builder │  ──► Formats untrusted data, sets prompt boundaries & disclaimers
    └─────────────────┘
             │
             ▼
    ┌─────────────────┐
    │  LLM Provider   │  ──► Offline Mock / Keyless fallback or OpenAI-compatible API
    └─────────────────┘
             │
             ▼
    ┌─────────────────┐
    │GroundingService │  ──► Validates claim support, detects overstatements, assigns state
    └─────────────────┘
             │
             ▼
  Grounded Answer + Provenance
```

---

## 3. Subsystem Components Detail

### 1. Query Builder (`RAGQueryBuilder`)
* **Purpose**: Converts natural language analyst questions and sample static findings into a structured query (`StructuredRetrievalQuery`).
* **Key Logic**: Uses regex patterns to extract technique IDs (`T1412`, `T1437.001`) and CVE IDs (`CVE-2024-XXXX`). Formats static findings using candidate capability phrasing to prevent converting static evidence into confirmed runtime claims.

### 2. Document Loader (`MitreMobileLoader`)
* **Purpose**: Loads external cybersecurity documentation into normalized `CybersecurityDocument` records.
* **Key Logic**: Loads pinned MITRE ATT&CK Mobile v15.1 catalog data (`source_version="15.1"`), assigning explicit trust levels (`AUTHORITATIVE` for official MITRE docs). Computes deterministic SHA-256 content hashes (`source_type:identifier:normalized_content`) to prevent duplicate ingestion.

### 3. Cybersecurity Chunker (`CybersecurityChunker`)
* **Purpose**: Splits long cybersecurity documents into section-aware text chunks (`DocumentChunk`).
* **Key Logic**: Preserves logical headers (`Overview`, `Description`, `Detection`, `Procedure Examples`, `Mitigations`) and prevents breaking technical identifiers across chunk boundaries.

### 4. Embedding Provider (`BaseEmbeddingProvider`)
* **Purpose**: Generates vector representations of text chunks.
* **Providers**:
  - `TFIDFEmbeddingProvider`: CPU-friendly, 100% offline lexical vectorizer using `numpy` and regex tokenization. Serves as default zero-dependency fallback.
  - `SentenceTransformerEmbeddingProvider`: Dense semantic embedding provider (`sentence-transformers/all-MiniLM-L6-v2`) with lazy loading and graceful offline skipping when model weights are un-cached.

### 5. Vector Store (`SQLiteVectorStore`)
* **Purpose**: Local MVP vector database operating on SQLite `RagChunk.embedding_json` records.
* **Key Logic**: Computes dynamic `numpy` cosine similarity scores between query vectors and stored chunk embeddings, returning top-K ordered results.

### 6. Hybrid Retriever (`HybridRetriever`)
* **Purpose**: Executes 4-pass scoring over candidate knowledge chunks.
* **Passes**:
  1. Exact ID Matching (`exact_id_score = 1.0`)
  2. Lexical Keyword Overlap (`lexical_score`)
  3. Semantic Vector Cosine Search (`semantic_score`)
  4. Source Trust & Freshness Signals (`trust_score`, `freshness_score`)
* **Relevance Control**: Excludes zero-relevance chunks regardless of trust level.

### 7. Context Builder (`RAGContextBuilder`)
* **Purpose**: Assembles `GroundedContext` prompt text for LLM generation.
* **Key Logic**: Constructs labeled prompt sections (`=== SYSTEM INSTRUCTIONS ===`, `=== USER QUESTION ===`, `=== APK EVIDENCE ===`, `=== RETRIEVED CYBERSECURITY KNOWLEDGE ===`). Applies prompt-injection defense instructions stating retrieved items are untrusted DATA.

### 8. LLM Provider Abstraction (`BaseLLMProvider`)
* **Purpose**: Pluggable generation layer.
* **Implementations**:
  - `MockLLMProvider`: Keyless, 100% offline provider generating structured evidence summaries with explicit disclaimers.
  - `OpenAILikeLLMProvider`: HTTP API adapter using `httpx` with safe offline fallback when API keys are unconfigured.

### 9. Grounding Validation Service (`GroundingValidationService`)
* **Purpose**: Evaluates generated text against retrieved context chunks.
* **Key Logic**: Detects static capability overstatements, unsupported IDs, and assigns deterministic grounding states (`SUPPORTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`).

### 10. Query Logger (`RagQueryLog`)
* **Purpose**: Asynchronously logs analyst queries, retrieval metrics, and latency into `RagQueryLog`.
* **Key Logic**: Wrapped in `_safe_log_query` exception handling so logging failures never break primary API responses. Sanitizes all inputs to prevent storing secrets or raw binaries.

---

## 4. Distinction Between Garud-AI Subsystems

To maintain strict architectural clarity during research presentation and viva defense, the table below delineates the 8 core operational layers of Garud-AI:

| Component / Layer | Primary Role | Source of Truth / Scope | Modifiable by RAG? |
| :--- | :--- | :--- | :--- |
| **Cybersecurity RAG** | Explanatory cybersecurity context & domain Q&A | Pinned MITRE v15.1 seed dataset | N/A (RAG subsystem itself) |
| **Static Analysis** | Sample-specific static evidence extraction | Decompiled APK bytecode, Manifest, YARA | **NO** (Read-only input to RAG) |
| **MITRE Static Mapping** | Deterministic mapping of static findings to techniques | 19 audited Phase 3.4.1 rule catalog | **NO** (Read-only input to RAG) |
| **Global Threat Intel** | External reputation & threat pulse lookup | VirusTotal, AbuseIPDB, AlienVault OTX | **NO** (Read-only input to RAG) |
| **Malware DNA** | Structural & feature set similarity math | Weighted Jaccard index over 10 feature sets | **NO** (Read-only input to RAG) |
| **Threat Memory** | Corpus sample relationship & SHA-256 identity | Historical corpus database records | **NO** (Read-only input to RAG) |
| **Risk Engine** | **Deterministic source of truth for sample verdict** | Immutable weighted risk score engine | **NO (100% FROZEN & ISOLATED)** |
| **Digital Twin** | Security posture version control & drift tracking | Multi-version APK posture snapshots | **NO (100% FROZEN & ISOLATED)** |

> [!IMPORTANT]
> The deterministic **Risk Engine** is the sole source of truth for sample risk score (`risk_score`), risk level (`risk_level`), and malware verdict (`malware_verdict`). The RAG subsystem **cannot** modify or override risk engine verdicts under any circumstances.

---

## 5. Retrieval & Ranking Architecture

### Implemented Ranking Formula

Every retrieved chunk is assigned a scalar ranking score (bounded `[0.0, 1.0]`):

$$\text{Score} = 0.35 \times \text{Exact ID} + 0.35 \times \text{Semantic} + 0.15 \times \text{Lexical} + 0.10 \times \text{Trust} + 0.05 \times \text{Freshness}$$

* **Exact ID Match (`0.35`)**: Evaluates direct technique/CVE ID matches (`T1412`, `CVE-2024-XXXX`).
* **Semantic Score (`0.35`)**: Cosine similarity between query and chunk dense embeddings.
* **Lexical Score (`0.15`)**: Token overlap ratio (TF-IDF keyword matching).
* **Trust Level (`0.10`)**: Normalized score for document authority (`AUTHORITATIVE = 1.0`, `HIGH = 0.8`, `MEDIUM = 0.5`).
* **Freshness (`0.05`)**: Decay score based on document verification date.

### Core Ranking Controls

1. **Relevance Precedence over Trust**: Trust is a tie-breaker among relevant chunks. Zero-relevance items are excluded regardless of trust score.
2. **Lexical Fallback**: TF-IDF provides lexical keyword matching. It is **not** a semantic model and does not perform conceptual embedding.
3. **MVP Vector Storage**: SQLite vector storage uses in-memory/JSON cosine distance calculation, serving as local evaluation infrastructure rather than production scale vector databases (e.g. pgvector or FAISS).

---

## 6. Grounding States & Evidence Provenance

The Grounding Service evaluates LLM responses and assigns one of three explicit states:

1. **`SUPPORTED`**: All statements in the answer directly correspond to evidence chunks present in the retrieved context.
2. **`PARTIALLY_SUPPORTED`**: The response contains valid retrieved information but includes an overstatement (e.g., claiming static permission presence proves active runtime exploitation). A static boundary disclaimer is automatically appended.
3. **`INSUFFICIENT_EVIDENCE`**: The query references topics or identifiers absent from the RAG seed dataset. The system returns zero provenance chunks and refuses to hallucinate facts.

### Evidence Provenance Tracking
Every answer includes a `provenance` array containing chunk IDs, source document titles, technique IDs, trust levels, and exact retrieval scores, enabling total analyst auditability.

---

## 7. Security Boundaries & Risk Engine Independence

### Strict Non-Negotiable Boundaries

1. **Static Analysis Boundary**: Static analysis detects candidate capabilities and permissions. It does **not** prove confirmed runtime execution.
2. **Malware DNA Boundary**: Malware DNA Jaccard scores measure structural feature overlap. They do **not** prove malware lineage, author attribution, campaign origin, or repacking.
3. **MITRE Boundary**: The RAG subsystem rejects unsupported techniques rather than inventing explanations.
4. **Prompt Injection Safety**: Natural language inputs are treated as untrusted data (`=== USER QUESTION ===`). System instructions remain isolated. Prompt injection attempts cannot bypass grounding checks or expose API credentials.
5. **Risk Engine Independence**: Pre/post RAG inquiry snapshots confirm that RAG interactions leave `risk_score`, `risk_level`, `malware_verdict`, `classification`, `digital_twin_id`, and `version_number` **100% unmutated**.

---

## 8. Evaluation Summary & Dataset Scope

### Dataset Summary (`GOLDEN_QUERIES`)
* **10 Total Queries**: CAT-A (5 retrieval-positive), CAT-B (2 sample-context), CAT-C (1 negative/unsupported), CAT-D (2 adversarial/safety).

### Empirical Evaluation Metrics
* **Recall@3**: **100% (1.000)** on CAT-A queries
* **Hit@3**: **100% (1.000)** on CAT-A queries
* **MRR**: **1.000** on CAT-A queries
* **Grounding Accuracy**: **100% (3/3)** on controlled grounding scenarios
* **API Resilience (TEST A–J)**: 10/10 failure modes passed cleanly

> [!NOTE]
> These metrics reflect a controlled laboratory evaluation benchmark. They do **not** represent universal retrieval accuracy or production-wide security guarantees.

---

## 9. Dataset & Catalog Terminology

To avoid ambiguity, GARUD-AI technical documentation strictly distinguishes:

- **MITRE Static Mapping Catalog**: The 19 audited Phase 3.4.1 static analysis rules used to map decompiled APK findings to ATT&CK techniques.
- **MITRE RAG Seed Dataset**: The 11 audited Phase 3.4.1 MITRE ATT&CK Mobile v15.1 technique documents (`T1406`, `T1412`, `T1420`, `T1426`, `T1430`, `T1432`, `T1437`, `T1437.001`, `T1409`, `T1624`, `T1626`) ingested into the RAG vector store.

> [!IMPORTANT]
> The current RAG seed dataset contains **only** these 11 audited techniques and is **not** the complete MITRE ATT&CK Mobile v15.1 knowledge base (~100+ techniques).

---

## 10. Limitations & Realistic Future Work

### Limitations
1. Small benchmark dataset (10 queries).
2. Seed dataset limited to 11 MITRE ATT&CK Mobile v15.1 techniques.
3. SentenceTransformer dense search requires cached local model weights.
4. Offline TF-IDF vectorization is lexical, not semantic.
5. Local SQLite vector storage is MVP-scale.
6. Live external threat intelligence (VirusTotal, AbuseIPDB, OTX) is not benchmarked by this offline RAG test suite.

### Realistic Future Improvements
1. Full ingestion of the complete MITRE ATT&CK Mobile matrix (~100+ techniques).
2. Integration of NVD CVE feeds, CISA KEV catalogs, and Android Security Bulletins.
3. Migration of SQLite vector store to production vector databases (`pgvector` or `FAISS`).
4. Pre-caching SentenceTransformer model weights for offline dense vector search.
5. Expansion of evaluation dataset to 100+ golden queries with human expert verification.
6. Continuous evaluation pipelines and automated adversarial red-teaming.

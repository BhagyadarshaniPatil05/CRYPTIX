# Frontend AI Intelligence Workspace Specification (Sub-phase 3.5.7)

## Overview

The **Frontend AI Intelligence Workspace** provides an analyst-assisted interface within the **GARUD-AI / CRYPTIX** APK Investigation workspace (`/apks/:id`).

> **CORE PRINCIPLE**: RAG provides cybersecurity knowledge and grounded explanations. It does NOT replace the deterministic risk engine and does NOT independently determine malware classification.

---

## User Workflow

```
Open APK Investigation Workspace (/apks/:id)
                │
                ▼
Select "AI INTELLIGENCE" Tab
                │
                ▼
Review RAG Health & Service Status Bar
                │
                ▼
Select Suggested Prompt Chip or Enter Custom Cybersecurity Question
                │
                ▼
Click "Submit Inquiry" (On-Demand Execution)
                │
                ▼
   POST /api/v1/rag/ask (Axios API Client)
                │
                ▼
┌─────────────────────────────────────────────────────────┐
│ Grounded AI Assessment Panel                            │
│ ├─ Grounding Badge (SUPPORTED / PARTIAL / INSUFFICIENT) │
│ ├─ Answer Prose with Static Boundary Notice             │
│ ├─ Supported Claims List                                │
│ ├─ Unsupported Claims & Warnings Alerts                 │
│ └─ Evidence References Tags                             │
├─────────────────────────────────────────────────────────┤
│ Retrieved Cybersecurity Knowledge Provenance            │
│ ├─ Expandable Source Cards (MITRE v15.1, CVE, NVD)      │
│ ├─ Score Breakdown (Relevance, Exact ID, Semantic, etc) │
│ ├─ Retrieval Reason Badges                              │
│ └─ Official Documentation Link                          │
└─────────────────────────────────────────────────────────┘
```

---

## API Client Integration (`src/api/api.js`)

The AI Intelligence Workspace consumes the existing RAG REST APIs implemented in Sub-phase 3.5.6 using the central `axios` instance (`api`):

1. **`getRAGHealth()`** $\rightarrow$ `GET /api/v1/rag/health`:
   - Checks vector store type, embedding provider, LLM provider, and model.
   - Displays real-time operational status (`Operational`, `Disabled`, or `Unavailable`).
   - Never exposes API keys or secrets.

2. **`retrieveRAGKnowledge(payload)`** $\rightarrow$ `POST /api/v1/rag/retrieve`:
   - Executes query building and hybrid retrieval over the vector store without invoking an LLM.

3. **`askRAGQuestion(payload)`** $\rightarrow$ `POST /api/v1/rag/ask`:
   - Sends analyst question and extracted APK context (`technique_ids`, `apk_evidence`, `top_k`).
   - Returns grounded answer, grounding state, claims, warnings, and provenance chunks.

---

## Security & Input Validation Controls

1. **Strict Request Payload Contract**:
   - The frontend sends strictly: `question`, `apk_id`, `technique_ids`, `cve_ids`, `apk_evidence`, `mitre_analysis`, `malware_dna_context`, `threat_memory_context`, `global_ti_context`, and `top_k`.
   - The frontend **NEVER** sends `risk_score`, `override_verdict`, `malware_verdict`, or `classification`.
   - Adheres to the backend's `extra="forbid"` Pydantic model configuration.

2. **No Secret Exposure**:
   - No API keys or credentials exist in frontend source code, environment variables, or `localStorage`.

3. **Grounding State vs Malware Verdict**:
   - Grounding state (`SUPPORTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`) measures the factual consistency of AI explanations against retrieved context evidence.
   - Grounding state is presented neutrally and is **NEVER** displayed as a malware verdict or risk level.

4. **Retrieval Score Semantics**:
   - Retrieval scores ($0.35 \times \text{ID Match} + 0.35 \times \text{Semantic} + 0.15 \times \text{Lexical} + 0.10 \times \text{Trust} + 0.05 \times \text{Freshness}$) are internal ranking signals used to rank retrieved chunks.
   - Retrieval scores are **NEVER** presented as malware probabilities or classification confidence.

5. **Malware DNA Structural Similarity Semantics**:
   - Malware DNA similarity uses structural feature vector similarity math (weighted Jaccard index) to identify shared structural features.
   - Malware DNA similarity **NEVER** establishes definitive malware lineage, repacked sample ancestry, authorship, or origin.

6. **MITRE Knowledge Base Scope**:
   - Current MITRE RAG knowledge is based on the audited Phase 3.4.1 Mobile ATT&CK v15.1 seed techniques.
   - It represents seed knowledge for local RAG evaluation and is **NOT** the complete MITRE ATT&CK Mobile v15.1 knowledge base.

7. **Static Analysis Boundary Notice**:
   - Prominently displays notice: *"Static analysis identifies candidate capabilities, permissions, and indicators. Runtime execution was not independently established."*

8. **On-Demand Execution Only**:
   - RAG requests are triggered strictly when the analyst explicitly submits a question or clicks a prompt chip.
   - RAG is never automatically executed on page load or during core APK upload analysis.

9. **APK Evidence vs External Knowledge Separation**:
   - APK-specific evidence (DEX findings, permission grants) is clearly separated from external domain knowledge (MITRE ATT&CK Mobile v15.1 docs, NVD CVE records).


# GARUD-AI / CRYPTIX RAG PRESENTATION TALKING POINTS
**Concise Slide-Ready Bullets for Project Presentations & Defense Slides**

---

## Slide 1: The Cybersecurity Explanation Problem
* **Static Evidence vs. Analyst Interpretation**: Raw findings (permissions, DEX bytecode calls, YARA rules) lack domain context.
* **LLM Risks in Security**: Generic LLMs hallucinate non-existent CVEs, overstate static evidence, and lack verifiable audit trails.
* **Garud-AI Solution**: Grounded RAG subsystem linking static findings to authoritative MITRE ATT&CK Mobile v15.1 knowledge.

---

## Slide 2: RAG Subsystem Architecture
* **Multi-Stage Pipeline**: Query Builder $\rightarrow$ Hybrid Retriever $\rightarrow$ Context Builder $\rightarrow$ LLM Provider $\rightarrow$ Grounding Validation.
* **Offline Execution**: 100% keyless `MockLLMProvider` fallback and offline TF-IDF vectorization for local evaluation.
* **Evidence Provenance**: Returns exact chunk IDs, source titles, technique IDs, and retrieval scores for every answer.

---

## Slide 3: Hybrid Retrieval & 5-Factor Ranking Formula
* **4-Pass Scoring Pipeline**: Exact ID Match + Lexical Keyword Overlap + Dense Vector Cosine Similarity + Trust/Freshness.
* **Weighted Ranking Formula**:
  $$\text{Score} = 0.35 \times \text{Exact ID} + 0.35 \times \text{Semantic} + 0.15 \times \text{Lexical} + 0.10 \times \text{Trust} + 0.05 \times \text{Freshness}$$
* **Relevance Control**: Exact technique ID matches outrank generic high-trust docs; zero-relevance chunks are excluded.

---

## Slide 4: Grounding Validation & Safety Boundaries
* **Deterministic Grounding States**: `SUPPORTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`.
* **Static Capability Boundary**: Enforces disclaimer that static permissions/findings do not prove active runtime execution.
* **Malware DNA Boundary**: Clarifies Jaccard score represents structural similarity, not proven malware lineage.

---

## Slide 5: Security Boundaries & Risk Independence
* **Prompt Injection Defense**: Separates untrusted user queries (`=== USER QUESTION ===`) from system instructions.
* **Deterministic Risk Engine Isolation**: RAG interactions leave `risk_score`, `risk_level`, and `malware_verdict` **100% unmutated**.
* **Risk Engine Sovereignty**: The deterministic Risk Engine remains the sole source of truth for sample verdicts.

---

## Slide 6: Evaluation Benchmark & Methodology
* **Structured Evaluation Dataset**: 10 `GOLDEN_QUERIES` across CAT-A (retrieval), CAT-B (context), CAT-C (negative), and CAT-D (safety).
* **Audited Seed Catalog**: 11 Phase 3.4.1 MITRE ATT&CK Mobile v15.1 technique documents.
* **Resilience Suite**: 10 API failure and edge-case scenarios evaluated (TEST A through TEST J).

---

## Slide 7: Empirical Results
* **Retrieval Performance**: **Recall@3 = 100%**, **Hit@3 = 100%**, **MRR = 1.000** on CAT-A queries.
* **Grounding Accuracy**: **100% (3/3)** on controlled grounding scenarios.
* **Test Suite Verification**: RAG Evaluation Suite: **25 PASSED**, **1 SKIPPED** (26 total); Full Backend: **167 PASSED**, **1 SKIPPED** (168 total).

---

## Slide 8: Limitations & Controlled Scope
* **Controlled Benchmark**: Metrics reflect the 10-query benchmark dataset, not universal security guarantees.
* **Seed Catalog Scope**: Restricted to 11 audited MITRE Mobile v15.1 techniques (not the complete ~100+ ATT&CK Mobile matrix).
* **MVP Vector Store**: SQLite vector storage designed for local offline evaluation.

---

## Slide 9: Future Engineering Roadmap
* **Full ATT&CK Ingestion**: Expand vector store to the complete MITRE ATT&CK Mobile knowledge base.
* **Richer Data Sources**: Integrate NVD CVE feeds, CISA KEV catalogs, and Android Security Bulletins.
* **Production Vector Infrastructure**: Migrate SQLite vector store to `pgvector` or `FAISS` for enterprise scaling.
* **Automated Red-Teaming**: Expand continuous evaluation dataset to 100+ benchmark queries.

# GARUD-AI / CRYPTIX CYBERSECURITY RAG VIVA Q&A
**Comprehensive Oral Examination & Defense Guide**

---

### Q1: What is Retrieval-Augmented Generation (RAG)?
**Answer:** RAG is an AI architecture that combines an information retrieval system with a generative Language Model (LLM). Instead of relying solely on an LLM's static training memory, RAG first fetches relevant external documents from a database based on the user's query, inserts those documents into the LLM's prompt context, and instructs the LLM to generate an answer grounded strictly in that retrieved evidence.

---

### Q2: Why did you use RAG in GARUD-AI?
**Answer:** In malware analysis, raw static analysis outputs (such as extracted permissions or DEX bytecode API calls) lack domain explanation. Standard LLMs can hallucinate non-existent CVEs or techniques. RAG allows GARUD-AI to dynamically retrieve authoritative cybersecurity knowledge (such as MITRE ATT&CK Mobile technique documentation) and present grounded, explainable threat context to analysts without risking hallucinated information.

---

### Q3: Why not rely only on a standard pre-trained LLM?
**Answer:** Standard LLMs suffer from three main limitations in cybersecurity:
1. **Hallucination**: They may invent non-existent CVE numbers, attack vectors, or mitigations.
2. **Knowledge Cutoffs**: They cannot dynamically access updated internal threat catalogs or specific sample evidence.
3. **Lack of Auditability**: Standard LLM outputs do not provide verifiable source citations or provenance traces for security auditing.

---

### Q4: What is a Vector Store?
**Answer:** A vector store is a specialized database designed to store, index, and query high-dimensional mathematical vector representations (embeddings) of text chunks. It allows the system to perform fast similarity searches (such as cosine distance) to find text chunks that are conceptually similar to an analyst's query.

---

### Q5: What is an Embedding?
**Answer:** An embedding is a numerical vector (a list of floating-point numbers) that represents the semantic or lexical meaning of a piece of text in a high-dimensional space. Texts with similar meanings or shared keywords have embeddings that sit close to each other in this space.

---

### Q6: What is TF-IDF?
**Answer:** TF-IDF stands for **Term Frequency-Inverse Document Frequency**. It is a statistical lexical vectorization method that measures how important a word is to a document relative to a collection of documents. Words that appear frequently in a specific chunk but rarely across the entire corpus receive higher numerical weights.

---

### Q7: Is TF-IDF a semantic embedding method?
**Answer:** **No.** TF-IDF is a **lexical (keyword-based)** vectorizer, not a semantic model. It measures exact word occurrences and frequency statistics. It does not understand synonyms, contextual semantics, or conceptual meaning (e.g., TF-IDF does not know that "SMS" and "text message" are conceptually related unless the exact words match).

---

### Q8: What is Hybrid Retrieval?
**Answer:** Hybrid retrieval combines multiple search techniques—such as exact identifier matching, lexical keyword matching (TF-IDF), dense semantic vector search, and metadata signals (source trust level and document freshness)—into a single unified scoring pipeline. This ensures high precision for technical terms while maintaining broad semantic recall.

---

### Q9: Explain your ranking score formula.
**Answer:** GARUD-AI uses a 5-factor score fusion formula to calculate a candidate chunk's ranking score:
$$\text{Score} = 0.35 \times \text{Exact ID} + 0.35 \times \text{Semantic} + 0.15 \times \text{Lexical} + 0.10 \times \text{Trust} + 0.05 \times \text{Freshness}$$
- **Exact ID (35%)**: Direct matches for technique or CVE IDs (`T1412`).
- **Semantic (35%)**: Vector cosine similarity.
- **Lexical (15%)**: TF-IDF token overlap.
- **Trust (10%)**: Document authority rating.
- **Freshness (5%)**: Verification recency.

---

### Q10: Why does document trust not dominate search relevance?
**Answer:** Because an authoritative document (`Trust = 1.0`) on an irrelevant topic (e.g., an official policy document on passwords) is useless for answering a question about SMS interception. In our ranking formula, zero-relevance chunks are excluded entirely, ensuring that trust acts only as a tie-breaker among genuinely relevant documents.

---

### Q11: What is Grounding in RAG?
**Answer:** Grounding is the process of verifying that every claim in an LLM's generated response is directly supported by the retrieved context chunks. If an LLM makes an assertion not present in the retrieved text, the response is ungrounded (an overstatement or hallucination).

---

### Q12: What does `INSUFFICIENT_EVIDENCE` mean in your system?
**Answer:** `INSUFFICIENT_EVIDENCE` is a grounding state assigned when an analyst asks about a topic or identifier (e.g., an unsupported CVE) that does not exist in the retrieved cybersecurity knowledge base. Instead of guessing or fabricating an answer, the system explicitly reports that context is unavailable.

---

### Q13: What is Provenance?
**Answer:** Provenance refers to the verifiable lineage and source traceability of an AI response. In GARUD-AI, every RAG response includes a list of exact retrieved document chunks, including their source title, technique ID, trust level, and retrieval score, allowing analysts to audit the exact evidence behind every statement.

---

### Q14: How do you prevent LLM hallucinations?
**Answer:** We prevent hallucinations through three mechanisms:
1. **Strict Context Prompting**: Instructing the LLM to answer *only* using the provided text.
2. **Grounding Validation Service**: Programmatically checking response claims against retrieved chunks post-generation.
3. **Fallback to `INSUFFICIENT_EVIDENCE`**: Returning a clear refusal state when relevant chunks are absent.

---

### Q15: How do you handle Prompt Injection attempts?
**Answer:** User questions are placed inside a clearly demarcated data block (`=== USER QUESTION ===`) separate from system instructions (`=== SYSTEM INSTRUCTIONS ===`). The system instructions inform the LLM that user input and retrieved chunks are untrusted DATA, not executable commands. Furthermore, post-generation grounding checks verify that adversarial instructions cannot alter risk scores or system outputs.

---

### Q16: Can the RAG subsystem change or override the malware verdict?
**Answer:** **No.** The RAG subsystem is strictly isolated from the deterministic Risk Engine. Pre- and post-RAG state snapshots confirm that fields like `risk_score`, `risk_level`, `malware_verdict`, `classification`, `digital_twin_id`, and `version_number` remain 100% unmutated under any RAG query.

---

### Q17: Why is static analysis capability not proof of runtime behavior?
**Answer:** Static analysis inspects the APK package (permissions, bytecode, manifest declarations) without executing the code. A permission declaration like `SEND_SMS` indicates that the app has the *candidate capability* to send text messages, but it does not prove that the code actually executes or performs malicious SMS fraud at runtime.

---

### Q18: What does Malware DNA similarity mean in GARUD-AI?
**Answer:** Malware DNA is a categorical Jaccard set similarity score calculated over 10 normalized static feature sets (permissions, DEX findings, YARA matches, etc.). It represents **structural feature similarity** across APK samples. It does **not** prove definitive malware lineage, author attribution, campaign origin, or repacking.

---

### Q19: Why is the MITRE ATT&CK version pinned in your system?
**Answer:** We pin the catalog to **MITRE ATT&CK Mobile v15.1** to ensure deterministic consistency and auditability. Pinned versions guarantee that rule mappings, technique definitions, and evaluation metrics remain reproducible across different environments without breaking due to upstream schema changes.

---

### Q20: What are the current limitations of your RAG implementation?
**Answer:**
1. Small benchmark dataset (10 golden queries).
2. Seed dataset limited to 11 Phase 3.4.1 audited MITRE Mobile techniques.
3. Dense vector search is conditional on locally cached model weights.
4. SQLite vector storage is MVP-scale for local evaluation.
5. Live external threat intelligence (VT, AbuseIPDB, OTX) is not benchmarked by the offline RAG test suite.

---

### Q21: Why is SQLite acceptable for your RAG vector store MVP?
**Answer:** SQLite is built into Python's standard library, requires zero external service daemons or open network ports, and allows 100% reproducible, isolated in-memory test execution (`sqlite:///:memory:`). For local evaluation on a seed dataset of 11 documents, SQLite cosine distance math provides exact, fast results without infrastructure overhead.

---

### Q22: What happens when the LLM provider is unavailable or unconfigured?
**Answer:** The system applies a safe offline fallback to `MockLLMProvider`. The mock provider extracts retrieved context chunks, formats a structured evidence summary, appends static boundary disclaimers, and returns a valid response with zero secret leakage and zero network errors.

---

### Q23: What happens when RAG is disabled (`RAG_ENABLED=False`)?
**Answer:** When RAG is disabled via configuration, the `/api/v1/rag/health` endpoint reports `status="disabled"`, while `/retrieve` and `/ask` return **HTTP 503 Service Unavailable** with a clean error message. Non-RAG core platform routes (static analysis, Digital Twin, risk scoring) continue running normally.

---

### Q24: How did you evaluate your RAG subsystem?
**Answer:** We created a controlled evaluation dataset (`GOLDEN_QUERIES`) of 10 structured queries divided into CAT-A (retrieval-positive), CAT-B (sample-context), CAT-C (negative/unsupported), and CAT-D (adversarial). We evaluated retrieval metrics (Recall@3, Hit@3, MRR), grounding accuracy, and 10 API resilience failure scenarios (TEST A–J).

---

### Q25: What do Recall@3, Hit@3, and Mean Reciprocal Rank (MRR) mean?
**Answer:**
- **Recall@3**: The proportion of expected ground-truth target chunks that appear in the Top-3 retrieved results (100% on CAT-A queries).
- **Hit@3**: The percentage of queries where at least one correct target chunk appeared in the Top-3 results (100% on CAT-A queries).
- **MRR (Mean Reciprocal Rank)**: The average of the reciprocal ranks of the first correct answer ($1/\text{rank}$). An MRR of 1.000 means the correct target chunk ranked #1 for 100% of CAT-A queries.

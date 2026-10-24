# GARUD-AI / CRYPTIX RAG SUBSYSTEM VIVA EXPLANATION SCRIPTS
**Natural Presentation & Oral Defense Scripts for Student Presenters**

---

## A. 30-Second Explanation (Elevator Pitch)

> "In Garud-AI, our core static analysis engine extracts permissions, bytecode findings, and risk scores deterministically. However, raw findings don't explain *why* a behavior is dangerous to a human analyst. To solve this, we implemented an on-demand **Cybersecurity RAG Subsystem**.
>
> When an analyst asks a question, our Query Builder extracts technique IDs, our Hybrid Retriever scores candidate MITRE ATT&CK Mobile chunks using a 5-factor formula, and our Context Builder feeds that evidence to an LLM. Finally, our Grounding Service verifies every claim against retrieved context to prevent hallucinations.
>
> Most importantly, RAG is strictly an analyst assistant—it **cannot** alter the deterministic risk score or malware verdict of our platform."

---

## B. 1-Minute Explanation (Standard Overview)

> "When analyzing suspicious Android APKs in Garud-AI, automated static analysis provides exact evidence—like `SEND_SMS` permissions or `SmsManager` bytecode calls. But raw findings lack domain explanation. Standard LLMs often hallucinate non-existent CVEs or overstate static findings into unconfirmed runtime verdicts.
>
> To solve this, we built a **Grounded Cybersecurity RAG Subsystem** backed by an audited seed catalog of MITRE ATT&CK Mobile v15.1 technique documents.
>
> Here is how it works:
> First, an analyst submits a query. Our **Query Builder** extracts technical identifiers like technique IDs or CVEs. Second, our **Hybrid Retriever** scores knowledge chunks using a 5-factor formula combining exact ID matches, semantic vectors, lexical TF-IDF, source trust, and freshness. Third, our **Context Builder** packages the retrieved chunks with prompt-injection disclaimers.
>
> After the LLM generates a response, our **Grounding Validation Service** programmatically inspects the output to ensure claims match retrieved evidence without overstating static capability into runtime execution.
>
> Crucially, our Risk Engine remains 100% isolated and frozen—RAG provides explanatory context, while our Risk Engine remains the sole source of truth for malware verdicts."

---

## C. 2–3 Minute Detailed Explanation (Deep-Dive Defense)

> "Good morning examiners. Today I would like to explain the **Cybersecurity RAG Subsystem** in Garud-AI.
>
> In mobile malware investigation, there is a fundamental gap between *evidence collection* and *analyst interpretation*. Our static analyzers extract exact artifacts—such as decompiled DEX bytecode methods, manifest intent filters, YARA rule matches, and certificate signatures. However, an analyst reviewing a sample needs to understand the broader attack context, such as MITRE ATT&CK Mobile techniques and mitigations.
>
> Relying on generic public LLMs is risky because LLMs hallucinate non-existent CVEs, leak secrets, or make claims unsupported by the evidence.
>
> To address this, we designed a multi-stage **Retrieval-Augmented Generation** pipeline:
>
> 1. **Query Construction**: When an analyst submits an inquiry, our `RAGQueryBuilder` extracts exact technique IDs like `T1412` or `T1437.001` and normalizes cybersecurity keywords.
> 2. **Hybrid Retrieval**: Our `HybridRetriever` executes a 4-pass scoring pipeline using a weighted score fusion formula:
>    $$\text{Score} = 0.35 \times \text{Exact ID} + 0.35 \times \text{Semantic} + 0.15 \times \text{Lexical} + 0.10 \times \text{Trust} + 0.05 \times \text{Freshness}$$
>    This guarantees that exact technique matches outrank generic high-trust documents, while TF-IDF provides robust lexical keyword fallback offline.
> 3. **Context Assembly & Safety Boundaries**: `RAGContextBuilder` structures the prompt into isolated sections, marking user questions and retrieved context as untrusted data to resist prompt-injection attacks.
> 4. **Grounded Generation & Validation**: The LLM generates an answer, which is passed to our `GroundingValidationService`. This service checks if statements exceed static boundaries—for instance, if an answer claims static permission presence proves active runtime exploitation, the system flags it as `PARTIALLY_SUPPORTED` and appends a static capability disclaimer. If evidence is missing, it sets `INSUFFICIENT_EVIDENCE` rather than hallucinating.
>
> We evaluated this subsystem on a controlled 10-query benchmark dataset across CAT-A through CAT-D categories. On our retrieval-positive queries, we achieved **100% Recall@3**, **100% Hit@3**, and an **MRR of 1.000**. We also ran 10 API resilience failure tests (TEST A through TEST J), confirming 100% pass rates and proving complete risk engine independence.
>
> In conclusion, our RAG subsystem provides explainable, grounded intelligence to security analysts while preserving the deterministic Risk Engine as the immutable source of truth."

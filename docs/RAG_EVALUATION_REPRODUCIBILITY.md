# GARUD-AI / CRYPTIX CYBERSECURITY RAG REPRODUCIBILITY GUIDE
**Reproducible Evaluation Instructions & Verification Checklist**

---

## 1. Overview

This document provides a step-by-step reproducibility guide for executing and verifying the evaluation of the GARUD-AI / CRYPTIX Cybersecurity RAG subsystem (Sub-phases 3.5.8.1 through 3.5.8.4).

All evaluation tests run **100% offline**, without requiring external network connections, live LLM API keys, or pre-downloaded dense vector model weights.

---

## 2. Prerequisites & Environment Setup

### System & Python Requirements
* **Operating System**: Windows / Linux / macOS
* **Python Version**: Python 3.10+ (Tested on Python 3.14.3)
* **Key Python Dependencies**: `fastapi`, `pytest`, `sqlalchemy`, `pydantic`, `httpx`, `numpy`

### Environment Variables
Set `PYTHONPATH` to point to the `backend` directory before executing tests:

#### Windows PowerShell:
```powershell
$env:PYTHONPATH="backend"
```

#### Windows Command Prompt (CMD):
```cmd
set PYTHONPATH=backend
```

#### Linux / macOS Bash:
```bash
export PYTHONPATH=backend
```

> [!CAUTION]
> **Zero Secrets Policy**: Never put API keys, bearer tokens, or sensitive credentials into environment variables or test files when reproducing evaluation runs.

---

## 3. Database Isolation & Seed Data

### Isolated In-Memory Database
All evaluation tests utilize isolated SQLite in-memory databases (`sqlite:///:memory:`):
- Every test function receives a clean, isolated database session.
- Tests do **not** write to or modify local disk databases (`cryptix.db` or PostgreSQL).
- Production state remains 100% untouched.

### Seed Knowledge Dataset Requirements
The evaluation uses the Phase 3.4.1 audited seed catalog of **11 MITRE ATT&CK Mobile v15.1 technique documents**:
`T1406`, `T1412`, `T1420`, `T1426`, `T1430`, `T1432`, `T1437`, `T1437.001`, `T1409`, `T1624`, `T1626`.

The seed fixture (`seeded_evaluation_store`) automatically populates an in-memory `RagDocument` and `RagChunk` dataset prior to executing retrieval and grounding assertions.

---

## 4. Test Execution Commands

### A. Run RAG Evaluation Test Suite Only

Executes all 26 benchmark, grounding, safety, and resilience tests:

```powershell
cmd /c "set PYTHONPATH=backend&& python -m pytest backend/tests/test_rag_evaluation.py -v"
```

#### Expected Test Output:
```text
backend/tests/test_rag_evaluation.py::test_golden_dataset_structure_and_categories PASSED
backend/tests/test_rag_evaluation.py::test_cat_a_retrieval_targets_exist_in_seed_catalog PASSED
...
backend/tests/test_rag_evaluation.py::test_conditional_sentence_transformers_semantic_retrieval SKIPPED
...
backend/tests/test_rag_evaluation.py::test_api_test_j_error_classification PASSED

================= 25 passed, 1 skipped in 7.41s =================
```

---

### B. Run Full Backend Regression Suite

Executes all 168 backend unit and integration tests across all modules:

```powershell
cmd /c "set PYTHONPATH=backend&& python -m pytest backend/tests -v"
```

#### Expected Test Output:
```text
================ 167 passed, 1 skipped in 46.99s ================
```

---

## 5. Offline Behavior & SentenceTransformer Handling

### Offline TF-IDF Lexical Vectorization
By default, retrieval evaluation uses the built-in `TFIDFEmbeddingProvider`, which operates purely in-memory using standard library and `numpy` math without external network calls or model downloads.

### Conditional SentenceTransformer Behavior
If `sentence-transformers` library or local model weights (`all-MiniLM-L6-v2`) are unavailable offline, the test `test_conditional_sentence_transformers_semantic_retrieval` will automatically output `SKIPPED`.

This behavior is **expected and intentional**:
- It prevents tests from failing due to missing offline network access.
- It verifies that the system gracefully handles un-cached dense models without crashing the application.

---

## 6. How to Interpret Evaluation Metrics

### Retrieval Metrics (CAT-A Queries Q1–Q5)
- **Recall@3 = 100% (1.000)**: All defined ground-truth target chunks were present in the Top-3 retrieved results.
- **Hit@3 = 100% (1.000)**: At least one ground-truth target chunk was present in the Top-3 retrieved results for 100% of queries.
- **MRR = 1.000**: The ground-truth target chunk ranked #1 for 100% of CAT-A queries.

> [!NOTE]
> Retrieval ranking scores ($0.35\text{ID} + 0.35\text{Semantic} + 0.15\text{Lexical} + 0.10\text{Trust} + 0.05\text{Freshness}$) order retrieved chunks. They are **ranking signals**, not statistical probabilities.

### Grounding Metrics (Controlled Scenarios)
- **Grounding Accuracy = 100% (3/3)**: Evaluates whether responses are classified into appropriate grounding states (`SUPPORTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`).

---

## 7. Known Evaluation Limitations

When reviewing or publishing evaluation results, maintain the following explicit caveats:

1. **Benchmark Scope**: Evaluated on 10 structured queries (`GOLDEN_QUERIES`).
2. **Seed Catalog**: Restricted to 11 audited MITRE Mobile v15.1 seed techniques.
3. **Retrieval Metric Sample**: Metrics derived from 5 CAT-A retrieval-positive queries.
4. **Grounding Metric Sample**: Grounding accuracy derived from 3 controlled synthetic scenarios.
5. **Conditional Dense Vector Search**: Dense semantic search requires cached weights and was skipped offline.
6. **No Universal Accuracy Claim**: Metrics apply solely to this controlled benchmark dataset.
7. **No Complete ATT&CK Coverage**: The seed catalog is not the complete ATT&CK Mobile matrix (~100+ techniques).
8. **Static Boundary**: Static findings represent candidate capabilities, not confirmed runtime execution.
9. **DNA Similarity Boundary**: DNA Jaccard scores represent structural similarity, not proof of lineage/origin.
10. **Prompt Injection Boundary**: Tests confirm resistance for evaluated attack strings, not universal protection.
11. **External TI Scope**: External reputation APIs (VirusTotal, AbuseIPDB, OTX) are not evaluated by this benchmark.
12. **Vector Store Scale**: Local SQLite vector storage is MVP-scale for offline evaluation.

---

## 8. Verification Checklist

To confirm complete reproducibility of Sub-phase 3.5.8:

- [x] All 25 active RAG evaluation tests in `test_rag_evaluation.py` pass cleanly.
- [x] 1 conditional test (`test_conditional_sentence_transformers_semantic_retrieval`) skips gracefully offline.
- [x] All 167 non-skipped backend regression tests in `backend/tests` pass cleanly.
- [x] Application code under `backend/app/*` remains **100% unchanged**.
- [x] `docs/RAG_EVALUATION_REPORT.md` and `docs/RAG_EVALUATION_REPRODUCIBILITY.md` exist and are up to date.

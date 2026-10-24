# Threat Memory & Historical Intelligence Engine Documentation

## Overview
The **Threat Memory & Historical Intelligence Engine** in `CRYPTIX / Garud-AI` provides local historical sample lookup, binary identity verification, and structural capability matching across all previously analyzed APK samples.

It answers two primary threat operation questions:
1. *"Have we seen this sample or something similar before?"*
2. *"What did our previous analysis tell us about its risk posture and capabilities?"*

Threat Memory is **100% local, deterministic, and explainable**. It does NOT rely on external threat feeds (VirusTotal, AbuseIPDB, OTX), LLMs, RAG, vector databases, or machine learning embeddings.

---

## 1. Decision Tree Hierarchy

```
                               Incoming APK
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
       Exact SHA-256 in DB?                 No Exact SHA Match
                    │                               │
           ┌────────┴────────┐                      ▼
          YES                NO           Query Malware DNA Similarity
           │                                        │
           ▼                               ┌────────┴────────┐
      KNOWN_EXACT                          │                 │
 (Exact Binary Match)               Score >= 65.0%    Score >= 35.0%
                                           │                 │
                                           ▼                 ▼
                                    HIGH_SIMILARITY   RELATED_SAMPLE
                                    (Lineage Match)   (Capability Overlap)
                                                             │
                                                             ▼
                                                      Score < 35.0%
                                                             │
                                                             ▼
                                                        NEW_SAMPLE
                                                   (Unseen Locally)
```

### Hierarchy Rules

1. **LEVEL 1 — EXACT MATCH (`KNOWN_EXACT`)**:
   - Compares incoming file SHA-256 against existing `APKMetadata` records.
   - Exact SHA-256 match takes **absolute precedence** over Malware DNA similarity scores.
   - Meaning: *"The exact binary has previously been analyzed in the local corpus."*

2. **LEVEL 2 — HIGH DNA SIMILARITY (`HIGH_SIMILARITY`)**:
   - Evaluated when no exact SHA-256 match exists.
   - Queries Malware DNA Jaccard similarity score against prior stored DNA records.
   - Threshold: $\text{Similarity Score} \ge 65.0\%$.
   - Meaning: *"The sample exhibits high structural and behavioral similarity to a historical sample."*

3. **LEVEL 3 — RELATED SAMPLE (`RELATED_SAMPLE`)**:
   - Evaluated when top Malware DNA similarity is $\ge 35.0\%$ but $< 65.0\%$.
   - Meaning: *"The sample shares meaningful static capabilities with a historical sample."*

4. **LEVEL 4 — NEW SAMPLE (`NEW_SAMPLE`)**:
   - Evaluated when no exact SHA-256 match exists and top Malware DNA similarity is $< 35.0\%$ (or no prior samples exist).
   - Meaning: *"No matching historical sample was found in local Threat Memory."*
   - **Crucial Analyst Notice**: `NEW_SAMPLE` indicates the file is unseen locally. It does NOT mean the file is safe, benign, or globally unknown.

5. **EXPLICIT ERROR ISOLATION (`ERROR`)**:
   - If a database query or evaluation exception occurs, the system records `ERROR` status. Database errors are NEVER silently disguised as `NEW_SAMPLE`.

---

## 2. Persistence Model (`ThreatMemory`)

- **Table Name**: `threat_memory`
- **Fields**:
  - `id`: Integer (PK, autoincrement)
  - `apk_id`: Integer (FK to `apk_metadata.id`, unique=True, index=True)
  - `sha256`: String (index=True)
  - `dna_hash`: String (nullable=True, index=True)
  - `status`: String (`KNOWN_EXACT`, `HIGH_SIMILARITY`, `RELATED_SAMPLE`, `NEW_SAMPLE`, `ERROR`)
  - `matched_apk_id`: Integer (FK to `apk_metadata.id`, nullable=True)
  - `similarity_score`: Float (nullable=True)
  - `historical_risk_score`: Integer (nullable=True)
  - `historical_threat_level`: String (nullable=True)
  - `historical_family`: String (nullable=True)
  - `digital_twin_id`: Integer (nullable=True)
  - `match_explanation_json`: Text (JSON string containing shared features, differing features, and narrative explanation)
  - `created_at`: DateTime (UTC default)
  - `updated_at`: DateTime (UTC default)

---

## 3. Configurable Heuristic Thresholds

Located in `backend/app/threat_memory/config.py`:
- `HIGH_SIMILARITY_THRESHOLD = 65.0`
- `RELATED_SAMPLE_THRESHOLD = 35.0`

---

## 4. API Specification

- `GET /api/v1/threat-memory/{apk_id}`: Retrieves Threat Memory record, decision status, exact match flag, best match payload, similar historical samples, and detailed explanation.
- `GET /api/v1/threat-memory/{apk_id}/matches?limit=5`: Retrieves top N historical threat matches.

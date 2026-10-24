# CRYPTIX / GARUD-AI — Investigation Module & Digital Twin Debug Report

## Executive Summary
This debug report documents the root cause analysis, technical fixes, empirical runtime database tests, and full regression verification for the Investigation Module and Digital Twin versioning engine in GARUD-AI / CRYPTIX.

---

## 1. Digital Twin Version Proliferation Bug Analysis

### Root Cause Analysis
Prior to this fix, navigating to an APK investigation page (`/apks/:id`) or refreshing the page executed `getReport(apk_id)` (`GET /api/v1/reports/:id`). 
In `backend/app/reporting/report_service.py`, `generate_apk_report(db, apk_id)` directly invoked `analyze_uploaded_apk(db, apk_id)`.
`analyze_uploaded_apk` called `save_digital_twin(db, apk, twin)`, which queried the database for an existing `DigitalTwin` row and unconditionally incremented `current_version = current_version + 1` while inserting a new `DigitalTwinVersion` record into SQL database storage.

Consequently:
- Every page load created a new version (`v1 -> v2 -> v3 ... v13`).
- Every tab navigation or refresh created a new version.
- Read operations were non-idempotent and mutated database state.

### Code Change Implemented
In `backend/app/reporting/report_service.py`, `generate_apk_report(db, apk_id)` was modified to perform an idempotent read lookup:
1. Query `DigitalTwin` and its associated `DigitalTwinVersion` records for `apk_id`.
2. If an existing Digital Twin version exists, construct the report payload directly from stored SQL fields (`DigitalTwinVersion` + `APKMetadata`) without calling `analyze_uploaded_apk` or `save_digital_twin`.
3. If no Digital Twin version exists (e.g. initial upload or legacy sample), invoke `analyze_uploaded_apk(db, apk_id)` once to create Version 1.

---

## 2. Investigation Tabs Debug & Audit Matrix

| Investigation Tab | Root Cause | Backend Status Code | Frontend Handling Status | Technical Fix Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **Manifest & Permissions** | String array permissions (e.g. `["android.permission.INTERNET"]`) caused severity filtering `(item.severity)` to evaluate to `""` and filter all items out when `severityFilter !== "ALL"`. | `200 OK` | `200 OK` (Rendered 0 items when filter applied) | Derived severity dynamically using `getPermSeverity` for string permissions; added explicit static capability security disclaimer. |
| **Malware DNA** | `getMalwareDNA(apkId)` returned `404 Not Found` when DNA record was not generated for a sample, causing the frontend to throw an unhandled catch and render a red error banner. | `404 Not Found` (Missing DB row) / `500 Error` | Rendered Red Error Banner | Caught `404` gracefully to render informative "DNA Not Generated" card; preserved `500` server error boxes; added structural similarity disclaimer; added zero historical samples fallback. |
| **Threat Memory** | `getThreatMemory(apkId)` returned `404 Not Found` for unindexed samples, causing frontend to display "THREAT MEMORY UNAVAILABLE" red error box. | `404 Not Found` / `500 Error` | Rendered Red Error Box | Handled `404` as default `NEW_SAMPLE` classification with scope notice explaining that `NEW_SAMPLE` means unindexed locally, not safe. Preserved `500` server errors. |
| **Global Threat Intelligence** | Provider endpoints without API keys returned `status="NOT_CONFIGURED"`. Raw errors on failed connections showed unhandled error banners. | `200 OK` (`NOT_CONFIGURED` / `NOT_FOUND`) / `500 Error` | Unhandled Error Banners on HTTP errors | Handled `404` gracefully as `NOT_CONFIGURED` status; preserved HTTP `500` error boxes; maintained privacy policy notice (hash-only lookups). |
| **MITRE ATT&CK** | `getMitreMappings(apkId)` returned `404 Not Found` for samples with zero rule hits, throwing an exception and rendering a red error box. | `404 Not Found` / `500 Error` | Rendered Red Error Box | Handled `404` gracefully by initializing empty mappings structure; rendered clean zero-mapping state with rule explanation; added static evidence disclaimer; preserved HTTP `500` error boxes. |

---

## 3. Empirical Database & Runtime Version-Count Verification

An automated database verification script (`scratch/test_version_count.py`) was executed against the SQLite database instance (`cryptix.db`) with an analyzed sample (`APK #1`):

```text
INITIAL DIGITAL TWIN STATE: current_version = 26

--- Testing 5 GET Requests / Page Refreshes ---
GET Request / Refresh #1: current_version = 26
GET Request / Refresh #2: current_version = 26
GET Request / Refresh #3: current_version = 26
GET Request / Refresh #4: current_version = 26
GET Request / Refresh #5: current_version = 26
RESULT: SUCCESS! current_version remained 26 across all 5 GET requests/refreshes.

--- Testing 1st Intentional Re-analysis ---
After 1st intentional re-analysis: current_version = 27
RESULT: SUCCESS! current_version incremented from 26 -> 27.

--- Testing 2nd Intentional Re-analysis ---
After 2nd intentional re-analysis: current_version = 28
RESULT: SUCCESS! current_version incremented from 27 -> 28.

==================================================
DIGITAL TWIN IDEMPOTENCY & VERSION VERIFICATION: PASSED (100%)
==================================================
```

---

## 4. Automated Pytest Test Suite Results

The full backend Pytest regression suite was executed via:
`$env:PYTHONPATH="backend"; python -m pytest backend/tests -v`

### Result Summary
- **Total Tests Collected**: 168
- **PASSED**: 167
- **SKIPPED**: 1 (`test_conditional_sentence_transformers_semantic_retrieval` — skipped intentionally due to offline environment model weights)
- **FAILED**: 0

---

## 5. Security Terminology & Analyst Disclaimers Enforced
Across all investigation tabs, security terminology has been aligned strictly with static analysis capabilities:
- **Manifest Permissions**: Declared requested permissions represent *candidate capabilities*, not confirmed runtime execution.
- **Malware DNA**: Jaccard similarity measures *static feature overlap* (shared libraries/code structure), not definitive malware lineage or infection probability.
- **Threat Memory**: `NEW_SAMPLE` indicates that a binary is *unindexed in the local corpus*, not that it is benign or safe.
- **MITRE ATT&CK**: Mappings represent *rule-based static detections*, not confirmed active exploitation or dynamic behavior.
- **Global Threat Intelligence**: Provider status accurately reports `NOT_CONFIGURED` or `NOT_FOUND` without fake scores or unverified claims.

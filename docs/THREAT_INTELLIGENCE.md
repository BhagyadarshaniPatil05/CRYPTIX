# Phase 3.3 — Global Threat Intelligence Integration Documentation

## 1. Overview
GARUD-AI / CRYPTIX Phase 3.3 introduces **Global Threat Intelligence (TI) Integration**, allowing local static analysis findings, Malware DNA fingerprints, and Threat Memory decisions to be enriched with external reputation signals from **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX**.

---

## 2. Fundamental Architectural Guarantees

### 🔒 Privacy Rule: Hash-First Lookups Only
- **Never Upload Binary Files**: Raw APK binaries are NEVER uploaded to VirusTotal or external cloud API services.
- **Hash-First Queries**: Queries to VirusTotal use the calculated `SHA-256` digest exclusively (`GET /api/v3/files/{sha256}`).
- **Sanitized Extracted IOCs**: IP reputation queries are restricted to extracted public IPv4 addresses. Private, loopback, multicast, or link-local IP addresses (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`) are filtered prior to external network requests.

### 🛡️ Pipeline Resilience & Isolation
- **Non-Blocking Execution**: External Threat Intelligence queries run in Step 17 of the static analysis pipeline, wrapped in an isolated exception handler.
- **Fail-Safe Integrity**: Network timeouts, missing API keys, rate limits, or provider outages will **NEVER** crash local static analysis, Digital Twin creation, Malware DNA generation, or Threat Memory evaluation.

### 🏷️ Honest UI State Representation
- **No Fabricated Data**: If API keys are unconfigured, the UI clearly displays `NOT_CONFIGURED` badges and explanatory notices rather than generating dummy threat scores.

---

## 3. Supported Threat Intelligence Providers

### A. VirusTotal (v3 File Hash Engine)
- **Endpoint**: `GET https://www.virustotal.com/api/v3/files/{sha256}`
- **Authentication**: `x-apikey: <key>` header
- **Normalized Data**:
  - `malicious`, `suspicious`, `harmless`, `undetected` engine counts
  - `total_engines` evaluated
  - Detection alias / meaningful name
  - Direct permalink to VirusTotal GUI

### B. AbuseIPDB (v2 IP Reputation Engine)
- **Endpoint**: `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
- **Authentication**: `Key: <key>` header
- **Normalized Data**:
  - `abuse_confidence_score` (0% to 100%)
  - `total_reports` & `num_distinct_users`
  - ISP, Domain, and Country Code
  - Whitelist status

### C. AlienVault OTX (v1 Threat Indicator Engine)
- **Endpoint**: `GET https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general`
- **Authentication**: `X-OTX-API-KEY: <key>` header
- **Normalized Data**:
  - Associated community pulse count
  - Pulse names and threat tags

---

## 4. DB Caching Strategy
- **ORM Model**: `ThreatIntelligence` model (`threat_intelligence` table).
- **TTL Expiry**: Configurable cache TTL (default `24` hours via `TI_CACHE_TTL_HOURS`).
- **Cache Lookup**: Before calling external endpoints, the cache service checks for unexpired DB records matching `(provider, indicator_type, indicator_value)`. Valid hits set `cached = True`.

---

## 5. API Endpoints

### `GET /api/v1/threat-intelligence/{apk_id}`
Returns all Threat Intelligence provider lookup records and provider configuration statuses for a specified APK sample.

### `GET /api/v1/threat-intelligence/{apk_id}/summary`
Returns a high-level Threat Intelligence status and threat detection summary per provider for a given sample.

---

## 6. Testing & Verification
- Comprehensive Pytest test suite in `backend/tests/test_threat_intelligence.py`.
- **53/53 tests passing** (42 baseline tests + 11 TI unit & integration tests).
- Frontend production build verified with `npm run build` (vite v8.2.1).

# CRYPTIX / Garud-AI — Frontend Architecture & Backend API Mapping

**Document Version:** 1.0.0 (Phase 2.1 Completion)  
**Date:** September 8, 2026  
**Status:** Comprehensive Audit & System Mapping Completed  
**Repository:** `CRYPTIX-main`  

---

## 1. Executive Summary & Frontend Audit Overview

Phase 2.1 establishes the frontend architecture audit and backend REST API mapping for **CRYPTIX**, transitioning the platform toward the final **Garud-AI Android Malware Analysis and Investigation Platform**.

The current frontend is built with **React 19** and **Vite 8**, running as a Single Page Application (SPA). A complete audit reveals that while the backend boasts a mature 37-endpoint REST API capable of static APK parsing, YARA scanning, DEX bytecode inspection, digital twin snapshot creation, version diffing, and threat hunting, the existing frontend only utilizes **3 out of 37 endpoints** (`/dashboard/metrics`, `/threat-dashboard/risk-distribution`, `/threat-dashboard/top-permissions`).

This document provides an authoritative blueprint for bridging this gap during Phase 2. It details the current tech stack, dual-port architecture, complete 37-endpoint API inventory, current mismatches, target Garud-AI SOC workflow mapping, SOC information architecture, visual design system, and a phased implementation roadmap.

---

## 2. Current Frontend Architecture & Tech Stack

```
frontend/
├── package.json
├── index.html
├── vite.config.js
├── eslint.config.js
└── src/
    ├── main.jsx
    ├── App.jsx
    ├── index.css
    ├── App.css
    ├── api/
    │   └── api.js
    ├── pages/
    │   └── Dashboard.jsx
    └── components/
        ├── MetricCard.jsx
        ├── RiskDistributionChart.jsx
        └── TopPermissionsChart.jsx
```

### Core Technologies:
* **Frontend Framework:** React 19 (`react` ^19.2.8, `react-dom` ^19.2.8)
* **Build Tool & Dev Server:** Vite 8 (`vite` ^8.2.0, `@vitejs/plugin-react` ^6.0.4)
* **HTTP Client:** Axios (`axios` ^1.19.0)
* **Visualization Library:** Recharts (`recharts` ^3.10.1)
* **Routing Library:** React Router DOM (`react-router-dom` ^7.18.2) — *Installed in `package.json` but not yet wired up in `App.jsx`.*

### Current State Summary:
* **Layout:** Single monolithic `Dashboard.jsx` view with inline CSS styling (`backgroundColor: "#0f172a"`).
* **Navigation:** None. Rendered directly via `App.jsx`.
* **State Management:** Local React component state (`useState`, `useEffect`).

---

## 3. Dual-Port System Architecture (FE :5173 / BE :8000)

CRYPTIX operates under a decoupled dual-port system architecture:

```
+---------------------------------------+         HTTP REST JSON         +---------------------------------------+
|          React / Vite Frontend        | <----------------------------> |             FastAPI Backend           |
|                                       |       http://127.0.0.1:8000    |                                       |
|  - Host: http://localhost:5173        |         /api/v1/*              |  - Host: http://127.0.0.1:8000        |
|  - Axios Instance (src/api/api.js)    |                                |  - CORS Middleware: allow_origins=["*"]|
|  - Reactive UI & Recharts Graphs      |                                |  - SQLite / PostgreSQL DB             |
+---------------------------------------+                                +---------------------------------------+
```

* **Frontend Server:** Vite dev server listening on `http://localhost:5173`.
* **Backend Server:** FastAPI application listening on `http://127.0.0.1:8000`.
* **Cross-Origin Resource Sharing (CORS):** Backend `main.py` equips `CORSMiddleware` with `allow_origins=["*"]`, enabling cross-origin API requests from port 5173.
* **Base API URL:** Configured in `frontend/src/api/api.js` as `http://127.0.0.1:8000/api/v1`.

---

## 4. Complete Backend REST API Endpoint Inventory (37 Endpoints)

The CRYPTIX backend exposes 37 verified OpenAPI routes across 13 functional router modules:

| # | HTTP Method | Endpoint Path | Router Module | Parameters / Payload | Primary Purpose / Return Object | Status |
|---|---|---|---|---|---|---|
| 1 | `POST` | `/api/v1/upload` | `upload.py` | `file: UploadFile` | Upload APK, validate magic bytes, stream SHA-256, store file, create DB record | **VERIFIED** |
| 2 | `POST` | `/api/v1/analysis/{apk_id}` | `analysis.py` | `apk_id: int` | Trigger full multi-analyzer static pipeline & twin snapshot creation | **VERIFIED** |
| 3 | `GET` | `/api/v1/twins/{twin_id}` | `digital_twin.py` | `twin_id: int` | Fetch Digital Twin metadata record | **VERIFIED** |
| 4 | `GET` | `/api/v1/twins/{twin_id}/latest` | `digital_twin.py` | `twin_id: int` | Fetch latest Digital Twin snapshot version | **VERIFIED** |
| 5 | `GET` | `/api/v1/twins/{twin_id}/versions` | `digital_twin.py` | `twin_id: int` | Fetch list of all historical twin versions | **VERIFIED** |
| 6 | `GET` | `/api/v1/twins/{twin_id}/compare/{old}/{new}` | `digital_twin.py` | `twin_id, old, new` | Structural diff comparison between 2 version snapshots | **VERIFIED** |
| 7 | `GET` | `/api/v1/twins/{twin_id}/timeline` | `digital_twin.py` | `twin_id: int` | Chronological risk score evolution timeline | **VERIFIED** |
| 8 | `GET` | `/api/v1/twins/{twin_id}/drift` | `digital_twin.py` | `twin_id: int` | Security posture drift metrics & feature mutations | **VERIFIED** |
| 9 | `GET` | `/api/v1/twins/{twin_id}/summary` | `digital_twin.py` | `twin_id: int` | High-level summary of twin security posture | **VERIFIED** |
| 10 | `GET` | `/api/v1/twins/{twin_id}/analytics` | `digital_twin.py` | `twin_id: int` | Aggregated analytics & mutation stats | **VERIFIED** |
| 11 | `GET` | `/api/v1/twins/{twin_id}/risk-graph` | `digital_twin.py` | `twin_id: int` | Graph nodes/edges representation for risk visualization | **VERIFIED** |
| 12 | `GET` | `/api/v1/twins/{twin_id}/drift/report` | `digital_twin.py` | `twin_id: int` | Plain-text / formatted narrative report of security drift | **VERIFIED** |
| 13 | `GET` | `/api/v1/dashboard/metrics` | `dashboard.py` | None | Total APKs, high/med/low risk count, average risk score | **VERIFIED** |
| 14 | `GET` | `/api/v1/threat-dashboard/top-permissions` | `threat_dashboard.py` | None | Top dangerous permissions across analyzed APK corpus | **VERIFIED** |
| 15 | `GET` | `/api/v1/threat-dashboard/risk-distribution` | `threat_dashboard.py` | None | Breakdown of APK risk levels (High, Medium, Low) | **VERIFIED** |
| 16 | `GET` | `/api/v1/threat-dashboard/threat-levels` | `threat_dashboard.py` | None | Threat severity breakdown (Critical, High, Medium, Low) | **VERIFIED** |
| 17 | `GET` | `/api/v1/threat-dashboard/recent-analyses` | `threat_dashboard.py` | None | List of recent APK analysis results | **VERIFIED** |
| 18 | `GET` | `/api/v1/similarity/{twin_id}` | `similarity.py` | `twin_id: int` | Find similar APKs based on permission/behavior overlaps | **VERIFIED** |
| 19 | `GET` | `/api/v1/family/{twin_id}` | `family_classification.py` | `twin_id: int` | Rule-based malware family classification | **VERIFIED** |
| 20 | `GET` | `/api/v1/hunt/high-risk` | `threat_hunting.py` | None | Query all high-risk APKs in database | **VERIFIED** |
| 21 | `GET` | `/api/v1/hunt/sms` | `threat_hunting.py` | None | Query all APKs requesting SMS permissions | **VERIFIED** |
| 22 | `GET` | `/api/v1/hunt/root` | `threat_hunting.py` | None | Query all APKs requesting Root execution capabilities | **VERIFIED** |
| 23 | `GET` | `/api/v1/hunt/family/{family_name}` | `threat_hunting.py` | `family_name: str` | Query all APKs matching specific malware family | **VERIFIED** |
| 24 | `GET` | `/api/v1/recommendation/{twin_id}` | `recommendation.py` | `twin_id: int` | Generate security remediation recommendations | **VERIFIED** |
| 25 | `GET` | `/api/v1/security-score/{twin_id}` | `security_score.py` | `twin_id: int` | Calculated security score (0-100), letter grade & risk factors | **VERIFIED** |
| 26 | `GET` | `/api/v1/incident-response/{twin_id}` | `incident_response.py` | `twin_id: int` | Step-by-step incident response containment playbook | **VERIFIED** |
| 27 | `GET` | `/api/v1/executive-summary/{twin_id}` | `executive_summary.py` | `twin_id: int` | Executive-ready summary for management / non-technical SOC | **VERIFIED** |
| 28 | `GET` | `/api/v1/reports/{apk_id}` | `report.py` | `apk_id: int` | Complete JSON report for given APK ID | **VERIFIED** |
| 29 | `GET` | `/api/v1/reports/{apk_id}/pdf` | `report.py` | `apk_id: int` | Generate and download PDF report binary | **VERIFIED** |
| 30 | `GET` | `/api/v1/twin-health/{twin_id}` | `twin_health.py` | `twin_id: int` | Health score, status, and historical health trend | **VERIFIED** |
| 31 | `GET` | `/api/v1/twin-lifecycle/{twin_id}` | `twin_lifecycle.py` | `twin_id: int` | Lifecycle stage (Active, Deprecated, Compromised) | **VERIFIED** |
| 32 | `GET` | `/api/v1/twin-events/{twin_id}` | `twin_events.py` | `twin_id: int` | Timeline of security events associated with twin | **VERIFIED** |
| 33 | `GET` | `/api/v1/twin-prediction/{twin_id}` | `twin_prediction.py` | `twin_id: int` | Predictive risk progression and drift velocity | **VERIFIED** |
| 34 | `GET` | `/api/v1/twin-dashboard/{twin_id}` | `twin_dashboard.py` | `twin_id: int` | Unified twin dashboard dataset | **VERIFIED** |
| 35 | `GET` | `/api/v1/twin-risk-trend/{twin_id}` | `twin_risk_trend.py` | `twin_id: int` | Historical risk trend data points for charting | **VERIFIED** |
| 36 | `GET` | `/api/v1/twin-recommendations/{twin_id}`| `twin_recommendations.py` | `twin_id: int` | Extended twin recommendations | **VERIFIED** |
| 37 | `GET` | `/` | `main.py` | None | System status root endpoint | **VERIFIED** |

---

## 5. Frontend ↔ Backend API Mapping Matrix

| Backend API Endpoint | Target UI View / Component | Integrated in Current FE? | Planned Integration Stage |
|---|---|---|---|
| `/dashboard/metrics` | `DashboardOverview.jsx` (Metric Cards) | **YES** | Current |
| `/threat-dashboard/risk-distribution` | `RiskDistributionChart.jsx` (Pie Chart) | **YES** | Current |
| `/threat-dashboard/top-permissions` | `TopPermissionsChart.jsx` (Bar Chart) | **YES** | Current |
| `/threat-dashboard/threat-levels` | `ThreatLevelsWidget.jsx` | **NO** | Phase 2.2 |
| `/threat-dashboard/recent-analyses` | `RecentAnalysesTable.jsx` | **NO** | Phase 2.2 |
| `/upload` | `APKUploadModal.jsx` / `Dropzone.jsx` | **NO** | Phase 2.2 |
| `/analysis/{apk_id}` | `AnalysisProgressModal.jsx` | **NO** | Phase 2.2 |
| `/reports/{apk_id}` | `APKDetailView.jsx` (Full Static Results) | **NO** | Phase 2.3 |
| `/reports/{apk_id}/pdf` | `APKDetailView.jsx` ("Download PDF" Button) | **NO** | Phase 2.3 |
| `/security-score/{twin_id}` | `SecurityScoreCard.jsx` (Grade Badge) | **NO** | Phase 2.3 |
| `/family/{twin_id}` | `MalwareFamilyBadge.jsx` | **NO** | Phase 2.3 |
| `/recommendation/{twin_id}` | `RecommendationsTab.jsx` | **NO** | Phase 2.3 |
| `/incident-response/{twin_id}` | `IncidentPlaybookTab.jsx` | **NO** | Phase 2.3 |
| `/executive-summary/{twin_id}` | `ExecutiveSummaryTab.jsx` | **NO** | Phase 2.3 |
| `/twins/{twin_id}` | `DigitalTwinOverview.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/latest` | `DigitalTwinOverview.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/versions` | `TwinVersionHistoryTable.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/compare/{old}/{new}` | `TwinDiffViewer.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/timeline` | `TwinRiskTimelineChart.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/drift` | `TwinDriftCard.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/summary` | `TwinSummaryCard.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/analytics` | `TwinAnalyticsPanel.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/risk-graph` | `TwinRiskGraph.jsx` | **NO** | Phase 2.4 |
| `/twins/{twin_id}/drift/report` | `TwinDriftReportModal.jsx` | **NO** | Phase 2.4 |
| `/twin-health/{twin_id}` | `TwinHealthBadge.jsx` | **NO** | Phase 2.4 |
| `/twin-lifecycle/{twin_id}` | `TwinLifecycleCard.jsx` | **NO** | Phase 2.4 |
| `/twin-events/{twin_id}` | `TwinEventLog.jsx` | **NO** | Phase 2.4 |
| `/twin-prediction/{twin_id}` | `TwinPredictionWidget.jsx` | **NO** | Phase 2.4 |
| `/twin-dashboard/{twin_id}` | `DigitalTwinDashboard.jsx` | **NO** | Phase 2.4 |
| `/twin-risk-trend/{twin_id}` | `TwinRiskTrendChart.jsx` | **NO** | Phase 2.4 |
| `/twin-recommendations/{twin_id}`| `TwinRecommendationsCard.jsx` | **NO** | Phase 2.4 |
| `/similarity/{twin_id}` | `SimilaritySearchTab.jsx` | **NO** | Phase 2.5 |
| `/hunt/high-risk` | `ThreatHuntingView.jsx` (Filter: High Risk) | **NO** | Phase 2.5 |
| `/hunt/sms` | `ThreatHuntingView.jsx` (Filter: SMS) | **NO** | Phase 2.5 |
| `/hunt/root` | `ThreatHuntingView.jsx` (Filter: Root) | **NO** | Phase 2.5 |
| `/hunt/family/{family_name}` | `ThreatHuntingView.jsx` (Filter: Family) | **NO** | Phase 2.5 |

---

## 6. Current Frontend / Backend Mismatches & Deficits

Our comprehensive audit identifies 7 major deficits in the current frontend implementation:

1. **API Utilization Gap (8% Coverage):** Only 3 out of 37 endpoints are called. 34 REST API endpoints remain completely unintegrated into the user interface.
2. **Missing Core User Flow (Upload & Analyze):** Users cannot upload APK files or trigger static analysis from the browser interface.
3. **No Multi-Page Navigation:** `react-router-dom` is installed, but `App.jsx` renders `Dashboard.jsx` directly without routes or navigation bars.
4. **Missing APK Investigation Workspace:** There is no detail view for deep-diving into individual APK static analysis findings (manifest, permissions, certificates, strings, DEX bytecode, YARA matches).
5. **Missing Digital Twin Monitoring Interface:** Twin snapshots, risk timelines, drift detection, and version comparisons exist in the backend but have no frontend visibility.
6. **Missing Threat Hunting Interface:** Threat hunting queries (high-risk, SMS permissions, Root access, malware families) cannot be executed visually.
7. **Styling & Component Hierarchy Constraints:** Inline CSS styling (`style={{...}}`) is used exclusively instead of a scalable CSS framework (like Tailwind CSS) or component design system.

---

## 7. Target Garud-AI SOC Investigation Workflow Mapping

The Garud-AI SOC platform follows a 9-stage investigation pipeline. Here is how the backend capabilities map to each stage:

```
[1. Upload & Validation] ---> [2. Multi-Analyzer Static] ---> [3. Risk Scoring & Family] ---> [4. Digital Twin Versioning]
       |                              |                                |                                   |
       v                              v                                v                                   v
  /api/v1/upload              /api/v1/analysis/{id}            /api/v1/security-score/{id}         /api/v1/twins/{id}
                                                                   /api/v1/family/{id}                /api/v1/twins/{id}/latest

[5. Threat Hunting] <------- [6. Digital Twin Monitoring] <-- [7. Recommendations & IR] <--- [8. Executive Reporting]
       |                              |                                |                                   |
       v                              v                                v                                   v
  /api/v1/hunt/*              /api/v1/twins/{id}/drift         /api/v1/recommendation/{id}         /api/v1/reports/{id}
  /api/v1/similarity/{id}     /api/v1/twins/{id}/timeline      /api/v1/incident-response/{id}      /api/v1/reports/{id}/pdf
                                                                                                   /api/v1/executive-summary/{id}
```

---

## 8. SOC Information Architecture & Multi-Page Navigation Design

To support SOC analysts, the frontend will be structured into 6 primary operational views:

```
+---------------------------------------------------------------------------------------------------+
|  CRYPTIX / Garud-AI Navigation Header                                                             |
|  [ Dashboard ]  [ APK Scanner ]  [ Threat Intel & Hunting ]  [ Digital Twins ]  [ System Status ] |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  /                      -> Executive SOC Dashboard Overview                                       |
|  /apks                  -> APK Repository & Recent Uploads List                                   |
|  /apks/:id              -> Multi-Tab APK Static Analysis & Investigation Workspace               |
|  /twins                 -> Digital Twin Management & Posture Overview                             |
|  /twins/:id             -> Individual Digital Twin Version Diff & Drift Monitoring                |
|  /hunting               -> Threat Hunting, Overlap Search & Malware Family Filter                 |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 9. SOC Dashboard & Analytics Visualization Design

The main SOC Dashboard view (`/`) provides high-level situational awareness:
* **Metric Cards Grid:** Total APKs, Critical Risk, High Risk, Medium Risk, Low Risk, Average Risk Score (`/dashboard/metrics`).
* **Threat Distribution Panel:** Recharts Donut/Pie Chart representing risk breakdown (`/threat-dashboard/risk-distribution`) and Threat Severity levels (`/threat-dashboard/threat-levels`).
* **Permissions Risk Heatmap:** Recharts Horizontal Bar Chart displaying top dangerous permissions across all analyzed APKs (`/threat-dashboard/top-permissions`).
* **Recent Incident Queue:** Interactive data table rendering recent APK analysis results with risk badges and instant action links (`/threat-dashboard/recent-analyses`).

---

## 10. APK Investigation Workflow & Detail View Architecture

When an analyst opens `/apks/:id`, a comprehensive multi-tab workspace loads, calling `/reports/{apk_id}`:

* **Header Banner:** App Name, Package Name, SHA-256 Hash, Risk Level Badge (Critical, High, Medium, Low), Security Score (0-100), PDF Download Button (`/reports/{apk_id}/pdf`).
* **Tab 1: Overview & Risk Summary:** Security Score card, Risk Engine breakdown, Malware Family classification badge (`/family/{twin_id}`).
* **Tab 2: Manifest & Permissions:** List of requested permissions categorized by severity (Critical, High, Medium, Low), exported components, and intent filter analysis.
* **Tab 3: Static Behaviors & DEX Code:** API pattern matches (`Runtime.exec`, `su`, `DexClassLoader`), reflection calls, crypto usage, and DEX bytecode scan findings.
* **Tab 4: Strings, IOCs & YARA:** Extracted URLs, IP addresses, Base64 strings, Firebase URLs, API keys, and compiled YARA rule matches.
* **Tab 5: Certificate & Signature:** Signature algorithm, SHA-256/SHA-1 fingerprints, Issuer/Subject details, serial number, and self-signed status.
* **Tab 6: Remediation & Playbook:** Recommended security mitigations (`/recommendation/{twin_id}`) and step-by-step Incident Response Plan (`/incident-response/{twin_id}`).

---

## 11. Digital Twin Monitoring & Version Comparison View

The Digital Twin monitoring workspace (`/twins/:id`) exposes security posture state over time:

* **Twin Status Card:** Package Name, Active Version, Health Score (`/twin-health/{twin_id}`), Lifecycle State (`/twin-lifecycle/{twin_id}`).
* **Risk Timeline Chart:** Recharts Line/Area Chart mapping risk score changes across versions (`/twins/{twin_id}/timeline` & `/twin-risk-trend/{twin_id}`).
* **Drift & Mutation Summary:** Visual diff card highlighting newly added permissions, exported components, or static behaviors between builds (`/twins/{twin_id}/drift`).
* **Version Side-by-Side Diff Viewer:** Interactive comparison tool selecting Version A vs. Version B (`/twins/{twin_id}/compare/{old}/{new}`).
* **Risk Prediction Widget:** Future risk trajectory and drift velocity gauge (`/twin-prediction/{twin_id}`).

---

## 12. Threat Hunting & Similarity Search Interface Design

The Threat Hunting workspace (`/hunting`) allows security analysts to perform targeted queries across the analyzed APK corpus:

* **Preset Quick Filters:**
  * **High Risk Corpus:** `/hunt/high-risk`
  * **SMS Permission Requesters:** `/hunt/sms`
  * **Root Execution Attempts:** `/hunt/root`
  * **Malware Family Query:** `/hunt/family/{family_name}`
* **Similarity Search Engine:** Input a Twin ID to query structural similarity scores and permission/behavior overlaps (`/similarity/{twin_id}`).

---

## 13. Reporting, Recommendations & Incident Response View

Provides dedicated views for security leadership and incident response teams:

* **Executive Summary View (`/executive-summary/{twin_id}`):** Formatted high-level narrative summary of threat findings, business risk impact, and security posture grade.
* **Incident Response Playbook View (`/incident-response/{twin_id}`):** Actionable containment steps (e.g., block C2 IP, revoke SMS permission, quarantine device).
* **One-Click PDF Generator:** Triggers `/reports/{apk_id}/pdf` to stream a clean, print-ready PDF binary to the browser.

---

## 14. Component Architecture & Reusability Strategy

To ensure code maintainability, frontend components will be organized into reusable design layers:

```
src/
├── components/
│   ├── common/
│   │   ├── Navbar.jsx
│   │   ├── Sidebar.jsx
│   │   ├── MetricCard.jsx
│   │   ├── RiskBadge.jsx
│   │   ├── GradeBadge.jsx
│   │   └── LoadingSpinner.jsx
│   ├── upload/
│   │   ├── APKUploadModal.jsx
│   │   └── Dropzone.jsx
│   ├── investigation/
│   │   ├── OverviewTab.jsx
│   │   ├── ManifestTab.jsx
│   │   ├── BehaviorsTab.jsx
│   │   ├── StringsTab.jsx
│   │   └── CertificateTab.jsx
│   ├── digital_twin/
│   │   ├── TwinHealthCard.jsx
│   │   ├── TwinDiffViewer.jsx
│   │   └── TwinTimelineChart.jsx
│   └── charts/
│       ├── RiskDistributionChart.jsx
│       ├── TopPermissionsChart.jsx
│       └── RiskTrendChart.jsx
```

---

## 15. Design System, Typography & Color Palette

GARUD-AI adopts a restrained, technical Android Threat Operations Center (SOC) aesthetic:

* **Background & Surface Colors:**
  * Base Background: `#07090D` (Quiet dark base with subtle 32px grid pattern)
  * Card / Panel Surface: `#0D1118` (Primary panel container)
  * Elevated Surface: `#121923` (Elevated stats card & popover surface)
  * Border / Divider: `#202A36` (Neutral border used across containers)
* **Text Colors:**
  * Primary Text: `#F1F5F9` (Slate 100)
  * Secondary Text: `#94a3b8` (Slate 400)
  * Muted Text: `#7D8A9A` (Technical labels)
* **Accent Colors (Used Selectively):**
  * **Primary Accent:** `#5EE7F7` (Electric Ice Cyan - reserved for active states, key metrics, active nav)
  * **Secondary Accent:** `#8B9CFF` (Slate Indigo - for secondary indicators & sub-navigation)
* **Semantic Severity & Risk Colors:**
  * **Critical:** `#FF4D5A` (Bright Red)
  * **High:** `#FF8A3D` (Orange)
  * **Medium:** `#F4C95D` (Amber Yellow)
  * **Low / Safe:** `#36D399` (Emerald Green)
* **Typography:** `Inter` for primary UI text; `JetBrains Mono` for SHA-256 hashes, APK IDs, package names, code locations, and technical metadata.

---

## 16. Frontend Dependencies & Package Audit

```json
{
  "dependencies": {
    "axios": "^1.19.0",
    "react": "^19.2.8",
    "react-dom": "^19.2.8",
    "react-router-dom": "^7.18.2",
    "recharts": "^3.10.1"
  }
}
```

### Dependency Recommendations for Phase 2:
1. **Lucide Icons (`lucide-react`):** Strongly recommended for consistent SOC icons (shield, upload, bug, file-text, activity, alert-triangle).
2. **Tailwind CSS (`tailwindcss` + `@tailwindcss/vite`):** Highly recommended for clean utility-first styling, replacing verbosely inline `style={{...}}` props.

---

## 17. Phase 2 Implementation Roadmap & Step-by-Step Plan

```
Phase 2.1: Frontend Audit & REST API Mapping (COMPLETED)
    │
    ▼
Phase 2.2: Core Navigation, Layout & APK Upload Pipeline Integration (COMPLETED)
    │  - Set up React Router DOM routes & CommandNav SOC Header
    │  - Built APK Upload Dropzone & Modal pipeline connected to POST /upload and POST /analysis/{id}
    │  - Integrated Command Center Dashboard with real backend metrics & recent analyses
    │
    ▼
Phase 2.3: Multi-Tab APK Investigation Workspace & Static Reports (COMPLETED)
    │  - Built /apks/:id static forensic workspace with 6 dedicated tabs
    │  - Integrated Manifest, Permissions, Behaviors, DEX, Strings/IOCs, YARA, Certs & Playbook
    │  - Connected PDF report download binary stream (GET /reports/{id}/pdf)
    │
    ▼
Phase 2.4: Digital Twin Monitoring, Diff Viewer & Posture Analytics (COMPLETED)
    │  - Built /twins & /twins/:id workspace with Digital Twins repository table
    │  - Implemented version diff viewer & posture drift assessment narrative
    │  - Charted risk posture trajectory line graph across sequential builds
    │  - Integrated twin health metrics, lifecycle state, and audit event stream
    │
    ▼
Phase 2.5: Threat Hunting, Similarity Search & Phase 2 Final Verification
       - Build /hunting workspace with quick filter buttons (High Risk, SMS, Root, Family)
       - Implement APK similarity search engine UI
       - Conduct end-to-end integration testing and final build verification
```

---

## 18. Viva & Demonstration Explanation Guide

When presenting the CRYPTIX frontend during project demonstration and viva evaluations:

1. **Dual-Port Decoupled Architecture:** Explain that CRYPTIX separates presentation (React/Vite on port 5173) from core business logic and heavy static parsing (FastAPI on port 8000). REST API calls are authenticated and routed seamlessly via CORS.
2. **Why Digital Twin in Frontend?:** Explain that Android malware frequently mutates across app updates. The Digital Twin UI allows security analysts to view an application's security posture over time, track permission drift, compare version diffs, and detect stealthy feature additions.
3. **Static Analysis Transparency:** Demonstrate that every static analyzer result (Androguard metadata, APKTool decompilation, Manifest permission severities, Certificate fingerprints, DEX bytecode patterns, YARA rule matches) is parsed by the backend and rendered interactively in specialized tabs.
4. **Threat Hunting Capability:** Highlight how analysts can query the entire analyzed APK corpus for specific indicators (e.g. SMS permissions, Root access attempts, or shared malware signatures) without re-analyzing files manually.

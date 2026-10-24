# CRYPTIX CURRENT SYSTEM ARCHITECTURE & TECHNICAL GUIDE

**Project Name:** CRYPTIX (Targeting Garud-AI Platform)  
**Document Version:** 1.0.0  
**Date:** September 8, 2026  

---

## 1. High-Level System Architecture

The current system is built as a decoupled **Client-Server Architecture**:

```mermaid
graph TD
    UI[React / Vite Frontend] -->|REST API Requests HTTP| API[FastAPI Backend /api/v1]
    API --> Router[API Routers]
    Router --> Service[Service Layer]
    Service --> Pipeline[Static Analysis Pipeline]
    
    Pipeline --> AG[Androguard Service]
    Pipeline --> AT[APKTool Decoder]
    Pipeline --> MA[Manifest Analyzers]
    Pipeline --> CA[Certificate Analyzer]
    Pipeline --> SA[String & Indicator Extractor]
    Pipeline --> BA[Static Behavior Detector]
    Pipeline --> DA[DEX Bytecode Analyzer]
    Pipeline --> YA[YARA Scanner Engine]
    Pipeline --> RE[Risk Scoring Engine]
    Pipeline --> MAA[Malware Analysis Agent]
    Pipeline --> DT[Digital Twin Engine]
    
    Service --> DB[(PostgreSQL / SQLAlchemy ORM)]
    DT --> DB
```

---

## 2. Component Architecture Deep-Dive

### A. Frontend Architecture
* **Framework:** React 19 + Vite 8 (ESM JavaScript).
* **HTTP Client:** Axios configured with base URL `http://127.0.0.1:8000/api/v1`.
* **State Management:** Local React component state (`useState`, `useEffect`).
* **Visualizations:** Recharts for pie chart (`RiskDistributionChart`) and bar chart (`TopPermissionsChart`).
* **Current Pages:** Single page (`Dashboard.jsx`) rendered by `App.jsx`.

### B. Backend Architecture
* **Framework:** FastAPI (Python asynchronous ASGI framework).
* **Entry Point:** `app/main.py`.
* **Middlewares:** `CORSMiddleware` configured to allow all origins (`*`).
* **Configuration:** `app/config/settings.py` loads environment variables via `python-dotenv`.
* **Logger:** Custom logger wrapping standard Python `logging` module in `app/core/logger.py`.

### C. Database Architecture
* **ORM:** SQLAlchemy 2.0 (`declarative_base()`, `sessionmaker`).
* **Database Driver:** `psycopg2-binary` for PostgreSQL.
* **Core Models:**
  1. `APKMetadata` (`apk_metadata` table): Stores uploaded APK file metadata (`id`, `file_name`, `sha256`, `file_size`, `file_path`, `package_name`, `version`, `status`, `upload_time`).
  2. `APKAnalysis` (`apk_analysis` table): Stores basic Android manifest info (`apk_id`, `package_name`, `app_name`, `version_name`, `version_code`, `min_sdk`, `target_sdk`).
  3. `DigitalTwin` (`digital_twins` table): Tracks top-level Digital Twin instance (`id`, `apk_id`, `package_name`, `app_name`, `current_version`, `created_at`, `updated_at`).
  4. `DigitalTwinVersion` (`digital_twin_versions` table): Stores complete versioned security snapshot in JSON columns (`permissions`, `dangerous_permissions`, `exported_components`, `intent_filters`, `certificate`, `indicators`, `behaviors`, `dex_findings`, `yara_matches`, `risk_score`, `risk_level`, `threat_level`).

---

## 3. Data Flows & Sequences

### A. APK Upload Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Frontend
    participant API as Upload Router (/upload)
    participant Service as Upload Service
    participant Hash as Hash Utility
    participant DB as Database (APKMetadata)
    participant Disk as File Storage

    User->>Frontend: Select & upload APK file
    Frontend->>API: POST /api/v1/upload (multipart/form-data)
    API->>Service: validate_apk(file)
    Service-->>API: returns True (.apk extension check)
    API->>Service: save_apk(file)
    Service->>Disk: Write bytes to uploads/apk_files/<filename>
    API->>Hash: generate_sha256(file_path)
    Hash-->>API: sha256_hash_string
    API->>DB: get_apk_by_hash(sha256)
    alt Hash Already Exists
        DB-->>API: Returns existing record
        API-->>Frontend: HTTP 409 Conflict ("APK already exists")
    else Hash Is New
        API->>DB: create_apk(metadata)
        DB-->>API: Returns saved APK object (ID)
        API-->>Frontend: HTTP 200 OK (id, filename, sha256, size, status)
    end
```

### B. SHA-256 Flow & Significance

```text
APK File Stream
     ↓
SHA-256 Hash Function (hashlib.sha256)
     ↓
64-character Hexadecimal Hash String
     ↓
Query Local DB: `SELECT * FROM apk_metadata WHERE sha256 = :hash`
     ↓
├── Match Found    → Local Exact-Sample Match (Return existing APK record / HTTP 409)
└── Match Not Found → New Local Sample (Proceed to Storage & DB Entry)
```

**Technical Clarification:**
SHA-256 provides a unique cryptographic fingerprint for **exact file identity**.
* It answers: *"Have we processed this exact file in our local database before?"*
* It does **NOT** answer: *"Is this file malicious globally?"* or *"Is this a variant of known malware?"* (That requires external Threat Intelligence lookup and Malware DNA similarity matching).

---

### C. Static Analysis Pipeline Flow

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant API as Analysis Router (/analysis/{id})
    participant Pipeline as analysis_service.py
    participant AG as Androguard
    participant AT as APKTool
    participant Manifest as Manifest Analyzers
    participant Cert as Certificate Analyzer
    participant String as String & Indicator Extractor
    participant Behavior as Static Behavior Detector
    participant DEX as DEX Analyzer
    participant YARA as YARA Scanner
    participant Risk as Risk Engine
    participant Agent as Malware Agent
    participant Twin as Digital Twin Service
    participant DB as PostgreSQL DB

    Client->>API: POST /api/v1/analysis/{apk_id}
    API->>Pipeline: analyze_uploaded_apk(db, apk_id)
    Pipeline->>DB: get_apk_by_id(apk_id)
    
    Pipeline->>AG: analyze_apk(file_path)
    AG-->>Pipeline: package_name, app_name, versions, permissions, components
    
    Pipeline->>AT: decode_apk(file_path)
    AT-->>Pipeline: decoded_folder_path
    
    Pipeline->>Manifest: analyze_exported_components() & analyze_intent_filters()
    Manifest-->>Pipeline: exported activities/services, intent actions
    
    Pipeline->>Cert: analyze_certificate(file_path)
    Cert-->>Pipeline: issuer, subject, serial_number
    
    Pipeline->>String: extract_strings(file_path) & detect_indicators(strings)
    String-->>Pipeline: URLs, IPs, emails, API keys, Base64
    
    Pipeline->>Behavior: detect_behaviors(strings)
    Behavior-->>Pipeline: matching suspicious API signatures
    
    Pipeline->>DEX: analyze_dex(file_path)
    DEX-->>Pipeline: class/method bytecode matches
    
    Pipeline->>YARA: scan_with_yara(file_path)
    YARA-->>Pipeline: matched rule names and tags
    
    Pipeline->>Risk: calculate_risk_score(...)
    Risk-->>Pipeline: risk_score (int), risk_level (Low/Med/High/Critical)
    
    Pipeline->>Agent: analyze_threat(agent_input)
    Agent-->>Pipeline: threat_level, confidence, summary, key_findings
    
    Pipeline->>Twin: save_digital_twin(db, apk, twin)
    Twin->>DB: INSERT into digital_twins & digital_twin_versions
    
    Pipeline-->>API: Return complete JSON analysis object
    API-->>Client: HTTP 200 OK
```

---

## 4. Comprehensive Analyzer Explanations

### 1. Androguard Integration (`app/analysis/androguard_service.py`)
* **What it is:** Python reverse-engineering tool for Android files.
* **Why used:** Parses binary Android XML (`AndroidManifest.xml`) and DEX headers directly in Python without unzipping external tools.
* **Input:** Raw `.apk` file path.
* **Output:** Dict containing `package_name`, `app_name`, `version_name`, `version_code`, `min_sdk`, `target_sdk`, `permissions`, `activities`, `services`, `receivers`.

### 2. APKTool Decoder (`app/apktool/decoder.py`)
* **What it is:** Standard Android reverse engineering tool wrapper.
* **Why used:** Decodes binary XML resources into human-readable plaintext XML and disassembles DEX bytecode into Smali files.
* **Input:** Raw `.apk` file path.
* **Execution:** Calls `java -jar tools/apktool/apktool.jar d -f <apk_path> -o decoded/<stem>`.
* **Output:** Path to decoded directory containing readable `AndroidManifest.xml` and `smali/` folders.

### 3. Manifest Analysis (`app/manifest/`)
* **Exported Components (`exported_analyzer.py`):** Uses `lxml.etree` to find `<activity>`, `<service>`, `<receiver>`, `<provider>` elements where `android:exported="true"`. Exported components can be launched by any external app, posing attack surface vulnerabilities.
* **Intent Filters (`intent_filter_analyzer.py`):** Parses `<intent-filter>` elements for `<action>` and `<category>` (e.g. `android.intent.action.BOOT_COMPLETED` for persistent auto-start on device reboot).
* **Permission Analysis (`app/security/manifest_analyzer.py`):** Matches permissions against `DANGEROUS_PERMISSIONS` dictionary to classify severity (High/Critical) and rationale (e.g., `SEND_SMS` allows financial toll fraud).

### 4. Certificate Analysis (`app/certificate/certificate_analyzer.py`)
* **What it does:** Extracts X.509 signing certificate details via Androguard (`apk.get_certificates()`).
* **Input:** Raw `.apk` file path.
* **Output:** Issuer name, subject name, serial number.

### 5. String Analysis (`app/string_analysis/`)
* **String Extractor (`string_extractor.py`):** Calls `dex.get_strings()` across all DEX files to collect static string constants.
* **Indicator Detector (`indicator_detector.py`):** Scans collected strings using Regular Expressions (`re`) to extract C2 URLs, IP addresses, email addresses, Firebase databases, API keys, Base64 blocks, and Bitcoin wallet addresses.

### 6. Behavior Analysis (`app/behavior_analysis/behavior_detector.py`)
* **IMPORTANT CLARIFICATION:** The current implementation is **STATIC BEHAVIOR SIGNATURE MATCHING**.
* It checks if suspicious API string names (e.g., `getLine1Number`, `sendTextMessage`, `Cipher.getInstance`) exist in the DEX string pool.
* It does **NOT** observe actual dynamic runtime execution in an Android emulator or device sandbox.

### 7. DEX Analysis (`app/dex_analysis/dex_analyzer.py`)
* **What it does:** Iterates through DEX classes (`dex.get_classes()`) and methods (`cls.get_methods()`).
* **Pattern Matching:** Matches class names and method signatures against `API_PATTERNS` dictionary (detecting reflection `Class.forName`, dynamic loading `DexClassLoader`, crypto operations `Cipher`, root detection `su`).

### 8. YARA Scanner Engine (`app/yara_engine/yara_scanner.py`)
* **What it is:** Signature matching engine for malware research.
* **Execution:** Compiles `.yar` files located in `app/yara_engine/rules/` and scans the raw `.apk` file.
* **Output:** List of matched rule names, rule namespaces, tags, and rule metadata severities.

### 9. Risk Scoring Engine (`app/security/risk_engine.py`)
* **IMPORTANT CLARIFICATION:** The risk scoring engine is **RULE-BASED**, NOT Machine Learning.
* **Weights:**
  * `Critical` finding = +25 points
  * `High` finding = +15 points
  * `Medium` finding = +8 points
  * `Low` finding = +3 points
* **Risk Levels:**
  * Score $\ge 70 \implies$ **Critical**
  * Score $40 - 69 \implies$ **High**
  * Score $20 - 39 \implies$ **Medium**
  * Score $< 20 \implies$ **Low**

### 10. Digital Twin System (`app/digital_twin/`)
* **Concept:** A persistent, versioned digital replica of an APK's security posture over time.
* **State Capture:** Stores all extracted permissions, components, certificate info, indicators, behaviors, DEX findings, YARA matches, and risk scores into `digital_twin_versions`.
* **Drift Detection:** Compares Version $N$ against Version $N-1$ to detect newly added dangerous permissions, modified components, or risk escalation.

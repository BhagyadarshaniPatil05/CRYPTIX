# CRYPTIX & GARUD-AI PLATFORM VIVA STUDY NOTES

**Project Name:** CRYPTIX (Phase 1 Garud-AI Platform Foundation)  
**Target Architecture:** Multi-Agent AI Malware Analysis & Digital Twin Platform  
**Document Version:** 1.0.0  

---

## 1. Core Project Fundamentals

### Q1: What is CRYPTIX?
**Answer:** CRYPTIX is an Android malware analysis and security investigation backend platform. It automates static reverse engineering of Android Package (.apk) files, extracts security indicators, performs signature scanning, calculates rule-based risk scores, and maintains a versioned Digital Twin of application security posture.

### Q2: What problem does CRYPTIX solve?
**Answer:** Manual reverse engineering of Android malware is time-consuming and requires highly specialized tools (Androguard, APKTool, YARA). CRYPTIX automates the disassembly, static inspection, component extraction, and risk assessment into a unified API and Digital Twin system.

### Q3: How does the APK upload flow work?
**Answer:**
1. **Extension Check:** Validates file extension is `.apk`.
2. **Container Check:** Inspects the first 4 magic bytes for ZIP header signature (`PK\x03\x04`).
3. **Pre-Storage SHA-256 Hashing:** Calculates cryptographic SHA-256 directly from memory stream.
4. **Local Duplicate Lookup:** Queries local database; if SHA-256 already exists, rejects with `HTTP 409 Conflict` (0 files written to disk).
5. **Collision-Resistant Storage:** Saves file under `<sha256>.apk` path and stores original filename in database metadata.

### Q4: Why is SHA-256 used during upload?
**Answer:** SHA-256 provides a unique cryptographic fingerprint for **exact file identity**. It answers: *"Have we analyzed this exact file in our local system before?"* It prevents duplicate processing and file overwrites.  
*Clarification:* SHA-256 does NOT determine if an APK is globally malicious; global reputation requires external Threat Intelligence lookups.

---

## 2. Static Analysis Subsystems

### Q5: What does Androguard do?
**Answer:** Androguard is a Python reverse-engineering library that parses binary Android XML (`AndroidManifest.xml`) and DEX bytecode headers without executing external processes. It extracts package names, version codes/names, target SDKs, permissions, activities, services, and receivers.

### Q6: What does APKTool do?
**Answer:** APKTool is an external Java utility (`apktool.jar`) that disassembles binary Android resources into human-readable XML files and Smali code in a `decoded/` folder. It enables deep manifest parsing for intent filters and exported components.

### Q7: What is manifest analysis?
**Answer:** Manifest analysis inspects `AndroidManifest.xml` for:
1. **Dangerous Permissions:** Maps requested permissions against a severity dictionary (Low, Medium, High, Critical).
2. **Exported Components:** Identifies activities, services, receivers, and providers with `android:exported="true"`, representing external attack surface.
3. **Intent Filters:** Extracts activity actions (e.g. `BOOT_COMPLETED`) to detect auto-start behaviors.

### Q8: What is certificate fingerprinting?
**Answer:** Certificate analysis extracts raw X.509 DER certificate bytes from the APK signature and computes SHA-256 and SHA-1 public certificate fingerprints.  
*Interpretation:* Certificate fingerprints provide an immutable cryptographic developer signature for publisher tracking and developer correlation.

### Q9: What are Indicators of Compromise (IOCs)?
**Answer:** IOCs are static network and system artifacts extracted from DEX string pools using regular expressions, including C2 URLs, IP addresses, email addresses, Firebase URLs, API keys, Base64 blocks, and Bitcoin wallet addresses.

### Q10: What is static behavior analysis?
**Answer:** Static behavior analysis checks DEX string pools against sensitive Android API signatures (`Runtime.exec`, `DexClassLoader`, `su`, `SmsManager`).  
*Crucial distinction:* This is **STATIC pattern matching**, NOT dynamic runtime execution. No code is executed on the host.

### Q11: What is DEX analysis?
**Answer:** DEX analysis inspects class names and method signatures in DEX bytecode against `API_PATTERNS` to detect reflection, dynamic code loading, native library calls, and cryptography APIs (`Cipher`, `MessageDigest`).

### Q12: What is YARA?
**Answer:** YARA is a pattern-matching engine used by malware researchers. CRYPTIX compiles `.yar` rules in `app/yara_engine/rules/` and scans the raw APK to detect malware signatures and behavioral tags.

---

## 3. Risk Engine & Digital Twin

### Q13: How does the current risk engine work?
**Answer:** The risk engine is **RULE-BASED**. It sums weighted severities across dangerous permissions, static behaviors, and YARA matches:
* `Critical` = +25 points
* `High` = +15 points
* `Medium` = +8 points
* `Low` = +3 points  

**Risk Thresholds:** Score $\ge 70 \implies$ **Critical**, $40-69 \implies$ **High**, $20-39 \implies$ **Medium**, $< 20 \implies$ **Low**.

### Q14: What is a Digital Twin in CRYPTIX?
**Answer:** A Digital Twin is a persistent, versioned digital replica of an APK's security posture. It stores state snapshots in `digital_twins` and `digital_twin_versions` database tables, allowing security analysts to track security drift and version changes over time.

---

## 4. Architectural Boundaries & Future Roadmap

### Q15: Why is the current system NOT yet dynamic analysis?
**Answer:** Dynamic analysis requires running the APK inside an isolated Android emulator or sandbox to capture live process, network, SMS, and filesystem activity. Current CRYPTIX analysis is 100% static inspection of files and strings without code execution.

### Q16: Why is the current risk engine NOT Machine Learning (ML)?
**Answer:** It uses deterministic rule-based severity weights and thresholds. Machine learning models require trained classifiers (e.g., Random Forest or SVM) trained on labeled dataset vectors.

### Q17: What advanced Garud-AI features are planned for future phases?
**Answer:**
1. **Global Threat Intelligence:** VirusTotal / AbuseIPDB / OTZ hash lookups.
2. **Malware DNA Fingerprinting:** High-dimensional vector synthesis.
3. **Threat Memory:** Fast exact and DNA similarity lookups.
4. **MITRE ATT&CK Mapping:** Automatic mapping of evidence to ATT&CK technique IDs.
5. **Cybersecurity RAG Engine:** AI retrieval over MITRE and CVE threat reports.
6. **Multi-Agent AI Investigation:** Collaborative LLM agent orchestration.
7. **Dynamic Android Sandbox:** Live behavioral monitoring in isolated environments.

---

## 5. Phase 3.1 — Malware DNA Fingerprinting Engine

### Q18: What is Malware DNA in Garud-AI?
**Answer:** Malware DNA is a deterministic static feature fingerprint (`DNA-<sha256>`) and categorical Jaccard set similarity engine. It abstracts static features (permissions, components, intent filters, behaviors, DEX bytecode, YARA rules, IOC presence, certificate fingerprints) into a canonical, deduplicated, sorted JSON structure and computes a hash over the normalized feature set.

### Q19: How does Malware DNA differ from File SHA-256?
**Answer:**
* **File SHA-256:** Cryptographic hash of exact raw file bytes. Changing 1 byte (e.g. repacking an APK with a new comment or different certificate) yields a completely different file SHA-256.
* **Malware DNA Hash (`DNA-<sha256>`):** Hash of canonical normalized static features. Repacked samples or variants with identical capabilities produce **identical Malware DNA hashes**, enabling instant lineage and family matching even when file SHA-256 hashes differ.

### Q20: How does Jaccard Similarity work in Malware DNA?
**Answer:** For any feature set $A$ and $B$, the Jaccard similarity index is:
$$J(A, B) = \frac{|A \cap B|}{|A \cup B|}$$
Where $|A \cap B|$ is the count of shared features, and $|A \cup B|$ is the count of total unique features across both samples.

### Q21: What are the category weights used for similarity scoring?
**Answer:**
* **Manifest Features (Permissions, Components, Intents, SDKs):** 20%
* **Static Behaviors:** 25%
* **DEX Bytecode Patterns:** 20%
* **YARA Rules:** 15%
* **IOC Presence Categories:** 10%
* **Certificate Signature:** 10%
* *Total Weighted Similarity Score:* $\sum (\text{Category Jaccard} \times \text{Weight}) \times 100\%$

### Q22: Is Malware DNA an ML vector or embedding?
**Answer:** **No.** It is a 100% deterministic, explainable static set similarity algorithm. It guarantees 100% reproducible results without black-box ML model drift or vector quantization errors. It outputs exact lists of shared and differing features for analyst auditability.

---

## 6. Phase 3.2 — Threat Memory & Historical Intelligence Engine

### Q23: What is Threat Memory in Garud-AI?
**Answer:** Threat Memory is GARUD-AI's local historical intelligence layer. It evaluates incoming APK samples against previously analyzed database records using a 4-level decision tree (Exact SHA-256 Match, High DNA Similarity, Related Sample, New Sample) to retrieve prior threat evidence, historical risk scores, and Digital Twin references.

### Q24: What is the 4-level decision hierarchy in Threat Memory?
**Answer:**
1. **LEVEL 1 (`KNOWN_EXACT`):** Exact binary SHA-256 match found in local database. Takes absolute precedence over DNA.
2. **LEVEL 2 (`HIGH_SIMILARITY`):** Malware DNA Jaccard similarity $\ge 65.0\%$. Indicates strong structural lineage or repacked malware variant.
3. **LEVEL 3 (`RELATED_SAMPLE`):** Malware DNA Jaccard similarity $\ge 35.0\%$. Indicates meaningful capability or framework overlap.
4. **LEVEL 4 (`NEW_SAMPLE`):** No exact SHA-256 match and no Malware DNA similarity $\ge 35.0\%$.

### Q25: Does `NEW_SAMPLE` mean the APK is safe or benign?
**Answer:** **No.** `NEW_SAMPLE` only means the sample has not been previously seen in the **local Threat Memory database**. The sample must still be evaluated strictly by the static analysis pipeline, risk engine, and YARA scanner.

### Q26: Does Threat Memory use external threat feeds or AI/RAG?
**Answer:** **No.** Threat Memory is 100% local, offline, deterministic, and explainable. It does NOT make outbound network calls to external feeds (VirusTotal, AbuseIPDB) nor does it use LLM RAG or vector databases.

---

## 7. Phase 3.3 — Global Threat Intelligence Integration

### Q27: What is Global Threat Intelligence (TI) in Garud-AI?
**Answer:** Global Threat Intelligence enriches local static analysis, Malware DNA, and Threat Memory evidence with external reputation signals from **VirusTotal** (file hash reputation), **AbuseIPDB** (extracted IP reputation), and **AlienVault OTX** (indicator pulses).

### Q28: What is the Hash-First Privacy Rule?
**Answer:** GARUD-AI **never uploads raw APK binary files** to VirusTotal or external cloud threat feeds. VirusTotal queries use the calculated `SHA-256` hash digest exclusively (`GET /api/v3/files/{sha256}`). This protects sample secrecy and analyst confidentiality.

### Q29: How does AbuseIPDB query IP addresses safely?
**Answer:** Before sending IP addresses to AbuseIPDB, GARUD-AI filters out private, loopback, link-local, or multicast IPs (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`). Only valid public IPv4 addresses extracted during string analysis are queried.

### Q30: How does TI failure isolation work in the analysis pipeline?
**Answer:** External TI queries execute in Step 17 of the static analysis pipeline wrapped in an isolated exception handler. Network timeouts, rate limits, missing API keys, or provider outages will **never crash** local static analysis, Digital Twin creation, Malware DNA generation, or Threat Memory evaluation.

### Q31: How does DB caching work for Threat Intelligence?
**Answer:** Queries are cached in the `threat_intelligence` table with a configurable TTL (default 24 hours). Before calling external endpoints, the cache service checks for unexpired matching records. Valid hits set `cached = True` to conserve API quota.

---

## 8. Phase 3.4 — MITRE ATT&CK + IOC Intelligence Mapping

### Q32: What is the MITRE ATT&CK mapping engine in Garud-AI?
**Answer:** The MITRE ATT&CK mapping engine translates normalized static analysis evidence (DEX bytecode patterns, suspicious APIs, dangerous permissions, manifest intents, IOCs, YARA matches) into standardized adversary tactics and techniques defined in the official **MITRE ATT&CK for Mobile (v15.1)** matrix.

### Q33: Does Garud-AI use AI or Machine Learning to classify MITRE techniques?
**Answer:** **No.** GARUD-AI uses a **100% deterministic, rule-based mapping engine**. Every technique mapping is directly traceable to the specific static evidence items and rule IDs (`RULE-MOB-001` to `RULE-MOB-027`) that triggered it. It does NOT use LLMs, vector databases, embeddings, or black-box ML classifiers.

### Q34: How does Garud-AI control false positives for dangerous permissions?
**Answer:** Manifest permissions requested in isolation (e.g. `SEND_SMS` permission without `SmsManager` DEX API) default to `MEDIUM` confidence. When supported by active DEX bytecode or static behavior API calls, confidence is elevated to `HIGH` with an explicit audit rationale.

### Q35: What ATT&CK domain is prioritized in Garud-AI?
**Answer:** GARUD-AI prioritizes **MITRE ATT&CK for Mobile (v15.1)** (e.g., `T1406` Dynamic Code Loading/Obfuscation, `T1517` Remote Subprocess Execution, `T1630` Premium Service Abuse, `T1430` Location Tracking, `T1626` Rooting / Privilege Escalation, `T1437` Application Protocol C2).

### Q36: How is MITRE mapping isolated in the analysis pipeline?
**Answer:** MITRE mapping executes in **Step 18** of the static analysis pipeline wrapped in an isolated exception handler. Any error or malformed data in mapping will **never crash** previous static analysis, Digital Twin creation, Malware DNA fingerprinting, Threat Memory evaluation, or Global Threat Intelligence lookups.





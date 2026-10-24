# Phase 3.4.1 — MITRE ATT&CK Mapping Accuracy Audit & Technical Documentation

## 1. Executive Summary
GARUD-AI / CRYPTIX Phase 3.4.1 completes the **MITRE ATT&CK Mapping Accuracy Audit & Semantic Correction**.

Following an exhaustive audit of all 27 mapping rules against the official **MITRE ATT&CK for Mobile (v15.1)** matrix taxonomy, incorrect technique assignments (such as treating T1517 as shell execution, T1407 as embedded API keys, T1630 as premium SMS, and T1471 as crypto APIs) were removed or replaced with semantically accurate Mobile ATT&CK techniques.

---

## 2. Audit Findings & Mapping Corrections Table

| Rule ID | Evidence Source | Trigger Pattern | Old Mapping (Incorrect) | New Mapping (Audited & Corrected) | Status | Semantic Rationale & Limitation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE-MOB-001` | DEX | `DexClassLoader` | T1406 (Obfuscated) | **T1406** (Obfuscated Files) | **RETAINED** | Dynamic code loading capability (`MEDIUM` confidence). Static capability only. |
| `RULE-MOB-002` | DEX | `PathClassLoader` | T1406 (Obfuscated) | **T1406** (Obfuscated Files) | **RETAINED** | Class loading capability (`LOW` confidence). |
| `RULE-MOB-003` | DEX | `Class.forName` | T1406 (Obfuscated) | **T1406** (Obfuscated Files) | **RETAINED** | Reflection API capability (`LOW` confidence). |
| `RULE-MOB-004` | DEX | `Method.invoke` | T1406 (Obfuscated) | **T1406** (Obfuscated Files) | **RETAINED** | Reflection invocation capability (`LOW` confidence). |
| `RULE-MOB-005` | DEX | `SmsManager` | T1630 (Indicator Removal) | **T1412** (SMS Control) | **CORRECTED** | Replaced T1630 (Indicator Removal) with official Mobile technique **T1412 (SMS Control)** (`HIGH` confidence). |
| `RULE-MOB-006` | Permission | `SEND_SMS` | T1630 (Indicator Removal) | **T1412** (SMS Control) | **CORRECTED** | Replaced T1630 with **T1412** (`MEDIUM` confidence). Permission grant provides candidate capability. |
| `RULE-MOB-007` | Permission | `RECEIVE_SMS` | T1630 (Indicator Removal) | **T1412** (SMS Control) | **CORRECTED** | Replaced T1630 with **T1412** (`MEDIUM` confidence). Permission grant provides candidate capability. |
| `RULE-MOB-008` | Permission | `READ_SMS` | T1630 (Indicator Removal) | **T1412** (SMS Control) | **CORRECTED** | Replaced T1630 with **T1412** (`MEDIUM` confidence). Permission grant provides candidate capability. |
| `RULE-MOB-009` | DEX | `LocationManager` | T1430 (Location Tracking)| **T1430** (Location Tracking) | **RETAINED** | Location API capability (`HIGH` confidence). |
| `RULE-MOB-010` | Permission | `ACCESS_FINE_LOCATION` | T1430 (Location Tracking)| **T1430** (Location Tracking) | **RETAINED** | Location permission (`MEDIUM` confidence). |
| `RULE-MOB-011` | Behavior | `su` | T1626 (Elevation Control) | **T1626** (Elevation Control) | **RETAINED** | Root binary execution reference (`MEDIUM` candidate confidence). |
| `RULE-MOB-012` | DEX | `HttpURLConnection` | T1437 (App Protocol) | **T1437.001** (Web Protocols) | **CORRECTED** | Mapped to sub-technique **T1437.001** (`MEDIUM` confidence). Static HTTP capability only. |
| `RULE-MOB-013` | DEX | `Socket` | T1437 (App Protocol) | **T1437** (App Protocol) | **RETAINED** | Raw TCP socket capability (`MEDIUM` confidence). |
| `RULE-MOB-014` | DEX | `TelephonyManager` | T1426 (System Info) | **T1426** (System Info) | **RETAINED** | Telephony API system info query (`MEDIUM` confidence). |
| `RULE-MOB-015` | Permission | `READ_CONTACTS` | T1426 (System Info) | **T1432** (Access Contact List)| **CORRECTED** | Replaced T1426 with official Mobile technique **T1432 (Access Contact List)** (`MEDIUM` confidence). |
| `RULE-MOB-016` | Intent | `BOOT_COMPLETED` | T1624 (Event Triggered) | **T1624** (Event Triggered) | **RETAINED** | System boot completion broadcast receiver (`HIGH` confidence). |
| `RULE-MOB-017` | Intent | `SMS_RECEIVED` | T1624 (Event Triggered) | **T1624** (Event Triggered) | **RETAINED** | Incoming SMS broadcast receiver (`HIGH` confidence). |
| `RULE-MOB-018` | Permission | `RECORD_AUDIO` | T1420 (Audio Capture) | **T1420** (Audio Capture) | **RETAINED** | Microphone permission (`MEDIUM` confidence). |
| `RULE-MOB-019` | IOC | `api_keys` | T1407 (Download Code) | **T1409** (Credentials in Files)| **CORRECTED** | Replaced T1407 (Download Code) with **T1409 (Credentials in Files)** (`MEDIUM` confidence). |
| *Removed* | DEX/Behavior | `Runtime.exec` | T1517 (Access Notif.) | **NO ATT&CK MAPPING** | **REMOVED** | T1517 is Access Notifications. Shell command execution has no specific Mobile technique. Kept as DEX evidence item. |
| *Removed* | DEX/Behavior | `ProcessBuilder` | T1517 (Access Notif.) | **NO ATT&CK MAPPING** | **REMOVED** | Removed invalid T1517 mapping. Kept as DEX evidence item. |
| *Removed* | Behavior | `busybox`, `chmod` | T1626 (Elevation Control) | **NO ATT&CK MAPPING** | **REMOVED** | `busybox`/`chmod` alone do not prove elevation control abuse. Kept as static behavior findings. |
| *Removed* | IOC | `ip_addresses` | T1437 (App Protocol) | **NO ATT&CK MAPPING** | **REMOVED** | Raw IP strings alone do not prove C2 behavior. Kept as pure IOC evidence. |
| *Removed* | IOC | `base64_strings` | T1407 (Download Code) | **NO ATT&CK MAPPING** | **REMOVED** | Base64 strings alone do not prove code download. Kept as pure IOC evidence. |
| *Removed* | DEX | `Cipher`, `MessageDigest` | T1471 (Ransomware Encrypt)| **NO ATT&CK MAPPING** | **REMOVED** | Crypto APIs do not prove ransomware encryption for impact. Kept as DEX cryptography findings. |

---

## 3. Explicit Static Analysis Limitation Statement

> **ATTENTION**: Static MITRE Mobile ATT&CK mappings in GARUD-AI represent **evidence-supported candidate capabilities** based on static bytecode, permissions, intent filters, and signatures. They do **NOT** guarantee that active runtime behavior, C2 transmission, or malicious exploitation occurred.

---

## 4. Verification & Regression Matrix

- **Backend Pytest Test Suite**: **62/62 PASSED** (53 baseline + 9 semantic accuracy tests, 100% pass rate in 17.32s).
- **Frontend Production Build**: `npm run build` completed cleanly in 1.01s with 0 errors.

"""
Semantically Corrected Mapping Rules for MITRE ATT&CK for Mobile (v15.1).
Maps normalized static analysis findings to official Mobile ATT&CK techniques with
explainable confidence levels, capability language, and explicit static-analysis limitation notices.
"""

MITRE_RULES = [
    # 1. Dynamic Code Loading & Reflection (T1406)
    {
        "rule_id": "RULE-MOB-001",
        "technique_id": "T1406",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "DexClassLoader",
        "confidence": "MEDIUM",
        "explanation": "Static DEX analysis identified DexClassLoader capability, which allows dynamic loading of application classes at runtime.",
        "limitation": "Static analysis indicates dynamic loading capability only; runtime loading or execution of external payload is unconfirmed.",
    },
    {
        "rule_id": "RULE-MOB-002",
        "technique_id": "T1406",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "PathClassLoader",
        "confidence": "LOW",
        "explanation": "Static DEX analysis identified PathClassLoader usage for class loading.",
        "limitation": "Standard Android classloader pattern; does not prove malicious obfuscation.",
    },
    {
        "rule_id": "RULE-MOB-003",
        "technique_id": "T1406",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "Class.forName",
        "confidence": "LOW",
        "explanation": "Static DEX analysis identified Class.forName reflection API capability.",
        "limitation": "Reflection is common in framework libraries; candidate obfuscation only.",
    },
    {
        "rule_id": "RULE-MOB-004",
        "technique_id": "T1406",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "Method.invoke",
        "confidence": "LOW",
        "explanation": "Static DEX analysis identified Method.invoke reflection invocation API capability.",
        "limitation": "Reflection is common in framework libraries; candidate obfuscation only.",
    },

    # 2. SMS Control (T1412) - Replaced incorrect T1630
    {
        "rule_id": "RULE-MOB-005",
        "technique_id": "T1412",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "SmsManager",
        "confidence": "HIGH",
        "explanation": "Static DEX bytecode analysis identified SmsManager API usage for sending or reading SMS messages.",
        "limitation": "Static bytecode references confirmed API presence; actual message transmission depends on runtime execution.",
    },
    {
        "rule_id": "RULE-MOB-006",
        "technique_id": "T1412",
        "evidence_type": "DANGEROUS_PERMISSION",
        "evidence_key": "android.permission.SEND_SMS",
        "confidence": "MEDIUM",
        "explanation": "Manifest requests SEND_SMS permission, indicating candidate SMS control capability.",
        "limitation": "Permission grant alone provides capability only; actual SMS transmission requires supporting API calls.",
    },
    {
        "rule_id": "RULE-MOB-007",
        "technique_id": "T1412",
        "evidence_type": "DANGEROUS_PERMISSION",
        "evidence_key": "android.permission.RECEIVE_SMS",
        "confidence": "MEDIUM",
        "explanation": "Manifest requests RECEIVE_SMS permission, indicating candidate SMS interception capability.",
        "limitation": "Permission grant alone provides capability only; actual SMS interception requires broadcast handling.",
    },
    {
        "rule_id": "RULE-MOB-008",
        "technique_id": "T1412",
        "evidence_type": "DANGEROUS_PERMISSION",
        "evidence_key": "android.permission.READ_SMS",
        "confidence": "MEDIUM",
        "explanation": "Manifest requests READ_SMS permission, indicating candidate SMS reading capability.",
        "limitation": "Permission grant alone provides capability only; actual SMS database access requires runtime execution.",
    },

    # 3. Location Tracking (T1430)
    {
        "rule_id": "RULE-MOB-009",
        "technique_id": "T1430",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "LocationManager",
        "confidence": "HIGH",
        "explanation": "Static DEX bytecode analysis identified LocationManager API references for GPS/network location tracking.",
        "limitation": "Static bytecode references confirmed location API capability; runtime tracking depends on execution.",
    },
    {
        "rule_id": "RULE-MOB-010",
        "technique_id": "T1430",
        "evidence_type": "DANGEROUS_PERMISSION",
        "evidence_key": "android.permission.ACCESS_FINE_LOCATION",
        "confidence": "MEDIUM",
        "explanation": "Manifest requests ACCESS_FINE_LOCATION permission for precise location access.",
        "limitation": "Permission grant alone provides location access capability; runtime location polling requires active API calls.",
    },

    # 4. Abuse Elevation Control Mechanism / Rooting (T1626)
    {
        "rule_id": "RULE-MOB-011",
        "technique_id": "T1626",
        "evidence_type": "STATIC_BEHAVIOR",
        "evidence_key": "su",
        "confidence": "MEDIUM",
        "explanation": "Static string analysis detected 'su' binary string reference, indicating candidate root access capability check.",
        "limitation": "Static string reference indicates root capability check; successful root elevation is unconfirmed.",
    },

    # 5. Application Layer Protocol (T1437 / T1437.001) - Replaced incorrect raw IP mapping
    {
        "rule_id": "RULE-MOB-012",
        "technique_id": "T1437.001",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "HttpURLConnection",
        "confidence": "MEDIUM",
        "explanation": "Static DEX bytecode analysis identified HttpURLConnection networking API for potential web protocol communication.",
        "limitation": "Static API finding indicates HTTP communication capability; active C2 transmission is unconfirmed.",
    },
    {
        "rule_id": "RULE-MOB-013",
        "technique_id": "T1437",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "Socket",
        "confidence": "MEDIUM",
        "explanation": "Static DEX bytecode analysis identified raw Socket communication capability.",
        "limitation": "Static API finding indicates raw TCP socket capability; active C2 connection is unconfirmed.",
    },

    # 6. System Information Discovery (T1426)
    {
        "rule_id": "RULE-MOB-014",
        "technique_id": "T1426",
        "evidence_type": "DEX_BEHAVIOR",
        "evidence_key": "TelephonyManager",
        "confidence": "MEDIUM",
        "explanation": "Static DEX bytecode analysis identified TelephonyManager API usage to query device hardware or subscriber state.",
        "limitation": "Static API finding indicates system info query capability.",
    },

    # 7. Access Contact List (T1432) - Replaced incorrect T1426
    {
        "rule_id": "RULE-MOB-015",
        "technique_id": "T1432",
        "evidence_type": "DANGEROUS_PERMISSION",
        "evidence_key": "android.permission.READ_CONTACTS",
        "confidence": "MEDIUM",
        "explanation": "Manifest requests READ_CONTACTS permission, indicating candidate contact list access capability.",
        "limitation": "Permission grant alone provides capability only; actual contact harvesting requires runtime query.",
    },

    # 8. Event Triggered Execution (T1624)
    {
        "rule_id": "RULE-MOB-016",
        "technique_id": "T1624",
        "evidence_type": "MANIFEST_INTENT",
        "evidence_key": "BOOT_COMPLETED",
        "confidence": "HIGH",
        "explanation": "Manifest intent filter registers for BOOT_COMPLETED broadcast to achieve automatic execution on system boot.",
        "limitation": "Manifest registration confirmed; actual execution occurs when device reboots.",
    },
    {
        "rule_id": "RULE-MOB-017",
        "technique_id": "T1624",
        "evidence_type": "MANIFEST_INTENT",
        "evidence_key": "SMS_RECEIVED",
        "confidence": "HIGH",
        "explanation": "Manifest intent filter registers for SMS_RECEIVED broadcast to trigger code execution on incoming messages.",
        "limitation": "Manifest registration confirmed; actual execution occurs when an SMS is received.",
    },

    # 9. Audio Capture (T1420)
    {
        "rule_id": "RULE-MOB-018",
        "technique_id": "T1420",
        "evidence_type": "DANGEROUS_PERMISSION",
        "evidence_key": "android.permission.RECORD_AUDIO",
        "confidence": "MEDIUM",
        "explanation": "Manifest requests RECORD_AUDIO permission, indicating candidate ambient audio capture capability.",
        "limitation": "Permission grant alone provides capability only; actual audio recording requires MediaRecorder/AudioRecord API calls.",
    },

    # 10. Credentials in Files (T1409) - Replaced incorrect T1407
    {
        "rule_id": "RULE-MOB-019",
        "technique_id": "T1409",
        "evidence_type": "IOC_INDICATOR",
        "evidence_key": "api_keys",
        "confidence": "MEDIUM",
        "explanation": "Extracted hardcoded API key string patterns embedded in binary assets indicate candidate credentials in files.",
        "limitation": "Static string regex match; active credential abuse requires runtime context.",
    },
]

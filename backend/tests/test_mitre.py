"""
Comprehensive Test Suite for Phase 3.4.1 — MITRE ATT&CK Mapping Accuracy Audit & Correction.
Validates official Mobile ATT&CK technique IDs (v15.1), rejection of incorrect mappings (T1517 for Runtime.exec,
T1407 for API keys, T1630 for SMS, T1471 for Cipher), permission confidence controls, and REST APIs.
"""
import pytest
from app.models.apk import APKMetadata
from app.models.mitre import MitreMapping
from app.mitre.catalog import get_technique, ATTACK_VERSION, ATTACK_DOMAIN
from app.mitre.mapping_engine import extract_normalized_evidence, map_evidence_to_mitre
from app.mitre.service import evaluate_and_store_mitre_mappings, get_mitre_mappings_by_apk


# =====================================================================
# 1. CATALOG ACCURACY TESTS
# =====================================================================

def test_technique_catalog_accuracy():
    # T1406: Obfuscated Files or Information
    t1406 = get_technique("T1406")
    assert t1406 is not None
    assert t1406["technique_name"] == "Obfuscated Files or Information"
    assert t1406["tactic"] == "Defense Evasion"
    assert t1406["domain"] == ATTACK_DOMAIN

    # T1412: SMS Control (Replaced incorrect T1630)
    t1412 = get_technique("T1412")
    assert t1412 is not None
    assert t1412["technique_name"] == "SMS Control"
    assert t1412["tactic"] == "Collection"

    # T1409: Credentials in Files (Replaced incorrect T1407)
    t1409 = get_technique("T1409")
    assert t1409 is not None
    assert t1409["technique_name"] == "Credentials in Files"
    assert t1409["tactic"] == "Credential Access"

    # T1437.001: Application Layer Protocol: Web Protocols
    t1437_sub = get_technique("T1437.001")
    assert t1437_sub is not None
    assert t1437_sub["is_subtechnique"] is True
    assert t1437_sub["parent_id"] == "T1437"

    # T1517 (Access Notifications) should NOT be in our catalog as "Execution via System Subprocess"
    t1517 = get_technique("T1517")
    assert t1517 is None


# =====================================================================
# 2. SEMANTIC ACCURACY & NEGATIVE MAPPING TESTS
# =====================================================================

def test_runtime_exec_does_not_map_to_t1517():
    sample_analysis = {
        "dex_findings": [{"api": "Runtime.exec", "category": "Command Execution", "severity": "High", "reason": "Executes shell"}],
        "behaviors": [{"api": "ProcessBuilder", "severity": "High", "reason": "Process creation"}],
    }
    mappings = map_evidence_to_mitre(sample_analysis)
    tech_ids = [m["technique_id"] for m in mappings]

    # Runtime.exec / ProcessBuilder must NOT map to T1517 (Access Notifications)
    assert "T1517" not in tech_ids


def test_api_keys_do_not_map_to_t1407_or_t1471():
    sample_analysis = {
        "indicators": {"api_keys": ["AIzaSy1234567890"], "base64_strings": ["SGVsbG8gV29ybGQ="]},
        "dex_findings": [{"api": "Cipher", "category": "Cryptography", "severity": "Low", "reason": "Encryption"}],
    }
    mappings = map_evidence_to_mitre(sample_analysis)
    tech_ids = [m["technique_id"] for m in mappings]

    # API keys must NOT map to T1407 (Download New Code)
    assert "T1407" not in tech_ids
    # Cipher API must NOT map to T1471 (Data Encrypted for Impact / Ransomware)
    assert "T1471" not in tech_ids

    # API keys map to T1409 (Credentials in Files)
    assert "T1409" in tech_ids


def test_sms_behavior_maps_to_t1412_not_t1630():
    sample_analysis = {
        "dex_findings": [{"api": "SmsManager", "category": "SMS", "severity": "Critical", "reason": "SMS API"}],
        "dangerous_permissions": [{"permission": "android.permission.SEND_SMS", "severity": "Critical", "reason": "SMS"}],
    }
    mappings = map_evidence_to_mitre(sample_analysis)
    tech_ids = [m["technique_id"] for m in mappings]

    # SMS must NOT map to T1630 (Indicator Removal on Host)
    assert "T1630" not in tech_ids
    # SMS maps to T1412 (SMS Control)
    assert "T1412" in tech_ids


def test_ip_address_alone_does_not_map_to_t1437():
    sample_analysis = {
        "indicators": {"ip_addresses": ["1.1.1.1", "8.8.8.8"]},
    }
    mappings = map_evidence_to_mitre(sample_analysis)
    tech_ids = [m["technique_id"] for m in mappings]

    # Extracted IP strings alone without networking APIs must NOT map to T1437
    assert "T1437" not in tech_ids
    assert "T1437.001" not in tech_ids


def test_permission_only_confidence_is_medium_not_high():
    sample_analysis = {
        "dangerous_permissions": [{"permission": "android.permission.SEND_SMS", "severity": "Critical", "reason": "SMS"}],
    }
    mappings = map_evidence_to_mitre(sample_analysis)
    sms_mapping = next(m for m in mappings if m["evidence_reference"] == "android.permission.SEND_SMS")

    # Permission grant alone provides capability only -> MEDIUM confidence
    assert sms_mapping["confidence"] == "MEDIUM"


def test_permission_supported_by_dex_behavior_elevates_to_high():
    sample_analysis = {
        "dangerous_permissions": [{"permission": "android.permission.SEND_SMS", "severity": "Critical", "reason": "SMS"}],
        "dex_findings": [{"api": "SmsManager", "category": "SMS", "severity": "Critical", "reason": "SMS API"}],
    }
    mappings = map_evidence_to_mitre(sample_analysis)
    sms_perm_mapping = next(m for m in mappings if m["evidence_reference"] == "android.permission.SEND_SMS")

    # Permission supported by active DEX API -> elevated to HIGH confidence
    assert sms_perm_mapping["confidence"] == "HIGH"


# =====================================================================
# 3. DATABASE PERSISTENCE & API ENDPOINT TESTS
# =====================================================================

def test_mitre_persistence_service(client):
    from app.database.session import get_db

    db = next(client.app.dependency_overrides[get_db]())
    apk = APKMetadata(
        file_name="mitre_audit_test.apk",
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        file_size=2048,
        file_path="uploads/mitre_audit_test.apk",
        status="uploaded"
    )
    db.add(apk)
    db.commit()
    db.refresh(apk)

    sample_analysis = {
        "dex_findings": [{"api": "DexClassLoader", "category": "Dynamic Loading", "severity": "Critical", "reason": "Loads code"}],
        "dangerous_permissions": [{"permission": "android.permission.RECORD_AUDIO", "severity": "High", "reason": "Audio"}],
    }

    saved = evaluate_and_store_mitre_mappings(db=db, apk_id=apk.id, analysis_results=sample_analysis)
    assert len(saved) >= 2

    retrieved = get_mitre_mappings_by_apk(db=db, apk_id=apk.id)
    assert len(retrieved) == len(saved)
    assert any(r.technique_id == "T1406" for r in retrieved)


def test_mitre_api_endpoints(client):
    from app.database.session import get_db

    db = next(client.app.dependency_overrides[get_db]())
    apk = APKMetadata(
        file_name="api_mitre_audit.apk",
        sha256="0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
        file_size=4096,
        file_path="uploads/api_mitre_audit.apk",
        status="uploaded"
    )
    db.add(apk)
    db.commit()
    db.refresh(apk)

    mapping = MitreMapping(
        apk_id=apk.id,
        technique_id="T1406",
        technique_name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        evidence_type="DEX_BEHAVIOR",
        evidence_reference="DexClassLoader",
        evidence_summary="Loads code dynamically. Limitation: Static analysis capability only.",
        confidence="MEDIUM",
        rule_id="RULE-MOB-001",
        attack_version=ATTACK_VERSION,
    )
    db.add(mapping)
    db.commit()

    # GET /api/v1/mitre/{apk_id}
    res = client.get(f"/api/v1/mitre/{apk.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["apk_id"] == apk.id
    assert data["total_mappings"] == 1
    assert data["mappings"][0]["technique_id"] == "T1406"
    assert data["mappings"][0]["technique_name"] == "Obfuscated Files or Information"

    # GET /api/v1/mitre/{apk_id}/tactics
    res_tactics = client.get(f"/api/v1/mitre/{apk.id}/tactics")
    assert res_tactics.status_code == 200
    data_tactics = res_tactics.json()
    assert "Defense Evasion" in data_tactics["tactics"]

    # GET /api/v1/mitre/{apk_id}/iocs
    res_iocs = client.get(f"/api/v1/mitre/{apk.id}/iocs")
    assert res_iocs.status_code == 200
    data_iocs = res_iocs.json()
    assert "ioc_technique_mappings" in data_iocs

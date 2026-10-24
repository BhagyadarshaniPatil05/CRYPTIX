import pytest
from app.models.apk import APKMetadata
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion
from app.models.malware_dna import MalwareDNA
from app.threat_memory.config import (
    HIGH_SIMILARITY_THRESHOLD,
    RELATED_SAMPLE_THRESHOLD,
    STATUS_KNOWN_EXACT,
    STATUS_HIGH_SIMILARITY,
    STATUS_RELATED_SAMPLE,
    STATUS_NEW_SAMPLE,
    STATUS_ERROR,
)
from app.threat_memory.decision_engine import evaluate_threat_memory
from app.threat_memory.memory_service import (
    evaluate_and_store_threat_memory,
    get_threat_memory_by_apk_id,
    get_historical_matches,
)
from app.malware_dna.dna_service import generate_and_store_dna


def test_threshold_configuration_constants():
    assert HIGH_SIMILARITY_THRESHOLD == 65.0
    assert RELATED_SAMPLE_THRESHOLD == 35.0
    assert STATUS_KNOWN_EXACT == "KNOWN_EXACT"
    assert STATUS_HIGH_SIMILARITY == "HIGH_SIMILARITY"
    assert STATUS_RELATED_SAMPLE == "RELATED_SAMPLE"
    assert STATUS_NEW_SAMPLE == "NEW_SAMPLE"
    assert STATUS_ERROR == "ERROR"


def test_new_sample_classification(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apk = APKMetadata(
        file_name="first_sample.apk",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        file_size=1024,
        file_path="/tmp/first_sample.apk",
        package_name="com.first.sample",
        version="1.0"
    )
    db.add(apk)
    db.commit()
    db.refresh(apk)

    generate_and_store_dna(db, apk.id, {"permissions": ["android.permission.INTERNET"]})

    decision = evaluate_threat_memory(db, apk.id)
    assert decision["status"] == STATUS_NEW_SAMPLE
    assert decision["exact_match"] is False
    assert decision["best_match"] is None
    assert "NEW TO LOCAL THREAT MEMORY" in decision["explanation"]["summary"]


def test_exact_sha256_match(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    sha_val = "2222222222222222222222222222222222222222222222222222222222222222"

    apk1 = APKMetadata(
        file_name="original.apk",
        sha256=sha_val,
        file_size=2048,
        file_path="/tmp/original.apk",
        package_name="com.example.app",
        version="1.0"
    )
    db.add(apk1)
    db.commit()
    db.refresh(apk1)

    generate_and_store_dna(db, apk1.id, {"permissions": ["android.permission.INTERNET"]})

    # Add Digital Twin to simulate prior risk metrics
    twin = DigitalTwin(apk_id=apk1.id, package_name="com.example.app", app_name="Original")
    db.add(twin)
    db.commit()
    db.refresh(twin)

    ver = DigitalTwinVersion(
        digital_twin_id=twin.id,
        version_number=1,
        package_name="com.example.app",
        risk_score=75,
        risk_level="HIGH",
        threat_level="CRITICAL",
        permissions=["android.permission.INTERNET"]
    )
    db.add(ver)
    db.commit()

    # Second APK record with identical SHA-256 (re-uploaded sample)
    apk2 = APKMetadata(
        file_name="duplicate.apk",
        sha256=sha_val,
        file_size=2048,
        file_path="/tmp/duplicate.apk",
        package_name="com.example.app",
        version="1.0"
    )
    db.add(apk2)
    db.commit()
    db.refresh(apk2)

    generate_and_store_dna(db, apk2.id, {"permissions": ["android.permission.INTERNET"]})

    decision = evaluate_threat_memory(db, apk2.id)
    assert decision["status"] == STATUS_KNOWN_EXACT
    assert decision["exact_match"] is True
    assert decision["best_match"]["apk_id"] == apk1.id
    assert decision["best_match"]["risk_score"] == 75
    assert decision["best_match"]["threat_level"] == "CRITICAL"


def test_exact_sha256_takes_precedence_over_dna(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    sha_val = "3333333333333333333333333333333333333333333333333333333333333333"

    apk1 = APKMetadata(
        file_name="sample_a.apk",
        sha256=sha_val,
        file_size=1000,
        file_path="/tmp/sample_a.apk",
        package_name="com.precedence.test",
        version="1.0"
    )
    apk2 = APKMetadata(
        file_name="sample_b.apk",
        sha256=sha_val,
        file_size=1000,
        file_path="/tmp/sample_b.apk",
        package_name="com.precedence.test",
        version="1.0"
    )
    db.add(apk1)
    db.add(apk2)
    db.commit()

    # Give them different static features so DNA would be different
    generate_and_store_dna(db, apk1.id, {"permissions": ["android.permission.INTERNET"]})
    generate_and_store_dna(db, apk2.id, {"permissions": ["android.permission.CAMERA"]})

    decision = evaluate_threat_memory(db, apk2.id)
    # Exact SHA match MUST take precedence over DNA
    assert decision["status"] == STATUS_KNOWN_EXACT
    assert decision["exact_match"] is True


def test_high_dna_similarity_match(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apk1 = APKMetadata(
        file_name="malware_v1.apk",
        sha256="4444444444444444444444444444444444444444444444444444444444444444",
        file_size=3000,
        file_path="/tmp/malware_v1.apk",
        package_name="com.trojan.v1",
        version="1.0"
    )
    apk2 = APKMetadata(
        file_name="malware_v2_repacked.apk",
        sha256="5555555555555555555555555555555555555555555555555555555555555555",
        file_size=3010,
        file_path="/tmp/malware_v2_repacked.apk",
        package_name="com.trojan.v2",
        version="2.0"
    )
    db.add(apk1)
    db.add(apk2)
    db.commit()

    payload_1 = {
        "permissions": ["android.permission.INTERNET", "android.permission.SEND_SMS"],
        "behaviors": [{"behavior": "SMS Exfiltration", "category": "SMS Fraud"}]
    }
    payload_2 = {
        "permissions": ["android.permission.INTERNET", "android.permission.SEND_SMS"],
        "behaviors": [{"behavior": "SMS Exfiltration", "category": "SMS Fraud"}]
    }

    generate_and_store_dna(db, apk1.id, payload_1)
    generate_and_store_dna(db, apk2.id, payload_2)

    decision = evaluate_threat_memory(db, apk2.id)
    assert decision["status"] == STATUS_HIGH_SIMILARITY
    assert decision["exact_match"] is False
    assert decision["best_match"]["apk_id"] == apk1.id
    assert decision["best_match"]["similarity_score"] == 100.0


def test_related_dna_similarity_match(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apk1 = APKMetadata(
        file_name="base_framework.apk",
        sha256="6666666666666666666666666666666666666666666666666666666666666666",
        file_size=4000,
        file_path="/tmp/base_framework.apk",
        package_name="com.framework.base",
        version="1.0"
    )
    apk2 = APKMetadata(
        file_name="variant_app.apk",
        sha256="7777777777777777777777777777777777777777777777777777777777777777",
        file_size=4100,
        file_path="/tmp/variant_app.apk",
        package_name="com.framework.variant",
        version="1.1"
    )
    db.add(apk1)
    db.add(apk2)
    db.commit()

    # Payload 1 has internet, camera, sms, location, behaviors
    payload_1 = {
        "permissions": ["android.permission.INTERNET", "android.permission.CAMERA", "android.permission.SEND_SMS", "android.permission.ACCESS_FINE_LOCATION"],
        "behaviors": [{"behavior": "SMS Exfiltration", "category": "SMS Fraud"}, {"behavior": "Location Tracking", "category": "Spyware"}]
    }
    # Payload 2 shares internet and camera, but has unique vibrate, read_contacts
    payload_2 = {
        "permissions": ["android.permission.INTERNET", "android.permission.CAMERA", "android.permission.VIBRATE", "android.permission.READ_CONTACTS"],
        "behaviors": []
    }

    generate_and_store_dna(db, apk1.id, payload_1)
    generate_and_store_dna(db, apk2.id, payload_2)

    decision = evaluate_threat_memory(db, apk2.id)
    assert decision["status"] in [STATUS_RELATED_SAMPLE, STATUS_HIGH_SIMILARITY]
    assert decision["best_match"]["apk_id"] == apk1.id


def test_multiple_historical_matches(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apks = []
    for i in range(4):
        a = APKMetadata(
            file_name=f"hist_sample_{i}.apk",
            sha256=f"a{i}" * 32,
            file_size=1000 + i,
            file_path=f"/tmp/hist_{i}.apk",
            package_name=f"com.hist.sample{i}",
            version="1.0"
        )
        db.add(a)
        apks.append(a)
    db.commit()

    # Target
    generate_and_store_dna(db, apks[0].id, {"permissions": ["android.permission.INTERNET", "android.permission.CAMERA"]})
    # Identical features (100% match)
    generate_and_store_dna(db, apks[1].id, {"permissions": ["android.permission.INTERNET", "android.permission.CAMERA"]})
    # Partial features
    generate_and_store_dna(db, apks[2].id, {"permissions": ["android.permission.INTERNET"]})
    # Unrelated
    generate_and_store_dna(db, apks[3].id, {"permissions": ["android.permission.VIBRATE"]})

    matches = get_historical_matches(db, apks[0].id, limit=5)
    assert len(matches) >= 2
    # Ensure descending order of similarity score
    assert matches[0]["similarity_score"] >= matches[1]["similarity_score"]


def test_explanation_generation(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apk = APKMetadata(
        file_name="explain.apk",
        sha256="8888888888888888888888888888888888888888888888888888888888888888",
        file_size=1000,
        file_path="/tmp/explain.apk",
        package_name="com.explain.test",
        version="1.0"
    )
    db.add(apk)
    db.commit()

    generate_and_store_dna(db, apk.id, {"permissions": ["android.permission.INTERNET"]})
    decision = evaluate_threat_memory(db, apk.id)
    assert "explanation" in decision
    assert "summary" in decision["explanation"]
    assert "match_type" in decision["explanation"]


def test_missing_malware_dna_handling(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apk = APKMetadata(
        file_name="nodna.apk",
        sha256="9999999999999999999999999999999999999999999999999999999999999999",
        file_size=1000,
        file_path="/tmp/nodna.apk",
        package_name="com.nodna.test",
        version="1.0"
    )
    db.add(apk)
    db.commit()

    # Do not create MalwareDNA record
    decision = evaluate_threat_memory(db, apk.id)
    assert decision["status"] == STATUS_NEW_SAMPLE
    assert decision["best_match"] is None


def test_error_status_isolation(monkeypatch, client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    # Simulate database error during query
    def mock_query(*args, **kwargs):
        raise RuntimeError("Database connection failure")

    monkeypatch.setattr(db, "query", mock_query)

    decision = evaluate_threat_memory(db, 1)
    assert decision["status"] == STATUS_ERROR
    assert "Database connection failure" in decision["explanation"]["error_detail"]


def test_threat_memory_api_endpoints(client):
    from app.database.session import get_db
    db = next(client.app.dependency_overrides[get_db]())

    apk1 = APKMetadata(
        file_name="tm_api1.apk",
        sha256="e" * 64,
        file_size=1200,
        file_path="/tmp/tm_api1.apk",
        package_name="com.tm.api1",
        version="1.0"
    )
    apk2 = APKMetadata(
        file_name="tm_api2.apk",
        sha256="f" * 64,
        file_size=1200,
        file_path="/tmp/tm_api2.apk",
        package_name="com.tm.api2",
        version="1.0"
    )
    db.add(apk1)
    db.add(apk2)
    db.commit()

    payload = {"permissions": ["android.permission.INTERNET"]}
    generate_and_store_dna(db, apk1.id, payload)
    generate_and_store_dna(db, apk2.id, payload)

    evaluate_and_store_threat_memory(db, apk1.id)
    evaluate_and_store_threat_memory(db, apk2.id)

    # 1. GET /api/v1/threat-memory/{apk_id}
    res_get = client.get(f"/api/v1/threat-memory/{apk1.id}")
    assert res_get.status_code == 200
    data = res_get.json()
    assert data["apk_id"] == apk1.id
    assert data["status"] in [STATUS_HIGH_SIMILARITY, STATUS_RELATED_SAMPLE, STATUS_KNOWN_EXACT, STATUS_NEW_SAMPLE]

    # 2. GET /api/v1/threat-memory/{apk_id}/matches
    res_match = client.get(f"/api/v1/threat-memory/{apk1.id}/matches")
    assert res_match.status_code == 200
    matches_data = res_match.json()
    assert matches_data["apk_id"] == apk1.id

    # 3. GET 404 test
    res_404 = client.get("/api/v1/threat-memory/99999")
    assert res_404.status_code == 404

import io
import zipfile
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.security.manifest_analyzer import analyze_permissions
from app.security.risk_engine import calculate_risk_score
from app.certificate.certificate_analyzer import analyze_certificate
from app.string_analysis.indicator_detector import detect_indicators
from app.behavior_analysis.behavior_detector import detect_behaviors
from app.dex_analysis.dex_analyzer import analyze_dex
from app.yara_engine.yara_scanner import scan_with_yara
from app.manifest.exported_analyzer import analyze_exported_components
from app.manifest.intent_filter_analyzer import analyze_intent_filters
from app.digital_twin.twin_engine import create_digital_twin
from app.apktool.decoder import decode_apk
from app.services.analysis_service import analyze_uploaded_apk

from app.models.apk import APKMetadata
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion
from app.database.database import Base


def create_synthetic_zip_apk(tmp_path, filename="synthetic.apk", manifest_xml=None) -> Path:
    """
    Generate a synthetic ZIP/APK container file on disk for portable test execution.
    """
    apk_file = tmp_path / filename

    if manifest_xml is None:
        manifest_xml = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.garud.test">\n'
            '    <uses-permission android:name="android.permission.INTERNET"/>\n'
            '    <uses-permission android:name="android.permission.SEND_SMS"/>\n'
            '    <application android:label="TestApp">\n'
            '        <activity android:name=".MainActivity" android:exported="true">\n'
            '            <intent-filter>\n'
            '                <action android:name="android.intent.action.MAIN"/>\n'
            '                <category android:name="android.intent.category.LAUNCHER"/>\n'
            '            </intent-filter>\n'
            '        </activity>\n'
            '    </application>\n'
            '</manifest>'
        )

    with zipfile.ZipFile(apk_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", b"DEX_HEADER_MOCK_DATA_SU_GETLINE1NUMBER_CIPHER")

    return apk_file


# ---------------------------------------------------------
# 1. Manifest & Permissions Tests
# ---------------------------------------------------------
def test_manifest_permission_analysis():
    permissions = [
        "android.permission.INTERNET",
        "android.permission.SEND_SMS",
        "android.permission.CAMERA"
    ]
    dangerous = analyze_permissions(permissions)

    assert len(dangerous) == 3
    severities = {p["permission"]: p["severity"] for p in dangerous}
    assert severities["android.permission.INTERNET"] == "Low"
    assert severities["android.permission.SEND_SMS"] == "Critical"
    assert severities["android.permission.CAMERA"] == "High"


def test_exported_components_analysis(tmp_path):
    decoded_dir = tmp_path / "decoded_app"
    decoded_dir.mkdir()
    manifest_file = decoded_dir / "AndroidManifest.xml"
    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">\n'
        '    <application>\n'
        '        <activity android:name=".ExportedActivity" android:exported="true"/>\n'
        '        <activity android:name=".PrivateActivity" android:exported="false"/>\n'
        '    </application>\n'
        '</manifest>'
    )
    manifest_file.write_text(manifest_xml, encoding="utf-8")

    exported = analyze_exported_components(str(decoded_dir))
    assert len(exported["activities"]) == 1
    assert exported["activities"][0]["name"] == ".ExportedActivity"


def test_intent_filter_analysis(tmp_path):
    decoded_dir = tmp_path / "decoded_app"
    decoded_dir.mkdir()
    manifest_file = decoded_dir / "AndroidManifest.xml"
    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">\n'
        '    <application>\n'
        '        <activity android:name=".MainActivity">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n'
        '                <category android:name="android.intent.category.DEFAULT"/>\n'
        '            </intent-filter>\n'
        '        </activity>\n'
        '    </application>\n'
        '</manifest>'
    )
    manifest_file.write_text(manifest_xml, encoding="utf-8")

    filters = analyze_intent_filters(str(decoded_dir))
    assert len(filters) == 1
    assert "android.intent.action.BOOT_COMPLETED" in filters[0]["actions"]


# ---------------------------------------------------------
# 2. Certificate Analysis & SHA-256 Fingerprinting
# ---------------------------------------------------------
def test_certificate_analysis_missing_cert(tmp_path):
    apk_file = create_synthetic_zip_apk(tmp_path, "no_cert.apk")
    result = analyze_certificate(str(apk_file))

    assert "status" in result
    assert result["certificate_count"] == 0
    assert result["certificates"] == []


# ---------------------------------------------------------
# 3. String & Indicator Tests
# ---------------------------------------------------------
def test_indicator_detection():
    strings = [
        "https://c2-command.com/api/v1",
        "192.168.1.100",
        "attacker@malware.org",
        "https://myproject.firebaseio.com",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    ]
    indicators = detect_indicators(strings)

    assert "https://c2-command.com/api/v1" in indicators["urls"]
    assert "192.168.1.100" in indicators["ip_addresses"]
    assert "attacker@malware.org" in indicators["emails"]
    assert "https://myproject.firebaseio.com" in indicators["firebase_urls"]
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in indicators["bitcoin_addresses"]


# ---------------------------------------------------------
# 4. Behavior & DEX Analysis Tests
# ---------------------------------------------------------
def test_static_behavior_detection():
    strings = [
        "Runtime.exec",
        "su",
        "DexClassLoader"
    ]
    behaviors = detect_behaviors(strings)
    apis = [b["api"] for b in behaviors]

    assert "Runtime.exec" in apis
    assert "su" in apis
    assert "DexClassLoader" in apis



def test_dex_analysis_synthetic(tmp_path):
    apk_file = create_synthetic_zip_apk(tmp_path, "dex_test.apk")
    findings = analyze_dex(str(apk_file))

    assert isinstance(findings, list)


# ---------------------------------------------------------
# 5. YARA Engine Tests
# ---------------------------------------------------------
def test_yara_scanner_synthetic(tmp_path):
    apk_file = create_synthetic_zip_apk(tmp_path, "yara_test.apk")
    matches = scan_with_yara(str(apk_file))

    assert isinstance(matches, list)


# ---------------------------------------------------------
# 6. Risk Engine Rule-Based Calculation
# ---------------------------------------------------------
def test_risk_engine_calculation():
    dangerous_permissions = [
        {"permission": "android.permission.SEND_SMS", "severity": "Critical", "reason": "SMS"}
    ]
    behaviors = [
        {"api": "getLine1Number", "severity": "High", "reason": "Phone Number"}
    ]
    yara_matches = [
        {"rule": "sms_trojan", "severity": "Critical"}
    ]

    risk = calculate_risk_score(dangerous_permissions, behaviors, yara_matches)

    # 25 (Critical) + 15 (High) + 25 (Critical) = 65 -> High Risk Level
    assert risk["risk_score"] == 65
    assert risk["risk_level"] == "High"


# ---------------------------------------------------------
# 7. Resilient Pipeline Failure Isolation Test
# ---------------------------------------------------------
def test_pipeline_resilience_on_analyzer_failure(tmp_path):
    """
    Verify that if APKTool fails, the analysis pipeline does NOT crash,
    and returns explicit failure metadata while completing remaining analyzers.
    """
    apk_file = create_synthetic_zip_apk(tmp_path, "pipeline_resilience.apk")

    test_db_file = tmp_path / "test_pipeline.db"
    engine = create_engine(f"sqlite:///{test_db_file}")
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    apk_record = APKMetadata(
        file_name="pipeline_resilience.apk",
        sha256="dummy_sha256_hash_value_12345",
        file_size=1024,
        file_path=str(apk_file),
        status="uploaded"
    )
    db.add(apk_record)
    db.commit()
    db.refresh(apk_record)

    result = analyze_uploaded_apk(db, apk_record.id)

    assert result is not None
    assert "analyzer_status" in result
    assert result["analyzer_status"]["apktool"]["status"] == "FAILED"
    assert "risk_score" in result
    assert "digital_twin_id" in result

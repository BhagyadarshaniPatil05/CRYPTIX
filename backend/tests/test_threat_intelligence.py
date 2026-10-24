"""
Comprehensive Test Suite for Phase 3.3 — Global Threat Intelligence Integration.
Tests VirusTotal, AbuseIPDB, AlienVault OTX providers, DB caching, pipeline isolation, and API endpoints.
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import httpx

from app.config.settings import settings
from app.models.apk import APKMetadata
from app.models.threat_intelligence import ThreatIntelligence
from app.threat_intelligence.config import (
    PROVIDER_VIRUSTOTAL,
    PROVIDER_ABUSEIPDB,
    PROVIDER_OTX,
    IND_TYPE_HASH,
    IND_TYPE_IP,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_NOT_CONFIGURED,
    STATUS_DISABLED,
    STATUS_RATE_LIMITED,
    STATUS_TIMEOUT,
    STATUS_UNAUTHORIZED,
    STATUS_FORBIDDEN,
    STATUS_ERROR,
)
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.otx import OTXProvider
from app.threat_intelligence.cache_service import get_cached_ti, save_ti_result
from app.threat_intelligence.service import enrich_sample_threat_intelligence, get_threat_intelligence_by_apk


# =====================================================================
# 1. VIRUSTOTAL PROVIDER TESTS
# =====================================================================

def test_virustotal_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_ENABLED", True)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    provider = VirusTotalProvider()
    res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res["status"] == STATUS_NOT_CONFIGURED
    assert res["found"] is False


def test_virustotal_disabled(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_ENABLED", False)
    provider = VirusTotalProvider()
    res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res["status"] == STATUS_DISABLED
    assert res["found"] is False


def test_virustotal_success_200(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_ENABLED", True)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 3,
                    "undetected": 40,
                    "harmless": 10,
                },
                "meaningful_name": "Trojan.AndroidOS.Agent",
                "type_description": "Android Package",
                "reputation": -25,
            }
        }
    }

    with patch("httpx.Client.get", return_value=mock_response):
        provider = VirusTotalProvider()
        res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert res["status"] == STATUS_SUCCESS
    assert res["found"] is True
    assert res["reputation"]["malicious"] == 12
    assert res["reputation"]["total_engines"] == 65


def test_virustotal_not_found_404(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_ENABLED", True)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key")

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("httpx.Client.get", return_value=mock_response):
        provider = VirusTotalProvider()
        res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert res["status"] == STATUS_NOT_FOUND
    assert res["found"] is False


def test_virustotal_status_codes(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_ENABLED", True)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key")
    provider = VirusTotalProvider()

    for code, expected_status in [(401, STATUS_UNAUTHORIZED), (403, STATUS_FORBIDDEN), (429, STATUS_RATE_LIMITED)]:
        mock_resp = MagicMock()
        mock_resp.status_code = code
        with patch("httpx.Client.get", return_value=mock_resp):
            res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            assert res["status"] == expected_status


def test_virustotal_timeout(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_ENABLED", True)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key")

    with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Timeout")):
        provider = VirusTotalProvider()
        res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert res["status"] == STATUS_TIMEOUT


# =====================================================================
# 2. ABUSEIPDB PROVIDER TESTS
# =====================================================================

def test_abuseipdb_private_ip_filter(monkeypatch):
    monkeypatch.setattr(settings, "ABUSEIPDB_ENABLED", True)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "dummy_ip_key")

    provider = AbuseIPDBProvider()
    res = provider.lookup_indicator("127.0.0.1", IND_TYPE_IP)
    assert res["status"] == STATUS_NOT_FOUND
    assert res["found"] is False
    assert "Skipped private" in res["error_detail"]

    res_priv = provider.lookup_indicator("192.168.1.50", IND_TYPE_IP)
    assert res_priv["status"] == STATUS_NOT_FOUND


def test_abuseipdb_success_200(monkeypatch):
    monkeypatch.setattr(settings, "ABUSEIPDB_ENABLED", True)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "dummy_ip_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "1.1.1.1",
            "abuseConfidenceScore": 85,
            "countryCode": "US",
            "usageType": "Data Center",
            "isp": "Cloudflare",
            "totalReports": 42,
        }
    }

    with patch("httpx.Client.get", return_value=mock_response):
        provider = AbuseIPDBProvider()
        res = provider.lookup_indicator("1.1.1.1", IND_TYPE_IP)

    assert res["status"] == STATUS_SUCCESS
    assert res["found"] is True
    assert res["reputation"]["abuse_confidence_score"] == 85
    assert res["reputation"]["total_reports"] == 42


# =====================================================================
# 3. ALIENVAULT OTX PROVIDER TESTS
# =====================================================================

def test_otx_success_200(monkeypatch):
    monkeypatch.setattr(settings, "OTX_ENABLED", True)
    monkeypatch.setattr(settings, "OTX_API_KEY", "dummy_otx_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 2,
            "pulses": [
                {"id": "p1", "name": "Android Anubis Botnet", "author_name": "AlienVault", "tags": ["anubis", "trojan"]},
                {"id": "p2", "name": "Banking Malware Pulse", "author_name": "Analyst", "tags": ["banking"]},
            ]
        }
    }

    with patch("httpx.Client.get", return_value=mock_response):
        provider = OTXProvider()
        res = provider.lookup_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IND_TYPE_HASH)

    assert res["status"] == STATUS_SUCCESS
    assert res["found"] is True
    assert res["reputation"]["pulse_count"] == 2
    assert "Android Anubis Botnet" in res["reputation"]["pulse_names"]


# =====================================================================
# 4. DATABASE CACHING TESTS
# =====================================================================

def test_cache_service_valid_and_expired(tmp_path, monkeypatch):
    from app.database.database import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    db_file = tmp_path / "cache_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    # Save a valid TI record
    res_dict = {
        "provider": PROVIDER_VIRUSTOTAL,
        "indicator": "test_hash_123",
        "indicator_type": IND_TYPE_HASH,
        "status": STATUS_SUCCESS,
        "found": True,
        "reputation": {"malicious": 5},
        "raw_metadata": None,
    }
    save_ti_result(db, apk_id=1, result=res_dict)

    cached = get_cached_ti(db, PROVIDER_VIRUSTOTAL, IND_TYPE_HASH, "test_hash_123")
    assert cached is not None
    assert cached.found is True

    # Test expired cache entry
    expired_record = ThreatIntelligence(
        apk_id=1,
        provider=PROVIDER_ABUSEIPDB,
        indicator_type=IND_TYPE_IP,
        indicator_value="8.8.8.8",
        status=STATUS_SUCCESS,
        found=False,
        normalized_result_json="{}",
        cached=False,
        queried_at=datetime.utcnow() - timedelta(days=2),
        expires_at=datetime.utcnow() - timedelta(days=1),
    )
    db.add(expired_record)
    db.commit()

    expired_cached = get_cached_ti(db, PROVIDER_ABUSEIPDB, IND_TYPE_IP, "8.8.8.8")
    assert expired_cached is None

    db.close()


# =====================================================================
# 5. PIPELINE ISOLATION & API ENDPOINTS
# =====================================================================

def test_threat_intelligence_api_endpoints(client, monkeypatch):
    from app.database.session import get_db

    # Create dummy APK in DB
    db = next(client.app.dependency_overrides[get_db]())
    apk = APKMetadata(
        file_name="test_sample.apk",
        sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        file_size=1024,
        file_path="uploads/test_sample.apk",
        status="uploaded"
    )
    db.add(apk)
    db.commit()
    db.refresh(apk)

    # Populate ThreatIntelligence record
    ti_rec = ThreatIntelligence(
        apk_id=apk.id,
        provider=PROVIDER_VIRUSTOTAL,
        indicator_type=IND_TYPE_HASH,
        indicator_value=apk.sha256,
        status=STATUS_NOT_CONFIGURED,
        found=False,
        normalized_result_json='{"malicious": 0}',
        cached=False,
    )
    db.add(ti_rec)
    db.commit()

    # GET /api/v1/threat-intelligence/{apk_id}
    res = client.get(f"/api/v1/threat-intelligence/{apk.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["apk_id"] == apk.id
    assert data["total_records"] == 1
    assert data["records"][0]["provider"] == PROVIDER_VIRUSTOTAL

    # GET /api/v1/threat-intelligence/{apk_id}/summary
    res_summary = client.get(f"/api/v1/threat-intelligence/{apk.id}/summary")
    assert res_summary.status_code == 200
    data_summary = res_summary.json()
    assert data_summary["apk_id"] == apk.id
    assert "threats_detected" in data_summary

    # GET 404 for non-existent APK
    res_404 = client.get("/api/v1/threat-intelligence/9999")
    assert res_404.status_code == 404

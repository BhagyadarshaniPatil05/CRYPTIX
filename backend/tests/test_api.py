import io
import zipfile
import pytest
from fastapi.testclient import TestClient


def create_test_apk_bytes(content=b"sample_apk_content") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b'<manifest package="com.test.app"/>')
        zf.writestr("classes.dex", b"DEX_HEADER")
    buffer.seek(0)
    return buffer.getvalue()


def test_root_endpoint(client):
    """
    Test GET / root endpoint.
    """
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "Backend Running"


def test_openapi_json(client):
    """
    Test GET /openapi.json specification endpoint.
    """
    res = client.get("/openapi.json")
    assert res.status_code == 200
    paths = res.json().get("paths", {})
    assert len(paths) >= 30


def test_dashboard_metrics_empty_db(client):
    """
    Test GET /api/v1/dashboard/metrics on empty database.
    """
    res = client.get("/api/v1/dashboard/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "total_apks" in data
    assert data["total_apks"] == 0


def test_threat_dashboard_endpoints(client):
    """
    Test threat dashboard endpoints on clean database.
    """
    r1 = client.get("/api/v1/threat-dashboard/top-permissions")
    assert r1.status_code == 200

    r2 = client.get("/api/v1/threat-dashboard/risk-distribution")
    assert r2.status_code == 200

    r3 = client.get("/api/v1/threat-dashboard/threat-levels")
    assert r3.status_code == 200

    r4 = client.get("/api/v1/threat-dashboard/recent-analyses")
    assert r4.status_code == 200


def test_upload_analysis_and_digital_twin_flow(client):
    """
    End-to-End API Test Flow:
    1. POST /api/v1/upload
    2. POST /api/v1/analysis/{apk_id}
    3. GET /api/v1/twins/{twin_id}
    4. GET /api/v1/twins/{twin_id}/latest
    5. GET /api/v1/twins/{twin_id}/timeline
    6. GET /api/v1/twins/{twin_id}/drift
    """
    apk_bytes = create_test_apk_bytes(b"v1_content")

    # 1. Upload
    up_res = client.post(
        "/api/v1/upload",
        files={"file": ("e2e_app.apk", io.BytesIO(apk_bytes), "application/vnd.android.package-archive")}
    )
    assert up_res.status_code == 200
    apk_id = up_res.json()["id"]

    # 2. Analysis
    an_res = client.post(f"/api/v1/analysis/{apk_id}")
    assert an_res.status_code == 200
    an_data = an_res.json()
    assert "digital_twin_id" in an_data
    twin_id = an_data["digital_twin_id"]

    # 3. Digital Twin Lookup
    twin_res = client.get(f"/api/v1/twins/{twin_id}")
    assert twin_res.status_code == 200

    # 4. Latest Version Lookup
    latest_res = client.get(f"/api/v1/twins/{twin_id}/latest")
    assert latest_res.status_code == 200

    # 5. Timeline Lookup
    time_res = client.get(f"/api/v1/twins/{twin_id}/timeline")
    assert time_res.status_code == 200

    # 6. Drift Metrics Lookup (1 version -> returns Not enough versions status)
    drift_res = client.get(f"/api/v1/twins/{twin_id}/drift")
    assert drift_res.status_code == 200
    assert drift_res.json()["status"] == "Not enough versions"

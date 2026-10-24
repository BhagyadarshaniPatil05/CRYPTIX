import io
import zipfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.database import Base
from app.database.session import get_db
from app.config.settings import settings
from app.utils.hash_utils import generate_sha256_from_file_object
from app.services.upload_service import validate_apk

# Import all SQLAlchemy models to register them on Base.metadata
from app.models.apk import APKMetadata
from app.models.apk_analysis import APKAnalysis
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion



@pytest.fixture(autouse=True)
def setup_db_and_folder(tmp_path, monkeypatch):
    """
    Setup clean file-backed SQLite database schema and temporary upload folder for each test.
    """
    test_db_file = tmp_path / "test_cryptix.db"
    test_db_url = f"sqlite:///{test_db_file}"
    test_engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    test_upload_dir = tmp_path / "uploads"
    test_upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "UPLOAD_FOLDER", test_upload_dir)

    yield

    Base.metadata.drop_all(bind=test_engine)



def create_synthetic_apk(filename="test.apk", content=b"synthetic_manifest_data") -> tuple[str, bytes]:
    """
    Helper function to generate a minimal valid synthetic ZIP/APK file in-memory.
    Note: Synthetic ZIP container for testing structure only.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", content)
        zf.writestr("classes.dex", b"DEX_HEADER_MOCK")
    buffer.seek(0)
    return filename, buffer.getvalue()


client = TestClient(app)


def test_1_valid_apk_upload():
    """
    Test uploading a valid synthetic APK file with .apk extension and ZIP magic header.
    """
    filename, apk_bytes = create_synthetic_apk("sample_app.apk", b"content_v1")

    response = client.post(
        "/api/v1/upload",
        files={"file": (filename, io.BytesIO(apk_bytes), "application/vnd.android.package-archive")}
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["filename"] == "sample_app.apk"
    assert "sha256" in data
    assert data["size"] == len(apk_bytes)

    # Verify permanent storage path is named after SHA-256
    sha256 = data["sha256"]
    stored_path = settings.UPLOAD_FOLDER / f"{sha256}.apk"
    assert stored_path.exists()


def test_2_invalid_extension():
    """
    Test uploading a file with invalid extension (e.g. .txt).
    """
    filename, apk_bytes = create_synthetic_apk("sample_app.txt", b"content_v1")

    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample_app.txt", io.BytesIO(apk_bytes), "text/plain")}
    )

    assert response.status_code == 400
    assert "Only files with .apk extension are allowed" in response.json()["detail"]


def test_3_invalid_magic_bytes_non_zip():
    """
    Test uploading a file with .apk extension but invalid non-ZIP content.
    """
    fake_apk_bytes = b"THIS_IS_PLAIN_TEXT_NOT_A_ZIP_CONTAINER"

    response = client.post(
        "/api/v1/upload",
        files={"file": ("fake_app.apk", io.BytesIO(fake_apk_bytes), "application/vnd.android.package-archive")}
    )

    assert response.status_code == 400
    assert "ZIP/APK archive container" in response.json()["detail"]

    # Verify no file was written to upload storage
    assert len(list(settings.UPLOAD_FOLDER.glob("*.apk"))) == 0


def test_4_sha256_generation():
    """
    Test SHA-256 calculation utility directly from stream.
    """
    test_stream = io.BytesIO(b"Hello Garud-AI SHA256 Stream")
    calculated_hash = generate_sha256_from_file_object(test_stream)

    import hashlib
    expected_hash = hashlib.sha256(b"Hello Garud-AI SHA256 Stream").hexdigest()

    assert calculated_hash == expected_hash
    # Stream pointer must be reset to 0
    assert test_stream.tell() == 0


def test_5_duplicate_sha256_detection():
    """
    Test that re-uploading an identical APK returns HTTP 409 Conflict.
    """
    filename, apk_bytes = create_synthetic_apk("duplicate_test.apk", b"identical_content")

    # First upload -> Success
    res1 = client.post(
        "/api/v1/upload",
        files={"file": (filename, io.BytesIO(apk_bytes), "application/vnd.android.package-archive")}
    )
    assert res1.status_code == 200

    # Second upload of same content -> 409 Conflict
    res2 = client.post(
        "/api/v1/upload",
        files={"file": ("different_name.apk", io.BytesIO(apk_bytes), "application/vnd.android.package-archive")}
    )
    assert res2.status_code == 409
    assert "APK already exists" in res2.json()["detail"]


def test_6_same_filename_different_content_no_overwrite():
    """
    Test uploading two different files with the SAME filename.
    Verify that the second upload does NOT overwrite the first file on disk.
    """
    # File 1: app.apk with content_A
    fn1, bytes1 = create_synthetic_apk("app.apk", b"content_version_A")
    res1 = client.post(
        "/api/v1/upload",
        files={"file": (fn1, io.BytesIO(bytes1), "application/vnd.android.package-archive")}
    )
    assert res1.status_code == 200
    hash1 = res1.json()["sha256"]

    # File 2: app.apk with content_B (different hash)
    fn2, bytes2 = create_synthetic_apk("app.apk", b"content_version_B")
    res2 = client.post(
        "/api/v1/upload",
        files={"file": (fn2, io.BytesIO(bytes2), "application/vnd.android.package-archive")}
    )
    assert res2.status_code == 200
    hash2 = res2.json()["sha256"]

    assert hash1 != hash2

    # Both files must exist independently on disk under their respective hash names
    file1_path = settings.UPLOAD_FOLDER / f"{hash1}.apk"
    file2_path = settings.UPLOAD_FOLDER / f"{hash2}.apk"

    assert file1_path.exists()
    assert file2_path.exists()
    assert file1_path.read_bytes() == bytes1
    assert file2_path.read_bytes() == bytes2


def test_7_failed_upload_does_not_leave_unwanted_files():
    """
    Test that invalid or duplicate uploads leave 0 unwanted files in upload storage.
    """
    # Attempt invalid magic bytes upload
    client.post(
        "/api/v1/upload",
        files={"file": ("bad.apk", io.BytesIO(b"INVALID"), "application/vnd.android.package-archive")}
    )

    # Storage directory must remain completely empty
    files_on_disk = list(settings.UPLOAD_FOLDER.iterdir())
    assert len(files_on_disk) == 0

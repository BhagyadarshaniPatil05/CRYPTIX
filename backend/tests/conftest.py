import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.main import app
from app.database.database import Base
from app.database.session import get_db
from app.config.settings import settings

# Import all SQLAlchemy ORM models to ensure full table registration
from app.models.apk import APKMetadata
from app.models.apk_analysis import APKAnalysis
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion
from app.models.malware_dna import MalwareDNA
from app.models.threat_memory import ThreatMemory
from app.models.threat_intelligence import ThreatIntelligence
from app.models.mitre import MitreMapping
from app.models.rag import RagDocument, RagChunk, RagQueryLog



@pytest.fixture(autouse=True)
def setup_isolated_env(tmp_path, monkeypatch):
    """
    Sets up an isolated file-backed SQLite database and temporary upload/decoded folder
    for each test to prevent mutation of development or production data.
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


@pytest.fixture
def client():
    """
    FastAPI TestClient fixture.
    """
    return TestClient(app)

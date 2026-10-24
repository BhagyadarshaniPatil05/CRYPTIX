from pathlib import Path
import os
from dotenv import load_dotenv

# Project root
BASE_DIR = Path(__file__).resolve().parents[3]

# Load .env
load_dotenv(BASE_DIR / ".env")


class Settings:
    PROJECT_NAME = "CRYPTIX"
    VERSION = "1.0.0"
    BASE_DIR = BASE_DIR

    DB_HOST = os.getenv("DB_HOST")
    DB_PORT = os.getenv("DB_PORT")
    DB_NAME = os.getenv("DB_NAME")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DATABASE_URL = os.getenv("DATABASE_URL")

    UPLOAD_FOLDER = BASE_DIR / "uploads" / "apk_files"

    # --- Global Threat Intelligence Configurations ---
    VIRUSTOTAL_ENABLED = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() in ("true", "1", "yes")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_TIMEOUT_SECONDS = int(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "10"))
    VIRUSTOTAL_CACHE_TTL_SECONDS = int(os.getenv("VIRUSTOTAL_CACHE_TTL_SECONDS", "86400"))

    ABUSEIPDB_ENABLED = os.getenv("ABUSEIPDB_ENABLED", "false").lower() in ("true", "1", "yes")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    ABUSEIPDB_TIMEOUT_SECONDS = int(os.getenv("ABUSEIPDB_TIMEOUT_SECONDS", "10"))
    ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))
    ABUSEIPDB_CACHE_TTL_SECONDS = int(os.getenv("ABUSEIPDB_CACHE_TTL_SECONDS", "86400"))

    OTX_ENABLED = os.getenv("OTX_ENABLED", "false").lower() in ("true", "1", "yes")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    OTX_TIMEOUT_SECONDS = int(os.getenv("OTX_TIMEOUT_SECONDS", "10"))
    OTX_CACHE_TTL_SECONDS = int(os.getenv("OTX_CACHE_TTL_SECONDS", "86400"))

    MAX_INDICATORS_PER_PROVIDER = int(os.getenv("MAX_INDICATORS_PER_PROVIDER", "10"))

    # --- Phase 3.5 RAG System Configurations ---
    RAG_ENABLED = os.getenv("RAG_ENABLED", "true").lower() in ("true", "1", "yes")
    RAG_VECTOR_STORE = os.getenv("RAG_VECTOR_STORE", "sqlite")
    RAG_EMBEDDING_PROVIDER = os.getenv("RAG_EMBEDDING_PROVIDER", "tfidf")
    RAG_LLM_PROVIDER = os.getenv("RAG_LLM_PROVIDER", "mock")
    RAG_LLM_API_KEY = os.getenv("RAG_LLM_API_KEY", "")
    RAG_LLM_MODEL = os.getenv("RAG_LLM_MODEL", "gpt-4o-mini")
    RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))


settings = Settings()
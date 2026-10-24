import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config.settings import settings

logger = logging.getLogger("cryptix.database")

# Construct Database Connection URL
if settings.DATABASE_URL:
    DATABASE_URL = settings.DATABASE_URL
elif all([settings.DB_USER, settings.DB_PASSWORD, settings.DB_HOST, settings.DB_PORT, settings.DB_NAME]):
    DATABASE_URL = (
        f"postgresql://{settings.DB_USER}:"
        f"{settings.DB_PASSWORD}@"
        f"{settings.DB_HOST}:"
        f"{settings.DB_PORT}/"
        f"{settings.DB_NAME}"
    )
else:
    # Fallback to local SQLite database for development when PostgreSQL is not configured
    sqlite_db_path = settings.BASE_DIR / "cryptix.db"
    DATABASE_URL = f"sqlite:///{sqlite_db_path}"
    logger.info(f"PostgreSQL credentials not fully specified. Falling back to local SQLite DB: {DATABASE_URL}")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
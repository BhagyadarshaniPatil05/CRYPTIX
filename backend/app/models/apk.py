from sqlalchemy import Column, Integer, String, BigInteger, DateTime
from datetime import datetime

from app.database.database import Base


class APKMetadata(Base):
    __tablename__ = "apk_metadata"

    id = Column(Integer, primary_key=True, index=True)

    file_name = Column(String, nullable=False)

    sha256 = Column(String, index=True, nullable=False)

    file_size = Column(BigInteger, nullable=False)

    file_path = Column(String, nullable=False)

    package_name = Column(String, nullable=True)

    version = Column(String, nullable=True)

    status = Column(String, default="uploaded")

    upload_time = Column(DateTime, default=datetime.utcnow)
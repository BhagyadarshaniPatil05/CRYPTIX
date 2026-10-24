from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from app.database.database import Base


class APKAnalysis(Base):
    __tablename__ = "apk_analysis"

    id = Column(Integer, primary_key=True, index=True)

    apk_id = Column(Integer, ForeignKey("apk_metadata.id"))

    package_name = Column(String)
    app_name = Column(String)
    version_name = Column(String)
    version_code = Column(String)

    min_sdk = Column(String)
    target_sdk = Column(String)

    apk = relationship("APKMetadata")
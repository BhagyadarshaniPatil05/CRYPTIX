from app.database.database import engine, Base

from app.models.apk import APKMetadata
from app.models.apk_analysis import APKAnalysis
from app.models.digital_twin import DigitalTwin, DigitalTwinVersion

# Import all models here
from app.models.apk import APKMetadata
from app.models.apk_analysis import APKAnalysis

Base.metadata.create_all(bind=engine)

print("Database Tables Created Successfully!")
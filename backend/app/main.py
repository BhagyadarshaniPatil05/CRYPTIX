from fastapi import FastAPI

from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.upload import router as upload_router
from app.api.v1.analysis import router as analysis_router
from app.api.v1.digital_twin import router as twin_router

from app.api.v1.report import (
    router as report_router
)

from app.api.v1.dashboard import (
    router as dashboard_router
)

from app.api.v1.threat_dashboard import (
    router as threat_dashboard_router
)

from app.api.v1.similarity import (
    router as similarity_router
)

from app.api.v1.family_classification import (
    router as family_router
)

from app.api.v1.threat_hunting import (
    router as hunt_router
)

from app.api.v1.recommendation import (
    router as recommendation_router
)

from app.api.v1.security_score import (
    router as security_score_router
)

from app.api.v1.incident_response import (
    router as incident_response_router
)

from app.api.v1.executive_summary import (
    router as executive_summary_router
)

from app.api.v1.twin_health import (
    router as twin_health_router
)

from app.api.v1.twin_lifecycle import (
    router as twin_lifecycle_router
)

from app.api.v1.twin_events import (
    router as twin_events_router
)

from app.api.v1.twin_prediction import (
    router as twin_prediction_router
)

from app.api.v1.twin_dashboard import (
    router as twin_dashboard_router
)

from app.api.v1.twin_risk_trend import (
    router as twin_risk_trend_router
)

from app.api.v1.twin_recommendations import (
    router as twin_recommendations_router
)

from app.api.v1.malware_dna import (
    router as malware_dna_router
)

from app.api.v1.threat_memory import (
    router as threat_memory_router
)

from app.api.v1.threat_intelligence import (
    router as threat_intelligence_router
)

from app.api.v1.mitre import (
    router as mitre_router
)

from app.api.v1.rag import (
    router as rag_router
)


app = FastAPI(
    title="CRYPTIX",
    description="AI Powered Cyber Incident Response System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Root Endpoint
# -----------------------------
@app.get("/")
def root():
    return {
        "message": "Welcome to CRYPTIX",
        "status": "Backend Running"
    }

# -----------------------------
# Upload & Analysis API
# -----------------------------
app.include_router(upload_router, prefix="/api/v1", tags=["APK Upload"])
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(twin_router, prefix="/api/v1")
app.include_router(report_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(threat_dashboard_router, prefix="/api/v1")
app.include_router(similarity_router, prefix="/api/v1")
app.include_router(family_router, prefix="/api/v1")
app.include_router(hunt_router, prefix="/api/v1")
app.include_router(recommendation_router, prefix="/api/v1")
app.include_router(security_score_router, prefix="/api/v1")
app.include_router(incident_response_router, prefix="/api/v1")
app.include_router(executive_summary_router, prefix="/api/v1")

# Digital Twin Extended Subsystem Routers
app.include_router(twin_health_router, prefix="/api/v1")
app.include_router(twin_lifecycle_router, prefix="/api/v1")
app.include_router(twin_events_router, prefix="/api/v1")
app.include_router(twin_prediction_router, prefix="/api/v1")
app.include_router(twin_dashboard_router, prefix="/api/v1")
app.include_router(twin_risk_trend_router, prefix="/api/v1")
app.include_router(twin_recommendations_router, prefix="/api/v1")
app.include_router(malware_dna_router, prefix="/api/v1")
app.include_router(threat_memory_router, prefix="/api/v1")
app.include_router(threat_intelligence_router, prefix="/api/v1")
app.include_router(mitre_router, prefix="/api/v1")
app.include_router(rag_router, prefix="/api/v1")
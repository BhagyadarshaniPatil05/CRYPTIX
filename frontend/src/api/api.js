import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:8000/api/v1"
});

// Upload APK File
export const uploadAPK = async (file) => {
    const formData = new FormData();
    formData.append("file", file);
    const response = await api.post("/upload", formData, {
        headers: {
            "Content-Type": "multipart/form-data",
        },
    });
    return response.data;
};

// Trigger Static Analysis for an uploaded APK ID
export const triggerAnalysis = async (apkId) => {
    const response = await api.post(`/analysis/${apkId}`);
    return response.data;
};

// Dashboard Summary Metrics
export const getDashboardMetrics = async () => {
    const response = await api.get("/dashboard/metrics");
    return response.data;
};

// Risk Distribution Breakdown (High, Medium, Low)
export const getRiskDistribution = async () => {
    const response = await api.get("/threat-dashboard/risk-distribution");
    return response.data;
};

// Top Dangerous Permissions Heatmap
export const getTopPermissions = async () => {
    const response = await api.get("/threat-dashboard/top-permissions");
    return response.data;
};

// Threat Levels Breakdown
export const getThreatLevels = async () => {
    const response = await api.get("/threat-dashboard/threat-levels");
    return response.data;
};

// Recent Analyzed APK Samples Queue
export const getRecentAnalyses = async () => {
    const response = await api.get("/threat-dashboard/recent-analyses");
    return response.data;
};

// Full Report for single APK
export const getReport = async (apkId) => {
    const response = await api.get(`/reports/${apkId}`);
    return response.data;
};

// Security Score calculation
export const getSecurityScore = async (twinId) => {
    const response = await api.get(`/security-score/${twinId}`);
    return response.data;
};

// Malware Family classification
export const getFamilyClassification = async (twinId) => {
    const response = await api.get(`/family/${twinId}`);
    return response.data;
};

// Security Remediation recommendations
export const getRecommendations = async (twinId) => {
    const response = await api.get(`/recommendation/${twinId}`);
    return response.data;
};

// Incident Response playbook actions
export const getIncidentResponse = async (twinId) => {
    const response = await api.get(`/incident-response/${twinId}`);
    return response.data;
};

// Executive Summary narrative report
export const getExecutiveSummary = async (twinId) => {
    const response = await api.get(`/executive-summary/${twinId}`);
    return response.data;
};

// --- Digital Twin API Methods ---

// List all Digital Twins
export const getDigitalTwins = async () => {
    const response = await api.get("/twins");
    return response.data;
};

// Fetch single Digital Twin metadata
export const getDigitalTwin = async (twinId) => {
    const response = await api.get(`/twins/${twinId}`);
    return response.data;
};

// Fetch latest version snapshot of a Digital Twin
export const getLatestTwinVersion = async (twinId) => {
    const response = await api.get(`/twins/${twinId}/latest`);
    return response.data;
};

// Fetch all historical version snapshots of a Digital Twin
export const getTwinVersions = async (twinId) => {
    const response = await api.get(`/twins/${twinId}/versions`);
    return response.data;
};

// Compare two Digital Twin versions (v1 vs v2)
export const compareTwinVersions = async (twinId, v1, v2) => {
    const response = await api.get(`/twins/${twinId}/compare/${v1}/${v2}`);
    return response.data;
};

// Fetch posture drift metrics
export const getTwinDrift = async (twinId) => {
    const response = await api.get(`/twins/${twinId}/drift`);
    return response.data;
};

// Fetch formatted twin drift text report
export const getTwinDriftReport = async (twinId) => {
    const response = await api.get(`/twins/${twinId}/drift/report`);
    return response.data;
};

// Fetch twin health score & metrics
export const getTwinHealth = async (twinId) => {
    const response = await api.get(`/twin-health/${twinId}`);
    return response.data;
};

// Fetch twin lifecycle status
export const getTwinLifecycle = async (twinId) => {
    const response = await api.get(`/twin-lifecycle/${twinId}`);
    return response.data;
};

// Fetch twin audit event stream
export const getTwinEvents = async (twinId) => {
    const response = await api.get(`/twin-events/${twinId}`);
    return response.data;
};

// Fetch twin risk score progression trend
export const getTwinRiskTrend = async (twinId) => {
    const response = await api.get(`/twin-risk-trend/${twinId}`);
    return response.data;
};

// --- Malware DNA API Methods ---

export const getMalwareDNA = async (apkId) => {
    const response = await api.get(`/malware-dna/${apkId}`);
    return response.data;
};

export const compareMalwareDNA = async (apkId, targetApkId) => {
    const response = await api.get(`/malware-dna/${apkId}/compare/${targetApkId}`);
    return response.data;
};

export const getSimilarMalwareDNA = async (apkId, limit = 5, minThreshold = 30) => {
    const response = await api.get(`/malware-dna/${apkId}/similar`, {
        params: { limit, min_threshold: minThreshold }
    });
    return response.data;
};

// --- Threat Memory API Methods ---

export const getThreatMemory = async (apkId) => {
    const response = await api.get(`/threat-memory/${apkId}`);
    return response.data;
};

export const getThreatMatches = async (apkId, limit = 5) => {
    const response = await api.get(`/threat-memory/${apkId}/matches`, {
        params: { limit }
    });
    return response.data;
};

// --- Global Threat Intelligence API Methods ---

export const getThreatIntelligence = async (apkId) => {
    const response = await api.get(`/threat-intelligence/${apkId}`);
    return response.data;
};

export const getThreatIntelligenceSummary = async (apkId) => {
    const response = await api.get(`/threat-intelligence/${apkId}/summary`);
    return response.data;
};

// --- MITRE ATT&CK Mobile API Methods ---

export const getMitreMappings = async (apkId) => {
    const response = await api.get(`/mitre/${apkId}`);
    return response.data;
};

export const getMitreTactics = async (apkId) => {
    const response = await api.get(`/mitre/${apkId}/tactics`);
    return response.data;
};

export const getMitreIOCs = async (apkId) => {
    const response = await api.get(`/mitre/${apkId}/iocs`);
    return response.data;
};

// --- Cybersecurity RAG API Methods ---

export const getRAGHealth = async () => {
    const response = await api.get("/rag/health");
    return response.data;
};

export const retrieveRAGKnowledge = async (payload) => {
    const response = await api.post("/rag/retrieve", payload);
    return response.data;
};

export const askRAGQuestion = async (payload) => {
    const response = await api.post("/rag/ask", payload);
    return response.data;
};

export default api;
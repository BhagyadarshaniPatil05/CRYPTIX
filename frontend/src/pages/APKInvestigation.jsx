import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Loader2, ArrowLeft, ShieldAlert, RefreshCw } from "lucide-react";
import InvestigationHeader from "../components/investigation/InvestigationHeader";
import InvestigationNav from "../components/investigation/InvestigationNav";
import OverviewTab from "../components/investigation/OverviewTab";
import ManifestTab from "../components/investigation/ManifestTab";
import BehaviorsTab from "../components/investigation/BehaviorsTab";
import StringsTab from "../components/investigation/StringsTab";
import CertificateTab from "../components/investigation/CertificateTab";
import PlaybookTab from "../components/investigation/PlaybookTab";
import MalwareDNATab from "../components/investigation/MalwareDNATab";
import ThreatMemoryTab from "../components/investigation/ThreatMemoryTab";
import GlobalThreatIntelligenceTab from "../components/investigation/GlobalThreatIntelligenceTab";
import MitreTab from "../components/investigation/MitreTab";
import AIIntelligenceTab from "../components/investigation/AIIntelligenceTab";


import {
    getReport,
    getSecurityScore,
    getFamilyClassification,
    getRecommendations,
    getIncidentResponse,
    getExecutiveSummary
} from "../api/api";

function APKInvestigation() {
    const { id } = useParams();

    const [report, setReport] = useState(null);
    const [securityScore, setSecurityScore] = useState(null);
    const [familyData, setFamilyData] = useState(null);
    const [recommendationsData, setRecommendationsData] = useState(null);
    const [incidentData, setIncidentData] = useState(null);
    const [executiveSummaryData, setExecutiveSummaryData] = useState(null);

    const [activeTab, setActiveTab] = useState("overview");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchInvestigationData = async () => {
        setLoading(true);
        setError(null);
        try {
            // 1. Fetch Primary Report Data (GET /reports/{apk_id})
            const mainReport = await getReport(id);
            setReport(mainReport);

            const summary = mainReport.executive_summary || mainReport;
            const twinId = summary.digital_twin_id || mainReport.digital_twin_id;

            // 2. Fetch Auxiliary Twin Intelligence if twinId exists
            if (twinId) {
                const [secRes, famRes, recRes, incRes, execRes] = await Promise.allSettled([
                    getSecurityScore(twinId),
                    getFamilyClassification(twinId),
                    getRecommendations(twinId),
                    getIncidentResponse(twinId),
                    getExecutiveSummary(twinId)
                ]);

                if (secRes.status === "fulfilled") setSecurityScore(secRes.value);
                if (famRes.status === "fulfilled") setFamilyData(famRes.value);
                if (recRes.status === "fulfilled") setRecommendationsData(recRes.value);
                if (incRes.status === "fulfilled") setIncidentData(incRes.value);
                if (execRes.status === "fulfilled") setExecutiveSummaryData(execRes.value);
            }
        } catch (err) {
            console.error("APK investigation fetch error:", err);
            setError(`Failed to fetch static analysis report for APK ID ${id}. Ensure sample exists in database.`);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (id) {
            fetchInvestigationData();
        }
    }, [id]);

    if (loading) {
        return (
            <div style={{ padding: "80px 0", textAlign: "center" }}>
                <Loader2 size={46} color="#06b6d4" style={{ animation: "spin 1.2s linear infinite", marginBottom: "16px" }} />
                <h3 style={{ fontSize: "17px", fontWeight: "700", color: "var(--text-primary)" }}>
                    LOADING STATIC FORENSIC WORKSPACE...
                </h3>
                <p style={{ fontSize: "13px", color: "var(--text-muted)", marginTop: "6px" }}>
                    Retrieving manifest, permissions, DEX bytecode, YARA matches & Digital Twin telemetry
                </p>
            </div>
        );
    }

    if (error || !report) {
        return (
            <div style={{ padding: "40px 0" }}>
                <div
                    style={{
                        backgroundColor: "rgba(239, 68, 68, 0.12)",
                        border: "1px solid rgba(239, 68, 68, 0.4)",
                        borderRadius: "12px",
                        padding: "28px",
                        maxWidth: "600px",
                        margin: "0 auto",
                        textAlign: "center"
                    }}
                >
                    <ShieldAlert size={40} color="#ef4444" style={{ marginBottom: "12px" }} />
                    <h3 style={{ fontSize: "18px", fontWeight: "700", color: "#ef4444", marginBottom: "8px" }}>
                        SAMPLE NOT FOUND IN CORPUS
                    </h3>
                    <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "20px" }}>
                        {error}
                    </p>
                    <div style={{ display: "flex", justifyContent: "center", gap: "12px" }}>
                        <Link to="/apks" className="btn-secondary">
                            <ArrowLeft size={16} /> APK Repository
                        </Link>
                        <button className="btn-primary" onClick={fetchInvestigationData}>
                            <RefreshCw size={16} /> Retry
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    const reportData = report.report_data || report;
    const summary = reportData.executive_summary || reportData;
    const twinId = summary.digital_twin_id || reportData.digital_twin_id;

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            {/* Header Banner */}
            <InvestigationHeader
                reportData={reportData}
                securityScore={securityScore}
                twinId={twinId}
            />

            {/* Sub-Navigation Tabs */}
            <InvestigationNav
                activeTab={activeTab}
                onTabChange={(tab) => setActiveTab(tab)}
            />

            {/* Active Tab Workspace */}
            <div>
                {activeTab === "overview" && (
                    <OverviewTab
                        reportData={reportData}
                        securityScore={securityScore}
                        familyData={familyData}
                        executiveSummaryData={executiveSummaryData}
                    />
                )}

                {activeTab === "manifest" && (
                    <ManifestTab
                        reportData={reportData}
                    />
                )}

                {activeTab === "behaviors" && (
                    <BehaviorsTab
                        reportData={reportData}
                    />
                )}

                {activeTab === "strings" && (
                    <StringsTab
                        reportData={reportData}
                    />
                )}

                {activeTab === "certificate" && (
                    <CertificateTab
                        reportData={reportData}
                    />
                )}

                {activeTab === "dna" && (
                    <MalwareDNATab
                        apkId={id}
                    />
                )}

                {activeTab === "threat_memory" && (
                    <ThreatMemoryTab
                        apkId={id}
                    />
                )}

                {activeTab === "threat_intelligence" && (
                    <GlobalThreatIntelligenceTab
                        apkId={id}
                        sha256={reportData?.sha256}
                    />
                )}

                {activeTab === "mitre" && (
                    <MitreTab
                        apkId={id}
                    />
                )}

                {activeTab === "ai_intelligence" && (
                    <AIIntelligenceTab
                        apkId={id}
                        reportData={reportData}
                    />
                )}


                {activeTab === "playbook" && (
                    <PlaybookTab
                        recommendationsData={recommendationsData}
                        incidentData={incidentData}
                        apkId={id}
                    />
                )}
            </div>
        </div>
    );
}

export default APKInvestigation;

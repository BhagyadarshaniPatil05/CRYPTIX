import React from "react";
import { ShieldCheck, ShieldAlert, Cpu, AlertTriangle, Layers, Info } from "lucide-react";
import RiskBadge from "../common/RiskBadge";

function OverviewTab({ reportData, securityScore, familyData, executiveSummaryData }) {
    const summary = reportData.executive_summary || reportData;
    const threatAssessment = reportData.threat_assessment || {};

    const score = securityScore?.security_score ?? summary.risk_score ?? 0;
    const grade = securityScore?.grade || "N/A";
    const statusLabel = securityScore?.status || summary.risk_level || "Unknown";

    const familyName = familyData?.family || "Rule-Based Classifier Pending";
    const familyConfidence = familyData?.confidence || "Low";
    const familyReasons = familyData?.reasons || [];

    const summaryText = executiveSummaryData?.summary || threatAssessment.summary || 
        `Static analysis completed for ${summary.package_name || "APK"}. Calculated risk score is ${score}/100.`;

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Top Cards Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "16px" }}>
                {/* 1. Security Score Card */}
                <div className="garud-card" style={{ textAlign: "center", display: "flex", flexDirection: "column", justifyContent: "center" }}>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "700", marginBottom: "6px", letterSpacing: "0.5px" }}>
                        STATIC SECURITY SCORE
                    </div>
                    <div className="font-mono" style={{ fontSize: "44px", fontWeight: "800", color: "var(--accent-cyan)", lineHeight: "1" }}>
                        {score}<span style={{ fontSize: "16px", color: "var(--text-muted)" }}>/100</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "center", gap: "6px", marginTop: "10px" }}>
                        <span className="font-mono" style={{ fontSize: "11px", fontWeight: "800", padding: "2px 6px", borderRadius: "3px", backgroundColor: "var(--accent-cyan-bg)", color: "var(--accent-cyan)", border: "1px solid rgba(94, 231, 247, 0.3)" }}>
                            GRADE {grade}
                        </span>
                        <span style={{ fontSize: "12px", color: "var(--text-secondary)", alignSelf: "center" }}>
                            {statusLabel}
                        </span>
                    </div>
                </div>

                {/* 2. Malware Family Classification */}
                <div className="garud-card">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px" }}>
                        <ShieldAlert size={16} color="var(--high)" />
                        <h3 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)" }}>
                            MALWARE FAMILY CLASSIFICATION
                        </h3>
                    </div>

                    <div style={{ fontSize: "16px", fontWeight: "800", color: familyName === "Unknown" ? "var(--text-secondary)" : "var(--high)", marginBottom: "4px" }} className="font-mono">
                        {familyName}
                    </div>

                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "10px" }}>
                        Confidence: <strong style={{ color: "var(--text-primary)" }}>{familyConfidence}</strong>
                    </div>

                    {familyReasons.length > 0 && (
                        <div style={{ fontSize: "11px", color: "var(--text-secondary)", backgroundColor: "var(--bg-elevated)", padding: "6px 10px", borderRadius: "4px" }}>
                            <strong>Detection Reason:</strong> {familyReasons.join(", ")}
                        </div>
                    )}
                </div>

                {/* 3. Incident Severity & Threat Level */}
                <div className="garud-card">
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px" }}>
                        <AlertTriangle size={16} color="var(--critical)" />
                        <h3 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)" }}>
                            THREAT SEVERITY OVERVIEW
                        </h3>
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Threat Level:</span>
                        <RiskBadge level={summary.threat_level || threatAssessment.threat_level || summary.risk_level || "Low"} />
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Incident Severity:</span>
                        <strong className="font-mono" style={{ fontSize: "13px", color: "var(--text-primary)" }}>
                            {executiveSummaryData?.incident_severity || "Low"}
                        </strong>
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Recommendations:</span>
                        <span className="font-mono" style={{ fontSize: "13px", fontWeight: "700", color: "var(--accent-cyan)" }}>
                            {executiveSummaryData?.recommendation_count ?? 0} actions
                        </span>
                    </div>
                </div>
            </div>

            {/* Executive Summary Narrative Panel */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
                    <Info size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>EXECUTIVE ASSESSMENT SUMMARY</h3>
                </div>

                <div
                    style={{
                        padding: "14px",
                        backgroundColor: "var(--bg-elevated)",
                        borderRadius: "4px",
                        border: "1px solid var(--border-color)",
                        fontSize: "13px",
                        color: "var(--text-secondary)",
                        lineHeight: "1.6"
                    }}
                >
                    {summaryText}
                </div>
            </div>

            {/* Technical Specifications Grid */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
                    <Layers size={16} color="var(--accent-purple)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>SAMPLE TECHNICAL METADATA</h3>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "12px", fontSize: "12px" }}>
                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px" }}>
                        <div style={{ color: "var(--text-muted)", marginBottom: "2px" }}>Package Name</div>
                        <div className="font-mono" style={{ fontWeight: "700", color: "var(--text-primary)", wordBreak: "break-all" }}>
                            {summary.package_name || "N/A"}
                        </div>
                    </div>

                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px" }}>
                        <div style={{ color: "var(--text-muted)", marginBottom: "2px" }}>Version Name / Code</div>
                        <div className="font-mono" style={{ fontWeight: "700", color: "var(--text-primary)" }}>
                            {summary.version_name || "1.0"} ({summary.version_code || "1"})
                        </div>
                    </div>

                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px" }}>
                        <div style={{ color: "var(--text-muted)", marginBottom: "2px" }}>Min / Target SDK</div>
                        <div className="font-mono" style={{ fontWeight: "700", color: "var(--text-primary)" }}>
                            SDK {summary.min_sdk || "API"} / SDK {summary.target_sdk || "API"}
                        </div>
                    </div>

                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px" }}>
                        <div style={{ color: "var(--text-muted)", marginBottom: "2px" }}>File Size</div>
                        <div className="font-mono" style={{ fontWeight: "700", color: "var(--text-primary)" }}>
                            {summary.file_size ? `${(summary.file_size / (1024 * 1024)).toFixed(2)} MB` : "N/A"}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default OverviewTab;

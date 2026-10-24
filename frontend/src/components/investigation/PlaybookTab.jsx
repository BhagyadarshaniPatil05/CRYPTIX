import React from "react";
import { ShieldCheck, ShieldAlert, Download, FileText, CheckCircle2 } from "lucide-react";
import RiskBadge from "../common/RiskBadge";

function PlaybookTab({ recommendationsData, incidentData, apkId }) {
    const recommendations = recommendationsData?.recommendations || [];
    const actions = incidentData?.recommended_actions || [];
    const severity = incidentData?.incident_severity || recommendationsData?.risk_level || "Low";

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Incident Response Playbook Panel */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <ShieldAlert size={16} color="var(--critical)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>
                            INCIDENT RESPONSE CONTAINMENT PLAYBOOK
                        </h3>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Incident Severity:</span>
                        <RiskBadge level={severity} />
                    </div>
                </div>

                {actions.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                        {actions.map((actionText, idx) => (
                            <div
                                key={idx}
                                style={{
                                    backgroundColor: "var(--bg-elevated)",
                                    border: "1px solid var(--border-color)",
                                    borderRadius: "4px",
                                    padding: "10px 14px",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "10px"
                                }}
                            >
                                <CheckCircle2 size={15} color="var(--accent-cyan)" style={{ flexShrink: 0 }} />
                                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-primary)" }}>
                                    {actionText}
                                </span>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        Standard containment procedures: Sample is classified as low risk. Monitor application telemetry.
                    </div>
                )}
            </div>

            {/* Security Mitigation Recommendations */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <ShieldCheck size={16} color="var(--low)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>
                        SECURITY REMEDIATION RECOMMENDATIONS ({recommendations.length})
                    </h3>
                </div>

                {recommendations.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                        {recommendations.map((rec, idx) => (
                            <div
                                key={idx}
                                style={{
                                    backgroundColor: "var(--bg-elevated)",
                                    border: "1px solid var(--border-color)",
                                    borderRadius: "4px",
                                    padding: "12px 14px"
                                }}
                            >
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                                    <span style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-primary)" }}>
                                        Issue: {rec.issue || "Security Risk"}
                                    </span>
                                    <RiskBadge level={rec.severity || "Medium"} />
                                </div>
                                <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                    <strong>Mitigation:</strong> {rec.recommendation || "Remediate highlighted permission or configuration issue."}
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        No specific security remediation actions required for this sample.
                    </div>
                )}
            </div>

            {/* Binary PDF Download Box */}
            <div
                style={{
                    backgroundColor: "var(--bg-elevated)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    padding: "16px 20px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "14px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <FileText size={20} color="var(--accent-cyan)" />
                    <div>
                        <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)" }}>
                            EXECUTIVE FORENSIC PDF REPORT STREAM
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                            Generate complete static analysis dossier with certificate fingerprints & YARA signature logs.
                        </div>
                    </div>
                </div>

                {apkId && (
                    <a
                        href={`http://127.0.0.1:8000/api/v1/reports/${apkId}/pdf`}
                        target="_blank"
                        rel="noreferrer"
                        className="btn-primary"
                        style={{ fontSize: "12px", padding: "6px 14px" }}
                    >
                        <Download size={14} />
                        <span>DOWNLOAD PDF REPORT</span>
                    </a>
                )}
            </div>
        </div>
    );
}

export default PlaybookTab;

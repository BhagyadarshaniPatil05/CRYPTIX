import React, { useState } from "react";
import { ShieldCheck, AlertTriangle, FileText, ChevronDown, ChevronUp, Activity } from "lucide-react";

function TwinDriftPanel({ drift, driftReport }) {
    const [showReport, setShowReport] = useState(false);

    if (!drift) return null;

    const hasDrift = drift.has_drift ?? false;
    const delta = drift.risk_score_delta ?? 0;
    const summary = drift.drift_summary || (hasDrift ? "Posture drift detected across version iterations." : "No significant security posture drift detected.");

    const addedPerms = drift.permissions_added || [];
    const removedPerms = drift.permissions_removed || [];
    const addedBehaviors = drift.behaviors_added || [];
    const removedBehaviors = drift.behaviors_removed || [];

    const reportText = typeof driftReport === "string" ? driftReport : driftReport?.report || driftReport?.text || null;

    return (
        <div className="garud-card" style={{ padding: "20px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <Activity size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>SECURITY POSTURE DRIFT ASSESSMENT</h3>
                </div>

                <div
                    className="font-mono"
                    style={{
                        padding: "3px 8px",
                        borderRadius: "3px",
                        fontSize: "10px",
                        fontWeight: "700",
                        backgroundColor: hasDrift ? "var(--medium-bg)" : "var(--low-bg)",
                        color: hasDrift ? "var(--medium)" : "var(--low)",
                        border: hasDrift ? "1px solid var(--medium-border)" : "1px solid var(--low-border)",
                        display: "flex",
                        alignItems: "center",
                        gap: "4px"
                    }}
                >
                    {hasDrift ? <AlertTriangle size={12} /> : <ShieldCheck size={12} />}
                    {hasDrift ? "POSTURE DRIFT DETECTED" : "STABLE POSTURE"}
                </div>
            </div>

            {/* Summary Banner */}
            <div
                style={{
                    padding: "12px 14px",
                    backgroundColor: "var(--bg-elevated)",
                    borderRadius: "4px",
                    border: "1px solid var(--border-color)",
                    marginBottom: "14px",
                    fontSize: "12px",
                    lineHeight: "1.5"
                }}
            >
                <div style={{ fontWeight: "600", color: "var(--text-primary)", marginBottom: "2px" }}>Drift Summary:</div>
                <div style={{ color: "var(--text-secondary)" }}>{summary}</div>
                {drift.versions_compared && (
                    <div style={{ fontSize: "10px", color: "var(--accent-cyan)", marginTop: "4px" }}>
                        Versions Compared: {drift.versions_compared}
                    </div>
                )}
            </div>

            {/* Metrics Breakdown */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: "8px", marginBottom: "14px" }}>
                <div style={{ padding: "8px 10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", textAlign: "center" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase" }}>Risk Score Delta</div>
                    <div className="font-mono" style={{ fontSize: "15px", fontWeight: "700", color: delta > 0 ? "var(--critical)" : delta < 0 ? "var(--low)" : "var(--text-muted)", marginTop: "2px" }}>
                        {delta > 0 ? `+${delta}` : delta}
                    </div>
                </div>

                <div style={{ padding: "8px 10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", textAlign: "center" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase" }}>Permissions Added</div>
                    <div className="font-mono" style={{ fontSize: "15px", fontWeight: "700", color: "var(--low)", marginTop: "2px" }}>
                        +{addedPerms.length}
                    </div>
                </div>

                <div style={{ padding: "8px 10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", textAlign: "center" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase" }}>Permissions Removed</div>
                    <div className="font-mono" style={{ fontSize: "15px", fontWeight: "700", color: "var(--critical)", marginTop: "2px" }}>
                        -{removedPerms.length}
                    </div>
                </div>

                <div style={{ padding: "8px 10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", textAlign: "center" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase" }}>Behaviors Mutated</div>
                    <div className="font-mono" style={{ fontSize: "15px", fontWeight: "700", color: "var(--accent-cyan)", marginTop: "2px" }}>
                        {addedBehaviors.length + removedBehaviors.length}
                    </div>
                </div>
            </div>

            {/* Expandable Report Narrative */}
            {reportText && (
                <div>
                    <button
                        onClick={() => setShowReport(!showReport)}
                        style={{
                            padding: "6px 12px",
                            backgroundColor: "var(--bg-elevated)",
                            border: "1px solid var(--border-color)",
                            borderRadius: "4px",
                            color: "var(--accent-cyan)",
                            fontSize: "11px",
                            fontWeight: "700",
                            cursor: "pointer",
                            display: "flex",
                            alignItems: "center",
                            gap: "6px"
                        }}
                    >
                        <FileText size={13} />
                        {showReport ? "Hide Detailed Drift Narrative" : "View Detailed Drift Narrative Report"}
                        {showReport ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                    </button>

                    {showReport && (
                        <div
                            className="font-mono"
                            style={{
                                marginTop: "10px",
                                padding: "14px",
                                backgroundColor: "var(--bg-main)",
                                border: "1px solid var(--border-color)",
                                borderRadius: "4px",
                                fontSize: "11px",
                                color: "var(--text-secondary)",
                                whiteSpace: "pre-wrap",
                                lineHeight: "1.5"
                            }}
                        >
                            {reportText}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default TwinDriftPanel;

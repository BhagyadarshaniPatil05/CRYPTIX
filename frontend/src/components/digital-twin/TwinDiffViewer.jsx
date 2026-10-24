import React from "react";
import { GitCompare, ShieldAlert, PlusCircle, MinusCircle, AlertTriangle } from "lucide-react";

function TwinDiffViewer({ diff, v1, v2, loading }) {
    if (loading) {
        return (
            <div className="garud-card" style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                <GitCompare size={20} color="var(--accent-cyan)" className="animate-spin" style={{ marginBottom: "6px" }} />
                <div>Computing structural version diff between v{v1} and v{v2}...</div>
            </div>
        );
    }

    if (!diff) {
        return (
            <div className="garud-card" style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                <div>Select two versions above and click "Compare Versions" to view structural differences.</div>
            </div>
        );
    }

    const riskDelta = diff.risk_score_diff ?? 0;
    const isRiskIncreased = riskDelta > 0;
    const isRiskDecreased = riskDelta < 0;

    const addedPerms = diff.permissions_added || [];
    const removedPerms = diff.permissions_removed || [];
    const addedDangPerms = diff.dangerous_permissions_added || [];
    const removedDangPerms = diff.dangerous_permissions_removed || [];
    const addedBehaviors = diff.behaviors_added || [];
    const removedBehaviors = diff.behaviors_removed || [];

    return (
        <div className="garud-card" style={{ padding: "20px", marginBottom: "20px" }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <GitCompare size={18} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "15px", fontWeight: "800" }}>
                        STRUCTURAL VERSION DIFF (v{diff.version_from || v1} → v{diff.version_to || v2})
                    </h3>
                </div>

                {/* Risk Delta Badge */}
                <div
                    className="font-mono"
                    style={{
                        padding: "4px 10px",
                        borderRadius: "4px",
                        fontWeight: "800",
                        fontSize: "12px",
                        backgroundColor: isRiskIncreased
                            ? "var(--critical-bg)"
                            : isRiskDecreased
                            ? "var(--low-bg)"
                            : "var(--bg-elevated)",
                        color: isRiskIncreased ? "var(--critical)" : isRiskDecreased ? "var(--low)" : "var(--text-muted)",
                        border: isRiskIncreased
                            ? "1px solid var(--critical-border)"
                            : isRiskDecreased
                            ? "1px solid var(--low-border)"
                            : "1px solid var(--border-color)",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px"
                    }}
                >
                    <ShieldAlert size={14} />
                    Risk Delta: {isRiskIncreased ? `+${riskDelta}` : riskDelta} points
                </div>
            </div>

            {/* Metrics Overview Grid */}
            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                    gap: "10px",
                    marginBottom: "20px"
                }}
            >
                <div style={{ padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700" }}>Permissions Added</div>
                    <div className="font-mono" style={{ fontSize: "18px", fontWeight: "800", color: "var(--low)", marginTop: "2px" }}>+{addedPerms.length}</div>
                </div>

                <div style={{ padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700" }}>Permissions Removed</div>
                    <div className="font-mono" style={{ fontSize: "18px", fontWeight: "800", color: "var(--critical)", marginTop: "2px" }}>-{removedPerms.length}</div>
                </div>

                <div style={{ padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700" }}>Dangerous Added</div>
                    <div className="font-mono" style={{ fontSize: "18px", fontWeight: "800", color: addedDangPerms.length > 0 ? "var(--critical)" : "var(--low)", marginTop: "2px" }}>
                        +{addedDangPerms.length}
                    </div>
                </div>

                <div style={{ padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700" }}>Behaviors Delta</div>
                    <div className="font-mono" style={{ fontSize: "18px", fontWeight: "800", color: "var(--accent-cyan)", marginTop: "2px" }}>
                        +{addedBehaviors.length} / -{removedBehaviors.length}
                    </div>
                </div>
            </div>

            {/* Dangerous Permissions Alert Section */}
            {addedDangPerms.length > 0 && (
                <div
                    style={{
                        padding: "12px 14px",
                        borderRadius: "4px",
                        backgroundColor: "var(--critical-bg)",
                        border: "1px solid var(--critical-border)",
                        marginBottom: "16px"
                    }}
                >
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--critical)", fontWeight: "700", marginBottom: "6px", fontSize: "12px" }}>
                        <AlertTriangle size={14} /> NEW DANGEROUS PERMISSIONS INTRODUCED IN V{diff.version_to || v2}
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {addedDangPerms.map((perm, idx) => (
                            <span
                                key={idx}
                                className="font-mono"
                                style={{
                                    fontSize: "11px",
                                    padding: "2px 6px",
                                    backgroundColor: "rgba(255, 77, 90, 0.2)",
                                    color: "#ff8a93",
                                    borderRadius: "3px",
                                    border: "1px solid rgba(255, 77, 90, 0.4)"
                                }}
                            >
                                + {perm}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Side by Side Diff Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
                {/* Added Capabilities */}
                <div style={{ padding: "14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--low)", fontWeight: "700", fontSize: "12px", marginBottom: "10px" }}>
                        <PlusCircle size={14} /> ADDED CAPABILITIES (+{addedPerms.length + addedBehaviors.length})
                    </div>

                    {addedPerms.length === 0 && addedBehaviors.length === 0 ? (
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>No new permissions or behaviors added.</div>
                    ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                            {addedPerms.map((perm, idx) => (
                                <div key={idx} className="font-mono" style={{ fontSize: "11px", color: "var(--low)", padding: "3px 6px", backgroundColor: "var(--low-bg)", borderRadius: "3px" }}>
                                    + {perm}
                                </div>
                            ))}
                            {addedBehaviors.map((beh, idx) => (
                                <div key={idx} className="font-mono" style={{ fontSize: "11px", color: "var(--accent-cyan)", padding: "3px 6px", backgroundColor: "var(--accent-cyan-bg)", borderRadius: "3px" }}>
                                    + [Behavior] {typeof beh === "object" ? beh.behavior || JSON.stringify(beh) : beh}
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Removed Capabilities */}
                <div style={{ padding: "14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--critical)", fontWeight: "700", fontSize: "12px", marginBottom: "10px" }}>
                        <MinusCircle size={14} /> REMOVED CAPABILITIES (-{removedPerms.length + removedBehaviors.length})
                    </div>

                    {removedPerms.length === 0 && removedBehaviors.length === 0 ? (
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>No existing permissions or behaviors removed.</div>
                    ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                            {removedPerms.map((perm, idx) => (
                                <div key={idx} className="font-mono" style={{ fontSize: "11px", color: "var(--critical)", padding: "3px 6px", backgroundColor: "var(--critical-bg)", borderRadius: "3px" }}>
                                    - {perm}
                                </div>
                            ))}
                            {removedBehaviors.map((beh, idx) => (
                                <div key={idx} className="font-mono" style={{ fontSize: "11px", color: "var(--text-secondary)", padding: "3px 6px", backgroundColor: "rgba(125, 138, 154, 0.1)", borderRadius: "3px" }}>
                                    - [Behavior] {typeof beh === "object" ? beh.behavior || JSON.stringify(beh) : beh}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default TwinDiffViewer;

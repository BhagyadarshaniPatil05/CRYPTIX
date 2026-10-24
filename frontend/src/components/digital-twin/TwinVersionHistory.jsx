import React from "react";
import { History, CheckSquare, Square, GitCommit } from "lucide-react";

function TwinVersionHistory({ versions, selectedV1, selectedV2, onSelectV1, onSelectV2 }) {
    if (!versions || versions.length === 0) {
        return (
            <div className="garud-card" style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>
                <History size={24} color="var(--text-muted)" style={{ marginBottom: "6px" }} />
                <div>No version snapshots found for this Digital Twin.</div>
            </div>
        );
    }

    const getRiskBadgeColor = (level) => {
        switch (level?.toUpperCase()) {
            case "HIGH":
            case "CRITICAL":
                return { bg: "var(--critical-bg)", text: "var(--critical)", border: "var(--critical-border)" };
            case "MEDIUM":
                return { bg: "var(--medium-bg)", text: "var(--medium)", border: "var(--medium-border)" };
            case "LOW":
                return { bg: "var(--low-bg)", text: "var(--low)", border: "var(--low-border)" };
            default:
                return { bg: "rgba(125, 138, 154, 0.15)", text: "var(--text-muted)", border: "var(--border-color)" };
        }
    };

    return (
        <div className="garud-card" style={{ padding: "20px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <History size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>POSTURE EVOLUTION TIMELINE</h3>
                </div>
                <span className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                    {versions.length} Version{versions.length > 1 ? "s" : ""} Recorded
                </span>
            </div>

            {/* Interactive Timeline Graph Node Bar */}
            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    padding: "16px 20px",
                    backgroundColor: "var(--bg-elevated)",
                    borderRadius: "6px",
                    border: "1px solid var(--border-color)",
                    marginBottom: "16px",
                    overflowX: "auto"
                }}
            >
                {versions.map((ver, idx) => {
                    const isLast = idx === versions.length - 1;
                    const badge = getRiskBadgeColor(ver.risk_level);
                    const isV1 = selectedV1 === ver.version_number;
                    const isV2 = selectedV2 === ver.version_number;

                    return (
                        <React.Fragment key={ver.id || ver.version_number}>
                            {/* Version Node */}
                            <div
                                onClick={() => onSelectV2(ver.version_number)}
                                style={{
                                    display: "flex",
                                    flexDirection: "column",
                                    alignItems: "center",
                                    gap: "6px",
                                    cursor: "pointer",
                                    minWidth: "70px"
                                }}
                            >
                                <span className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600" }}>
                                    v{ver.version_number}
                                </span>

                                <div
                                    style={{
                                        width: "28px",
                                        height: "28px",
                                        borderRadius: "50%",
                                        backgroundColor: isV1
                                            ? "rgba(94, 231, 247, 0.2)"
                                            : isV2
                                            ? "rgba(139, 156, 255, 0.2)"
                                            : "var(--bg-surface)",
                                        border: isV1
                                            ? "2px solid var(--accent-cyan)"
                                            : isV2
                                            ? "2px solid var(--accent-purple)"
                                            : `2px solid ${badge.text}`,
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "center",
                                        transition: "all 0.15s ease"
                                    }}
                                >
                                    <GitCommit size={14} color={isV1 ? "var(--accent-cyan)" : isV2 ? "var(--accent-purple)" : badge.text} />
                                </div>

                                <span className="font-mono" style={{ fontSize: "10px", fontWeight: "700", color: badge.text }}>
                                    {ver.risk_score ?? 0} pts
                                </span>
                            </div>

                            {/* Timeline Connector Line */}
                            {!isLast && (
                                <div
                                    style={{
                                        flex: 1,
                                        height: "2px",
                                        backgroundColor: "var(--border-color)",
                                        margin: "0 8px",
                                        minWidth: "40px"
                                    }}
                                />
                            )}
                        </React.Fragment>
                    );
                })}
            </div>

            {/* Version Snapshot Detail List */}
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {versions.map((ver) => {
                    const isV1 = selectedV1 === ver.version_number;
                    const isV2 = selectedV2 === ver.version_number;
                    const badge = getRiskBadgeColor(ver.risk_level);
                    const permsCount = ver.permissions_json ? ver.permissions_json.length : 0;

                    return (
                        <div
                            key={ver.id || ver.version_number}
                            style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                padding: "12px 14px",
                                backgroundColor: isV1 || isV2 ? "rgba(94, 231, 247, 0.04)" : "var(--bg-elevated)",
                                borderRadius: "4px",
                                border: isV1
                                    ? "1px solid var(--accent-cyan)"
                                    : isV2
                                    ? "1px solid var(--accent-purple)"
                                    : "1px solid var(--border-color)",
                                transition: "all 0.15s ease"
                            }}
                        >
                            {/* Version Details */}
                            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                                <div
                                    className="font-mono"
                                    style={{
                                        fontSize: "13px",
                                        fontWeight: "800",
                                        color: "var(--text-primary)",
                                        backgroundColor: "var(--bg-surface)",
                                        padding: "4px 10px",
                                        borderRadius: "4px",
                                        border: "1px solid var(--border-color)"
                                    }}
                                >
                                    v{ver.version_number}
                                </div>

                                <div>
                                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "2px" }}>
                                        <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-primary)" }}>
                                            {ver.app_name || ver.package_name || `Build v${ver.version_number}`}
                                        </span>
                                        <span
                                            className="font-mono"
                                            style={{
                                                fontSize: "10px",
                                                padding: "1px 6px",
                                                borderRadius: "3px",
                                                backgroundColor: badge.bg,
                                                color: badge.text,
                                                border: `1px solid ${badge.border}`,
                                                fontWeight: "700"
                                            }}
                                        >
                                            {ver.risk_level || "UNKNOWN"} ({ver.risk_score ?? 0})
                                        </span>
                                    </div>
                                    <div style={{ fontSize: "11px", color: "var(--text-muted)", display: "flex", gap: "10px" }}>
                                        <span>Permissions: <strong style={{ color: "var(--text-secondary)" }}>{permsCount}</strong></span>
                                        <span>APK ID: <strong style={{ color: "var(--text-secondary)" }}>#{ver.apk_id}</strong></span>
                                        <span>Timestamp: <strong style={{ color: "var(--text-secondary)" }}>{ver.created_at ? new Date(ver.created_at).toLocaleString() : "N/A"}</strong></span>
                                    </div>
                                </div>
                            </div>

                            {/* Select Controls */}
                            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                                <button
                                    onClick={() => onSelectV1(ver.version_number)}
                                    style={{
                                        padding: "4px 10px",
                                        borderRadius: "4px",
                                        border: isV1 ? "1px solid var(--accent-cyan)" : "1px solid var(--border-color)",
                                        backgroundColor: isV1 ? "var(--accent-cyan-bg)" : "var(--bg-surface)",
                                        color: isV1 ? "var(--accent-cyan)" : "var(--text-muted)",
                                        fontSize: "11px",
                                        fontWeight: "700",
                                        cursor: "pointer",
                                        display: "flex",
                                        alignItems: "center",
                                        gap: "4px"
                                    }}
                                >
                                    {isV1 ? <CheckSquare size={13} /> : <Square size={13} />} Base (V1)
                                </button>

                                <button
                                    onClick={() => onSelectV2(ver.version_number)}
                                    style={{
                                        padding: "4px 10px",
                                        borderRadius: "4px",
                                        border: isV2 ? "1px solid var(--accent-purple)" : "1px solid var(--border-color)",
                                        backgroundColor: isV2 ? "var(--accent-purple-bg)" : "var(--bg-surface)",
                                        color: isV2 ? "var(--accent-purple)" : "var(--text-muted)",
                                        fontSize: "11px",
                                        fontWeight: "700",
                                        cursor: "pointer",
                                        display: "flex",
                                        alignItems: "center",
                                        gap: "4px"
                                    }}
                                >
                                    {isV2 ? <CheckSquare size={13} /> : <Square size={13} />} Target (V2)
                                </button>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export default TwinVersionHistory;

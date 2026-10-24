import React from "react";
import { GitCompare, ArrowRightLeft } from "lucide-react";

function TwinVersionSelector({ versions, v1, v2, onV1Change, onV2Change, onCompare }) {
    if (!versions || versions.length < 2) {
        return (
            <div className="garud-card" style={{ padding: "14px 18px", marginBottom: "20px", display: "flex", alignItems: "center", gap: "10px", color: "var(--text-muted)", fontSize: "12px" }}>
                <GitCompare size={16} color="var(--medium)" />
                <span>Single version detected. Upload a newer build of this package to enable side-by-side version comparison and posture drift analytics.</span>
            </div>
        );
    }

    return (
        <div className="garud-card" style={{ padding: "16px 20px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <GitCompare size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>VERSION COMPARISON SELECTOR</h3>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                    {/* Select V1 */}
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: "600" }}>Base (v1):</span>
                        <select
                            value={v1}
                            onChange={(e) => onV1Change(Number(e.target.value))}
                            className="font-mono"
                            style={{
                                padding: "5px 10px",
                                backgroundColor: "var(--bg-elevated)",
                                border: "1px solid var(--accent-cyan)",
                                borderRadius: "4px",
                                color: "var(--accent-cyan)",
                                fontSize: "12px",
                                fontWeight: "700",
                                outline: "none",
                                cursor: "pointer"
                            }}
                        >
                            {versions.map((ver) => (
                                <option key={ver.version_number} value={ver.version_number}>
                                    Version v{ver.version_number} ({ver.risk_level})
                                </option>
                            ))}
                        </select>
                    </div>

                    <div style={{ color: "var(--text-muted)", fontSize: "12px" }}>vs</div>

                    {/* Select V2 */}
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: "600" }}>Target (v2):</span>
                        <select
                            value={v2}
                            onChange={(e) => onV2Change(Number(e.target.value))}
                            className="font-mono"
                            style={{
                                padding: "5px 10px",
                                backgroundColor: "var(--bg-elevated)",
                                border: "1px solid var(--accent-purple)",
                                borderRadius: "4px",
                                color: "var(--accent-purple)",
                                fontSize: "12px",
                                fontWeight: "700",
                                outline: "none",
                                cursor: "pointer"
                            }}
                        >
                            {versions.map((ver) => (
                                <option key={ver.version_number} value={ver.version_number}>
                                    Version v{ver.version_number} ({ver.risk_level})
                                </option>
                            ))}
                        </select>
                    </div>

                    {/* Swap button */}
                    <button
                        onClick={() => {
                            const temp = v1;
                            onV1Change(v2);
                            onV2Change(temp);
                        }}
                        style={{
                            padding: "5px 8px",
                            borderRadius: "4px",
                            border: "1px solid var(--border-color)",
                            backgroundColor: "var(--bg-elevated)",
                            color: "var(--text-muted)",
                            cursor: "pointer"
                        }}
                        title="Swap Base and Target versions"
                    >
                        <ArrowRightLeft size={13} />
                    </button>

                    {/* Trigger button */}
                    <button
                        onClick={onCompare}
                        className="btn-primary"
                        style={{ fontSize: "12px", padding: "6px 14px" }}
                    >
                        <GitCompare size={13} /> Compare Versions
                    </button>
                </div>
            </div>
        </div>
    );
}

export default TwinVersionSelector;

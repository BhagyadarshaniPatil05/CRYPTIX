import React, { useState } from "react";
import { Cpu, Search, AlertCircle, Code } from "lucide-react";
import RiskBadge from "../common/RiskBadge";

function BehaviorsTab({ reportData }) {
    const behaviors = reportData.behavior_analysis || [];
    const dexFindings = reportData.dex_analysis || [];

    const [behaviorSearch, setBehaviorSearch] = useState("");

    const filteredBehaviors = behaviors.filter((item) => {
        const title = item.behavior || item.category || item.api || "";
        return title.toLowerCase().includes(behaviorSearch.toLowerCase());
    });

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Disclaimer Banner */}
            <div
                style={{
                    backgroundColor: "var(--bg-elevated)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "4px",
                    padding: "10px 14px",
                    fontSize: "12px",
                    color: "var(--text-secondary)",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px"
                }}
            >
                <AlertCircle size={15} color="var(--accent-cyan)" style={{ flexShrink: 0 }} />
                <span>
                    <strong>Static Indicator Notice:</strong> Behaviors listed below are static signature patterns detected during DEX bytecode and manifest inspection. They represent program capabilities, not observed runtime executions.
                </span>
            </div>

            {/* Static Behavior Indicators Panel */}
            <div className="garud-card" style={{ padding: "0", overflow: "hidden" }}>
                <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border-color)", backgroundColor: "var(--bg-elevated)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Cpu size={16} color="var(--accent-cyan)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>
                            STATIC BEHAVIOR INDICATORS ({behaviors.length})
                        </h3>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "6px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderRadius: "4px", padding: "4px 8px" }}>
                        <Search size={14} color="var(--text-muted)" />
                        <input
                            type="text"
                            placeholder="Filter behaviors..."
                            value={behaviorSearch}
                            onChange={(e) => setBehaviorSearch(e.target.value)}
                            className="font-mono"
                            style={{ background: "transparent", border: "none", color: "var(--text-primary)", outline: "none", fontSize: "12px" }}
                        />
                    </div>
                </div>

                {filteredBehaviors.length > 0 ? (
                    <table className="soc-table">
                        <thead>
                            <tr>
                                <th>BEHAVIOR PATTERN</th>
                                <th>SEVERITY</th>
                                <th>CATEGORY</th>
                                <th>DETAILED DESCRIPTION</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredBehaviors.map((item, idx) => {
                                const title = item.behavior || item.category || "Behavior Pattern";
                                const sev = item.severity || "Low";
                                const cat = item.category || "General";
                                const desc = item.description || "Pattern matched in DEX bytecode or manifest.";

                                return (
                                    <tr key={idx}>
                                        <td className="font-mono" style={{ fontSize: "12px", color: "var(--accent-cyan)", fontWeight: "600" }}>
                                            {title}
                                        </td>
                                        <td>
                                            <RiskBadge level={sev} />
                                        </td>
                                        <td className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                            {cat}
                                        </td>
                                        <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                            {desc}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                ) : (
                    <div style={{ padding: "30px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        No static behaviors match your search filter.
                    </div>
                )}
            </div>

            {/* DEX Bytecode Inspection Findings */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <Code size={16} color="var(--accent-purple)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>DEX BYTECODE SCANNING FINDINGS ({dexFindings.length})</h3>
                </div>

                {dexFindings.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "240px", overflowY: "auto" }}>
                        {dexFindings.map((finding, idx) => (
                            <div key={idx} style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                                    <span className="font-mono" style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-purple)" }}>
                                        Pattern: {finding.pattern || finding.rule_name || "DEX Match"}
                                    </span>
                                    <RiskBadge level={finding.severity || "Medium"} />
                                </div>
                                <div className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "2px" }}>
                                    Location: {finding.class_name || "N/A"} -&gt; {finding.method_name || "N/A"}
                                </div>
                                <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                                    {finding.description || "Matched sensitive API call in Dalvik executable."}
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        No suspicious bytecode patterns detected in DEX classes.
                    </div>
                )}
            </div>
        </div>
    );
}

export default BehaviorsTab;

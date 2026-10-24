import React, { useState } from "react";
import { ShieldAlert, Search, Layers, ListFilter } from "lucide-react";
import RiskBadge from "../common/RiskBadge";

function ManifestTab({ reportData }) {
    const permissions = reportData.permissions_analysis || [];
    const exportedComponents = reportData.exported_components || {};
    const intentFilters = reportData.intent_filters || [];

    const [permSearch, setPermSearch] = useState("");
    const [severityFilter, setSeverityFilter] = useState("ALL");

    const getPermSeverity = (item) => {
        if (typeof item === "object" && item !== null && item.severity) {
            return item.severity;
        }
        const permName = (typeof item === "string" ? item : item?.permission || "").toUpperCase();
        if (permName.includes("SMS") || permName.includes("CAMERA") || permName.includes("LOCATION") || permName.includes("RECORD_AUDIO")) {
            return "HIGH";
        }
        if (permName.includes("CONTACTS") || permName.includes("STORAGE") || permName.includes("PHONE") || permName.includes("SYSTEM_ALERT_WINDOW")) {
            return "MEDIUM";
        }
        return "LOW";
    };

    const filteredPermissions = permissions.filter((item) => {
        const permName = typeof item === "string" ? item : item?.permission || "";
        const matchesSearch = permName.toLowerCase().includes(permSearch.toLowerCase());
        const itemSev = getPermSeverity(item);
        const matchesSev = severityFilter === "ALL" || itemSev.toUpperCase() === severityFilter.toUpperCase();
        return matchesSearch && matchesSev;
    });

    const activities = exportedComponents.activities || [];
    const services = exportedComponents.services || [];
    const receivers = exportedComponents.receivers || [];
    const providers = exportedComponents.providers || [];

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Analyst Scope Disclaimer */}
            <div style={{ padding: "12px 16px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderLeft: "4px solid var(--accent-cyan)", borderRadius: "6px", fontSize: "12px", color: "var(--text-secondary)" }}>
                <strong style={{ color: "var(--text-primary)" }}>SECURITY NOTICE:</strong> Static permission declarations indicate requested candidate capabilities. Manifest declarations do NOT prove runtime execution or confirmed malicious behavior.
            </div>
            {/* Dangerous Permissions Section */}
            <div className="garud-card" style={{ padding: "0", overflow: "hidden" }}>
                <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border-color)", backgroundColor: "var(--bg-elevated)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <ShieldAlert size={16} color="var(--critical)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>
                            DANGEROUS PERMISSIONS ({permissions.length})
                        </h3>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderRadius: "4px", padding: "4px 8px" }}>
                            <Search size={14} color="var(--text-muted)" />
                            <input
                                type="text"
                                placeholder="Search permission..."
                                value={permSearch}
                                onChange={(e) => setPermSearch(e.target.value)}
                                className="font-mono"
                                style={{ background: "transparent", border: "none", color: "var(--text-primary)", outline: "none", fontSize: "12px" }}
                            />
                        </div>

                        <select
                            value={severityFilter}
                            onChange={(e) => setSeverityFilter(e.target.value)}
                            className="font-mono"
                            style={{
                                backgroundColor: "var(--bg-surface)",
                                border: "1px solid var(--border-color)",
                                color: "var(--text-primary)",
                                padding: "4px 8px",
                                borderRadius: "4px",
                                fontSize: "12px",
                                outline: "none",
                                cursor: "pointer"
                            }}
                        >
                            <option value="ALL">All Severities</option>
                            <option value="CRITICAL">Critical</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                        </select>
                    </div>
                </div>

                {filteredPermissions.length > 0 ? (
                    <table className="soc-table">
                        <thead>
                            <tr>
                                <th>PERMISSION IDENTIFIER</th>
                                <th>SEVERITY</th>
                                <th>CATEGORY</th>
                                <th>SECURITY IMPLICATION</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredPermissions.map((item, idx) => {
                                const permName = typeof item === "string" ? item : item?.permission;
                                const sev = getPermSeverity(item);
                                const category = (typeof item === "object" && item?.category) || "General";
                                const desc = (typeof item === "object" && item?.description) || "Requested candidate capability in AndroidManifest.xml.";

                                return (
                                    <tr key={idx}>
                                        <td className="font-mono" style={{ fontSize: "12px", color: "var(--accent-cyan)", fontWeight: "600" }}>
                                            {permName}
                                        </td>
                                        <td>
                                            <RiskBadge level={sev} />
                                        </td>
                                        <td className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                            {category}
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
                        No permissions matched the search filter.
                    </div>
                )}
            </div>

            {/* Exported Components Grid */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <Layers size={16} color="var(--accent-purple)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>EXPORTED APPLICATION COMPONENTS</h3>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                    {/* Activities */}
                    <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-cyan)", marginBottom: "8px" }}>
                            Exported Activities ({activities.length})
                        </div>
                        {activities.length === 0 ? (
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>No exported activities.</div>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "120px", overflowY: "auto" }}>
                                {activities.map((act, i) => (
                                    <div key={i} className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)" }}>
                                        {act}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Services */}
                    <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-purple)", marginBottom: "8px" }}>
                            Exported Services ({services.length})
                        </div>
                        {services.length === 0 ? (
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>No exported services.</div>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "120px", overflowY: "auto" }}>
                                {services.map((srv, i) => (
                                    <div key={i} className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)" }}>
                                        {srv}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Broadcast Receivers */}
                    <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--high)", marginBottom: "8px" }}>
                            Broadcast Receivers ({receivers.length})
                        </div>
                        {receivers.length === 0 ? (
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>No broadcast receivers.</div>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "120px", overflowY: "auto" }}>
                                {receivers.map((rec, i) => (
                                    <div key={i} className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)" }}>
                                        {rec}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Content Providers */}
                    <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--low)", marginBottom: "8px" }}>
                            Content Providers ({providers.length})
                        </div>
                        {providers.length === 0 ? (
                            <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>No content providers.</div>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "4px", maxHeight: "120px", overflowY: "auto" }}>
                                {providers.map((prov, i) => (
                                    <div key={i} className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)" }}>
                                        {prov}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Intent Filters Section */}
            {intentFilters.length > 0 && (
                <div className="garud-card">
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                        <ListFilter size={16} color="var(--accent-cyan)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>DECLARED INTENT FILTERS ({intentFilters.length})</h3>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "240px", overflowY: "auto" }}>
                        {intentFilters.map((filter, idx) => (
                            <div key={idx} style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                                <div className="font-mono" style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-cyan)", marginBottom: "4px" }}>
                                    Component: {filter.component || "Unknown"}
                                </div>
                                <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                    Actions: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{Array.isArray(filter.actions) ? filter.actions.join(", ") : filter.actions}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

export default ManifestTab;

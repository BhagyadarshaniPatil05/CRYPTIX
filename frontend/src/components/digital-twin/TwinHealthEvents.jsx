import React from "react";
import { Activity, Clock, CheckCircle2 } from "lucide-react";

function TwinHealthEvents({ health, events }) {
    const healthMetrics = [
        { label: "Data Integrity", value: health?.data_integrity || "100%", status: "PASSED" },
        { label: "Version Continuity", value: health?.version_continuity || "VALID", status: "PASSED" },
        { label: "Snapshot Health", value: health?.health_grade || health?.grade || "OPTIMAL", status: "HEALTHY" },
        { label: "Sync Status", value: "SYNCHRONIZED", status: "ACTIVE" }
    ];

    const eventList = Array.isArray(events) ? events : events?.events || events?.log || [];

    return (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "20px" }}>
            {/* Twin Health Metrics */}
            <div className="garud-card" style={{ padding: "18px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <Activity size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>TWIN INTEGRITY METRICS</h3>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                    {healthMetrics.map((metric, idx) => (
                        <div
                            key={idx}
                            style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                padding: "8px 12px",
                                backgroundColor: "var(--bg-elevated)",
                                borderRadius: "4px",
                                border: "1px solid var(--border-color)"
                            }}
                        >
                            <span style={{ fontSize: "12px", color: "var(--text-secondary)", fontWeight: "500" }}>
                                {metric.label}
                            </span>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                <span className="font-mono" style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-primary)" }}>
                                    {metric.value}
                                </span>
                                <CheckCircle2 size={13} color="var(--low)" />
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Audit Event Stream */}
            <div className="garud-card" style={{ padding: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Clock size={16} color="var(--accent-cyan)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>TWIN AUDIT EVENT LOG</h3>
                    </div>
                    <span className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                        {eventList.length} Event{eventList.length !== 1 ? "s" : ""}
                    </span>
                </div>

                {eventList.length === 0 ? (
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic", textAlign: "center", padding: "16px 0" }}>
                        No twin lifecycle events recorded yet.
                    </div>
                ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "180px", overflowY: "auto" }}>
                        {eventList.map((evt, idx) => (
                            <div
                                key={idx}
                                style={{
                                    padding: "6px 10px",
                                    backgroundColor: "var(--bg-elevated)",
                                    borderRadius: "4px",
                                    border: "1px solid var(--border-color)",
                                    fontSize: "11px"
                                }}
                            >
                                <div style={{ display: "flex", justifyContent: "space-between", color: "var(--accent-cyan)", fontWeight: "600", marginBottom: "2px" }}>
                                    <span>{typeof evt === "object" ? evt.event || evt.type || "TWIN_EVENT" : "TWIN_MUTATION"}</span>
                                    <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                                        {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : "Recent"}
                                    </span>
                                </div>
                                <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>
                                    {typeof evt === "object" ? evt.description || evt.message || JSON.stringify(evt) : String(evt)}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

export default TwinHealthEvents;

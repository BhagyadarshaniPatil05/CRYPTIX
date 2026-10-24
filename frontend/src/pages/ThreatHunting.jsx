import React from "react";
import { Search, ShieldAlert, Cpu, Key } from "lucide-react";

function ThreatHunting() {
    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Header Strip */}
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "16px 20px",
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px"
                }}
            >
                <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "2px" }}>
                        <Search size={18} color="var(--accent-purple)" />
                        <h1 style={{ fontSize: "18px", fontWeight: "800", letterSpacing: "0.5px" }}>
                            THREAT HUNTING & SIMILARITY QUERY CONSOLE
                        </h1>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        Query corpus for dangerous permission combinations, SMS interceptors, root shell executions, and family signatures.
                    </p>
                </div>
            </div>

            {/* Main Console Box */}
            <div className="garud-card" style={{ textAlign: "center", padding: "48px 24px" }}>
                <Search size={36} color="var(--accent-purple)" style={{ marginBottom: "14px" }} />
                <h2 style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)", marginBottom: "6px" }}>
                    THREAT HUNTING CONSOLE
                </h2>
                <p style={{ fontSize: "12px", color: "var(--text-muted)", maxWidth: "500px", margin: "0 auto 20px auto", lineHeight: "1.5" }}>
                    Advanced indicator query engine, permission similarity search, and cross-sample malware family correlation.
                </p>

                <div
                    className="font-mono"
                    style={{
                        fontSize: "11px",
                        color: "var(--accent-purple)",
                        backgroundColor: "var(--accent-purple-bg)",
                        padding: "6px 14px",
                        borderRadius: "4px",
                        border: "1px solid rgba(139, 156, 255, 0.3)",
                        display: "inline-block",
                        fontWeight: "700"
                    }}
                >
                    PLANNED MODULE — COMING IN PHASE 2.5
                </div>
            </div>
        </div>
    );
}

export default ThreatHunting;

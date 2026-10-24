import React from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Cpu, Activity, ShieldAlert, Clock, RefreshCw } from "lucide-react";

function TwinHeader({ twin, latestVersion, health, lifecycle }) {
    if (!twin) return null;

    const healthScore = health?.health_score ?? health?.score ?? "N/A";
    const healthGrade = health?.health_grade ?? health?.grade ?? "UNHEALTHY";
    const healthTrend = health?.trend ?? "STABLE";

    const riskLevel = latestVersion?.risk_level ?? "UNKNOWN";
    const riskScore = latestVersion?.risk_score ?? 0;

    const getRiskColor = (level) => {
        switch (level?.toUpperCase()) {
            case "HIGH":
            case "CRITICAL":
                return "var(--critical)";
            case "MEDIUM":
                return "var(--medium)";
            case "LOW":
                return "var(--low)";
            default:
                return "var(--text-muted)";
        }
    };

    const getHealthColor = (grade) => {
        switch (grade?.toUpperCase()) {
            case "HEALTHY":
            case "OPTIMAL":
            case "A":
            case "B":
                return "var(--low)";
            case "MODERATE":
            case "C":
                return "var(--medium)";
            default:
                return "var(--critical)";
        }
    };

    return (
        <div style={{ marginBottom: "20px" }}>
            {/* Back link */}
            <Link
                to="/twins"
                style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                    color: "var(--text-muted)",
                    fontSize: "12px",
                    textDecoration: "none",
                    marginBottom: "12px",
                    fontWeight: "600"
                }}
            >
                <ArrowLeft size={14} /> Back to Digital Twins Repository
            </Link>

            {/* Header Card */}
            <div
                style={{
                    padding: "18px 22px",
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px"
                }}
            >
                <div
                    style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        flexWrap: "wrap",
                        gap: "16px"
                    }}
                >
                    {/* Left details */}
                    <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                            <Cpu size={20} color="var(--accent-cyan)" />
                            <h1 style={{ fontSize: "18px", fontWeight: "800", letterSpacing: "0.5px" }}>
                                {twin.app_name || twin.package_name || `Twin #${twin.id}`}
                            </h1>
                            <span
                                className="font-mono"
                                style={{
                                    fontSize: "10px",
                                    color: "var(--accent-cyan)",
                                    backgroundColor: "var(--accent-cyan-bg)",
                                    padding: "2px 6px",
                                    borderRadius: "3px",
                                    border: "1px solid rgba(94, 231, 247, 0.3)",
                                    fontWeight: "700"
                                }}
                            >
                                TWIN ID: #{twin.id}
                            </span>
                        </div>

                        <div className="font-mono" style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "10px" }}>
                            {twin.package_name}
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: "14px", flexWrap: "wrap", fontSize: "11px", color: "var(--text-muted)" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                                <RefreshCw size={12} color="var(--accent-cyan)" />
                                <span>Version Snapshot: <strong style={{ color: "var(--text-primary)" }}>v{twin.current_version || latestVersion?.version_number || 1}</strong></span>
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                                <Clock size={12} color="var(--accent-cyan)" />
                                <span>Updated: <strong style={{ color: "var(--text-primary)" }}>{twin.updated_at ? new Date(twin.updated_at).toLocaleString() : "Recently"}</strong></span>
                            </div>
                        </div>
                    </div>

                    {/* Right stats badges */}
                    <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}>
                        {/* Health Badge */}
                        <div
                            style={{
                                padding: "8px 14px",
                                borderRadius: "4px",
                                backgroundColor: "var(--bg-elevated)",
                                border: `1px solid ${getHealthColor(healthGrade)}`,
                                textAlign: "center"
                            }}
                        >
                            <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700", marginBottom: "2px" }}>
                                Twin Health
                            </div>
                            <div style={{ fontSize: "16px", fontWeight: "800", color: getHealthColor(healthGrade), display: "flex", alignItems: "center", justifyContent: "center", gap: "4px" }}>
                                <Activity size={14} />
                                {typeof healthScore === "number" ? `${healthScore}%` : healthScore}
                            </div>
                            <div style={{ fontSize: "9px", color: "var(--text-muted)", marginTop: "2px" }}>
                                Grade: {healthGrade} ({healthTrend})
                            </div>
                        </div>

                        {/* Lifecycle Badge */}
                        <div
                            style={{
                                padding: "8px 14px",
                                borderRadius: "4px",
                                backgroundColor: "var(--bg-elevated)",
                                border: "1px solid var(--border-color)",
                                textAlign: "center"
                            }}
                        >
                            <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700", marginBottom: "2px" }}>
                                Lifecycle State
                            </div>
                            <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-cyan)", marginTop: "2px" }}>
                                {lifecycle?.status || lifecycle?.state || "MONITORED"}
                            </div>
                            <div style={{ fontSize: "9px", color: "var(--text-muted)", marginTop: "2px" }}>
                                Active Telemetry
                            </div>
                        </div>

                        {/* Current Risk Badge */}
                        <div
                            style={{
                                padding: "8px 14px",
                                borderRadius: "4px",
                                backgroundColor: "var(--bg-elevated)",
                                border: `1px solid ${getRiskColor(riskLevel)}`,
                                textAlign: "center"
                            }}
                        >
                            <div style={{ fontSize: "9px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700", marginBottom: "2px" }}>
                                Risk Posture
                            </div>
                            <div style={{ fontSize: "16px", fontWeight: "800", color: getRiskColor(riskLevel), display: "flex", alignItems: "center", justifyContent: "center", gap: "4px" }}>
                                <ShieldAlert size={14} />
                                {riskScore} / 100
                            </div>
                            <div style={{ fontSize: "9px", color: getRiskColor(riskLevel), fontWeight: "700", marginTop: "2px" }}>
                                {riskLevel} RISK
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default TwinHeader;

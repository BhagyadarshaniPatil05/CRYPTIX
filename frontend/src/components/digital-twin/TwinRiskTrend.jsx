import React from "react";
import { TrendingUp } from "lucide-react";
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    Tooltip,
    CartesianGrid,
    ResponsiveContainer
} from "recharts";

function TwinRiskTrend({ trendData }) {
    let chartData = [];

    if (Array.isArray(trendData)) {
        chartData = trendData.map((item) => ({
            name: `v${item.version ?? item.version_number ?? 1}`,
            score: item.risk_score ?? item.score ?? 0,
            level: item.risk_level ?? "UNKNOWN"
        }));
    } else if (trendData?.trend && Array.isArray(trendData.trend)) {
        chartData = trendData.trend.map((item) => ({
            name: `v${item.version ?? item.version_number ?? 1}`,
            score: item.risk_score ?? item.score ?? 0,
            level: item.risk_level ?? "UNKNOWN"
        }));
    }

    if (chartData.length === 0) {
        return (
            <div className="garud-card" style={{ padding: "20px", marginBottom: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                <TrendingUp size={20} color="var(--text-muted)" style={{ marginBottom: "6px" }} />
                <div>Insufficient version history to chart risk trajectory.</div>
            </div>
        );
    }

    const CustomTooltip = ({ active, payload }) => {
        if (active && payload && payload.length) {
            const data = payload[0].payload;
            return (
                <div
                    style={{
                        backgroundColor: "var(--bg-elevated)",
                        border: "1px solid var(--border-color)",
                        padding: "8px 12px",
                        borderRadius: "4px",
                        boxShadow: "0 4px 12px rgba(0,0,0,0.5)"
                    }}
                >
                    <div style={{ fontWeight: "700", color: "var(--text-primary)", fontSize: "12px" }}>{data.name}</div>
                    <div style={{ color: "var(--accent-cyan)", fontSize: "11px", marginTop: "2px" }}>
                        Risk Score: <strong style={{ color: "var(--text-primary)" }}>{data.score} / 100</strong>
                    </div>
                    <div style={{ color: "var(--text-muted)", fontSize: "10px", marginTop: "2px" }}>
                        Posture Level: <strong style={{ color: "var(--medium)" }}>{data.level}</strong>
                    </div>
                </div>
            );
        }
        return null;
    };

    return (
        <div className="garud-card" style={{ padding: "20px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <TrendingUp size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>RISK POSTURE TRAJECTORY</h3>
                </div>
                <span className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                    Scale: 0 (Secure) - 100 (Critical)
                </span>
            </div>

            <div style={{ width: "100%", height: "220px" }}>
                <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                        <XAxis dataKey="name" stroke="var(--text-muted)" tick={{ fontSize: 11 }} />
                        <YAxis domain={[0, 100]} stroke="var(--text-muted)" tick={{ fontSize: 11 }} />
                        <Tooltip content={<CustomTooltip />} />
                        <Line
                            type="monotone"
                            dataKey="score"
                            stroke="var(--accent-cyan)"
                            strokeWidth={2.5}
                            dot={{ r: 5, fill: "var(--accent-cyan)", stroke: "var(--bg-surface)", strokeWidth: 2 }}
                            activeDot={{ r: 7, fill: "var(--critical)" }}
                        />
                    </LineChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}

export default TwinRiskTrend;

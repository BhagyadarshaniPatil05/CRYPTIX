import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Shield, ShieldAlert, AlertTriangle, Activity, PieChart as PieIcon, BarChart3, Clock, ArrowRight, Loader2, RefreshCw, Database } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import RiskBadge from "../components/common/RiskBadge";
import { getDashboardMetrics, getRiskDistribution, getTopPermissions, getThreatLevels, getRecentAnalyses } from "../api/api";

const RISK_COLORS = ["#FF4D5A", "#FF8A3D", "#F4C95D", "#36D399"];

function Overview() {
    const [metrics, setMetrics] = useState(null);
    const [riskDist, setRiskDist] = useState([]);
    const [topPerms, setTopPerms] = useState([]);
    const [threatLevels, setThreatLevels] = useState({});
    const [recentAnalyses, setRecentAnalyses] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchData = async () => {
        setLoading(true);
        setError(null);
        try {
            const [mRes, rRes, pRes, tRes, recRes] = await Promise.all([
                getDashboardMetrics(),
                getRiskDistribution(),
                getTopPermissions(),
                getThreatLevels(),
                getRecentAnalyses()
            ]);

            setMetrics(mRes);

            const distData = [
                { name: "High", value: rRes.High || 0 },
                { name: "Medium", value: rRes.Medium || 0 },
                { name: "Low", value: rRes.Low || 0 }
            ].filter(item => item.value > 0);

            setRiskDist(distData);
            setTopPerms(pRes || []);
            setThreatLevels(tRes || {});
            setRecentAnalyses(recRes || []);
        } catch (err) {
            console.error("Dashboard data load error:", err);
            setError("Failed to connect to FastAPI backend. Ensure server is active at http://127.0.0.1:8000.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    if (loading) {
        return (
            <div style={{ padding: "80px 0", textAlign: "center" }}>
                <Loader2 size={36} color="var(--accent-cyan)" className="animate-spin" style={{ marginBottom: "16px" }} />
                <h3 className="font-mono" style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-primary)" }}>
                    INITIALIZING THREAT OPERATIONS CENTER...
                </h3>
                <p style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "6px" }}>
                    Synchronizing posture metrics & incident telemetry from backend
                </p>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "40px 0", maxWidth: "600px", margin: "0 auto" }}>
                <div
                    style={{
                        backgroundColor: "var(--critical-bg)",
                        border: "1px solid var(--critical-border)",
                        borderRadius: "6px",
                        padding: "24px",
                        textAlign: "center"
                    }}
                >
                    <ShieldAlert size={36} color="var(--critical)" style={{ marginBottom: "12px" }} />
                    <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--critical)", marginBottom: "8px" }}>
                        BACKEND CONNECTION FAILURE
                    </h3>
                    <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "20px" }}>
                        {error}
                    </p>
                    <button className="btn-primary" onClick={fetchData}>
                        <RefreshCw size={14} /> Retry Telemetry Sync
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
            {/* Header Control Strip */}
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
                        <h1 style={{ fontSize: "18px", fontWeight: "800", letterSpacing: "0.5px" }}>
                            THREAT POSTURE OVERVIEW
                        </h1>
                        <span className="font-mono" style={{ fontSize: "11px", color: "var(--accent-cyan)", backgroundColor: "var(--accent-cyan-bg)", padding: "2px 6px", borderRadius: "3px" }}>
                            LIVE TELEMETRY
                        </span>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        Real-time static posture assessment, risk distribution, and analyzed incident corpus.
                    </p>
                </div>

                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                    <button className="btn-secondary" onClick={fetchData} title="Sync backend telemetry">
                        <RefreshCw size={14} /> Sync Metrics
                    </button>
                </div>
            </div>

            {/* SECTION 1: THREAT POSTURE STRIP */}
            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                    gap: "1px",
                    backgroundColor: "var(--border-color)",
                    borderRadius: "6px",
                    overflow: "hidden",
                    border: "1px solid var(--border-color)"
                }}
            >
                {/* Total Corpus */}
                <div style={{ padding: "18px 20px", backgroundColor: "var(--bg-surface)" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "6px" }}>
                        Analyzed Corpus
                    </div>
                    <div className="font-mono" style={{ fontSize: "28px", fontWeight: "800", color: "var(--text-primary)" }}>
                        {metrics?.total_apks || 0}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>Total APK samples</div>
                </div>

                {/* High Risk */}
                <div style={{ padding: "18px 20px", backgroundColor: "var(--bg-surface)" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--critical)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "6px" }}>
                        High Risk
                    </div>
                    <div className="font-mono" style={{ fontSize: "28px", fontWeight: "800", color: "var(--critical)" }}>
                        {metrics?.high_risk || 0}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>Critical severity samples</div>
                </div>

                {/* Medium Risk */}
                <div style={{ padding: "18px 20px", backgroundColor: "var(--bg-surface)" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--medium)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "6px" }}>
                        Medium Risk
                    </div>
                    <div className="font-mono" style={{ fontSize: "28px", fontWeight: "800", color: "var(--medium)" }}>
                        {metrics?.medium_risk || 0}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>Moderate severity samples</div>
                </div>

                {/* Low Risk */}
                <div style={{ padding: "18px 20px", backgroundColor: "var(--bg-surface)" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--low)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "6px" }}>
                        Low Risk
                    </div>
                    <div className="font-mono" style={{ fontSize: "28px", fontWeight: "800", color: "var(--low)" }}>
                        {metrics?.low_risk || 0}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>Benign / Low threat samples</div>
                </div>

                {/* Average Risk Score */}
                <div style={{ padding: "18px 20px", backgroundColor: "var(--bg-surface)" }}>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-purple)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "6px" }}>
                        Avg Risk Score
                    </div>
                    <div className="font-mono" style={{ fontSize: "28px", fontWeight: "800", color: "var(--accent-cyan)" }}>
                        {metrics?.average_risk_score ? Number(metrics.average_risk_score).toFixed(1) : "0.0"}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>Scale 0 to 100</div>
                </div>
            </div>

            {/* SECTION 2: POSTURE & CLASSIFICATION */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
                {/* Risk Distribution Chart */}
                <div className="garud-card">
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
                        <PieIcon size={16} color="var(--accent-cyan)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>RISK SEVERITY BREAKDOWN</h3>
                    </div>

                    {riskDist.length > 0 ? (
                        <div style={{ height: "240px", width: "100%" }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={riskDist}
                                        dataKey="value"
                                        nameKey="name"
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={55}
                                        outerRadius={85}
                                        paddingAngle={4}
                                    >
                                        {riskDist.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={RISK_COLORS[index % RISK_COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ backgroundColor: "var(--bg-elevated)", borderColor: "var(--border-color)", color: "#fff", borderRadius: "4px" }}
                                    />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <div style={{ height: "180px", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                            No risk distribution telemetry recorded in database yet
                        </div>
                    )}
                </div>

                {/* Threat Classification Levels */}
                <div className="garud-card">
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
                        <ShieldAlert size={16} color="var(--high)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>THREAT SEVERITY CLASSIFICATION</h3>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", borderLeft: "3px solid var(--critical)" }}>
                            <span style={{ fontSize: "13px", fontWeight: "600" }}>CRITICAL THREAT</span>
                            <span className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--critical)" }}>
                                {threatLevels.Critical || 0}
                            </span>
                        </div>

                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", borderLeft: "3px solid var(--high)" }}>
                            <span style={{ fontSize: "13px", fontWeight: "600" }}>HIGH THREAT</span>
                            <span className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--high)" }}>
                                {threatLevels.High || 0}
                            </span>
                        </div>

                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", borderLeft: "3px solid var(--medium)" }}>
                            <span style={{ fontSize: "13px", fontWeight: "600" }}>MEDIUM THREAT</span>
                            <span className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--medium)" }}>
                                {threatLevels.Medium || 0}
                            </span>
                        </div>

                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", borderLeft: "3px solid var(--low)" }}>
                            <span style={{ fontSize: "13px", fontWeight: "600" }}>LOW THREAT</span>
                            <span className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--low)" }}>
                                {threatLevels.Low || 0}
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            {/* SECTION 3: TOP DANGEROUS PERMISSIONS HEATMAP */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
                    <BarChart3 size={16} color="var(--critical)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>TOP DANGEROUS PERMISSION FREQUENCY</h3>
                </div>

                {topPerms.length > 0 ? (
                    <div style={{ height: "260px", width: "100%" }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={topPerms} layout="vertical" margin={{ left: 160, right: 20, top: 10, bottom: 10 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                                <XAxis type="number" stroke="var(--text-muted)" tick={{ fontSize: 11 }} />
                                <YAxis type="category" dataKey="permission" stroke="var(--text-muted)" tick={{ fontSize: 11, fill: "var(--text-secondary)" }} width={150} />
                                <Tooltip contentStyle={{ backgroundColor: "var(--bg-elevated)", borderColor: "var(--border-color)", color: "#fff", borderRadius: "4px" }} />
                                <Bar dataKey="count" fill="var(--critical)" radius={[0, 3, 3, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                ) : (
                    <div style={{ height: "140px", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        No permission frequency telemetry recorded in database
                    </div>
                )}
            </div>

            {/* SECTION 4: RECENT INCIDENT CORPUS QUEUE */}
            <div className="garud-card" style={{ padding: "0", overflow: "hidden" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: "1px solid var(--border-color)", backgroundColor: "rgba(13, 17, 24, 0.9)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Clock size={16} color="var(--accent-cyan)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>RECENT INCIDENT INVESTIGATIONS</h3>
                    </div>
                    <Link to="/apks" style={{ fontSize: "12px", color: "var(--accent-cyan)", textDecoration: "none", fontWeight: "700", display: "flex", alignItems: "center", gap: "4px" }}>
                        Inspect Full Corpus <ArrowRight size={14} />
                    </Link>
                </div>

                {recentAnalyses.length > 0 ? (
                    <table className="soc-table">
                        <thead>
                            <tr>
                                <th>PACKAGE IDENTIFIER</th>
                                <th>POSTURE LEVEL</th>
                                <th>RISK SCORE</th>
                                <th>THREAT CLASS</th>
                                <th style={{ textAlign: "right" }}>ACTION</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recentAnalyses.map((item, idx) => (
                                <tr key={idx}>
                                    <td className="font-mono" style={{ fontSize: "12px" }}>
                                        <strong>{item.package_name}</strong>
                                    </td>
                                    <td>
                                        <RiskBadge level={item.risk_level} />
                                    </td>
                                    <td className="font-mono" style={{ fontSize: "12px" }}>
                                        {item.risk_score} / 100
                                    </td>
                                    <td className="font-mono" style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                        {item.threat_level || "UNKNOWN"}
                                    </td>
                                    <td style={{ textAlign: "right" }}>
                                        {item.apk_id ? (
                                            <Link
                                                to={`/apks/${item.apk_id}`}
                                                style={{
                                                    padding: "4px 10px",
                                                    borderRadius: "4px",
                                                    backgroundColor: "var(--accent-cyan-bg)",
                                                    border: "1px solid rgba(94, 231, 247, 0.3)",
                                                    color: "var(--accent-cyan)",
                                                    fontSize: "11px",
                                                    fontWeight: "700",
                                                    textDecoration: "none"
                                                }}
                                            >
                                                Investigate
                                            </Link>
                                        ) : (
                                            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Analyzed</span>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <div style={{ padding: "30px", textAlign: "center", color: "var(--text-muted)" }}>
                        <Database size={24} color="var(--text-muted)" style={{ marginBottom: "8px" }} />
                        <div style={{ fontSize: "13px", color: "var(--text-primary)", fontWeight: "600", marginBottom: "4px" }}>
                            NO ANALYZED SAMPLES IN CORPUS
                        </div>
                        <div style={{ fontSize: "12px" }}>
                            The analysis database is empty. Click "+ ANALYZE APK" above to acquire your first sample.
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

export default Overview;

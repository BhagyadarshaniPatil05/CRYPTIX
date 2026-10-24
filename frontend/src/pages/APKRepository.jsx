import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Database, Search, Filter, Loader2, ArrowRight, Shield, ArrowUpDown } from "lucide-react";
import RiskBadge from "../components/common/RiskBadge";
import { getRecentAnalyses } from "../api/api";

function APKRepository() {
    const [samples, setSamples] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");
    const [riskFilter, setRiskFilter] = useState("ALL");
    const [sortBy, setSortBy] = useState("NEWEST");

    useEffect(() => {
        const fetchRepository = async () => {
            setLoading(true);
            try {
                const res = await getRecentAnalyses();
                setSamples(res || []);
            } catch (err) {
                console.error("Repository load error:", err);
            } finally {
                setLoading(false);
            }
        };
        fetchRepository();
    }, []);

    const filteredSamples = samples
        .filter((item) => {
            const matchesSearch = (item.package_name || "").toLowerCase().includes(searchTerm.toLowerCase());
            const matchesRisk = riskFilter === "ALL" || (item.risk_level || "").toUpperCase() === riskFilter.toUpperCase();
            return matchesSearch && matchesRisk;
        })
        .sort((a, b) => {
            if (sortBy === "RISK_HIGH") {
                return (b.risk_score || 0) - (a.risk_score || 0);
            }
            // default newest
            return new Date(b.created_at || 0) - new Date(a.created_at || 0);
        });

    const highRiskCount = samples.filter(s => (s.risk_level || "").toUpperCase() === "HIGH" || (s.risk_level || "").toUpperCase() === "CRITICAL").length;

    if (loading) {
        return (
            <div style={{ padding: "80px 0", textAlign: "center" }}>
                <Loader2 size={36} color="var(--accent-cyan)" className="animate-spin" style={{ marginBottom: "16px" }} />
                <h3 className="font-mono" style={{ fontSize: "14px", fontWeight: "700" }}>LOADING APK CORPUS...</h3>
            </div>
        );
    }

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Header Control Strip */}
            <div
                style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "16px 20px",
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    flexWrap: "wrap",
                    gap: "12px"
                }}
            >
                <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "2px" }}>
                        <Database size={18} color="var(--accent-cyan)" />
                        <h1 style={{ fontSize: "18px", fontWeight: "800", letterSpacing: "0.5px" }}>
                            APK INVESTIGATION CORPUS
                        </h1>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        Searchable repository of analyzed Android application packages and threat assessments.
                    </p>
                </div>

                {/* Compact Corpus Metrics */}
                <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
                    <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "700" }}>Total Corpus</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>{samples.length}</div>
                    </div>
                    <div style={{ height: "24px", width: "1px", backgroundColor: "var(--border-color)" }} />
                    <div style={{ textAlign: "right" }}>
                        <div style={{ fontSize: "10px", color: "var(--critical)", textTransform: "uppercase", fontWeight: "700" }}>High Risk</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--critical)" }}>{highRiskCount}</div>
                    </div>
                </div>
            </div>

            {/* Filter & Search Bar */}
            <div className="garud-card" style={{ padding: "14px 18px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "14px", flexWrap: "wrap" }}>
                    <div style={{ flex: 1, minWidth: "260px", display: "flex", alignItems: "center", gap: "8px", backgroundColor: "var(--bg-elevated)", border: "1px solid var(--border-color)", borderRadius: "4px", padding: "6px 12px" }}>
                        <Search size={15} color="var(--text-muted)" />
                        <input
                            type="text"
                            placeholder="Search by package name..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="font-mono"
                            style={{
                                background: "transparent",
                                border: "none",
                                color: "var(--text-primary)",
                                outline: "none",
                                width: "100%",
                                fontSize: "12px"
                            }}
                        />
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Filter size={14} color="var(--text-muted)" />
                        <span style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: "600" }}>Severity:</span>
                        <select
                            value={riskFilter}
                            onChange={(e) => setRiskFilter(e.target.value)}
                            className="font-mono"
                            style={{
                                backgroundColor: "var(--bg-elevated)",
                                border: "1px solid var(--border-color)",
                                color: "var(--text-primary)",
                                padding: "6px 10px",
                                borderRadius: "4px",
                                fontSize: "12px",
                                outline: "none",
                                cursor: "pointer"
                            }}
                        >
                            <option value="ALL">All Severities</option>
                            <option value="HIGH">High / Critical Risk</option>
                            <option value="MEDIUM">Medium Risk</option>
                            <option value="LOW">Low Risk</option>
                        </select>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <ArrowUpDown size={14} color="var(--text-muted)" />
                        <span style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: "600" }}>Sort:</span>
                        <select
                            value={sortBy}
                            onChange={(e) => setSortBy(e.target.value)}
                            className="font-mono"
                            style={{
                                backgroundColor: "var(--bg-elevated)",
                                border: "1px solid var(--border-color)",
                                color: "var(--text-primary)",
                                padding: "6px 10px",
                                borderRadius: "4px",
                                fontSize: "12px",
                                outline: "none",
                                cursor: "pointer"
                            }}
                        >
                            <option value="NEWEST">Newest Analyses</option>
                            <option value="RISK_HIGH">Highest Risk Score</option>
                        </select>
                    </div>
                </div>
            </div>

            {/* Repository Data Table */}
            <div className="garud-card" style={{ padding: "0", overflow: "hidden" }}>
                {filteredSamples.length > 0 ? (
                    <div style={{ overflowX: "auto" }}>
                        <table className="soc-table">
                            <thead>
                                <tr>
                                    <th>PACKAGE IDENTIFIER</th>
                                    <th>POSTURE LEVEL</th>
                                    <th>RISK SCORE</th>
                                    <th>THREAT CLASS</th>
                                    <th>ANALYSIS DATE</th>
                                    <th style={{ textAlign: "right" }}>ACTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredSamples.map((item, idx) => (
                                    <tr key={idx}>
                                        <td className="font-mono" style={{ fontSize: "12px" }}>
                                            <strong style={{ color: "var(--text-primary)" }}>{item.package_name}</strong>
                                        </td>
                                        <td>
                                            <RiskBadge level={item.risk_level} />
                                        </td>
                                        <td className="font-mono" style={{ fontSize: "12px" }}>
                                            <strong style={{ color: "var(--accent-cyan)" }}>{item.risk_score}</strong> / 100
                                        </td>
                                        <td className="font-mono" style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                            {item.threat_level || "UNKNOWN"}
                                        </td>
                                        <td className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                            {item.created_at ? new Date(item.created_at).toLocaleString() : "Recently"}
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
                                                        textDecoration: "none",
                                                        display: "inline-flex",
                                                        alignItems: "center",
                                                        gap: "4px"
                                                    }}
                                                >
                                                    <span>INVESTIGATE</span>
                                                    <ArrowRight size={13} />
                                                </Link>
                                            ) : (
                                                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Analyzed</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-muted)" }}>
                        <Database size={32} color="var(--text-muted)" style={{ marginBottom: "8px" }} />
                        <h3 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)", marginBottom: "4px" }}>
                            NO ANALYZED SAMPLES IN CORPUS
                        </h3>
                        <p style={{ fontSize: "12px", maxWidth: "420px", margin: "0 auto 14px auto" }}>
                            The investigation corpus is empty or no packages match the selected severity query.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
}

export default APKRepository;

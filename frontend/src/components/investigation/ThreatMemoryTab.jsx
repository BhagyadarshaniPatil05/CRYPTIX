import React, { useEffect, useState } from "react";
import {
    Database,
    ShieldCheck,
    GitCompare,
    Layers,
    AlertCircle,
    Copy,
    Check,
    Loader2,
    ArrowRight,
    ExternalLink,
    Info,
    ShieldAlert
} from "lucide-react";
import { Link } from "react-router-dom";
import { getThreatMemory } from "../../api/api";

function ThreatMemoryTab({ apkId }) {
    const [memoryData, setMemoryData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        if (!apkId) return;

        const fetchData = async () => {
            setLoading(true);
            setError(null);
            try {
                const res = await getThreatMemory(apkId);
                setMemoryData(res);
            } catch (err) {
                console.error("Threat Memory fetch error:", err);
                const status = err.response?.status;
                if (status === 404) {
                    setMemoryData({
                        status: "NEW_SAMPLE",
                        sha256: "Sample SHA-256 Lookup",
                        exact_match: false,
                        explanation: { summary: "No matching historical binary or capability overlap found in local corpus." }
                    });
                } else {
                    setError(`Backend Server Error (${status || 500}): ${err.response?.data?.detail || "Failed to retrieve Threat Memory decision."}`);
                }
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [apkId]);

    const handleCopyHash = (text) => {
        if (!text) return;
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    if (loading) {
        return (
            <div style={{ padding: "40px", textAlign: "center", backgroundColor: "var(--bg-surface)", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                <Loader2 size={32} color="#5EE7F7" style={{ animation: "spin 1s linear infinite", marginBottom: "12px" }} />
                <div style={{ fontSize: "14px", color: "var(--text-secondary)", fontWeight: "600" }}>Querying Local Threat Memory & Historical Intelligence...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ padding: "24px", backgroundColor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", color: "#ef4444" }}>
                <AlertCircle size={20} style={{ marginBottom: "8px" }} />
                <div style={{ fontWeight: "700", marginBottom: "4px" }}>THREAT MEMORY BACKEND ERROR</div>
                <div style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{error}</div>
            </div>
        );
    }

    const status = memoryData.status || "NEW_SAMPLE";
    const explanation = memoryData.explanation || {};
    const bestMatch = memoryData.best_match;
    const similarSamples = memoryData.similar_samples || [];

    const getStatusStyle = (st) => {
        switch (st) {
            case "KNOWN_EXACT":
                return {
                    bg: "rgba(239, 68, 68, 0.12)",
                    border: "#ef4444",
                    text: "#ef4444",
                    title: "KNOWN EXACT SAMPLE",
                    sub: "The exact binary hash previously exists in local Threat Memory."
                };
            case "HIGH_SIMILARITY":
                return {
                    bg: "rgba(94, 231, 247, 0.12)",
                    border: "#5EE7F7",
                    text: "#5EE7F7",
                    title: "HIGH STRUCTURAL SIMILARITY MATCH",
                    sub: "High Malware DNA Jaccard similarity detected with historical sample."
                };
            case "RELATED_SAMPLE":
                return {
                    bg: "rgba(139, 156, 255, 0.12)",
                    border: "#8B9CFF",
                    text: "#8B9CFF",
                    title: "RELATED CAPABILITY OVERLAP",
                    sub: "Sample shares meaningful static capabilities with a historical sample."
                };
            case "NEW_SAMPLE":
                return {
                    bg: "rgba(148, 163, 184, 0.1)",
                    border: "#94a3b8",
                    text: "#94a3b8",
                    title: "NEW TO LOCAL THREAT MEMORY",
                    sub: "No matching historical binary or capability overlap found in local corpus."
                };
            default:
                return {
                    bg: "rgba(245, 158, 11, 0.12)",
                    border: "#f59e0b",
                    text: "#f59e0b",
                    title: "THREAT MEMORY ERROR",
                    sub: "An error occurred while querying Threat Memory records."
                };
        }
    };

    const statusStyle = getStatusStyle(status);

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Status Decision Banner */}
            <div
                style={{
                    backgroundColor: statusStyle.bg,
                    border: `1px solid ${statusStyle.border}`,
                    borderRadius: "8px",
                    padding: "20px",
                    display: "flex",
                    alignItems: "center",
                    justify: "space-between",
                    flexWrap: "wrap",
                    gap: "16px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div
                        style={{
                            width: "40px",
                            height: "40px",
                            borderRadius: "8px",
                            backgroundColor: "var(--bg-surface)",
                            border: `1px solid ${statusStyle.border}`,
                            display: "flex",
                            alignItems: "center",
                            justify: "center"
                        }}
                    >
                        <Database size={22} color={statusStyle.text} />
                    </div>
                    <div>
                        <div style={{ fontSize: "16px", fontWeight: "800", color: statusStyle.text, letterSpacing: "0.4px" }}>
                            {statusStyle.title}
                        </div>
                        <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                            {explanation.summary || statusStyle.sub}
                        </div>
                    </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <span
                        style={{
                            padding: "6px 14px",
                            borderRadius: "4px",
                            backgroundColor: "var(--bg-surface)",
                            border: `1px solid ${statusStyle.border}`,
                            color: statusStyle.text,
                            fontSize: "12px",
                            fontWeight: "800",
                            letterSpacing: "0.5px"
                        }}
                    >
                        STATUS: {status}
                    </span>
                </div>
            </div>

            {/* Analyst Notice for NEW_SAMPLE */}
            {status === "NEW_SAMPLE" && (
                <div
                    style={{
                        backgroundColor: "var(--bg-surface)",
                        border: "1px solid var(--border-color)",
                        borderLeft: "4px solid #06b6d4",
                        borderRadius: "6px",
                        padding: "14px 18px",
                        display: "flex",
                        alignItems: "flex-start",
                        gap: "12px"
                    }}
                >
                    <Info size={18} color="#06b6d4" style={{ marginTop: "2px", flexShrink: 0 }} />
                    <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.5" }}>
                        <strong style={{ color: "var(--text-primary)" }}>LOCAL THREAT MEMORY SCOPE NOTICE:</strong>{" "}
                        "NEW_SAMPLE" indicates that this file has not been previously analyzed in the local GARUD-AI corpus.{" "}
                        <span style={{ color: "#5EE7F7" }}>It does NOT indicate that the APK is benign, safe, or globally unknown.</span>
                    </div>
                </div>
            )}

            {/* Identity & Hash Verification Card */}
            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "20px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "14px"
                }}
            >
                <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                    <ShieldCheck size={16} color="#5EE7F7" />
                    EXACT BINARY SHA-256 LOOKUP
                </div>

                <div
                    style={{
                        backgroundColor: "var(--bg-main)",
                        border: "1px solid var(--border-color)",
                        borderRadius: "6px",
                        padding: "12px 14px",
                        display: "flex",
                        alignItems: "center",
                        justify: "space-between",
                        fontSize: "12px"
                    }}
                >
                    <div style={{ display: "flex", alignItems: "center", gap: "10px", overflow: "hidden" }}>
                        <span style={{ color: "var(--text-muted)", fontSize: "11px", fontWeight: "600" }}>SHA-256:</span>
                        <span style={{ fontFamily: "var(--font-mono, monospace)", color: "#5EE7F7", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {memoryData.sha256}
                        </span>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "12px", flexShrink: 0 }}>
                        <span
                            style={{
                                padding: "3px 8px",
                                borderRadius: "4px",
                                backgroundColor: memoryData.exact_match ? "rgba(239, 68, 68, 0.15)" : "rgba(16, 185, 129, 0.15)",
                                color: memoryData.exact_match ? "#ef4444" : "#10b981",
                                fontWeight: "700",
                                fontSize: "11px"
                            }}
                        >
                            {memoryData.exact_match ? "EXACT MATCH FOUND" : "NOT FOUND IN DB"}
                        </span>
                        <button
                            onClick={() => handleCopyHash(memoryData.sha256)}
                            style={{
                                background: "transparent",
                                border: "none",
                                color: copied ? "#10b981" : "var(--text-muted)",
                                cursor: "pointer",
                                display: "flex",
                                alignItems: "center",
                                gap: "4px",
                                fontSize: "11px"
                            }}
                        >
                            {copied ? <Check size={13} /> : <Copy size={13} />}
                        </button>
                    </div>
                </div>
            </div>

            {/* Best Match & Historical Intelligence Panel */}
            {bestMatch && (
                <div
                    style={{
                        backgroundColor: "var(--bg-surface)",
                        border: "1px solid var(--border-color)",
                        borderRadius: "8px",
                        padding: "20px",
                        display: "flex",
                        flexDirection: "column",
                        gap: "16px"
                    }}
                >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap" }}>
                        <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                            <GitCompare size={16} color="#5EE7F7" />
                            HISTORICAL MATCH INTELLIGENCE (BEST MATCH)
                        </div>

                        <Link
                            to={`/apks/${bestMatch.apk_id}`}
                            style={{
                                fontSize: "12px",
                                color: "#5EE7F7",
                                textDecoration: "none",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "4px",
                                fontWeight: "600"
                            }}
                        >
                            Inspect Historical APK #{bestMatch.apk_id} <ExternalLink size={12} />
                        </Link>
                    </div>

                    {/* Metric Cards Grid */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "12px" }}>
                        <div style={{ backgroundColor: "var(--bg-main)", padding: "14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>HISTORICAL SAMPLE</div>
                            <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)", marginTop: "4px" }}>
                                {bestMatch.file_name}
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                                {bestMatch.package_name}
                            </div>
                        </div>

                        <div style={{ backgroundColor: "var(--bg-main)", padding: "14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>SIMILARITY SCORE</div>
                            <div style={{ fontSize: "20px", fontWeight: "800", color: "#5EE7F7", marginTop: "4px" }}>
                                {bestMatch.similarity_score?.toFixed(1)}%
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                                {bestMatch.match_classification}
                            </div>
                        </div>

                        <div style={{ backgroundColor: "var(--bg-main)", padding: "14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>PREVIOUS RISK SCORE</div>
                            <div style={{ fontSize: "20px", fontWeight: "800", color: bestMatch.risk_score >= 70 ? "#ef4444" : "#f59e0b", marginTop: "4px" }}>
                                {bestMatch.risk_score !== null && bestMatch.risk_score !== undefined ? `${bestMatch.risk_score} / 100` : "N/A"}
                            </div>
                            <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                                Threat Level: {bestMatch.threat_level || "UNKNOWN"}
                            </div>
                        </div>

                        {bestMatch.digital_twin_id && (
                            <div style={{ backgroundColor: "var(--bg-main)", padding: "14px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                                <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>DIGITAL TWIN REF</div>
                                <div style={{ fontSize: "14px", fontWeight: "700", color: "#8B9CFF", marginTop: "4px" }}>
                                    Twin #{bestMatch.digital_twin_id}
                                </div>
                                <Link
                                    to={`/twins/${bestMatch.digital_twin_id}`}
                                    style={{ fontSize: "11px", color: "#5EE7F7", textDecoration: "none", marginTop: "2px", display: "inline-block" }}
                                >
                                    Inspect Posture Diff →
                                </Link>
                            </div>
                        )}
                    </div>

                    {/* Shared Features Evidence */}
                    {explanation.shared_features && explanation.shared_features.length > 0 && (
                        <div>
                            <div style={{ fontSize: "12px", fontWeight: "700", color: "#10b981", marginBottom: "8px" }}>
                                SHARED HISTORICAL EVIDENCE ({explanation.shared_features.length})
                            </div>
                            <div style={{ maxHeight: "160px", overflowY: "auto", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                {explanation.shared_features.map((item, idx) => (
                                    <span
                                        key={idx}
                                        style={{
                                            padding: "4px 8px",
                                            borderRadius: "4px",
                                            backgroundColor: "rgba(16, 185, 129, 0.12)",
                                            border: "1px solid rgba(16, 185, 129, 0.3)",
                                            color: "#10b981",
                                            fontSize: "11px",
                                            fontFamily: "var(--font-mono, monospace)"
                                        }}
                                    >
                                        {typeof item === "object" ? `[${item.category}] ${item.feature}` : item}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Top N Similar Historical Samples Table */}
            {similarSamples.length > 0 && (
                <div
                    style={{
                        backgroundColor: "var(--bg-surface)",
                        border: "1px solid var(--border-color)",
                        borderRadius: "8px",
                        padding: "20px"
                    }}
                >
                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)", marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
                        <Layers size={16} color="#5EE7F7" />
                        TOP HISTORICAL MATCHES IN THREAT MEMORY ({similarSamples.length})
                    </div>

                    <div style={{ overflowX: "auto" }}>
                        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
                            <thead>
                                <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
                                    <th style={{ padding: "10px 12px", fontWeight: "600" }}>SAMPLE ID</th>
                                    <th style={{ padding: "10px 12px", fontWeight: "600" }}>FILE / PACKAGE</th>
                                    <th style={{ padding: "10px 12px", fontWeight: "600" }}>SIMILARITY</th>
                                    <th style={{ padding: "10px 12px", fontWeight: "600" }}>CLASSIFICATION</th>
                                    <th style={{ padding: "10px 12px", fontWeight: "600" }}>PRIOR RISK</th>
                                    <th style={{ padding: "10px 12px", fontWeight: "600", textAlign: "right" }}>ACTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                {similarSamples.map((samp) => (
                                    <tr key={samp.apk_id} style={{ borderBottom: "1px solid var(--border-color)" }}>
                                        <td style={{ padding: "10px 12px", fontWeight: "700", color: "var(--text-primary)" }}>
                                            APK #{samp.apk_id}
                                        </td>
                                        <td style={{ padding: "10px 12px" }}>
                                            <div style={{ fontWeight: "600", color: "var(--text-primary)" }}>{samp.file_name}</div>
                                            <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>{samp.package_name}</div>
                                        </td>
                                        <td style={{ padding: "10px 12px", fontWeight: "700", color: "#5EE7F7" }}>
                                            {samp.similarity_score?.toFixed(1)}%
                                        </td>
                                        <td style={{ padding: "10px 12px" }}>
                                            <span
                                                style={{
                                                    padding: "3px 8px",
                                                    borderRadius: "4px",
                                                    backgroundColor: "rgba(94, 231, 247, 0.1)",
                                                    border: "1px solid rgba(94, 231, 247, 0.3)",
                                                    color: "#5EE7F7",
                                                    fontSize: "10px",
                                                    fontWeight: "700"
                                                }}
                                            >
                                                {samp.match_classification}
                                            </span>
                                        </td>
                                        <td style={{ padding: "10px 12px", fontWeight: "700", color: (samp.risk_score || 0) >= 70 ? "#ef4444" : "#f59e0b" }}>
                                            {samp.risk_score !== null && samp.risk_score !== undefined ? `${samp.risk_score}/100` : "N/A"}
                                        </td>
                                        <td style={{ padding: "10px 12px", textAlign: "right" }}>
                                            <Link
                                                to={`/apks/${samp.apk_id}`}
                                                style={{
                                                    backgroundColor: "var(--bg-main)",
                                                    border: "1px solid var(--border-color)",
                                                    color: "#5EE7F7",
                                                    padding: "4px 8px",
                                                    borderRadius: "4px",
                                                    fontSize: "11px",
                                                    textDecoration: "none",
                                                    fontWeight: "600",
                                                    display: "inline-flex",
                                                    alignItems: "center",
                                                    gap: "4px"
                                                }}
                                            >
                                                Inspect <ArrowRight size={12} />
                                            </Link>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}

export default ThreatMemoryTab;

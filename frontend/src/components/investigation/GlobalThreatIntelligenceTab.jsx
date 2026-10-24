import React, { useEffect, useState } from "react";
import {
    Globe,
    ShieldAlert,
    ShieldCheck,
    CheckCircle2,
    XCircle,
    AlertTriangle,
    ExternalLink,
    Lock,
    RefreshCw,
    Server,
    Activity,
    Info
} from "lucide-react";
import { getThreatIntelligence } from "../../api/api";

function GlobalThreatIntelligenceTab({ apkId, sha256 }) {
    const [tiData, setTiData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const loadThreatIntel = async () => {
        if (!apkId) return;
        setLoading(true);
        setError(null);
        try {
            const data = await getThreatIntelligence(apkId);
            setTiData(data);
        } catch (err) {
            console.error("Failed to load Threat Intelligence data:", err);
            const status = err.response?.status;
            if (status === 404) {
                setTiData({ records: [], providers_config: {} });
            } else {
                setError(`Backend Server Error (${status || 500}): ${err.response?.data?.detail || "Failed to load Threat Intelligence data"}`);
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadThreatIntel();
    }, [apkId]);

    if (loading) {
        return (
            <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-secondary)" }}>
                <RefreshCw size={24} className="spin" style={{ marginBottom: "12px", color: "var(--accent-cyan)" }} />
                <p style={{ fontSize: "14px" }}>Querying Global Threat Intelligence Providers...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div
                style={{
                    backgroundColor: "rgba(239, 68, 68, 0.1)",
                    border: "1px solid rgba(239, 68, 68, 0.3)",
                    borderRadius: "6px",
                    padding: "16px",
                    color: "var(--accent-rose)",
                    display: "flex",
                    alignItems: "center",
                    gap: "12px"
                }}
            >
                <AlertTriangle size={20} />
                <div>
                    <h4 style={{ margin: 0, fontSize: "14px", fontWeight: "700" }}>Threat Intelligence Error</h4>
                    <p style={{ margin: "4px 0 0 0", fontSize: "12px", opacity: 0.9 }}>{error}</p>
                </div>
            </div>
        );
    }

    const records = tiData?.records || [];
    const providersConfig = tiData?.providers_config || {};

    const vtRecord = records.find((r) => r.provider === "virustotal");
    const abuseRecords = records.filter((r) => r.provider === "abuseipdb");
    const otxRecord = records.find((r) => r.provider === "otx");

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* 1. Analyst Privacy & Operational Policy Banner */}
            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "16px 20px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "16px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div
                        style={{
                            padding: "8px",
                            borderRadius: "6px",
                            backgroundColor: "rgba(94, 231, 247, 0.1)",
                            color: "var(--accent-cyan)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center"
                        }}
                    >
                        <Lock size={20} />
                    </div>
                    <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span style={{ fontSize: "13px", fontWeight: "700", letterSpacing: "0.5px", color: "var(--text-primary)" }}>
                                HASH-FIRST REPUTATION ENRICHMENT
                            </span>
                            <span
                                style={{
                                    fontSize: "10px",
                                    padding: "2px 8px",
                                    borderRadius: "12px",
                                    backgroundColor: "rgba(16, 185, 129, 0.15)",
                                    color: "var(--accent-emerald)",
                                    fontWeight: "700",
                                    border: "1px solid rgba(16, 185, 129, 0.3)"
                                }}
                            >
                                PRIVACY ENFORCED
                            </span>
                        </div>
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "var(--text-secondary)" }}>
                            GARUD-AI performs hash lookups (SHA-256) and extracted public IOC checks only. Raw APK binary files are never uploaded to external services.
                        </p>
                    </div>
                </div>

                <button
                    onClick={loadThreatIntel}
                    style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "8px 14px",
                        borderRadius: "4px",
                        backgroundColor: "rgba(255, 255, 255, 0.05)",
                        border: "1px solid var(--border-color)",
                        color: "var(--text-primary)",
                        fontSize: "12px",
                        fontWeight: "600",
                        cursor: "pointer"
                    }}
                >
                    <RefreshCw size={14} />
                    <span>Refresh TI</span>
                </button>
            </div>

            {/* 2. TI Provider Connection Status Bar */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "16px" }}>
                {[
                    { key: "virustotal", name: "VirusTotal v3", type: "Hash Lookup Engine", record: vtRecord },
                    { key: "abuseipdb", name: "AbuseIPDB v2", type: "Extracted IP Intelligence", record: abuseRecords[0] },
                    { key: "otx", name: "AlienVault OTX", type: "Community Threat Pulses", record: otxRecord }
                ].map((item) => {
                    const config = providersConfig[item.key] || {};
                    const isConfigured = config.is_configured;
                    const status = item.record?.status || (isConfigured ? "SUCCESS" : "NOT_CONFIGURED");

                    let statusBadgeColor = "var(--text-secondary)";
                    let statusBg = "rgba(255, 255, 255, 0.05)";
                    let statusText = "UNCONFIGURED";

                    if (status === "SUCCESS") {
                        statusBadgeColor = "var(--accent-emerald)";
                        statusBg = "rgba(16, 185, 129, 0.1)";
                        statusText = "CONNECTED";
                    } else if (status === "NOT_FOUND") {
                        statusBadgeColor = "var(--accent-cyan)";
                        statusBg = "rgba(94, 231, 247, 0.1)";
                        statusText = "NO MATCH";
                    } else if (status === "RATE_LIMITED") {
                        statusBadgeColor = "var(--accent-amber)";
                        statusBg = "rgba(245, 158, 11, 0.1)";
                        statusText = "RATE LIMITED";
                    } else if (status === "UNAUTHORIZED" || status === "FORBIDDEN") {
                        statusBadgeColor = "var(--accent-rose)";
                        statusBg = "rgba(239, 68, 68, 0.1)";
                        statusText = "AUTH ERROR";
                    }

                    return (
                        <div
                            key={item.key}
                            style={{
                                backgroundColor: "var(--bg-surface)",
                                border: "1px solid var(--border-color)",
                                borderRadius: "8px",
                                padding: "16px"
                            }}
                        >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                                <div>
                                    <h4 style={{ margin: 0, fontSize: "14px", fontWeight: "700" }}>{item.name}</h4>
                                    <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>{item.type}</span>
                                </div>
                                <span
                                    style={{
                                        fontSize: "10px",
                                        fontWeight: "700",
                                        padding: "3px 8px",
                                        borderRadius: "4px",
                                        backgroundColor: statusBg,
                                        color: statusBadgeColor,
                                        border: `1px solid ${statusBadgeColor}40`
                                    }}
                                >
                                    {statusText}
                                </span>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* 3. VirusTotal File Reputation Section */}
            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "20px"
                }}
            >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <Globe size={18} style={{ color: "var(--accent-cyan)" }} />
                        <h3 style={{ margin: 0, fontSize: "15px", fontWeight: "700", letterSpacing: "0.5px" }}>
                            VIRUSTOTAL FILE REPUTATION
                        </h3>
                    </div>

                    {vtRecord?.normalized_result?.permalink && (
                        <a
                            href={vtRecord.normalized_result.permalink}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "6px",
                                fontSize: "12px",
                                color: "var(--accent-cyan)",
                                textDecoration: "none",
                                fontWeight: "600"
                            }}
                        >
                            <span>Open VirusTotal GUI</span>
                            <ExternalLink size={14} />
                        </a>
                    )}
                </div>

                {!vtRecord || vtRecord.status === "NOT_CONFIGURED" ? (
                    <div
                        style={{
                            backgroundColor: "rgba(255, 255, 255, 0.02)",
                            border: "1px dashed var(--border-color)",
                            borderRadius: "6px",
                            padding: "20px",
                            textAlign: "center"
                        }}
                    >
                        <Info size={24} style={{ color: "var(--text-secondary)", marginBottom: "8px" }} />
                        <p style={{ margin: 0, fontSize: "13px", fontWeight: "600", color: "var(--text-primary)" }}>
                            VirusTotal API Key Not Configured
                        </p>
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "var(--text-secondary)" }}>
                            To enable real-time VirusTotal hash lookups, set <code style={{ color: "var(--accent-cyan)" }}>VIRUSTOTAL_API_KEY</code> in your environment configuration.
                        </p>
                    </div>
                ) : vtRecord.status === "NOT_FOUND" ? (
                    <div style={{ padding: "16px", backgroundColor: "rgba(94, 231, 247, 0.05)", borderRadius: "6px", border: "1px solid rgba(94, 231, 247, 0.2)" }}>
                        <p style={{ margin: 0, fontSize: "13px", color: "var(--text-primary)" }}>
                            <strong>Hash Not Found:</strong> SHA-256 hash has not been previously submitted or indexed in VirusTotal.
                        </p>
                    </div>
                ) : (
                    <div>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "16px" }}>
                            <div style={{ backgroundColor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: "6px", padding: "12px", textAlign: "center" }}>
                                <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-rose)" }}>
                                    {vtRecord.normalized_result?.malicious ?? 0}
                                </span>
                                <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-rose)", marginTop: "2px" }}>MALICIOUS</div>
                            </div>
                            <div style={{ backgroundColor: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.2)", borderRadius: "6px", padding: "12px", textAlign: "center" }}>
                                <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-amber)" }}>
                                    {vtRecord.normalized_result?.suspicious ?? 0}
                                </span>
                                <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-amber)", marginTop: "2px" }}>SUSPICIOUS</div>
                            </div>
                            <div style={{ backgroundColor: "rgba(16, 185, 129, 0.1)", border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: "6px", padding: "12px", textAlign: "center" }}>
                                <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-emerald)" }}>
                                    {vtRecord.normalized_result?.harmless ?? 0}
                                </span>
                                <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-emerald)", marginTop: "2px" }}>HARMLESS</div>
                            </div>
                            <div style={{ backgroundColor: "rgba(255, 255, 255, 0.03)", border: "1px solid var(--border-color)", borderRadius: "6px", padding: "12px", textAlign: "center" }}>
                                <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--text-secondary)" }}>
                                    {vtRecord.normalized_result?.undetected ?? 0}
                                </span>
                                <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-secondary)", marginTop: "2px" }}>UNDETECTED</div>
                            </div>
                        </div>

                        {vtRecord.normalized_result?.meaningful_name && (
                            <div style={{ fontSize: "12px", color: "var(--text-secondary)", display: "flex", gap: "8px" }}>
                                <span style={{ fontWeight: "700", color: "var(--text-primary)" }}>Detection Alias:</span>
                                <span>{vtRecord.normalized_result.meaningful_name}</span>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* 4. AbuseIPDB Extracted IP Reputation Section */}
            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "20px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
                    <Server size={18} style={{ color: "var(--accent-cyan)" }} />
                    <h3 style={{ margin: 0, fontSize: "15px", fontWeight: "700", letterSpacing: "0.5px" }}>
                        ABUSEIPDB EXTRACTED IP REPUTATION
                    </h3>
                </div>

                {abuseRecords.length === 0 ? (
                    <div style={{ padding: "16px", backgroundColor: "rgba(255, 255, 255, 0.02)", borderRadius: "6px", border: "1px dashed var(--border-color)", textAlign: "center" }}>
                        <p style={{ margin: 0, fontSize: "12px", color: "var(--text-secondary)" }}>
                            No public IP address indicators extracted or queried for this sample.
                        </p>
                    </div>
                ) : (
                    <div style={{ overflowX: "auto" }}>
                        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                            <thead>
                                <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-secondary)" }}>
                                    <th style={{ padding: "8px 12px" }}>IP ADDRESS</th>
                                    <th style={{ padding: "8px 12px" }}>CONFIDENCE SCORE</th>
                                    <th style={{ padding: "8px 12px" }}>ISP / PROVIDER</th>
                                    <th style={{ padding: "8px 12px" }}>COUNTRY</th>
                                    <th style={{ padding: "8px 12px" }}>TOTAL REPORTS</th>
                                    <th style={{ padding: "8px 12px" }}>STATUS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {abuseRecords.map((r, idx) => {
                                    const rep = r.normalized_result || {};
                                    const score = rep.abuse_confidence_score ?? 0;
                                    const isPrivate = r.status === "NOT_FOUND" && r.error_detail?.includes("Skipped private");

                                    return (
                                        <tr key={idx} style={{ borderBottom: "1px solid var(--border-color)" }}>
                                            <td style={{ padding: "10px 12px", fontFamily: "JetBrains Mono, monospace", fontWeight: "700" }}>
                                                {r.indicator_value}
                                            </td>
                                            <td style={{ padding: "10px 12px" }}>
                                                {isPrivate ? (
                                                    <span style={{ color: "var(--text-secondary)" }}>N/A</span>
                                                ) : (
                                                    <span
                                                        style={{
                                                            fontWeight: "700",
                                                            color: score > 50 ? "var(--accent-rose)" : score > 15 ? "var(--accent-amber)" : "var(--accent-emerald)"
                                                        }}
                                                    >
                                                        {score}%
                                                    </span>
                                                )}
                                            </td>
                                            <td style={{ padding: "10px 12px", color: "var(--text-secondary)" }}>
                                                {rep.isp || (isPrivate ? "Local Network" : "Unknown")}
                                            </td>
                                            <td style={{ padding: "10px 12px", color: "var(--text-secondary)" }}>
                                                {rep.country_code || "-"}
                                            </td>
                                            <td style={{ padding: "10px 12px", color: "var(--text-secondary)" }}>
                                                {rep.total_reports ?? 0}
                                            </td>
                                            <td style={{ padding: "10px 12px" }}>
                                                {isPrivate ? (
                                                    <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", backgroundColor: "rgba(255,255,255,0.05)", color: "var(--text-secondary)" }}>
                                                        PRIVATE IP
                                                    </span>
                                                ) : r.status === "NOT_CONFIGURED" ? (
                                                    <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", backgroundColor: "rgba(245,158,11,0.1)", color: "var(--accent-amber)" }}>
                                                        NOT CONFIGURED
                                                    </span>
                                                ) : (
                                                    <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", backgroundColor: "rgba(16,185,129,0.1)", color: "var(--accent-emerald)" }}>
                                                        {r.status}
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* 5. AlienVault OTX Pulse Summary Section */}
            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "20px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
                    <Activity size={18} style={{ color: "var(--accent-cyan)" }} />
                    <h3 style={{ margin: 0, fontSize: "15px", fontWeight: "700", letterSpacing: "0.5px" }}>
                        ALIENVAULT OTX THREAT PULSES
                    </h3>
                </div>

                {!otxRecord || otxRecord.status === "NOT_CONFIGURED" ? (
                    <div style={{ padding: "16px", backgroundColor: "rgba(255, 255, 255, 0.02)", borderRadius: "6px", border: "1px dashed var(--border-color)", textAlign: "center" }}>
                        <p style={{ margin: 0, fontSize: "12px", color: "var(--text-secondary)" }}>
                            AlienVault OTX API key is not configured. Set <code style={{ color: "var(--accent-cyan)" }}>OTX_API_KEY</code> in configuration to retrieve community threat pulses.
                        </p>
                    </div>
                ) : otxRecord.status === "NOT_FOUND" || (otxRecord.normalized_result?.pulse_count ?? 0) === 0 ? (
                    <div style={{ padding: "16px", backgroundColor: "rgba(16, 185, 129, 0.05)", borderRadius: "6px", border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                        <p style={{ margin: 0, fontSize: "13px", color: "var(--text-primary)" }}>
                            <strong>No Active Pulses Found:</strong> Indicator is not currently associated with active AlienVault OTX community pulses.
                        </p>
                    </div>
                ) : (
                    <div>
                        <div style={{ marginBottom: "12px" }}>
                            <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Associated Pulses Count: </span>
                            <span style={{ fontSize: "14px", fontWeight: "700", color: "var(--accent-cyan)" }}>
                                {otxRecord.normalized_result.pulse_count}
                            </span>
                        </div>

                        {otxRecord.normalized_result.pulse_names?.length > 0 && (
                            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                                {otxRecord.normalized_result.pulse_names.map((pName, pIdx) => (
                                    <div
                                        key={pIdx}
                                        style={{
                                            padding: "8px 12px",
                                            backgroundColor: "rgba(255, 255, 255, 0.03)",
                                            borderRadius: "4px",
                                            border: "1px solid var(--border-color)",
                                            fontSize: "12px",
                                            color: "var(--text-primary)",
                                            fontWeight: "600"
                                        }}
                                    >
                                        • {pName}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

export default GlobalThreatIntelligenceTab;

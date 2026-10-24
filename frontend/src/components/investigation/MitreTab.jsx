import React, { useEffect, useState } from "react";
import {
    Target,
    ShieldAlert,
    CheckCircle2,
    AlertTriangle,
    ExternalLink,
    Search,
    Filter,
    RefreshCw,
    Info,
    ChevronDown,
    ChevronRight,
    X,
    FileCode,
    Cpu,
    Lock
} from "lucide-react";
import { getMitreMappings, getMitreIOCs } from "../../api/api";

function MitreTab({ apkId }) {
    const [mitreData, setMitreData] = useState(null);
    const [iocData, setIocData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const [searchTerm, setSearchTerm] = useState("");
    const [selectedConfidence, setSelectedConfidence] = useState("ALL");
    const [selectedTechnique, setSelectedTechnique] = useState(null);
    const [expandedTactics, setExpandedTactics] = useState({});

    const loadMitreData = async () => {
        if (!apkId) return;
        setLoading(true);
        setError(null);
        try {
            const [mappingsRes, iocsRes] = await Promise.allSettled([
                getMitreMappings(apkId),
                getMitreIOCs(apkId)
            ]);

            if (mappingsRes.status === "fulfilled") {
                setMitreData(mappingsRes.value);

                // Initialize all tactics as expanded
                const summary = mappingsRes.value.tactics_summary || {};
                const initialExpanded = {};
                Object.keys(summary).forEach((tactic) => {
                    initialExpanded[tactic] = true;
                });
                setExpandedTactics(initialExpanded);
            } else {
                const status = mappingsRes.reason?.response?.status;
                if (status === 404) {
                    setMitreData({
                        mappings: [],
                        total_mappings: 0,
                        confidence_counts: { HIGH: 0, MEDIUM: 0, LOW: 0 },
                        tactics_summary: {}
                    });
                } else {
                    setError(`Backend Server Error (${status || 500}): ${mappingsRes.reason?.response?.data?.detail || "Failed to load MITRE ATT&CK technique mappings"}`);
                }
            }

            if (iocsRes.status === "fulfilled") {
                setIocData(iocsRes.value);
            }
        } catch (err) {
            console.error("Failed to load MITRE ATT&CK data:", err);
            setError("Failed to load MITRE ATT&CK technique mappings");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadMitreData();
    }, [apkId]);

    const toggleTactic = (tactic) => {
        setExpandedTactics((prev) => ({ ...prev, [tactic]: !prev[tactic] }));
    };

    if (loading) {
        return (
            <div style={{ padding: "40px 0", textAlign: "center", color: "var(--text-secondary)" }}>
                <RefreshCw size={24} className="spin" style={{ marginBottom: "12px", color: "var(--accent-cyan)" }} />
                <p style={{ fontSize: "14px" }}>Mapping Evidence to MITRE Mobile ATT&CK Matrix...</p>
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
                    <h4 style={{ margin: 0, fontSize: "14px", fontWeight: "700" }}>MITRE ATT&CK Mapping Error</h4>
                    <p style={{ margin: "4px 0 0 0", fontSize: "12px", opacity: 0.9 }}>{error}</p>
                </div>
            </div>
        );
    }

    const mappings = mitreData?.mappings || [];
    const confidenceCounts = mitreData?.confidence_counts || { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const tacticsSummary = mitreData?.tactics_summary || {};

    // Filter mappings
    const filteredMappings = mappings.filter((m) => {
        const matchesSearch =
            m.technique_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
            m.technique_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            m.evidence_reference.toLowerCase().includes(searchTerm.toLowerCase()) ||
            m.tactic.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesConfidence =
            selectedConfidence === "ALL" || m.confidence.toUpperCase() === selectedConfidence;

        return matchesSearch && matchesConfidence;
    });

    // Group filtered mappings by tactic
    const groupedByTactic = {};
    filteredMappings.forEach((m) => {
        const tactic = m.tactic || "Other";
        if (!groupedByTactic[tactic]) {
            groupedByTactic[tactic] = [];
        }
        groupedByTactic[tactic].push(m);
    });

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Analyst Scope Disclaimer */}
            <div style={{ padding: "12px 16px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderLeft: "4px solid var(--accent-cyan)", borderRadius: "6px", fontSize: "12px", color: "var(--text-secondary)" }}>
                <strong style={{ color: "var(--text-primary)" }}>SECURITY NOTICE:</strong> MITRE Mobile ATT&CK mappings are rule-based detections derived from static binary evidence. Technique mapping indicates potential capability alignment, NOT confirmed runtime execution or active exploitation.
            </div>

            {/* 1. ATT&CK Mobile Domain Banner */}
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
                        <Target size={20} />
                    </div>
                    <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span style={{ fontSize: "13px", fontWeight: "700", letterSpacing: "0.5px", color: "var(--text-primary)" }}>
                                MITRE ATT&CK FOR MOBILE MATRIX (v15.1)
                            </span>
                            <span
                                style={{
                                    fontSize: "10px",
                                    padding: "2px 8px",
                                    borderRadius: "12px",
                                    backgroundColor: "rgba(139, 156, 255, 0.15)",
                                    color: "var(--accent-violet)",
                                    fontWeight: "700",
                                    border: "1px solid rgba(139, 156, 255, 0.3)"
                                }}
                            >
                                DETERMINISTIC MAPPING
                            </span>
                        </div>
                        <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "var(--text-secondary)" }}>
                            Static evidence findings are mapped to official Mobile ATT&CK techniques using deterministic, explainable rules. Zero black-box AI or unverified claims.
                        </p>
                    </div>
                </div>

                <button
                    onClick={loadMitreData}
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
                    <span>Re-Evaluate</span>
                </button>
            </div>

            {/* 2. Technique & Confidence Summary Strip */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "16px" }}>
                <div style={{ backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderRadius: "8px", padding: "16px", textAlign: "center" }}>
                    <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--text-primary)" }}>{mitreData?.total_mappings || 0}</span>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-secondary)", marginTop: "2px" }}>TOTAL TECHNIQUES</div>
                </div>

                <div style={{ backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderRadius: "8px", padding: "16px", textAlign: "center" }}>
                    <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-cyan)" }}>{Object.keys(tacticsSummary).length}</span>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-secondary)", marginTop: "2px" }}>TACTICS COVERED</div>
                </div>

                <div style={{ backgroundColor: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: "8px", padding: "16px", textAlign: "center" }}>
                    <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-rose)" }}>{confidenceCounts.HIGH}</span>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-rose)", marginTop: "2px" }}>HIGH CONFIDENCE</div>
                </div>

                <div style={{ backgroundColor: "rgba(245, 158, 11, 0.08)", border: "1px solid rgba(245, 158, 11, 0.2)", borderRadius: "8px", padding: "16px", textAlign: "center" }}>
                    <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-amber)" }}>{confidenceCounts.MEDIUM}</span>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-amber)", marginTop: "2px" }}>MEDIUM CONFIDENCE</div>
                </div>

                <div style={{ backgroundColor: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: "8px", padding: "16px", textAlign: "center" }}>
                    <span style={{ fontSize: "22px", fontWeight: "800", color: "var(--accent-emerald)" }}>{confidenceCounts.LOW}</span>
                    <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--accent-emerald)", marginTop: "2px" }}>LOW CONFIDENCE</div>
                </div>
            </div>

            {/* 3. Filter & Search Controls */}
            <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                <div style={{ position: "relative", flex: 1 }}>
                    <Search size={14} style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--text-secondary)" }} />
                    <input
                        type="text"
                        placeholder="Search techniques by ID (e.g. T1406), name, or evidence..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        style={{
                            width: "100%",
                            padding: "8px 12px 8px 34px",
                            borderRadius: "4px",
                            backgroundColor: "var(--bg-surface)",
                            border: "1px solid var(--border-color)",
                            color: "var(--text-primary)",
                            fontSize: "12px"
                        }}
                    />
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <Filter size={14} style={{ color: "var(--text-secondary)" }} />
                    <select
                        value={selectedConfidence}
                        onChange={(e) => setSelectedConfidence(e.target.value)}
                        style={{
                            padding: "8px 12px",
                            borderRadius: "4px",
                            backgroundColor: "var(--bg-surface)",
                            border: "1px solid var(--border-color)",
                            color: "var(--text-primary)",
                            fontSize: "12px",
                            cursor: "pointer"
                        }}
                    >
                        <option value="ALL">All Confidence Levels</option>
                        <option value="HIGH">High Confidence Only</option>
                        <option value="MEDIUM">Medium Confidence Only</option>
                        <option value="LOW">Low Confidence Only</option>
                    </select>
                </div>
            </div>

            {/* 4. Tactic Breakdown Accordions & Technique Matrix */}
            {Object.keys(groupedByTactic).length === 0 ? (
                <div style={{ padding: "30px", backgroundColor: "var(--bg-surface)", borderRadius: "8px", border: "1px dashed var(--border-color)", textAlign: "center" }}>
                    <Info size={24} style={{ color: "var(--text-secondary)", marginBottom: "8px" }} />
                    <p style={{ margin: 0, fontSize: "13px", fontWeight: "600", color: "var(--text-primary)" }}>
                        No MITRE Mobile ATT&CK techniques match the search criteria.
                    </p>
                </div>
            ) : (
                Object.keys(groupedByTactic).map((tactic) => {
                    const isExpanded = expandedTactics[tactic] !== false;
                    const tacticMappings = groupedByTactic[tactic];

                    return (
                        <div
                            key={tactic}
                            style={{
                                backgroundColor: "var(--bg-surface)",
                                border: "1px solid var(--border-color)",
                                borderRadius: "8px",
                                overflow: "hidden"
                            }}
                        >
                            <button
                                onClick={() => toggleTactic(tactic)}
                                style={{
                                    width: "100%",
                                    padding: "14px 20px",
                                    backgroundColor: "rgba(255, 255, 255, 0.02)",
                                    border: "none",
                                    borderBottom: isExpanded ? "1px solid var(--border-color)" : "none",
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "space-between",
                                    cursor: "pointer",
                                    color: "var(--text-primary)"
                                }}
                            >
                                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                                    {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                    <span style={{ fontSize: "14px", fontWeight: "700", letterSpacing: "0.5px" }}>
                                        TACTIC: {tactic.toUpperCase()}
                                    </span>
                                    <span
                                        style={{
                                            fontSize: "11px",
                                            fontWeight: "700",
                                            padding: "2px 8px",
                                            borderRadius: "12px",
                                            backgroundColor: "rgba(94, 231, 247, 0.1)",
                                            color: "var(--accent-cyan)",
                                            border: "1px solid rgba(94, 231, 247, 0.3)"
                                        }}
                                    >
                                        {tacticMappings.length} Technique{tacticMappings.length > 1 ? "s" : ""}
                                    </span>
                                </div>
                            </button>

                            {isExpanded && (
                                <div style={{ overflowX: "auto" }}>
                                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                                        <thead>
                                            <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-secondary)" }}>
                                                <th style={{ padding: "10px 16px" }}>TECHNIQUE ID</th>
                                                <th style={{ padding: "10px 16px" }}>TECHNIQUE NAME</th>
                                                <th style={{ padding: "10px 16px" }}>CONFIDENCE</th>
                                                <th style={{ padding: "10px 16px" }}>EVIDENCE REFERENCE</th>
                                                <th style={{ padding: "10px 16px" }}>RULE ID</th>
                                                <th style={{ padding: "10px 16px", textAlign: "right" }}>ACTIONS</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {tacticMappings.map((m) => {
                                                const conf = m.confidence?.toUpperCase() || "MEDIUM";
                                                let badgeBg = "rgba(245, 158, 11, 0.1)";
                                                let badgeColor = "var(--accent-amber)";
                                                if (conf === "HIGH") {
                                                    badgeBg = "rgba(239, 68, 68, 0.1)";
                                                    badgeColor = "var(--accent-rose)";
                                                } else if (conf === "LOW") {
                                                    badgeBg = "rgba(16, 185, 129, 0.1)";
                                                    badgeColor = "var(--accent-emerald)";
                                                }

                                                return (
                                                    <tr key={m.id} style={{ borderBottom: "1px solid var(--border-color)" }}>
                                                        <td style={{ padding: "12px 16px", fontFamily: "JetBrains Mono, monospace", fontWeight: "700", color: "var(--accent-cyan)" }}>
                                                            {m.technique_id}
                                                        </td>
                                                        <td style={{ padding: "12px 16px", fontWeight: "600" }}>
                                                            {m.technique_name}
                                                        </td>
                                                        <td style={{ padding: "12px 16px" }}>
                                                            <span
                                                                style={{
                                                                    fontSize: "10px",
                                                                    fontWeight: "800",
                                                                    padding: "3px 8px",
                                                                    borderRadius: "4px",
                                                                    backgroundColor: badgeBg,
                                                                    color: badgeColor,
                                                                    border: `1px solid ${badgeColor}40`
                                                                }}
                                                            >
                                                                {conf}
                                                            </span>
                                                        </td>
                                                        <td style={{ padding: "12px 16px", fontFamily: "JetBrains Mono, monospace", color: "var(--text-secondary)" }}>
                                                            {m.evidence_reference}
                                                        </td>
                                                        <td style={{ padding: "12px 16px", fontSize: "11px", color: "var(--text-secondary)" }}>
                                                            {m.rule_id}
                                                        </td>
                                                        <td style={{ padding: "12px 16px", textAlign: "right" }}>
                                                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                                                                <button
                                                                    onClick={() => setSelectedTechnique(m)}
                                                                    style={{
                                                                        padding: "4px 10px",
                                                                        borderRadius: "4px",
                                                                        backgroundColor: "rgba(255, 255, 255, 0.05)",
                                                                        border: "1px solid var(--border-color)",
                                                                        color: "var(--text-primary)",
                                                                        fontSize: "11px",
                                                                        fontWeight: "600",
                                                                        cursor: "pointer"
                                                                    }}
                                                                >
                                                                    Inspect Evidence
                                                                </button>

                                                                {m.official_url && (
                                                                    <a
                                                                        href={m.official_url}
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                        style={{
                                                                            display: "flex",
                                                                            alignItems: "center",
                                                                            gap: "4px",
                                                                            padding: "4px 8px",
                                                                            borderRadius: "4px",
                                                                            backgroundColor: "rgba(94, 231, 247, 0.08)",
                                                                            border: "1px solid rgba(94, 231, 247, 0.2)",
                                                                            color: "var(--accent-cyan)",
                                                                            fontSize: "11px",
                                                                            textDecoration: "none"
                                                                        }}
                                                                    >
                                                                        <ExternalLink size={12} />
                                                                    </a>
                                                                )}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    );
                })
            )}

            {/* 5. Technique Evidence Inspection Modal */}
            {selectedTechnique && (
                <div
                    style={{
                        position: "fixed",
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        backgroundColor: "rgba(0, 0, 0, 0.75)",
                        backdropFilter: "blur(4px)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        zIndex: 1000,
                        padding: "20px"
                    }}
                >
                    <div
                        style={{
                            backgroundColor: "var(--bg-surface)",
                            border: "1px solid var(--border-color)",
                            borderRadius: "8px",
                            width: "100%",
                            maxWidth: "640px",
                            maxHeight: "85vh",
                            overflowY: "auto",
                            padding: "24px"
                        }}
                    >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px" }}>
                            <div>
                                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                                    <span style={{ fontSize: "16px", fontWeight: "800", fontFamily: "JetBrains Mono, monospace", color: "var(--accent-cyan)" }}>
                                        {selectedTechnique.technique_id}
                                    </span>
                                    <span style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-primary)" }}>
                                        {selectedTechnique.technique_name}
                                    </span>
                                </div>
                                <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                    Tactic: <strong>{selectedTechnique.tactic}</strong> • Rule: <strong>{selectedTechnique.rule_id}</strong>
                                </span>
                            </div>

                            <button
                                onClick={() => setSelectedTechnique(null)}
                                style={{
                                    background: "none",
                                    border: "none",
                                    color: "var(--text-secondary)",
                                    cursor: "pointer",
                                    padding: "4px"
                                }}
                            >
                                <X size={20} />
                            </button>
                        </div>

                        <div style={{ display: "flex", flexDirection: "column", gap: "16px", fontSize: "13px" }}>
                            <div style={{ backgroundColor: "rgba(255, 255, 255, 0.03)", padding: "12px 16px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                                <h4 style={{ margin: "0 0 6px 0", fontSize: "12px", fontWeight: "700", color: "var(--text-secondary)" }}>WHY THIS TECHNIQUE WAS MAPPED</h4>
                                <p style={{ margin: 0, color: "var(--text-primary)", lineHeight: "1.5" }}>
                                    {selectedTechnique.evidence_summary}
                                </p>
                            </div>

                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                                <div style={{ backgroundColor: "rgba(255, 255, 255, 0.03)", padding: "12px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                                    <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: "700" }}>EVIDENCE TYPE</span>
                                    <div style={{ fontSize: "13px", fontWeight: "700", color: "var(--accent-cyan)", marginTop: "4px" }}>
                                        {selectedTechnique.evidence_type}
                                    </div>
                                </div>

                                <div style={{ backgroundColor: "rgba(255, 255, 255, 0.03)", padding: "12px", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
                                    <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: "700" }}>EVIDENCE REFERENCE</span>
                                    <div style={{ fontSize: "13px", fontWeight: "700", fontFamily: "JetBrains Mono, monospace", color: "var(--text-primary)", marginTop: "4px" }}>
                                        {selectedTechnique.evidence_reference}
                                    </div>
                                </div>
                            </div>

                            {selectedTechnique.description && (
                                <div style={{ backgroundColor: "rgba(94, 231, 247, 0.05)", padding: "12px 16px", borderRadius: "6px", border: "1px solid rgba(94, 231, 247, 0.2)" }}>
                                    <h4 style={{ margin: "0 0 4px 0", fontSize: "12px", fontWeight: "700", color: "var(--accent-cyan)" }}>MITRE OFFICIAL DESCRIPTION</h4>
                                    <p style={{ margin: 0, fontSize: "12px", color: "var(--text-primary)", opacity: 0.9, lineHeight: "1.5" }}>
                                        {selectedTechnique.description}
                                    </p>
                                </div>
                            )}

                            {selectedTechnique.official_url && (
                                <div style={{ textAlign: "right", marginTop: "8px" }}>
                                    <a
                                        href={selectedTechnique.official_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        style={{
                                            display: "inline-flex",
                                            alignItems: "center",
                                            gap: "6px",
                                            padding: "8px 14px",
                                            borderRadius: "4px",
                                            backgroundColor: "var(--accent-cyan)",
                                            color: "#000",
                                            fontSize: "12px",
                                            fontWeight: "700",
                                            textDecoration: "none"
                                        }}
                                    >
                                        <span>View Official MITRE ATT&CK Documentation</span>
                                        <ExternalLink size={14} />
                                    </a>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default MitreTab;

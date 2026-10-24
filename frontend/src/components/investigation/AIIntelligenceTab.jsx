import React, { useState, useEffect } from "react";
import {
    Bot,
    Send,
    RefreshCw,
    AlertTriangle,
    CheckCircle2,
    Info,
    ChevronDown,
    ChevronRight,
    ExternalLink,
    Shield,
    Database,
    FileText,
    Key,
    Sparkles,
    Cpu,
    XCircle,
    Activity,
    Layers,
    Lock
} from "lucide-react";

import { getRAGHealth, askRAGQuestion } from "../../api/api";

function AIIntelligenceTab({ apkId, reportData }) {
    // RAG Health State
    const [health, setHealth] = useState(null);
    const [healthLoading, setHealthLoading] = useState(true);

    // Analyst Question State
    const [question, setQuestion] = useState("");
    const [activeQuery, setActiveQuery] = useState(null);

    // Response & Loading State
    const [loading, setLoading] = useState(false);
    const [response, setResponse] = useState(null);
    const [error, setError] = useState(null);

    // Provenance Accordion Toggle State
    const [expandedChunks, setExpandedChunks] = useState({});

    // Suggested Questions list
    const suggestedQuestions = [
        "Why does this APK appear suspicious based on static analysis?",
        "What MITRE ATT&CK Mobile techniques are associated with this APK?",
        "What evidence suggests SMS-related capability?",
        "What security risks are associated with the observed permissions?",
        "Does this APK show structural similarity to previously analyzed samples?",
        "What capabilities should an analyst investigate further?"
    ];

    // 1. Fetch RAG Health on mount
    const fetchHealth = async () => {
        setHealthLoading(true);
        try {
            const data = await getRAGHealth();
            setHealth(data);
        } catch (err) {
            console.error("RAG health fetch error:", err);
            setHealth({
                status: "unavailable",
                rag_enabled: false,
                vector_store: "sqlite",
                embedding_provider: "tfidf",
                llm_provider: "mock",
                llm_model: "offline-v1",
                llm_configured: false
            });
        } finally {
            setHealthLoading(false);
        }
    };

    useEffect(() => {
        fetchHealth();
    }, []);

    // 2. Handle Inquiry Submission
    const handleAskQuestion = async (selectedQuestion) => {
        const qText = (selectedQuestion || question).trim();
        if (!qText) return;

        setLoading(true);
        setError(null);
        setActiveQuery(qText);

        // Collect APK evidence context from reportData (safely)
        const apkEvidence = [];
        const techniqueIds = [];

        if (reportData) {
            // Extract DEX findings as static capability evidence
            if (Array.isArray(reportData.dex_findings)) {
                reportData.dex_findings.slice(0, 5).forEach((d) => {
                    if (d.api) apkEvidence.push(`Static DEX finding: ${d.api} (${d.category || 'API'})`);
                });
            }
            // Extract dangerous permissions
            if (Array.isArray(reportData.dangerous_permissions)) {
                reportData.dangerous_permissions.slice(0, 5).forEach((p) => {
                    const name = typeof p === "string" ? p : p.permission;
                    if (name) apkEvidence.push(`Static permission grant: ${name}`);
                });
            }
            // Extract MITRE technique IDs if present
            if (Array.isArray(reportData.mitre_mappings)) {
                reportData.mitre_mappings.forEach((m) => {
                    if (m.technique_id && !techniqueIds.includes(m.technique_id)) {
                        techniqueIds.push(m.technique_id);
                    }
                });
            }
        }

        // Construct backend payload conforming to RAGAskRequest (STRICT: NO risk_score / override fields)
        const payload = {
            question: qText,
            apk_id: apkId ? parseInt(apkId, 10) : null,
            technique_ids: techniqueIds,
            apk_evidence: apkEvidence,
            top_k: 5
        };

        try {
            const res = await askRAGQuestion(payload);
            setResponse(res);

            // Initialize all provenance chunks as expanded by default
            if (res && Array.isArray(res.provenance)) {
                const initialExpanded = {};
                res.provenance.forEach((_, idx) => {
                    initialExpanded[idx] = true;
                });
                setExpandedChunks(initialExpanded);
            }
        } catch (err) {
            console.error("RAG ask error:", err);
            const status = err.response?.status;
            if (status === 400) {
                setError("Invalid Question: Question string cannot be empty or whitespace only.");
            } else if (status === 422) {
                setError("Request Validation Error: Question exceeds allowed length (4000 chars) or contains invalid parameters.");
            } else if (status === 503) {
                setError("AI Intelligence is currently unavailable (RAG system disabled in configuration). Deterministic APK analysis remains fully operational.");
            } else {
                setError("An unexpected error occurred while querying the Cybersecurity RAG Engine. Deterministic analysis remains unaffected.");
            }
        } finally {
            setLoading(false);
        }
    };

    const toggleChunk = (idx) => {
        setExpandedChunks((prev) => ({ ...prev, [idx]: !prev[idx] }));
    };

    // Helper for Grounding State Badge
    const renderGroundingBadge = (stateStr) => {
        const state = (stateStr || "INSUFFICIENT_EVIDENCE").toUpperCase();
        if (state === "SUPPORTED") {
            return (
                <div
                    style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        backgroundColor: "rgba(54, 211, 153, 0.12)",
                        border: "1px solid rgba(54, 211, 153, 0.35)",
                        color: "var(--low)",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.5px"
                    }}
                >
                    <CheckCircle2 size={15} />
                    <span>GROUNDING: SUPPORTED</span>
                </div>
            );
        } else if (state === "PARTIALLY_SUPPORTED") {
            return (
                <div
                    style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        backgroundColor: "rgba(244, 201, 93, 0.12)",
                        border: "1px solid rgba(244, 201, 93, 0.35)",
                        color: "var(--medium)",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.5px"
                    }}
                >
                    <AlertTriangle size={15} />
                    <span>GROUNDING: PARTIALLY SUPPORTED</span>
                </div>
            );
        } else {
            return (
                <div
                    style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        backgroundColor: "rgba(125, 138, 154, 0.12)",
                        border: "1px solid rgba(125, 138, 154, 0.35)",
                        color: "var(--text-muted)",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.5px"
                    }}
                >
                    <Info size={15} />
                    <span>GROUNDING: INSUFFICIENT EVIDENCE</span>
                </div>
            );
        }
    };

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Header & Service Health Strip */}
            <div className="garud-card" style={{ padding: "16px 20px" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <div
                            style={{
                                width: "36px",
                                height: "36px",
                                borderRadius: "6px",
                                backgroundColor: "var(--accent-cyan-bg)",
                                border: "1px solid rgba(94, 231, 247, 0.3)",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                color: "var(--accent-cyan)"
                            }}
                        >
                            <Bot size={20} />
                        </div>
                        <div>
                            <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                                CYBERSECURITY RAG INTELLIGENCE WORKSPACE
                            </h3>
                            <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                                Grounded Domain Knowledge Retrieval & Evidence-Backed Reasoning • APK ID #{apkId || "N/A"}
                            </p>
                        </div>
                    </div>

                    {/* RAG Health Status Indicator */}
                    <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                        {healthLoading ? (
                            <span style={{ fontSize: "12px", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: "6px" }}>
                                <RefreshCw size={12} className="spin" /> Checking Service Health...
                            </span>
                        ) : health?.status === "ok" ? (
                            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", fontWeight: "700", color: "var(--low)" }}>
                                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "var(--low)", boxShadow: "0 0 8px var(--low)" }}></span>
                                    RAG Engine Operational
                                </div>
                                <div style={{ fontSize: "11px", color: "var(--text-muted)", borderLeft: "1px solid var(--border-color)", paddingLeft: "12px" }}>
                                    Store: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{health.vector_store}</span> • Provider: <span className="font-mono" style={{ color: "var(--accent-cyan)" }}>{health.llm_provider}</span> ({health.llm_model})
                                </div>
                            </div>
                        ) : (
                            <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", fontWeight: "700", color: "var(--medium)" }}>
                                <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "var(--medium)" }}></span>
                                RAG Status: Disabled / Offline
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Question Composer & Suggested Prompts */}
            <div className="garud-card" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <h4 style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", letterSpacing: "0.5px" }}>
                        ANALYST INQUIRY COMPOSER
                    </h4>
                    <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                        {question.length} / 4000 chars
                    </span>
                </div>

                {/* Suggested Question Chips */}
                <div>
                    <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginBottom: "8px", fontWeight: "600" }}>
                        Suggested Analyst Inquiries (Click to prompt):
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {suggestedQuestions.map((sq, idx) => (
                            <button
                                key={idx}
                                onClick={() => {
                                    setQuestion(sq);
                                    handleAskQuestion(sq);
                                }}
                                disabled={loading}
                                style={{
                                    fontSize: "11px",
                                    padding: "5px 10px",
                                    borderRadius: "4px",
                                    backgroundColor: "var(--bg-elevated)",
                                    border: "1px solid var(--border-color)",
                                    color: "var(--accent-cyan)",
                                    cursor: loading ? "not-allowed" : "pointer",
                                    textAlign: "left",
                                    transition: "all 0.15s ease",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "6px"
                                }}
                                onMouseOver={(e) => (e.currentTarget.style.borderColor = "var(--accent-cyan)")}
                                onMouseOut={(e) => (e.currentTarget.style.borderColor = "var(--border-color)")}
                            >
                                <Sparkles size={11} />
                                <span>{sq}</span>
                            </button>
                        ))}
                    </div>
                </div>

                {/* Textarea & Submit */}
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <textarea
                        value={question}
                        onChange={(e) => setQuestion(e.target.value)}
                        placeholder="Ask a cybersecurity question about this APK sample (e.g. What capabilities does T1412 indicate for SMS privacy?)..."
                        rows={3}
                        maxLength={4000}
                        disabled={loading}
                        style={{
                            width: "100%",
                            padding: "12px",
                            borderRadius: "6px",
                            backgroundColor: "var(--bg-elevated)",
                            border: "1px solid var(--border-color)",
                            color: "var(--text-primary)",
                            fontSize: "13px",
                            fontFamily: "var(--font-sans)",
                            resize: "vertical",
                            outline: "none"
                        }}
                    />

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                        {question && (
                            <button
                                className="btn-secondary"
                                onClick={() => setQuestion("")}
                                disabled={loading}
                                style={{ padding: "8px 14px", fontSize: "12px" }}
                            >
                                Clear
                            </button>
                        )}
                        <button
                            className="btn-primary"
                            onClick={() => handleAskQuestion()}
                            disabled={loading || !question.trim()}
                            style={{
                                padding: "8px 18px",
                                fontSize: "12px",
                                display: "flex",
                                alignItems: "center",
                                gap: "8px",
                                opacity: loading || !question.trim() ? 0.5 : 1
                            }}
                        >
                            {loading ? (
                                <>
                                    <RefreshCw size={14} className="spin" />
                                    <span>Retrieving Knowledge...</span>
                                </>
                            ) : (
                                <>
                                    <Send size={14} />
                                    <span>Submit Inquiry</span>
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </div>

            {/* Error Display */}
            {error && (
                <div
                    style={{
                        backgroundColor: "rgba(255, 77, 90, 0.12)",
                        border: "1px solid rgba(255, 77, 90, 0.35)",
                        borderRadius: "6px",
                        padding: "14px 18px",
                        color: "var(--critical)",
                        display: "flex",
                        alignItems: "center",
                        gap: "12px",
                        fontSize: "13px"
                    }}
                >
                    <AlertTriangle size={18} />
                    <span>{error}</span>
                </div>
            )}

            {/* In-Flight RAG Pipeline Loading Indicator */}
            {loading && (
                <div className="garud-card" style={{ padding: "30px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: "12px" }}>
                    <RefreshCw size={28} className="spin" style={{ color: "var(--accent-cyan)" }} />
                    <div>
                        <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)" }}>
                            EXECUTING CYBERSECURITY RAG PIPELINE
                        </h4>
                        <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" }}>
                            Building query $\rightarrow$ Retrieving knowledge $\rightarrow$ Assembling grounded context $\rightarrow$ Validating grounding
                        </p>
                    </div>
                </div>
            )}

            {/* RAG Response Workspace */}
            {response && !loading && (
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                    {/* Grounded AI Assessment Panel */}
                    <div className="garud-card" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "10px", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px" }}>
                            <div>
                                <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: "600" }}>INQUIRY RESULT</div>
                                <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--accent-cyan)", marginTop: "2px" }}>
                                    "{activeQuery}"
                                </h3>
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                                {renderGroundingBadge(response.grounding?.state)}
                                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                    Provider: <span className="font-mono">{response.provider}</span> • Latency: {response.latency_ms}ms
                                </span>
                            </div>
                        </div>

                        {/* Grounding State Notice */}
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>
                            Grounding indicates how well the generated response is supported by the retrieved evidence. It does not determine the APK's malware verdict or risk score.
                        </div>

                        {/* AI Answer Content */}
                        <div style={{ backgroundColor: "var(--bg-elevated)", border: "1px solid var(--border-color)", borderRadius: "6px", padding: "16px" }}>
                            <div style={{ fontSize: "11px", fontWeight: "700", color: "var(--text-secondary)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                                <Bot size={14} color="var(--accent-cyan)" />
                                GROUNDED AI ASSESSMENT
                            </div>
                            <div
                                style={{
                                    fontSize: "13px",
                                    lineHeight: "1.6",
                                    color: "var(--text-primary)",
                                    whiteSpace: "pre-wrap"
                                }}
                            >
                                {response.answer}
                            </div>
                        </div>

                        {/* Claims & Warnings Section */}
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
                            {/* Supported Claims */}
                            <div style={{ backgroundColor: "var(--bg-elevated)", border: "1px solid var(--border-color)", borderRadius: "6px", padding: "14px" }}>
                                <h5 style={{ fontSize: "12px", fontWeight: "700", color: "var(--low)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                                    <CheckCircle2 size={14} /> SUPPORTED CLAIMS ({response.grounding?.supported_claims?.length || 0})
                                </h5>
                                {response.grounding?.supported_claims?.length > 0 ? (
                                    <ul style={{ paddingLeft: "18px", fontSize: "12px", color: "var(--text-secondary)", margin: 0 }}>
                                        {response.grounding.supported_claims.map((claim, idx) => (
                                            <li key={idx} style={{ marginBottom: "4px" }}>{claim}</li>
                                        ))}
                                    </ul>
                                ) : (
                                    <p style={{ fontSize: "12px", color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>No explicit supported claims extracted.</p>
                                )}
                            </div>

                            {/* Unsupported Claims & Warnings */}
                            <div style={{ backgroundColor: "var(--bg-elevated)", border: "1px solid var(--border-color)", borderRadius: "6px", padding: "14px" }}>
                                <h5 style={{ fontSize: "12px", fontWeight: "700", color: response.grounding?.unsupported_claims?.length > 0 ? "var(--critical)" : "var(--text-muted)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                                    <AlertTriangle size={14} /> UNSUPPORTED CLAIMS & WARNINGS ({ (response.grounding?.unsupported_claims?.length || 0) + (response.grounding?.warnings?.length || 0) })
                                </h5>
                                {response.grounding?.unsupported_claims?.length > 0 || response.grounding?.warnings?.length > 0 ? (
                                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", fontSize: "12px" }}>
                                        {response.grounding?.unsupported_claims?.map((uc, idx) => (
                                            <div key={idx} style={{ color: "var(--critical)" }}>• {uc}</div>
                                        ))}
                                        {response.grounding?.warnings?.map((w, idx) => (
                                            <div key={idx} style={{ color: "var(--medium)" }}>• {w}</div>
                                        ))}
                                    </div>
                                ) : (
                                    <p style={{ fontSize: "12px", color: "var(--low)", fontStyle: "italic", margin: 0 }}>✓ Zero unsupported claims or grounding warnings detected.</p>
                                )}
                            </div>
                        </div>

                        {/* Evidence References */}
                        {response.grounding?.evidence_references?.length > 0 && (
                            <div style={{ backgroundColor: "var(--bg-elevated)", border: "1px solid var(--border-color)", borderRadius: "6px", padding: "14px" }}>
                                <h5 style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-cyan)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                                    <Layers size={14} /> EVIDENCE REFERENCES ({response.grounding.evidence_references.length})
                                </h5>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                                    {response.grounding.evidence_references.map((ref, idx) => (
                                        <span key={idx} className="font-mono" style={{ fontSize: "11px", padding: "4px 8px", borderRadius: "4px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", color: "var(--accent-cyan)" }}>
                                            {ref}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Retrieved Cybersecurity Knowledge & Provenance Cards */}
                    <div className="garud-card" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                            <div>
                                <h4 style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                                    <Database size={16} color="var(--accent-cyan)" />
                                    RETRIEVED CYBERSECURITY KNOWLEDGE PROVENANCE ({response.provenance?.length || 0})
                                </h4>
                                <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                                    Current MITRE RAG knowledge is based on the audited Phase 3.4.1 Mobile ATT&CK v15.1 seed techniques. It is not the complete MITRE ATT&CK Mobile v15.1 knowledge base.
                                </p>
                            </div>
                        </div>

                        {/* Explanatory notice for retrieval scores */}
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>
                            Retrieval scores are ranking signals used to order retrieved knowledge. They are not probabilities and do not represent malware confidence.
                        </div>

                        {/* Provenance Chunks Accordion List */}
                        {response.provenance?.length > 0 ? (
                            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                                {response.provenance.map((item, idx) => {
                                    const isExpanded = expandedChunks[idx] !== false;
                                    return (
                                        <div
                                            key={idx}
                                            style={{
                                                backgroundColor: "var(--bg-elevated)",
                                                border: "1px solid var(--border-color)",
                                                borderRadius: "6px",
                                                overflow: "hidden"
                                            }}
                                        >
                                            {/* Chunk Header Bar */}
                                            <div
                                                onClick={() => toggleChunk(idx)}
                                                style={{
                                                    padding: "12px 16px",
                                                    backgroundColor: "rgba(255, 255, 255, 0.02)",
                                                    display: "flex",
                                                    alignItems: "center",
                                                    justifyContent: "space-between",
                                                    cursor: "pointer",
                                                    userSelect: "none"
                                                }}
                                            >
                                                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                                                    {isExpanded ? <ChevronDown size={16} color="var(--accent-cyan)" /> : <ChevronRight size={16} color="var(--text-muted)" />}
                                                    <span style={{ fontSize: "13px", fontWeight: "700", color: "var(--text-primary)" }}>
                                                        [{item.source_type || 'SOURCE'}] {item.title}
                                                    </span>
                                                    {item.technique_id && (
                                                        <span className="font-mono" style={{ fontSize: "11px", padding: "2px 6px", borderRadius: "3px", backgroundColor: "var(--accent-cyan-bg)", color: "var(--accent-cyan)", border: "1px solid rgba(94, 231, 247, 0.3)" }}>
                                                            {item.technique_id}
                                                        </span>
                                                    )}
                                                    {item.cve_id && (
                                                        <span className="font-mono" style={{ fontSize: "11px", padding: "2px 6px", borderRadius: "3px", backgroundColor: "rgba(255, 77, 90, 0.12)", color: "var(--critical)", border: "1px solid rgba(255, 77, 90, 0.3)" }}>
                                                            {item.cve_id}
                                                        </span>
                                                    )}
                                                </div>

                                                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                                                    <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                                                        Retrieval relevance score: <strong style={{ color: "var(--accent-cyan)" }}>{item.retrieval_score}</strong>
                                                    </span>
                                                    <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                                        Trust: {item.trust_level}
                                                    </span>
                                                </div>
                                            </div>

                                            {/* Expanded Chunk Details */}
                                            {isExpanded && (
                                                <div style={{ padding: "16px", borderTop: "1px solid var(--border-color)", display: "flex", flexDirection: "column", gap: "12px" }}>
                                                    {/* Score Breakdown Bar */}
                                                    <div style={{ backgroundColor: "var(--bg-surface)", padding: "10px 14px", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", flexWrap: "wrap", gap: "16px", fontSize: "11px" }}>
                                                        <div>Exact ID Match: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{item.exact_id_score}</span></div>
                                                        <div>Semantic Similarity: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{item.semantic_score}</span></div>
                                                        <div>Lexical Match: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{item.lexical_score}</span></div>
                                                        <div>Source Trust: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{item.trust_score}</span></div>
                                                        <div>Freshness: <span className="font-mono" style={{ color: "var(--text-primary)" }}>{item.freshness_score}</span></div>
                                                    </div>

                                                    {/* Retrieval Reasons */}
                                                    {item.retrieval_reasons?.length > 0 && (
                                                        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "11px" }}>
                                                            <span style={{ color: "var(--text-muted)", fontWeight: "600" }}>Retrieval Reasons:</span>
                                                            {item.retrieval_reasons.map((r, rIdx) => (
                                                                <span key={rIdx} style={{ padding: "2px 6px", borderRadius: "3px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
                                                                    {r}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}

                                                    {/* Chunk Content */}
                                                    <div style={{ backgroundColor: "var(--bg-main)", padding: "12px", borderRadius: "4px", border: "1px solid var(--border-color)", fontSize: "12px", lineHeight: "1.5", color: "var(--text-primary)", fontFamily: "var(--font-mono)", whiteSpace: "pre-wrap" }}>
                                                        {item.content}
                                                    </div>

                                                    {/* Metadata Footer & Source URL */}
                                                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "11px", color: "var(--text-muted)" }}>
                                                        <div>
                                                            Doc ID: #{item.document_id} • Chunk ID: #{item.chunk_id} • Version: {item.source_version} • Publisher: {item.publisher || "N/A"}
                                                        </div>
                                                        {item.url ? (
                                                            <a
                                                                href={item.url}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                style={{ color: "var(--accent-cyan)", display: "inline-flex", alignItems: "center", gap: "4px", textDecoration: "none", fontWeight: "600" }}
                                                            >
                                                                <span>Official Documentation</span>
                                                                <ExternalLink size={12} />
                                                            </a>
                                                        ) : (
                                                            <span style={{ color: "var(--text-muted)", fontStyle: "italic" }}>Source URL unavailable</span>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        ) : (
                            <p style={{ fontSize: "12px", color: "var(--text-muted)", fontStyle: "italic", margin: 0 }}>No knowledge chunks retrieved.</p>
                        )}
                    </div>
                </div>
            )}

            {/* Static Analysis Boundary Notice */}
            <div
                style={{
                    backgroundColor: "rgba(139, 156, 255, 0.08)",
                    border: "1px solid rgba(139, 156, 255, 0.3)",
                    borderRadius: "6px",
                    padding: "12px 16px",
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    fontSize: "12px",
                    color: "var(--accent-purple)"
                }}
            >
                <Shield size={16} />
                <span>
                    <strong>Static Analysis Boundary Notice:</strong> Static findings represent candidate capabilities and permissions. Runtime execution was not independently established.
                </span>
            </div>
        </div>
    );
}

export default AIIntelligenceTab;

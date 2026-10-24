import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { X, ShieldAlert, CheckCircle2, AlertTriangle, ArrowRight, Loader2, FileCheck, Clock } from "lucide-react";
import APKDropzone from "./APKDropzone";
import CopyButton from "../common/CopyButton";
import RiskBadge from "../common/RiskBadge";
import { uploadAPK, triggerAnalysis } from "../../api/api";

function APKUploadModal({ isOpen, onClose }) {
    const navigate = useNavigate();

    const [file, setFile] = useState(null);
    const [status, setStatus] = useState("IDLE"); // IDLE | UPLOADING | ANALYZING | COMPLETE | DUPLICATE | INVALID_FILE | ERROR
    const [uploadData, setUploadData] = useState(null);
    const [analysisData, setAnalysisData] = useState(null);
    const [errorMessage, setErrorMessage] = useState("");

    // Real Elapsed Time Measurement (measuring actual HTTP request duration)
    const [elapsedMs, setElapsedMs] = useState(0);
    const timerRef = useRef(null);
    const startTimeRef = useRef(null);

    const startTimer = () => {
        setElapsedMs(0);
        startTimeRef.current = Date.now();
        timerRef.current = setInterval(() => {
            if (startTimeRef.current) {
                setElapsedMs(Date.now() - startTimeRef.current);
            }
        }, 100);
    };

    const stopTimer = () => {
        if (timerRef.current) {
            clearInterval(timerRef.current);
            timerRef.current = null;
        }
    };

    useEffect(() => {
        return () => stopTimer();
    }, []);

    if (!isOpen) return null;

    const handleReset = () => {
        stopTimer();
        setFile(null);
        setStatus("IDLE");
        setUploadData(null);
        setAnalysisData(null);
        setErrorMessage("");
        setElapsedMs(0);
    };

    const handleClose = () => {
        handleReset();
        onClose();
    };

    const handleStartUploadAndAnalysis = async () => {
        if (!file) return;

        startTimer();
        try {
            // Step 1: Upload File (POST /upload)
            setStatus("UPLOADING");
            setErrorMessage("");
            
            const uploadRes = await uploadAPK(file);
            setUploadData(uploadRes);

            // Step 2: Trigger Static Analysis (POST /analysis/{apk_id})
            setStatus("ANALYZING");
            const analysisRes = await triggerAnalysis(uploadRes.id);
            setAnalysisData(analysisRes);

            stopTimer();
            setStatus("COMPLETE");
        } catch (err) {
            stopTimer();
            if (err.response) {
                const statusCode = err.response.status;
                const detail = err.response.data?.detail || "Upload / Analysis request failed";

                if (statusCode === 409) {
                    setStatus("DUPLICATE");
                    setErrorMessage(detail);
                } else if (statusCode === 400) {
                    setStatus("INVALID_FILE");
                    setErrorMessage(detail);
                } else {
                    setStatus("ERROR");
                    setErrorMessage(`Server Error (${statusCode}): ${detail}`);
                }
            } else {
                setStatus("ERROR");
                setErrorMessage(err.message || "Network Error: Could not connect to FastAPI backend on port 8000.");
            }
        }
    };

    const handleNavigateToInvestigation = (apkId) => {
        handleClose();
        navigate(`/apks/${apkId}`);
    };

    const formattedElapsed = (elapsedMs / 1000).toFixed(1) + "s";

    return (
        <div
            style={{
                position: "fixed",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: "rgba(5, 7, 12, 0.88)",
                backdropFilter: "blur(4px)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                zIndex: 1000,
                padding: "20px"
            }}
            onClick={handleClose}
        >
            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    width: "100%",
                    maxWidth: "600px",
                    overflow: "hidden",
                    boxShadow: "0 16px 40px rgba(0,0,0,0.7)"
                }}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Modal Header */}
                <div
                    style={{
                        padding: "16px 20px",
                        borderBottom: "1px solid var(--border-color)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        backgroundColor: "var(--bg-elevated)"
                    }}
                >
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <FileCheck size={18} color="var(--accent-cyan)" />
                        <div>
                            <h3 style={{ fontSize: "14px", fontWeight: "800", letterSpacing: "0.5px" }}>
                                SAMPLE ACQUISITION & STATIC INSPECTION
                            </h3>
                            <div className="font-mono" style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                                PRE-STORAGE SHA-256 VALIDATION ENFORCED
                            </div>
                        </div>
                    </div>
                    <button
                        onClick={handleClose}
                        style={{
                            background: "transparent",
                            border: "none",
                            color: "var(--text-muted)",
                            cursor: "pointer",
                            padding: "4px"
                        }}
                    >
                        <X size={18} />
                    </button>
                </div>

                {/* Modal Body */}
                <div style={{ padding: "20px" }}>
                    {status === "IDLE" && (
                        <div>
                            <APKDropzone
                                selectedFile={file}
                                onFileSelect={(f) => setFile(f)}
                                onClearFile={() => setFile(null)}
                            />

                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "20px" }}>
                                <button className="btn-secondary" onClick={handleClose}>
                                    Cancel
                                </button>
                                <button
                                    className="btn-primary"
                                    disabled={!file}
                                    onClick={handleStartUploadAndAnalysis}
                                    style={{
                                        opacity: file ? 1 : 0.5,
                                        cursor: file ? "pointer" : "not-allowed"
                                    }}
                                >
                                    <span>START SAMPLE INSPECTION</span>
                                    <ArrowRight size={14} />
                                </button>
                            </div>
                        </div>
                    )}

                    {(status === "UPLOADING" || status === "ANALYZING") && (
                        <div style={{ textAlign: "center", padding: "20px 10px" }}>
                            <Loader2 size={36} color="var(--accent-cyan)" className="animate-spin" style={{ marginBottom: "16px" }} />

                            <h3 style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)", marginBottom: "4px" }}>
                                {status === "UPLOADING" ? "STREAMING & CALCULATING SHA-256" : "ANALYSIS ENGINE PROCESSING SAMPLE"}
                            </h3>

                            <p style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "16px" }}>
                                {status === "UPLOADING"
                                    ? "Streaming binary buffer into memory & computing SHA-256 before disk commit..."
                                    : "Static analysis pipeline is parsing bytecode & manifest signatures on backend server..."}
                            </p>

                            {/* Real-time Elapsed Time Indicator */}
                            <div
                                style={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: "6px",
                                    padding: "4px 12px",
                                    borderRadius: "4px",
                                    backgroundColor: "var(--bg-elevated)",
                                    border: "1px solid var(--border-color)",
                                    fontSize: "12px",
                                    marginBottom: "20px"
                                }}
                            >
                                <Clock size={13} color="var(--accent-cyan)" />
                                <span style={{ color: "var(--text-muted)" }}>Elapsed Time:</span>
                                <span className="font-mono" style={{ fontWeight: "700", color: "var(--accent-cyan)" }}>
                                    {formattedElapsed}
                                </span>
                            </div>

                            {/* Honest Indeterminate Processing Status Box */}
                            <div
                                style={{
                                    backgroundColor: "var(--bg-elevated)",
                                    border: "1px solid var(--border-color)",
                                    borderRadius: "6px",
                                    padding: "16px",
                                    textAlign: "left",
                                    fontSize: "12px"
                                }}
                            >
                                {uploadData && (
                                    <div style={{ marginBottom: "12px", paddingBottom: "12px", borderBottom: "1px solid var(--border-color)" }}>
                                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                                            <span style={{ color: "var(--text-muted)" }}>FILE:</span>
                                            <span className="font-mono" style={{ color: "var(--text-primary)" }}>{uploadData.filename}</span>
                                        </div>
                                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                                            <span style={{ color: "var(--text-muted)" }}>SHA-256:</span>
                                            <span className="font-mono" style={{ color: "var(--accent-cyan)", fontSize: "11px" }}>
                                                {uploadData.sha256.substring(0, 24)}...
                                            </span>
                                        </div>
                                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                                            <span style={{ color: "var(--text-muted)" }}>APK ID:</span>
                                            <span className="font-mono" style={{ color: "var(--text-primary)" }}>#{uploadData.id}</span>
                                        </div>
                                    </div>
                                )}

                                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--text-secondary)" }}>
                                    <span className="pulse-analyzing" />
                                    <span>Executing Androguard, Manifest, DEX, String, YARA & Digital Twin engines...</span>
                                </div>
                            </div>
                        </div>
                    )}

                    {status === "COMPLETE" && analysisData && (
                        <div>
                            <div
                                style={{
                                    backgroundColor: "var(--low-bg)",
                                    border: "1px solid var(--low-border)",
                                    borderRadius: "6px",
                                    padding: "14px",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "12px",
                                    marginBottom: "16px"
                                }}
                            >
                                <CheckCircle2 size={24} color="var(--low)" />
                                <div>
                                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--low)" }}>
                                        STATIC INSPECTION COMPLETE
                                    </div>
                                    <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                        Completed in <span className="font-mono">{formattedElapsed}</span>. Digital Twin snapshot persisted.
                                    </div>
                                </div>
                            </div>

                            <div className="garud-card" style={{ marginBottom: "16px" }}>
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
                                    <div>
                                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>PACKAGE NAME</div>
                                        <div className="font-mono" style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)" }}>
                                            {analysisData.package_name}
                                        </div>
                                    </div>
                                    <RiskBadge level={analysisData.risk_level} />
                                </div>

                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", fontSize: "12px" }}>
                                    <div>
                                        <span style={{ color: "var(--text-muted)" }}>Risk Score: </span>
                                        <strong className="font-mono" style={{ color: "var(--accent-cyan)" }}>
                                            {analysisData.risk_score} / 100
                                        </strong>
                                    </div>
                                    <div>
                                        <span style={{ color: "var(--text-muted)" }}>APK ID: </span>
                                        <strong className="font-mono">#{uploadData?.id}</strong>
                                    </div>
                                </div>

                                {uploadData?.sha256 && (
                                    <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--border-color)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                            SHA-256: <span className="font-mono" style={{ color: "var(--text-secondary)" }}>{uploadData.sha256.substring(0, 20)}...</span>
                                        </div>
                                        <CopyButton text={uploadData.sha256} />
                                    </div>
                                )}
                            </div>

                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                                <button className="btn-secondary" onClick={handleReset}>
                                    Inspect Another Sample
                                </button>
                                <button
                                    className="btn-primary"
                                    onClick={() => handleNavigateToInvestigation(uploadData.id)}
                                >
                                    <span>OPEN CASE WORKSPACE</span>
                                    <ArrowRight size={14} />
                                </button>
                            </div>
                        </div>
                    )}

                    {status === "DUPLICATE" && (
                        <div>
                            <div
                                style={{
                                    backgroundColor: "var(--medium-bg)",
                                    border: "1px solid var(--medium-border)",
                                    borderRadius: "6px",
                                    padding: "14px",
                                    display: "flex",
                                    alignItems: "flex-start",
                                    gap: "12px",
                                    marginBottom: "16px"
                                }}
                            >
                                <AlertTriangle size={24} color="var(--medium)" style={{ flexShrink: 0, marginTop: "2px" }} />
                                <div>
                                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--medium)", marginBottom: "2px" }}>
                                        DUPLICATE SAMPLE DETECTED
                                    </div>
                                    <div style={{ fontSize: "12px", color: "var(--text-primary)" }}>
                                        This exact APK file is already present in the investigation corpus.
                                    </div>
                                </div>
                            </div>

                            <div className="garud-card" style={{ marginBottom: "16px" }}>
                                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>PRE-STORAGE HASH REJECTION</div>
                                <p style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                    The SHA-256 hash matched an existing record. File overwrite was prevented.
                                </p>
                            </div>

                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                                <button className="btn-secondary" onClick={handleReset}>
                                    Try Another File
                                </button>
                                <button className="btn-primary" onClick={() => { handleClose(); navigate('/apks'); }}>
                                    View APK Corpus
                                </button>
                            </div>
                        </div>
                    )}

                    {status === "INVALID_FILE" && (
                        <div>
                            <div
                                style={{
                                    backgroundColor: "var(--critical-bg)",
                                    border: "1px solid var(--critical-border)",
                                    borderRadius: "6px",
                                    padding: "14px",
                                    display: "flex",
                                    alignItems: "flex-start",
                                    gap: "12px",
                                    marginBottom: "16px"
                                }}
                            >
                                <ShieldAlert size={24} color="var(--critical)" style={{ flexShrink: 0, marginTop: "2px" }} />
                                <div>
                                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--critical)", marginBottom: "2px" }}>
                                        CONTAINER VALIDATION FAILED
                                    </div>
                                    <div style={{ fontSize: "12px", color: "var(--text-primary)" }}>
                                        {errorMessage || "File failed ZIP container header inspection."}
                                    </div>
                                </div>
                            </div>

                            <div style={{ display: "flex", justifyContent: "flex-end" }}>
                                <button className="btn-secondary" onClick={handleReset}>
                                    Select Valid APK
                                </button>
                            </div>
                        </div>
                    )}

                    {status === "ERROR" && (
                        <div>
                            <div
                                style={{
                                    backgroundColor: "var(--critical-bg)",
                                    border: "1px solid var(--critical-border)",
                                    borderRadius: "6px",
                                    padding: "14px",
                                    display: "flex",
                                    alignItems: "flex-start",
                                    gap: "12px",
                                    marginBottom: "16px"
                                }}
                            >
                                <ShieldAlert size={24} color="var(--critical)" style={{ flexShrink: 0, marginTop: "2px" }} />
                                <div>
                                    <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--critical)", marginBottom: "2px" }}>
                                        PIPELINE EXECUTION ERROR
                                    </div>
                                    <div style={{ fontSize: "12px", color: "var(--text-primary)" }}>
                                        {errorMessage}
                                    </div>
                                </div>
                            </div>

                            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                                <button className="btn-secondary" onClick={handleReset}>
                                    Retry
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default APKUploadModal;

import React from "react";
import { Link } from "react-router-dom";
import { FileCode, Download, ArrowLeft, ExternalLink } from "lucide-react";
import RiskBadge from "../common/RiskBadge";
import CopyButton from "../common/CopyButton";

function InvestigationHeader({ reportData, securityScore, twinId }) {
    const summary = reportData.executive_summary || reportData;
    const pkgName = summary.package_name || reportData.package_name || "Unknown Package";
    const appName = summary.app_name || reportData.app_name || "Unknown App";
    const sha256 = summary.sha256 || reportData.sha256;
    const apkId = summary.apk_id || reportData.apk_id;
    const resolvedTwinId = twinId || summary.digital_twin_id || reportData.digital_twin_id;

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <div>
                <Link
                    to="/apks"
                    style={{
                        color: "var(--text-muted)",
                        textDecoration: "none",
                        fontSize: "12px",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        fontWeight: "600"
                    }}
                >
                    <ArrowLeft size={13} /> Return to APK Corpus
                </Link>
            </div>

            <div
                style={{
                    backgroundColor: "var(--bg-surface)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    padding: "18px 22px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "16px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
                    <div
                        style={{
                            width: "44px",
                            height: "44px",
                            borderRadius: "6px",
                            backgroundColor: "var(--bg-elevated)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            border: "1px solid var(--border-color)"
                        }}
                    >
                        <FileCode size={22} color="var(--accent-cyan)" />
                    </div>

                    <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px", flexWrap: "wrap" }}>
                            <h1 style={{ fontSize: "18px", fontWeight: "800", color: "var(--text-primary)" }} className="font-mono">
                                {pkgName}
                            </h1>
                            <RiskBadge level={summary.risk_level || reportData.risk_level || "Low"} />
                            {securityScore?.grade && (
                                <span
                                    className="font-mono"
                                    style={{
                                        fontSize: "11px",
                                        fontWeight: "800",
                                        padding: "2px 8px",
                                        borderRadius: "4px",
                                        backgroundColor: "var(--accent-cyan-bg)",
                                        border: "1px solid rgba(94, 231, 247, 0.3)",
                                        color: "var(--accent-cyan)"
                                    }}
                                >
                                    GRADE {securityScore.grade}
                                </span>
                            )}
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: "14px", fontSize: "12px", color: "var(--text-muted)", flexWrap: "wrap" }}>
                            <span>App Name: <strong style={{ color: "var(--text-primary)" }}>{appName}</strong></span>
                            <span>|</span>
                            {sha256 && (
                                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                    <span>SHA-256:</span>
                                    <span className="font-mono" style={{ color: "var(--text-secondary)" }}>
                                        {sha256.substring(0, 16)}...
                                    </span>
                                    <CopyButton text={sha256} />
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Right Action Buttons */}
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    {resolvedTwinId && (
                        <Link
                            to={`/twins/${resolvedTwinId}`}
                            className="btn-secondary"
                            style={{ fontSize: "12px", padding: "6px 12px" }}
                        >
                            <ExternalLink size={14} />
                            <span>Digital Twin</span>
                        </Link>
                    )}

                    {apkId && (
                        <a
                            href={`http://127.0.0.1:8000/api/v1/reports/${apkId}/pdf`}
                            target="_blank"
                            rel="noreferrer"
                            className="btn-primary"
                            style={{ fontSize: "12px", padding: "6px 14px" }}
                        >
                            <Download size={14} />
                            <span>DOWNLOAD PDF</span>
                        </a>
                    )}
                </div>
            </div>
        </div>
    );
}

export default InvestigationHeader;

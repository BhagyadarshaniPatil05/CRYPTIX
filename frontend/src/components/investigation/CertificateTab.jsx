import React from "react";
import { Award, ShieldCheck, ShieldAlert, Key } from "lucide-react";
import CopyButton from "../common/CopyButton";

function CertificateTab({ reportData }) {
    const certAnalysis = reportData.certificate_analysis || {};
    const certs = certAnalysis.certificates || certAnalysis.cert_details || [];
    const cert = certs.length > 0 ? certs[0] : certAnalysis;

    const isSelfSigned = cert.is_self_signed ?? certAnalysis.is_self_signed ?? false;
    const issuer = cert.issuer || certAnalysis.issuer || "N/A";
    const subject = cert.subject || certAnalysis.subject || "N/A";
    const serial = cert.serial_number || certAnalysis.serial_number || "N/A";
    const sha256 = cert.sha256_fingerprint || certAnalysis.sha256_fingerprint || "N/A";
    const sha1 = cert.sha1_fingerprint || certAnalysis.sha1_fingerprint || "N/A";
    const sigAlg = cert.signature_algorithm || certAnalysis.signature_algorithm || "SHA256withRSA";

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* Header Status Card */}
            <div
                className="garud-card"
                style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: "14px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <Award size={22} color="var(--accent-cyan)" />
                    <div>
                        <h3 style={{ fontSize: "15px", fontWeight: "800" }}>X.509 DIGITAL CERTIFICATE & SIGNATURE</h3>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>APK Signing Key Certificate Inspection</div>
                    </div>
                </div>

                <div
                    className="font-mono"
                    style={{
                        padding: "3px 10px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: "700",
                        backgroundColor: isSelfSigned ? "var(--medium-bg)" : "var(--low-bg)",
                        color: isSelfSigned ? "var(--medium)" : "var(--low)",
                        border: isSelfSigned ? "1px solid var(--medium-border)" : "1px solid var(--low-border)",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px"
                    }}
                >
                    {isSelfSigned ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
                    {isSelfSigned ? "SELF-SIGNED CERTIFICATE" : "CA VERIFIED CERTIFICATE"}
                </div>
            </div>

            {/* Certificate Details Grid */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <Key size={16} color="var(--accent-purple)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>SIGNER IDENTIFICATION METADATA</h3>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>ISSUER DISTINGUISHED NAME</div>
                        <div className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)", wordBreak: "break-all" }}>
                            {issuer}
                        </div>
                    </div>

                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>SUBJECT DISTINGUISHED NAME</div>
                        <div className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)", wordBreak: "break-all" }}>
                            {subject}
                        </div>
                    </div>

                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>SERIAL NUMBER</div>
                        <div className="font-mono" style={{ fontSize: "11px", color: "var(--text-primary)", wordBreak: "break-all" }}>
                            {serial}
                        </div>
                    </div>

                    <div style={{ padding: "10px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>SIGNATURE ALGORITHM</div>
                        <div className="font-mono" style={{ fontSize: "11px", color: "var(--accent-cyan)" }}>
                            {sigAlg}
                        </div>
                    </div>
                </div>
            </div>

            {/* Cryptographic Fingerprints */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <Key size={16} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>CRYPTOGRAPHIC FINGERPRINTS</h3>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <div style={{ padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div>
                            <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>SHA-256 Fingerprint</div>
                            <div className="font-mono" style={{ fontSize: "11px", color: "var(--accent-cyan)", marginTop: "2px", wordBreak: "break-all" }}>
                                {sha256}
                            </div>
                        </div>
                        {sha256 !== "N/A" && <CopyButton text={sha256} />}
                    </div>

                    <div style={{ padding: "10px 14px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div>
                            <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>SHA-1 Fingerprint</div>
                            <div className="font-mono" style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px", wordBreak: "break-all" }}>
                                {sha1}
                            </div>
                        </div>
                        {sha1 !== "N/A" && <CopyButton text={sha1} />}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default CertificateTab;

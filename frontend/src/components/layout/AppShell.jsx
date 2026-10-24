import React, { useState } from "react";
import CommandNav from "./CommandNav";
import APKUploadModal from "../upload/APKUploadModal";

function AppShell({ children }) {
    const [isUploadOpen, setIsUploadOpen] = useState(false);

    return (
        <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
            <CommandNav onOpenUpload={() => setIsUploadOpen(true)} />

            <main style={{ flex: 1, padding: "24px", maxWidth: "1500px", margin: "0 auto", width: "100%" }}>
                {children}
            </main>

            <footer
                style={{
                    borderTop: "1px solid var(--border-color)",
                    backgroundColor: "var(--bg-surface)",
                    padding: "14px 24px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    fontSize: "11px",
                    color: "var(--text-muted)",
                    marginTop: "40px"
                }}
            >
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span className="font-mono" style={{ color: "var(--text-secondary)", fontWeight: "600" }}>
                        GARUD-AI OPERATIONS CENTER
                    </span>
                    <span>|</span>
                    <span>Android Security Inspection & Posture Telemetry Engine</span>
                </div>

                <div className="font-mono" style={{ fontSize: "11px" }}>
                    FASTAPI BACKEND: 127.0.0.1:8000/api/v1 ● PRE-STORAGE SHA-256 ENFORCED
                </div>
            </footer>

            <APKUploadModal
                isOpen={isUploadOpen}
                onClose={() => setIsUploadOpen(false)}
            />
        </div>
    );
}

export default AppShell;

import React, { useState, useRef } from "react";
import { UploadCloud, FileCode, CheckCircle2, X } from "lucide-react";

function APKDropzone({ onFileSelect, selectedFile, onClearFile }) {
    const [isDragOver, setIsDragOver] = useState(false);
    const fileInputRef = useRef(null);

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(true);
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragOver(false);

        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            const file = e.dataTransfer.files[0];
            onFileSelect(file);
        }
    };

    const handleFileInputChange = (e) => {
        if (e.target.files && e.target.files.length > 0) {
            const file = e.target.files[0];
            onFileSelect(file);
        }
    };

    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    return (
        <div style={{ width: "100%" }}>
            <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileInputChange}
                accept=".apk"
                style={{ display: "none" }}
            />

            {!selectedFile ? (
                <div
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    style={{
                        border: isDragOver
                            ? "2px dashed var(--accent-cyan)"
                            : "2px dashed var(--border-color)",
                        backgroundColor: isDragOver
                            ? "var(--accent-cyan-bg)"
                            : "var(--bg-elevated)",
                        borderRadius: "6px",
                        padding: "32px 20px",
                        textAlign: "center",
                        cursor: "pointer",
                        transition: "all 0.15s ease"
                    }}
                >
                    <div
                        style={{
                            width: "48px",
                            height: "48px",
                            borderRadius: "50%",
                            backgroundColor: "var(--bg-surface)",
                            border: "1px solid var(--border-color)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            margin: "0 auto 12px auto"
                        }}
                    >
                        <UploadCloud size={24} color={isDragOver ? "var(--accent-cyan)" : "var(--text-muted)"} />
                    </div>

                    <h3 style={{ fontSize: "14px", fontWeight: "700", marginBottom: "4px" }}>
                        {isDragOver ? "RELEASE TO DROP APK SAMPLE" : "DROP APK FILE FOR STATIC INSPECTION"}
                    </h3>

                    <p style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "14px" }}>
                        Supports Android Application Archive files (.apk)
                    </p>

                    <button
                        type="button"
                        className="btn-secondary"
                        onClick={(e) => {
                            e.stopPropagation();
                            fileInputRef.current?.click();
                        }}
                        style={{ fontSize: "12px", padding: "6px 14px" }}
                    >
                        Select File
                    </button>
                </div>
            ) : (
                <div
                    style={{
                        border: "1px solid rgba(94, 231, 247, 0.3)",
                        backgroundColor: "var(--accent-cyan-bg)",
                        borderRadius: "6px",
                        padding: "16px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between"
                    }}
                >
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                        <div
                            style={{
                                width: "36px",
                                height: "36px",
                                borderRadius: "4px",
                                backgroundColor: "var(--bg-surface)",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                border: "1px solid var(--border-color)"
                            }}
                        >
                            <FileCode size={20} color="var(--accent-cyan)" />
                        </div>
                        <div>
                            <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-primary)" }}>
                                {selectedFile.name}
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "2px" }}>
                                <span className="font-mono" style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                                    {formatBytes(selectedFile.size)}
                                </span>
                                <span style={{ fontSize: "11px", color: "var(--low)", display: "flex", alignItems: "center", gap: "4px" }}>
                                    <CheckCircle2 size={12} /> Ready for analysis
                                </span>
                            </div>
                        </div>
                    </div>

                    <button
                        onClick={onClearFile}
                        style={{
                            background: "transparent",
                            border: "none",
                            color: "var(--text-muted)",
                            cursor: "pointer",
                            padding: "4px"
                        }}
                        title="Remove selected file"
                    >
                        <X size={16} />
                    </button>
                </div>
            )}
        </div>
    );
}

export default APKDropzone;

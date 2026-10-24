import React, { useState } from "react";
import { Copy, Check } from "lucide-react";

function CopyButton({ text, label = "Copy" }) {
    const [copied, setCopied] = useState(false);

    const handleCopy = (e) => {
        e.stopPropagation();
        if (text) {
            navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    };

    return (
        <button
            onClick={handleCopy}
            className="btn-secondary"
            style={{
                padding: "4px 10px",
                fontSize: "12px",
                borderRadius: "6px",
                height: "28px"
            }}
            title="Copy SHA-256 Hash"
        >
            {copied ? (
                <>
                    <Check size={14} color="#10b981" />
                    <span style={{ color: "#10b981" }}>Copied!</span>
                </>
            ) : (
                <>
                    <Copy size={14} />
                    <span>{label}</span>
                </>
            )}
        </button>
    );
}

export default CopyButton;

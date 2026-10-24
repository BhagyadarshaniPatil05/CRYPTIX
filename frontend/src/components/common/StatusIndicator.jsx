import React from "react";

function StatusIndicator({ status = "online", label = "SYSTEM ONLINE" }) {
    const isOnline = status === "online";

    return (
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span className={isOnline ? "pulse-online" : "pulse-analyzing"} />
            <span
                className="font-mono"
                style={{
                    fontSize: "12px",
                    fontWeight: "600",
                    letterSpacing: "0.8px",
                    color: isOnline ? "#10b981" : "#06b6d4"
                }}
            >
                {label}
            </span>
        </div>
    );
}

export default StatusIndicator;

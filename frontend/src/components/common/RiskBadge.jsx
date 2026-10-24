import React from "react";

function RiskBadge({ level }) {
    const norm = (level || "low").toLowerCase();

    let style = {
        color: "var(--low)",
        backgroundColor: "var(--low-bg)",
        borderColor: "var(--low-border)"
    };

    if (norm === "critical") {
        style = {
            color: "var(--critical)",
            backgroundColor: "var(--critical-bg)",
            borderColor: "var(--critical-border)"
        };
    } else if (norm === "high") {
        style = {
            color: "var(--high)",
            backgroundColor: "var(--high-bg)",
            borderColor: "var(--high-border)"
        };
    } else if (norm === "medium") {
        style = {
            color: "var(--medium)",
            backgroundColor: "var(--medium-bg)",
            borderColor: "var(--medium-border)"
        };
    }

    return (
        <span
            className="font-mono"
            style={{
                display: "inline-flex",
                alignItems: "center",
                padding: "2px 8px",
                borderRadius: "3px",
                fontSize: "11px",
                fontWeight: "700",
                textTransform: "uppercase",
                letterSpacing: "0.4px",
                border: `1px solid ${style.borderColor}`,
                color: style.color,
                backgroundColor: style.backgroundColor
            }}
        >
            {level || "Low"}
        </span>
    );
}

export default RiskBadge;

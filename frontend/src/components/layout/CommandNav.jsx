import React from "react";
import { NavLink } from "react-router-dom";
import { Shield, Upload, Activity, Database, Search, Cpu } from "lucide-react";
import StatusIndicator from "../common/StatusIndicator";

function CommandNav({ onOpenUpload }) {
    return (
        <header
            style={{
                backgroundColor: "var(--bg-surface)",
                borderBottom: "1px solid var(--border-color)",
                padding: "0 24px",
                height: "60px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                position: "sticky",
                top: 0,
                zIndex: 100
            }}
        >
            {/* Left: Brand Identity */}
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <div
                    style={{
                        width: "32px",
                        height: "32px",
                        borderRadius: "4px",
                        backgroundColor: "rgba(94, 231, 247, 0.1)",
                        border: "1px solid rgba(94, 231, 247, 0.3)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center"
                    }}
                >
                    <Shield size={18} color="var(--accent-cyan)" />
                </div>

                <div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span
                            style={{
                                fontSize: "16px",
                                fontWeight: "800",
                                letterSpacing: "1.2px",
                                color: "var(--text-primary)"
                            }}
                        >
                            GARUD<span style={{ color: "var(--accent-cyan)" }}>-AI</span>
                        </span>
                        <span
                            className="font-mono"
                            style={{
                                fontSize: "10px",
                                padding: "1px 5px",
                                borderRadius: "3px",
                                backgroundColor: "rgba(139, 156, 255, 0.12)",
                                color: "var(--accent-purple)",
                                border: "1px solid rgba(139, 156, 255, 0.25)",
                                fontWeight: "700"
                            }}
                        >
                            SOC v2.4
                        </span>
                    </div>
                    <div
                        className="font-mono"
                        style={{
                            fontSize: "10px",
                            color: "var(--text-muted)",
                            letterSpacing: "0.5px"
                        }}
                    >
                        ANDROID THREAT OPERATIONS CENTER
                    </div>
                </div>
            </div>

            {/* Middle: Command Center Navigation Links */}
            <nav style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                <NavLink
                    to="/"
                    end
                    style={({ isActive }) => ({
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        textDecoration: "none",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.3px",
                        color: isActive ? "var(--accent-cyan)" : "var(--text-secondary)",
                        backgroundColor: isActive ? "var(--accent-cyan-bg)" : "transparent",
                        border: isActive ? "1px solid rgba(94, 231, 247, 0.25)" : "1px solid transparent",
                        transition: "all 0.15s ease"
                    })}
                >
                    <Activity size={15} />
                    <span>OVERVIEW</span>
                </NavLink>

                <NavLink
                    to="/apks"
                    style={({ isActive }) => ({
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        textDecoration: "none",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.3px",
                        color: isActive ? "var(--accent-cyan)" : "var(--text-secondary)",
                        backgroundColor: isActive ? "var(--accent-cyan-bg)" : "transparent",
                        border: isActive ? "1px solid rgba(94, 231, 247, 0.25)" : "1px solid transparent",
                        transition: "all 0.15s ease"
                    })}
                >
                    <Database size={15} />
                    <span>APK CORPUS</span>
                </NavLink>

                <NavLink
                    to="/hunting"
                    style={({ isActive }) => ({
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        textDecoration: "none",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.3px",
                        color: isActive ? "var(--accent-cyan)" : "var(--text-secondary)",
                        backgroundColor: isActive ? "var(--accent-cyan-bg)" : "transparent",
                        border: isActive ? "1px solid rgba(94, 231, 247, 0.25)" : "1px solid transparent",
                        transition: "all 0.15s ease"
                    })}
                >
                    <Search size={15} />
                    <span>THREAT HUNTING</span>
                </NavLink>

                <NavLink
                    to="/twins"
                    style={({ isActive }) => ({
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        padding: "6px 12px",
                        borderRadius: "4px",
                        textDecoration: "none",
                        fontSize: "12px",
                        fontWeight: "700",
                        letterSpacing: "0.3px",
                        color: isActive ? "var(--accent-cyan)" : "var(--text-secondary)",
                        backgroundColor: isActive ? "var(--accent-cyan-bg)" : "transparent",
                        border: isActive ? "1px solid rgba(94, 231, 247, 0.25)" : "1px solid transparent",
                        transition: "all 0.15s ease"
                    })}
                >
                    <Cpu size={15} />
                    <span>DIGITAL TWINS</span>
                </NavLink>
            </nav>

            {/* Right: System Status & Action */}
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                <StatusIndicator status="online" label="SYSTEM ● ONLINE" />

                <button onClick={onOpenUpload} className="btn-primary">
                    <Upload size={14} />
                    <span>+ ANALYZE APK</span>
                </button>
            </div>
        </header>
    );
}

export default CommandNav;

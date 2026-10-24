import React from "react";
import { Shield, FileText, Cpu, Key, Award, ShieldAlert, Dna, Database, Globe, Target, Bot } from "lucide-react";

function InvestigationNav({ activeTab, onTabChange }) {
    const tabs = [
        { id: "overview", label: "OVERVIEW", icon: Shield },
        { id: "manifest", label: "MANIFEST & PERMISSIONS", icon: FileText },
        { id: "behaviors", label: "STATIC BEHAVIORS & DEX", icon: Cpu },
        { id: "strings", label: "STRINGS, IOCs & YARA", icon: Key },
        { id: "certificate", label: "CERTIFICATE", icon: Award },
        { id: "dna", label: "MALWARE DNA", icon: Dna },
        { id: "threat_memory", label: "THREAT MEMORY", icon: Database },
        { id: "threat_intelligence", label: "GLOBAL THREAT INTEL", icon: Globe },
        { id: "mitre", label: "MITRE ATT&CK", icon: Target },
        { id: "ai_intelligence", label: "AI INTELLIGENCE", icon: Bot },
        { id: "playbook", label: "PLAYBOOK & REPORT", icon: ShieldAlert }
    ];


    return (
        <div
            style={{
                display: "flex",
                alignItems: "center",
                gap: "4px",
                borderBottom: "1px solid var(--border-color)",
                paddingBottom: "0",
                overflowX: "auto"
            }}
        >
            {tabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                    <button
                        key={tab.id}
                        onClick={() => onTabChange(tab.id)}
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "6px",
                            padding: "8px 14px",
                            borderRadius: "4px 4px 0 0",
                            border: "1px solid",
                            borderColor: isActive ? "var(--border-color)" : "transparent",
                            borderBottom: isActive ? "2px solid var(--accent-cyan)" : "none",
                            backgroundColor: isActive ? "var(--bg-surface)" : "transparent",
                            color: isActive ? "var(--accent-cyan)" : "var(--text-secondary)",
                            fontSize: "12px",
                            fontWeight: isActive ? "700" : "600",
                            letterSpacing: "0.3px",
                            cursor: "pointer",
                            whiteSpace: "nowrap",
                            transition: "all 0.15s ease"
                        }}
                    >
                        <Icon size={14} />
                        <span>{tab.label}</span>
                    </button>
                );
            })}
        </div>
    );
}

export default InvestigationNav;

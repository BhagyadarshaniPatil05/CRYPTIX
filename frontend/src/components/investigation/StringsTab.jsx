import React, { useState } from "react";
import { Key, ShieldAlert, Search, Globe, Server, Mail, Database, KeyRound } from "lucide-react";
import CopyButton from "../common/CopyButton";
import RiskBadge from "../common/RiskBadge";

function StringsTab({ reportData }) {
    const indicators = reportData.indicator_analysis || {};
    const yaraMatches = reportData.yara_analysis || [];

    const [iocSearch, setIocSearch] = useState("");
    const [selectedCategory, setSelectedCategory] = useState("ALL");

    const urls = indicators.urls || [];
    const ips = indicators.ip_addresses || [];
    const emails = indicators.emails || [];
    const firebase = indicators.firebase_urls || [];
    const apiKeys = indicators.api_keys || [];
    const base64 = indicators.base64_strings || [];
    const btc = indicators.bitcoin_addresses || [];

    const totalIocCount = urls.length + ips.length + emails.length + firebase.length + apiKeys.length + base64.length + btc.length;

    const allIocList = [
        ...urls.map(item => ({ category: "URL", value: item })),
        ...ips.map(item => ({ category: "IP Address", value: item })),
        ...emails.map(item => ({ category: "Email", value: item })),
        ...firebase.map(item => ({ category: "Firebase URL", value: item })),
        ...apiKeys.map(item => ({ category: "API Key", value: item })),
        ...base64.map(item => ({ category: "Base64 String", value: item })),
        ...btc.map(item => ({ category: "Bitcoin Address", value: item }))
    ];

    const filteredIocList = allIocList.filter(item => {
        const matchesSearch = item.value.toLowerCase().includes(iocSearch.toLowerCase());
        const matchesCat = selectedCategory === "ALL" || item.category === selectedCategory;
        return matchesSearch && matchesCat;
    });

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* IOC Summary Strip */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: "10px" }}>
                <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: "10px" }}>
                    <Globe size={18} color="var(--accent-cyan)" />
                    <div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>URLs</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>{urls.length}</div>
                    </div>
                </div>

                <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: "10px" }}>
                    <Server size={18} color="var(--high)" />
                    <div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>IP Addresses</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>{ips.length}</div>
                    </div>
                </div>

                <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: "10px" }}>
                    <Mail size={18} color="var(--accent-purple)" />
                    <div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>Emails</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>{emails.length}</div>
                    </div>
                </div>

                <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: "10px" }}>
                    <Database size={18} color="var(--medium)" />
                    <div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>Firebase endpoints</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>{firebase.length}</div>
                    </div>
                </div>

                <div style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", borderRadius: "4px", border: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: "10px" }}>
                    <KeyRound size={18} color="var(--critical)" />
                    <div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>API Keys</div>
                        <div className="font-mono" style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>{apiKeys.length}</div>
                    </div>
                </div>
            </div>

            {/* Extracted Indicators Table */}
            <div className="garud-card" style={{ padding: "0", overflow: "hidden" }}>
                <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border-color)", backgroundColor: "var(--bg-elevated)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Key size={16} color="var(--accent-cyan)" />
                        <h3 style={{ fontSize: "14px", fontWeight: "700" }}>EXTRACTED INDICATORS OF COMPROMISE ({totalIocCount})</h3>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", backgroundColor: "var(--bg-surface)", border: "1px solid var(--border-color)", borderRadius: "4px", padding: "4px 8px" }}>
                            <Search size={14} color="var(--text-muted)" />
                            <input
                                type="text"
                                placeholder="Search string value..."
                                value={iocSearch}
                                onChange={(e) => setIocSearch(e.target.value)}
                                className="font-mono"
                                style={{ background: "transparent", border: "none", color: "var(--text-primary)", outline: "none", fontSize: "12px" }}
                            />
                        </div>

                        <select
                            value={selectedCategory}
                            onChange={(e) => setSelectedCategory(e.target.value)}
                            className="font-mono"
                            style={{
                                backgroundColor: "var(--bg-surface)",
                                border: "1px solid var(--border-color)",
                                color: "var(--text-primary)",
                                padding: "4px 8px",
                                borderRadius: "4px",
                                fontSize: "12px",
                                outline: "none",
                                cursor: "pointer"
                            }}
                        >
                            <option value="ALL">All Categories</option>
                            <option value="URL">URLs</option>
                            <option value="IP Address">IP Addresses</option>
                            <option value="Email">Emails</option>
                            <option value="Firebase URL">Firebase URLs</option>
                            <option value="API Key">API Keys</option>
                            <option value="Base64 String">Base64 Strings</option>
                            <option value="Bitcoin Address">Bitcoin Addresses</option>
                        </select>
                    </div>
                </div>

                {filteredIocList.length > 0 ? (
                    <table className="soc-table">
                        <thead>
                            <tr>
                                <th>INDICATOR TYPE</th>
                                <th>STRING VALUE</th>
                                <th style={{ textAlign: "right" }}>COPY</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredIocList.map((item, idx) => (
                                <tr key={idx}>
                                    <td style={{ width: "160px" }}>
                                        <span className="font-mono" style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "3px", backgroundColor: "var(--bg-elevated)", color: "var(--accent-purple)", border: "1px solid var(--border-color)", fontWeight: "700" }}>
                                            {item.category}
                                        </span>
                                    </td>
                                    <td className="font-mono" style={{ fontSize: "12px", color: "var(--text-primary)", wordBreak: "break-all" }}>
                                        {item.value}
                                    </td>
                                    <td style={{ textAlign: "right" }}>
                                        <CopyButton text={item.value} />
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <div style={{ padding: "30px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        NO EXTRACTED IOC STRINGS FOUND
                    </div>
                )}
            </div>

            {/* YARA Signature Matches */}
            <div className="garud-card">
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
                    <ShieldAlert size={16} color="var(--critical)" />
                    <h3 style={{ fontSize: "14px", fontWeight: "700" }}>YARA RULE SIGNATURE MATCHES ({yaraMatches.length})</h3>
                </div>

                {yaraMatches.length > 0 ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                        {yaraMatches.map((match, idx) => {
                            const ruleName = typeof match === "string" ? match : match.rule_name || "YARA Rule";
                            const cat = match.category || "Malware Signature";
                            const desc = match.description || "Matched compiled YARA rule signature.";

                            return (
                                <div key={idx} style={{ padding: "12px", backgroundColor: "var(--critical-bg)", border: "1px solid var(--critical-border)", borderRadius: "4px" }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                                        <span className="font-mono" style={{ fontSize: "13px", fontWeight: "800", color: "var(--critical)" }}>
                                            Match: {ruleName}
                                        </span>
                                        <RiskBadge level="High" />
                                    </div>
                                    <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                                        {desc}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                ) : (
                    <div style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>
                        NO YARA MATCHES: No local YARA rule signatures matched this binary sample.
                    </div>
                )}
            </div>
        </div>
    );
}

export default StringsTab;

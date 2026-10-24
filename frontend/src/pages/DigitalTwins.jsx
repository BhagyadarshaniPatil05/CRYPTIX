import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { Search, Cpu, RefreshCw, Eye, AlertCircle, Plus } from "lucide-react";

import {
    getDigitalTwins,
    getDigitalTwin,
    getLatestTwinVersion,
    getTwinVersions,
    compareTwinVersions,
    getTwinDrift,
    getTwinDriftReport,
    getTwinHealth,
    getTwinLifecycle,
    getTwinEvents,
    getTwinRiskTrend
} from "../api/api";

import TwinHeader from "../components/digital-twin/TwinHeader";
import TwinVersionHistory from "../components/digital-twin/TwinVersionHistory";
import TwinVersionSelector from "../components/digital-twin/TwinVersionSelector";
import TwinDiffViewer from "../components/digital-twin/TwinDiffViewer";
import TwinDriftPanel from "../components/digital-twin/TwinDriftPanel";
import TwinRiskTrend from "../components/digital-twin/TwinRiskTrend";
import TwinHealthEvents from "../components/digital-twin/TwinHealthEvents";

function DigitalTwins() {
    const { id } = useParams();

    // Repository list state
    const [twinsList, setTwinsList] = useState([]);
    const [searchQuery, setSearchQuery] = useState("");
    const [loadingList, setLoadingList] = useState(true);

    // Single Twin detail workspace state
    const [twinData, setTwinData] = useState(null);
    const [latestVersion, setLatestVersion] = useState(null);
    const [versionsList, setVersionsList] = useState([]);
    const [driftData, setDriftData] = useState(null);
    const [driftReport, setDriftReport] = useState(null);
    const [healthData, setHealthData] = useState(null);
    const [lifecycleData, setLifecycleData] = useState(null);
    const [eventsData, setEventsData] = useState([]);
    const [riskTrendData, setRiskTrendData] = useState([]);
    const [diffData, setDiffData] = useState(null);

    // Version Comparison state
    const [v1, setV1] = useState(1);
    const [v2, setV2] = useState(1);
    const [loadingDiff, setLoadingDiff] = useState(false);
    const [loadingDetail, setLoadingDetail] = useState(false);
    const [errorMsg, setErrorMsg] = useState(null);

    // Fetch repository list when on /twins
    useEffect(() => {
        if (!id) {
            fetchTwinsRepository();
        } else {
            fetchTwinWorkspace(Number(id));
        }
    }, [id]);

    const fetchTwinsRepository = async () => {
        setLoadingList(true);
        setErrorMsg(null);
        try {
            const res = await getDigitalTwins();
            setTwinsList(Array.isArray(res) ? res : res?.twins || []);
        } catch (err) {
            console.error("Failed to load Digital Twins repository:", err);
            setErrorMsg("Could not connect to backend to retrieve Digital Twin models.");
        } finally {
            setLoadingList(false);
        }
    };

    const fetchTwinWorkspace = async (twinId) => {
        setLoadingDetail(true);
        setErrorMsg(null);
        try {
            const [twinRes, latestRes, versionsRes, driftRes, reportRes, healthRes, lifeRes, eventsRes, trendRes] =
                await Promise.allSettled([
                    getDigitalTwin(twinId),
                    getLatestTwinVersion(twinId),
                    getTwinVersions(twinId),
                    getTwinDrift(twinId),
                    getTwinDriftReport(twinId),
                    getTwinHealth(twinId),
                    getTwinLifecycle(twinId),
                    getTwinEvents(twinId),
                    getTwinRiskTrend(twinId)
                ]);

            if (twinRes.status === "fulfilled") setTwinData(twinRes.value);
            if (latestRes.status === "fulfilled") setLatestVersion(latestRes.value);
            
            let vers = [];
            if (versionsRes.status === "fulfilled") {
                vers = Array.isArray(versionsRes.value) ? versionsRes.value : [];
                setVersionsList(vers);
            }

            if (driftRes.status === "fulfilled") setDriftData(driftRes.value);
            if (reportRes.status === "fulfilled") setDriftReport(reportRes.value);
            if (healthRes.status === "fulfilled") setHealthData(healthRes.value);
            if (lifeRes.status === "fulfilled") setLifecycleData(lifeRes.value);
            if (eventsRes.status === "fulfilled") setEventsData(eventsRes.value);
            if (trendRes.status === "fulfilled") setRiskTrendData(trendRes.value);

            if (vers.length >= 2) {
                const num1 = vers[0].version_number;
                const num2 = vers[vers.length - 1].version_number;
                setV1(num1);
                setV2(num2);
                loadDiff(twinId, num1, num2);
            } else if (vers.length === 1) {
                setV1(vers[0].version_number);
                setV2(vers[0].version_number);
            }
        } catch (err) {
            console.error("Failed to load twin workspace:", err);
            setErrorMsg(`Digital Twin #${twinId} not found or error loading telemetry.`);
        } finally {
            setLoadingDetail(false);
        }
    };

    const loadDiff = async (twinId, ver1, ver2) => {
        setLoadingDiff(true);
        try {
            const diffRes = await compareTwinVersions(twinId, ver1, ver2);
            setDiffData(diffRes);
        } catch (err) {
            console.error("Failed to load version diff:", err);
            setDiffData(null);
        } finally {
            setLoadingDiff(false);
        }
    };

    const handleCompare = () => {
        if (id && v1 && v2) {
            loadDiff(Number(id), v1, v2);
        }
    };

    const filteredTwins = twinsList.filter((t) => {
        const query = searchQuery.toLowerCase();
        return (
            (t.package_name && t.package_name.toLowerCase().includes(query)) ||
            (t.app_name && t.app_name.toLowerCase().includes(query)) ||
            String(t.id).includes(query)
        );
    });

    // --- VIEW 1: REPOSITORY LIST (/twins) ---
    if (!id) {
        return (
            <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                {/* Header Control Strip */}
                <div
                    style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "16px 20px",
                        backgroundColor: "var(--bg-surface)",
                        border: "1px solid var(--border-color)",
                        borderRadius: "6px",
                        flexWrap: "wrap",
                        gap: "12px"
                    }}
                >
                    <div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "2px" }}>
                            <Cpu size={18} color="var(--accent-cyan)" />
                            <h1 style={{ fontSize: "18px", fontWeight: "800", letterSpacing: "0.5px" }}>
                                DIGITAL TWIN SECURITY POSTURE REPOSITORY
                            </h1>
                        </div>
                        <p style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                            Track application security posture evolution, version diffs, health trends, and capability drift over time.
                        </p>
                    </div>

                    <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                        <div style={{ position: "relative", width: "280px" }}>
                            <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)" }} />
                            <input
                                type="text"
                                placeholder="Search package or Twin ID..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="font-mono"
                                style={{
                                    width: "100%",
                                    padding: "6px 10px 6px 32px",
                                    backgroundColor: "var(--bg-elevated)",
                                    border: "1px solid var(--border-color)",
                                    borderRadius: "4px",
                                    color: "var(--text-primary)",
                                    fontSize: "12px",
                                    outline: "none"
                                }}
                            />
                        </div>
                    </div>
                </div>

                {errorMsg && (
                    <div style={{ padding: "12px 14px", backgroundColor: "var(--critical-bg)", border: "1px solid var(--critical-border)", borderRadius: "4px", color: "var(--critical)", fontSize: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
                        <AlertCircle size={15} /> {errorMsg}
                    </div>
                )}

                {loadingList ? (
                    <div className="garud-card" style={{ padding: "36px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                        <RefreshCw size={24} color="var(--accent-cyan)" className="animate-spin" style={{ marginBottom: "10px" }} />
                        <div>Loading Digital Twin posture models from database...</div>
                    </div>
                ) : filteredTwins.length === 0 ? (
                    <div className="garud-card" style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
                        <Cpu size={32} color="var(--text-muted)" style={{ marginBottom: "10px" }} />
                        <h3 style={{ fontSize: "15px", color: "var(--text-primary)", fontWeight: "700", marginBottom: "4px" }}>No Digital Twins Instantiated</h3>
                        <p style={{ fontSize: "12px", maxWidth: "440px", margin: "0 auto 16px auto" }}>
                            Upload an APK sample in the Threat Operations Center to automatically instantiate its Digital Twin security posture model.
                        </p>
                        <Link to="/" className="btn-primary" style={{ textDecoration: "none" }}>
                            <Plus size={14} /> Upload Sample
                        </Link>
                    </div>
                ) : (
                    <div className="garud-card" style={{ padding: "0", overflow: "hidden" }}>
                        <table className="soc-table">
                            <thead>
                                <tr>
                                    <th>TWIN ID</th>
                                    <th>APPLICATION PACKAGE</th>
                                    <th>CURRENT BUILD</th>
                                    <th>LAST UPDATED</th>
                                    <th>TELEMETRY STATUS</th>
                                    <th style={{ textAlign: "right" }}>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredTwins.map((twin) => (
                                    <tr key={twin.id}>
                                        <td>
                                            <span className="font-mono" style={{ fontSize: "12px", color: "var(--accent-cyan)", fontWeight: "700" }}>
                                                #{twin.id}
                                            </span>
                                        </td>
                                        <td>
                                            <div style={{ fontWeight: "700", color: "var(--text-primary)", fontSize: "13px" }}>
                                                {twin.app_name || twin.package_name || `Twin #${twin.id}`}
                                            </div>
                                            <div className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                                {twin.package_name}
                                            </div>
                                        </td>
                                        <td>
                                            <span className="font-mono" style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                                                v{twin.current_version || 1}
                                            </span>
                                        </td>
                                        <td className="font-mono" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                            {twin.updated_at ? new Date(twin.updated_at).toLocaleString() : "Recently"}
                                        </td>
                                        <td>
                                            <span
                                                className="font-mono"
                                                style={{
                                                    fontSize: "10px",
                                                    padding: "2px 6px",
                                                    borderRadius: "3px",
                                                    backgroundColor: "var(--low-bg)",
                                                    color: "var(--low)",
                                                    border: "1px solid var(--low-border)",
                                                    fontWeight: "700"
                                                }}
                                            >
                                                ACTIVE MONITORED
                                            </span>
                                        </td>
                                        <td style={{ textAlign: "right" }}>
                                            <Link
                                                to={`/twins/${twin.id}`}
                                                style={{
                                                    padding: "4px 10px",
                                                    borderRadius: "4px",
                                                    backgroundColor: "var(--accent-cyan-bg)",
                                                    border: "1px solid rgba(94, 231, 247, 0.3)",
                                                    color: "var(--accent-cyan)",
                                                    fontSize: "11px",
                                                    fontWeight: "700",
                                                    textDecoration: "none",
                                                    display: "inline-flex",
                                                    alignItems: "center",
                                                    gap: "4px"
                                                }}
                                            >
                                                <Eye size={13} /> Inspect Twin
                                            </Link>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        );
    }

    // --- VIEW 2: SINGLE DIGITAL TWIN WORKSPACE (/twins/:id) ---
    if (loadingDetail) {
        return (
            <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-muted)" }}>
                <RefreshCw size={24} color="var(--accent-cyan)" className="animate-spin" style={{ marginBottom: "10px" }} />
                <div className="font-mono" style={{ fontSize: "13px", fontWeight: "600" }}>Loading Digital Twin #{id} posture workspace...</div>
            </div>
        );
    }

    if (errorMsg || !twinData) {
        return (
            <div style={{ padding: "40px 20px", maxWidth: "600px", margin: "0 auto", textAlign: "center" }}>
                <div className="garud-card" style={{ padding: "30px" }}>
                    <AlertCircle size={36} color="var(--critical)" style={{ marginBottom: "10px" }} />
                    <h2 style={{ fontSize: "16px", color: "var(--text-primary)", marginBottom: "6px" }}>Digital Twin Workspace Error</h2>
                    <p style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "16px" }}>
                        {errorMsg || `Digital Twin #${id} could not be loaded.`}
                    </p>
                    <Link to="/twins" className="btn-primary" style={{ textDecoration: "none" }}>
                        Return to Digital Twins List
                    </Link>
                </div>
            </div>
        );
    }

    return (
        <div style={{ display: "flex", flexDirection: "column" }}>
            {/* Header Banner */}
            <TwinHeader
                twin={twinData}
                latestVersion={latestVersion}
                health={healthData}
                lifecycle={lifecycleData}
            />

            {/* Version History List */}
            <TwinVersionHistory
                versions={versionsList}
                selectedV1={v1}
                selectedV2={v2}
                onSelectV1={(num) => {
                    setV1(num);
                    loadDiff(Number(id), num, v2);
                }}
                onSelectV2={(num) => {
                    setV2(num);
                    loadDiff(Number(id), v1, num);
                }}
            />

            {/* Version Selector for Side-by-Side Comparison */}
            <TwinVersionSelector
                versions={versionsList}
                v1={v1}
                v2={v2}
                onV1Change={setV1}
                onV2Change={setV2}
                onCompare={handleCompare}
            />

            {/* Side-by-Side Version Diff Viewer */}
            <TwinDiffViewer
                diff={diffData}
                v1={v1}
                v2={v2}
                loading={loadingDiff}
            />

            {/* Posture Drift Panel */}
            <TwinDriftPanel
                drift={driftData}
                driftReport={driftReport}
            />

            {/* Risk Posture Trajectory Line Chart */}
            <TwinRiskTrend
                trendData={riskTrendData}
            />

            {/* Twin Health & Event Log */}
            <TwinHealthEvents
                health={healthData}
                events={eventsData}
            />
        </div>
    );
}

export default DigitalTwins;

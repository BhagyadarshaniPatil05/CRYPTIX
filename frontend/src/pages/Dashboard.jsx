import { useEffect, useState } from "react";
import api from "../api/api";

import MetricCard from "../components/MetricCard";

import RiskDistributionChart from "../components/RiskDistributionChart";

import TopPermissionsChart from "../components/TopPermissionsChart";

function Dashboard() {

    const [metrics, setMetrics] = useState(null);

    useEffect(() => {

        api.get("/dashboard/metrics")
            .then((response) => {
                setMetrics(response.data);
            })
            .catch((error) => {
                console.error(error);
            });

    }, []);

    if (!metrics) {
        return <h2>Loading Dashboard...</h2>;
    }

    return (
        <div
            style={{
                backgroundColor: "#0f172a",
                minHeight: "100vh",
                color: "white",
                padding: "30px"
            }}
        >
            <h1>CRYPTIX Security Dashboard</h1>

            <div
                style={{
                    display: "flex",
                    gap: "20px",
                    flexWrap: "wrap",
                    marginTop: "30px"
                }}
            >
                <MetricCard
                    title="Total APKs"
                    value={metrics.total_apks}
                />

                <MetricCard
                    title="High Risk"
                    value={metrics.high_risk}
                />

                <MetricCard
                    title="Medium Risk"
                    value={metrics.medium_risk}
                />

                <MetricCard
                    title="Low Risk"
                    value={metrics.low_risk}
                />

                <MetricCard
                    title="Average Risk"
                    value={metrics.average_risk_score}
                />
            </div>

            <RiskDistributionChart />

            <TopPermissionsChart />
        </div>
    );
}

export default Dashboard;
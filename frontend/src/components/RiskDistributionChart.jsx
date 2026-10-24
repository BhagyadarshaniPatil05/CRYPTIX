import { useEffect, useState } from "react";
import api from "../api/api";

import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    Legend
} from "recharts";

const COLORS = [
    "#ef4444",
    "#f59e0b",
    "#22c55e"
];

function RiskDistributionChart() {

    const [data, setData] =
        useState([]);

    useEffect(() => {

        api.get(
            "/threat-dashboard/risk-distribution"
        )
        .then((response) => {

            const chartData = [
                {
                    name: "High",
                    value: response.data.High
                },
                {
                    name: "Medium",
                    value: response.data.Medium
                },
                {
                    name: "Low",
                    value: response.data.Low
                }
            ];

            setData(chartData);

        });

    }, []);

    return (

        <div
            style={{
                background: "#1e293b",
                padding: "20px",
                borderRadius: "12px",
                marginTop: "30px"
            }}
        >

            <h2>
                Risk Distribution
            </h2>

            <PieChart
                width={400}
                height={300}
            >

                <Pie
                    data={data}
                    dataKey="value"
                    nameKey="name"
                    outerRadius={100}
                    label
                >

                    {
                        data.map(
                            (
                                entry,
                                index
                            ) => (
                                <Cell
                                    key={index}
                                    fill={
                                        COLORS[index]
                                    }
                                />
                            )
                        )
                    }

                </Pie>

                <Tooltip />

                <Legend />

            </PieChart>

        </div>

    );
}

export default RiskDistributionChart;
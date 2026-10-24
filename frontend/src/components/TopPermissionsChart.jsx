import { useEffect, useState } from "react";
import api from "../api/api";

import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    CartesianGrid
} from "recharts";

function TopPermissionsChart() {

    const [data, setData] = useState([]);

    useEffect(() => {

        api.get(
            "/threat-dashboard/top-permissions"
        )
        .then((response) => {
            setData(response.data);
        })
        .catch((error) => {
            console.error(error);
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
                Top Dangerous Permissions
            </h2>

            <BarChart
                width={1000}
                height={400}
                data={data}
                layout="vertical"
            >
                <CartesianGrid strokeDasharray="3 3" />

                <XAxis
                    type="number"
                />

                <YAxis
                    type="category"
                    dataKey="permission"
                    width={250}
                />

                <Tooltip />

                <Bar
                    dataKey="count"
                    fill="#ef4444"
                />
            </BarChart>

        </div>

    );
}

export default TopPermissionsChart;
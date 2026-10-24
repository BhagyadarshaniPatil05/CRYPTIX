function MetricCard({ title, value }) {

    return (
        <div
            style={{
                backgroundColor: "#1e293b",
                color: "white",
                padding: "20px",
                borderRadius: "12px",
                width: "220px",
                boxShadow: "0 4px 10px rgba(0,0,0,0.3)"
            }}
        >
            <h3>{title}</h3>

            <h1>{value}</h1>
        </div>
    );
}

export default MetricCard;
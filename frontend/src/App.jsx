import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import AppShell from "./components/layout/AppShell";
import Overview from "./pages/Overview";
import APKRepository from "./pages/APKRepository";
import APKInvestigation from "./pages/APKInvestigation";
import DigitalTwins from "./pages/DigitalTwins";
import ThreatHunting from "./pages/ThreatHunting";

function App() {
    return (
        <Router>
            <AppShell>
                <Routes>
                    <Route path="/" element={<Overview />} />
                    <Route path="/apks" element={<APKRepository />} />
                    <Route path="/apks/:id" element={<APKInvestigation />} />
                    <Route path="/twins" element={<DigitalTwins />} />
                    <Route path="/twins/:id" element={<DigitalTwins />} />
                    <Route path="/hunting" element={<ThreatHunting />} />
                </Routes>
            </AppShell>
        </Router>
    );
}

export default App;
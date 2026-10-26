import { useEffect, useRef, useState } from "react";
import { fetchDashboard } from "./api.js";
import SummaryCards from "./components/SummaryCards.jsx";
import AttacksChart from "./components/AttacksChart.jsx";
import TopIpsChart from "./components/TopIpsChart.jsx";
import BenchmarkPanel from "./components/BenchmarkPanel.jsx";
import SettingsPanel from "./components/SettingsPanel.jsx";
import LogTable from "./components/LogTable.jsx";

const POLL_INTERVAL_MS = 5000;

export default function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  async function load() {
    try {
      const payload = await fetchDashboard();
      setData(payload);
      setError(null);
    } catch (err) {
      if (err.message !== "unauthorized") {
        setError("Could not reach the dashboard API. Is the Flask server running?");
      }
    }
  }

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(pollRef.current);
  }, []);

  function handleSettingsChange(updated) {
    // Reflect the toggle immediately, then let the next poll resync fully.
    setData((prev) => (prev ? { ...prev, ...updated } : prev));
  }

  if (error) {
    return (
      <div className="dash">
        <div className="error-banner">{error}</div>
      </div>
    );
  }

  if (!data) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <>
      <header className="dash-topbar">
        <div className="dash-brand">🛡️ CyberSentinel</div>
        <nav className="dash-nav">
          <a href="/">Home</a>
          <a href="/login">Login</a>
          <a href="/search">Search</a>
          <a href="/fetch">Fetch File</a>
          <a href="/admin/logout">Logout</a>
        </nav>
      </header>

      <div className="dash">
        <div className="dash-header">
          <h1 style={{ margin: 0 }}>WAF Detection Dashboard</h1>
          <span className="status-line">
            <span className="live-dot" />
            Live &middot; refreshes every {POLL_INTERVAL_MS / 1000}s &middot; total blocked:{" "}
            <strong>{data.total}</strong>
          </span>
        </div>

        <SummaryCards summary={data.summary} />

        <div className="charts-grid">
          <div className="panel">
            <h2>Attacks per Day</h2>
            <AttacksChart timeline={data.timeline} />
          </div>
          <div className="panel">
            <h2>Top Source IPs</h2>
            <TopIpsChart topIps={data.top_ips} />
          </div>
        </div>

        <SettingsPanel
          wafEnabled={data.waf_enabled}
          queryMode={data.query_mode}
          onChange={handleSettingsChange}
        />

        <BenchmarkPanel benchmark={data.benchmark} />

        <LogTable logs={data.logs} />
      </div>
    </>
  );
}

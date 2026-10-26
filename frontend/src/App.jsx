import { useEffect, useRef, useState } from "react";
import { fetchDashboard } from "./api.js";
import StatStrip from "./components/StatStrip.jsx";
import TrafficChart from "./components/TrafficChart.jsx";
import AttackDistributionChart from "./components/AttackDistributionChart.jsx";
import TopPatternsChart from "./components/TopPatternsChart.jsx";
import TopIpsChart from "./components/TopIpsChart.jsx";
import BenchmarkPanel from "./components/BenchmarkPanel.jsx";
import SettingsPanel from "./components/SettingsPanel.jsx";
import LogTable from "./components/LogTable.jsx";

const POLL_INTERVAL_MS = 5000;

function ShieldMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M12 2.5l7.5 3v5.5c0 5-3.2 8.8-7.5 10.5-4.3-1.7-7.5-5.5-7.5-10.5V5.5l7.5-3z" />
      <path d="M9 12l2 2 4-4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

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
    setData((prev) => (prev ? { ...prev, ...updated } : prev));
  }

  return (
    <>
      <header className="dash-topbar">
        <div className="dash-brand">
          <ShieldMark />
          CyberSentinel
          <span className="brand-sub">WAF Console</span>
        </div>
        <nav className="dash-nav">
          <a href="/">Home</a>
          <a href="/login">Login</a>
          <a href="/search">Search</a>
          <a href="/fetch">Fetch File</a>
          <a className="nav-logout" href="/admin/logout">Log out</a>
        </nav>
      </header>

      <div className="dash">
        {error && <div className="error-banner">{error}</div>}

        {!data ? (
          <div className="loading">Loading dashboard…</div>
        ) : (
          <>
            <div className="dash-header">
              <h1>Detection Overview</h1>
              <span className="status-line">
                <span className="live-dot" />
                Live &middot; refreshes every {POLL_INTERVAL_MS / 1000}s
              </span>
            </div>

            <StatStrip
              totalRequests={data.total_requests}
              totalAllowed={data.total_allowed}
              totalBlocked={data.total}
              blockRate={data.block_rate}
              summary={data.summary}
            />

            <div className="panel">
              <div className="panel-head">
                <h2>Traffic Timeline</h2>
                <span className="status-line">allowed vs. blocked, per minute</span>
              </div>
              <TrafficChart timeline={data.traffic_timeline} />
            </div>

            <div className="charts-grid">
              <div className="panel">
                <div className="panel-head"><h2>Attack Type Breakdown</h2></div>
                <AttackDistributionChart distribution={data.attack_distribution} />
              </div>
              <div className="panel">
                <div className="panel-head"><h2>Top Matched Patterns</h2></div>
                <TopPatternsChart patterns={data.top_patterns} />
              </div>
              <div className="panel">
                <div className="panel-head"><h2>Top Source IPs</h2></div>
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
          </>
        )}
      </div>
    </>
  );
}

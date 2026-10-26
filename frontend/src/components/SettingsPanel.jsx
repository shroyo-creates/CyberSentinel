import { useState } from "react";
import { postSetting } from "../api.js";

export default function SettingsPanel({ wafEnabled, queryMode, onChange }) {
  const [busy, setBusy] = useState(false);

  async function toggle(action) {
    setBusy(true);
    try {
      const updated = await postSetting(action);
      onChange(updated);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <h2>Demo Settings</h2>
      <p className="status-line" style={{ marginTop: 0 }}>
        Two independent layers of defense. Try a payload like{" "}
        <code>' OR '1'='1' --</code> on <a href="/login">/login</a> in each combination below.
      </p>

      <div className="settings-grid">
        <div className="panel settings-card" style={{ marginBottom: 0 }}>
          <h3>WAF</h3>
          <p>
            Status:{" "}
            <strong className={wafEnabled ? "status-on" : "status-off"}>
              {wafEnabled ? "ENABLED" : "DISABLED"}
            </strong>
          </p>
          <button disabled={busy} onClick={() => toggle("toggle_waf")}>
            {wafEnabled ? "Disable WAF" : "Enable WAF"}
          </button>
        </div>

        <div className="panel settings-card" style={{ marginBottom: 0 }}>
          <h3>Login Query Mode</h3>
          <p>
            Mode:{" "}
            <strong className={queryMode === "vulnerable" ? "status-off" : "status-on"}>
              {queryMode.toUpperCase()}
            </strong>
          </p>
          <button disabled={busy} onClick={() => toggle("toggle_query_mode")}>
            Switch to {queryMode === "vulnerable" ? "SAFE" : "VULNERABLE"}
          </button>
        </div>
      </div>
    </div>
  );
}

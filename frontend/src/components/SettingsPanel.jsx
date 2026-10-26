import { useState } from "react";
import { postSetting } from "../api.js";

function ToggleRow({ title, statusText, statusClass, checked, disabled, onToggle }) {
  return (
    <div className="toggle-row">
      <div className="toggle-row-label">
        <span className="toggle-row-title">{title}</span>
        <span className={`toggle-row-status ${statusClass}`}>{statusText}</span>
      </div>
      <label className="switch">
        <input type="checkbox" checked={checked} disabled={disabled} onChange={onToggle} />
        <span className="switch-track" />
      </label>
    </div>
  );
}

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
      <div className="panel-head">
        <h2>Demo Settings</h2>
      </div>
      <p className="panel-note">
        Two independent layers of defense. Try <code>' OR '1'='1' --</code> on{" "}
        <a href="/login">/login</a> in each combination.
      </p>

      <div className="settings-grid">
        <ToggleRow
          title="Web Application Firewall"
          statusText={wafEnabled ? "ENABLED" : "DISABLED"}
          statusClass={wafEnabled ? "status-on" : "status-off"}
          checked={wafEnabled}
          disabled={busy}
          onToggle={() => toggle("toggle_waf")}
        />
        <ToggleRow
          title="Login query mode"
          statusText={queryMode.toUpperCase()}
          statusClass={queryMode === "vulnerable" ? "status-off" : "status-on"}
          checked={queryMode === "vulnerable"}
          disabled={busy}
          onToggle={() => toggle("toggle_query_mode")}
        />
      </div>
    </div>
  );
}

function Tile({ label, value, accent }) {
  return (
    <div className={`stat-tile accent-${accent}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

export default function StatStrip({ totalRequests, totalAllowed, totalBlocked, blockRate, summary }) {
  return (
    <div className="stat-strip">
      <Tile label="Requests Inspected" value={totalRequests} accent="blue" />
      <Tile label="Allowed" value={totalAllowed} accent="blue" />
      <Tile label="Blocked" value={totalBlocked} accent="red" />
      <Tile label="Block Rate" value={`${(blockRate * 100).toFixed(1)}%`} accent="amber" />
      <Tile label="SQL Injection" value={summary["SQL Injection"] ?? 0} accent="amber" />
      <Tile label="XSS" value={summary["XSS"] ?? 0} accent="purple" />
      <Tile label="Path Traversal" value={summary["Path Traversal"] ?? 0} accent="cyan" />
    </div>
  );
}

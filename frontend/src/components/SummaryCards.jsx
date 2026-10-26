export default function SummaryCards({ summary }) {
  return (
    <div className="summary-grid">
      <div className="summary-card sqli">
        <h2>{summary["SQL Injection"] ?? 0}</h2>
        <p>SQL Injection</p>
      </div>
      <div className="summary-card xss">
        <h2>{summary["XSS"] ?? 0}</h2>
        <p>XSS</p>
      </div>
      <div className="summary-card traversal">
        <h2>{summary["Path Traversal"] ?? 0}</h2>
        <p>Path Traversal</p>
      </div>
    </div>
  );
}

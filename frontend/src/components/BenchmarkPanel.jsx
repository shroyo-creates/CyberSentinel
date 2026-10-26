export default function BenchmarkPanel({ benchmark }) {
  if (!benchmark) {
    return (
      <div className="panel">
        <h2>Detection Accuracy Benchmark</h2>
        <p className="empty-state">
          No benchmark run yet. Run <code>python evaluate_waf.py</code> to score the WAF against a labeled dataset.
        </p>
      </div>
    );
  }

  const classes = Object.entries(benchmark.per_class || {});

  return (
    <div className="panel">
      <h2>Detection Accuracy Benchmark</h2>
      <p className="status-line" style={{ marginTop: 0 }}>
        From the last run of <code>python evaluate_waf.py</code> against{" "}
        <code>dataset/test_payloads.json</code> ({benchmark.total} labeled payloads).
      </p>

      <div className="summary-grid">
        <div className="summary-card">
          <h2>{(benchmark.accuracy * 100).toFixed(1)}%</h2>
          <p>Overall Accuracy</p>
        </div>
        <div className="summary-card">
          <h2>{benchmark.correct}/{benchmark.total}</h2>
          <p>Correctly Classified</p>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Class</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1 Score</th>
            <th>Support</th>
          </tr>
        </thead>
        <tbody>
          {classes.map(([name, m]) => (
            <tr key={name}>
              <td>{name}</td>
              <td>{m.precision.toFixed(2)}</td>
              <td>{m.recall.toFixed(2)}</td>
              <td>{m.f1.toFixed(2)}</td>
              <td>{m.support}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

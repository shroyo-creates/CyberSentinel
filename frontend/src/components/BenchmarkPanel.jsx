export default function BenchmarkPanel({ benchmark }) {
  if (!benchmark) {
    return (
      <div className="panel">
        <div className="panel-head">
          <h2>Detection Accuracy Benchmark</h2>
        </div>
        <p className="empty-state">
          No benchmark run yet. Run <code>python evaluate_waf.py</code> to score the WAF against a labeled dataset.
        </p>
      </div>
    );
  }

  const classes = Object.entries(benchmark.per_class || {});

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Detection Accuracy Benchmark</h2>
        <span className="status-line">
          {benchmark.total} labeled payloads &middot; {(benchmark.accuracy * 100).toFixed(1)}% accuracy
        </span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Class</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>F1</th>
              <th>Support</th>
            </tr>
          </thead>
          <tbody>
            {classes.map(([name, m]) => (
              <tr key={name}>
                <td>{name}</td>
                <td className="mono">{m.precision.toFixed(2)}</td>
                <td className="mono">{m.recall.toFixed(2)}</td>
                <td className="mono">{m.f1.toFixed(2)}</td>
                <td className="mono">{m.support}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

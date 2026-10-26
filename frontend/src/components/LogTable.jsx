import { useMemo, useState } from "react";

const ATTACK_TYPES = ["SQL Injection", "XSS", "Path Traversal"];

function tagClass(attackType) {
  return "tag tag-" + attackType.replace(/ /g, "-").toLowerCase();
}

export default function LogTable({ logs }) {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sortDir, setSortDir] = useState("desc"); // logs already arrive newest-first from the API

  const filtered = useMemo(() => {
    let rows = logs;

    if (typeFilter !== "all") {
      rows = rows.filter((entry) => entry.attack_type === typeFilter);
    }

    if (search.trim()) {
      const needle = search.trim().toLowerCase();
      rows = rows.filter(
        (entry) =>
          entry.payload.toLowerCase().includes(needle) ||
          entry.source_ip.toLowerCase().includes(needle) ||
          entry.blocked_url.toLowerCase().includes(needle)
      );
    }

    rows = [...rows].sort((a, b) =>
      sortDir === "desc"
        ? b.timestamp.localeCompare(a.timestamp)
        : a.timestamp.localeCompare(b.timestamp)
    );

    return rows;
  }, [logs, search, typeFilter, sortDir]);

  return (
    <div className="panel">
      <h2>Blocked Attempts ({filtered.length})</h2>

      <div className="toolbar">
        <input
          type="text"
          placeholder="Search payload, IP, or URL..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="all">All attack types</option>
          {ATTACK_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {filtered.length === 0 ? (
        <p className="empty-state">
          {logs.length === 0
            ? "No attacks blocked yet. Try running ./test_attacks.sh to generate some."
            : "No attempts match this filter."}
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th onClick={() => setSortDir(sortDir === "desc" ? "asc" : "desc")}>
                Time (UTC) {sortDir === "desc" ? "↓" : "↑"}
              </th>
              <th>Attack Type</th>
              <th>Matched Pattern</th>
              <th>Payload</th>
              <th>Source IP</th>
              <th>Blocked URL</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((entry, i) => (
              <tr key={i}>
                <td>{entry.timestamp}</td>
                <td><span className={tagClass(entry.attack_type)}>{entry.attack_type}</span></td>
                <td>{entry.matched_pattern}</td>
                <td><code>{entry.payload}</code></td>
                <td>{entry.source_ip}</td>
                <td><code>{entry.blocked_url}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

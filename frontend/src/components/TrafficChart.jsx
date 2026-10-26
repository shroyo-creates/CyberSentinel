import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from "recharts";

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="tooltip-box">
      <div style={{ color: "#c9d1d9", marginBottom: 4 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} style={{ color: p.color }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  );
}

export default function TrafficChart({ timeline }) {
  if (!timeline.length) {
    return <p className="empty-state">No traffic yet. Visit /login, /search, or /fetch to generate some.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={timeline} barCategoryGap={timeline.length < 6 ? "35%" : "10%"}>
        <CartesianGrid strokeDasharray="3 3" stroke="#212830" />
        <XAxis dataKey="time" tick={{ fill: "#7d8590", fontSize: 11 }} />
        <YAxis allowDecimals={false} tick={{ fill: "#7d8590", fontSize: 11 }} />
        <Tooltip content={<CustomTooltip />} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="allowed" name="Allowed" stackId="traffic" fill="#4493f8" isAnimationActive={false} />
        <Bar
          dataKey="blocked"
          name="Blocked"
          stackId="traffic"
          fill="#f85149"
          radius={[3, 3, 0, 0]}
          isAnimationActive={false}
        />
      </BarChart>
    </ResponsiveContainer>
  );
}

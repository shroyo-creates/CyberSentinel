import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function AttacksChart({ timeline }) {
  if (!timeline.length) {
    return <p className="empty-state">No attacks logged yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={timeline}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
        <XAxis dataKey="date" tick={{ fill: "#94a3b8", fontSize: 12 }} />
        <YAxis allowDecimals={false} tick={{ fill: "#94a3b8", fontSize: 12 }} />
        <Tooltip
          contentStyle={{ background: "#0b1220", border: "1px solid #334155", borderRadius: 6 }}
          labelStyle={{ color: "#e2e8f0" }}
        />
        <Bar dataKey="count" fill="#2563eb" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

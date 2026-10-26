import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function TopPatternsChart({ patterns }) {
  if (!patterns.length) {
    return <p className="empty-state">No attacks blocked yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={patterns} layout="vertical" margin={{ left: 10, right: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#212830" />
        <XAxis type="number" allowDecimals={false} tick={{ fill: "#7d8590", fontSize: 11 }} />
        <YAxis
          type="category"
          dataKey="pattern"
          width={160}
          tick={{ fill: "#7d8590", fontSize: 11 }}
        />
        <Tooltip
          contentStyle={{ background: "#161b22", border: "1px solid #212830", borderRadius: 6, fontSize: 12 }}
          labelStyle={{ color: "#c9d1d9" }}
        />
        <Bar dataKey="count" fill="#d29922" radius={[0, 3, 3, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

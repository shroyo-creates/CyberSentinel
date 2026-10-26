import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const COLORS = {
  "SQL Injection": "#d29922",
  "XSS": "#bc8cff",
  "Path Traversal": "#39c5cf",
};

export default function AttackDistributionChart({ distribution }) {
  const nonZero = distribution.filter((d) => d.value > 0);
  const total = nonZero.reduce((sum, d) => sum + d.value, 0);

  if (!total) {
    return <p className="empty-state">No attacks blocked yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={nonZero}
          dataKey="value"
          nameKey="name"
          innerRadius={55}
          outerRadius={85}
          paddingAngle={nonZero.length > 1 ? 3 : 0}
          isAnimationActive={false}
        >
          {nonZero.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || "#4493f8"} stroke="#10151d" />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: "#161b22", border: "1px solid #212830", borderRadius: 6, fontSize: 12 }}
          labelStyle={{ color: "#c9d1d9" }}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

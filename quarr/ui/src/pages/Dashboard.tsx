import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { api, EngagementSummary } from "../api";
import { Card, ErrorState, Spinner, EmptyState } from "../components";

const SEV_COLORS: Record<string, string> = {
  critical: "#b00020",
  high: "#e65100",
  medium: "#f9a825",
  low: "#0277bd",
  info: "#616161",
};

export default function Dashboard() {
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [severity, setSeverity] = useState<Record<string, number>>({});
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { engagements } = await api.listEngagements();
        setEngagements(engagements);
        // Aggregate severity across engagements.
        const agg: Record<string, number> = {};
        for (const e of engagements) {
          try {
            const detail = await api.getEngagement(e.id);
            for (const [k, v] of Object.entries(detail.severity_counts || {})) {
              agg[k] = (agg[k] || 0) + (v as number);
            }
          } catch {
            /* skip */
          }
        }
        setSeverity(agg);
      } catch (err: any) {
        setError(err.message || "Failed to load");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) return <Spinner label="Loading dashboard..." />;
  if (error) return <ErrorState message={error} />;

  const totalFindings = engagements.reduce((s, e) => s + e.findings, 0);
  const totalHosts = engagements.reduce((s, e) => s + e.hosts, 0);
  const totalTools = engagements.reduce((s, e) => s + e.tools_run, 0);
  const chartData = Object.entries(severity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Metric label="Engagements" value={engagements.length} />
        <Metric label="Hosts" value={totalHosts} />
        <Metric label="Findings" value={totalFindings} />
        <Metric label="Tools Run" value={totalTools} />
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="Findings by Severity">
          {chartData.length === 0 ? (
            <EmptyState message="No findings yet." />
          ) : (
            <div style={{ height: 260 }}>
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={chartData} dataKey="value" nameKey="name" outerRadius={90} label>
                    {chartData.map((d) => (
                      <Cell key={d.name} fill={SEV_COLORS[d.name] || "#888"} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card title="Recent Engagements">
          {engagements.length === 0 ? (
            <EmptyState message="No engagements. Create one from the Engagements page." />
          ) : (
            <ul className="space-y-2">
              {engagements.slice(0, 6).map((e) => (
                <li key={e.id}>
                  <Link className="text-sky-400 hover:underline" to={`/engagements/${e.id}`}>
                    {e.name}
                  </Link>
                  <span className="ml-2 text-xs text-slate-500">
                    {e.findings} findings · {e.hosts} hosts
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="card text-center">
      <div className="text-3xl font-bold text-sky-400">{value}</div>
      <div className="text-xs uppercase text-slate-500">{label}</div>
    </div>
  );
}

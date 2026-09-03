import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, auth, EngagementSummary } from "../api";
import { Card, ErrorState, Spinner, EmptyState } from "../components";

export default function Engagements() {
  const [items, setItems] = useState<EngagementSummary[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const canCreate = auth.role === "operator" || auth.role === "admin";
  const canDelete = auth.role === "admin";

  const load = async () => {
    setLoading(true);
    try {
      const { engagements } = await api.listEngagements();
      setItems(engagements);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const targets = scope.split(",").map((s) => s.trim()).filter(Boolean);
      await api.createEngagement(name, targets);
      setName("");
      setScope("");
      await load();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const remove = async (id: string) => {
    try {
      await api.deleteEngagement(id);
      await load();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Engagements</h1>
      {error && <ErrorState message={error} />}

      {canCreate && (
        <Card title="Create Engagement">
          <form onSubmit={create} className="flex flex-wrap items-end gap-3">
            <div className="flex-1">
              <label className="mb-1 block text-xs text-slate-400">Name</label>
              <input className="input" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="flex-1">
              <label className="mb-1 block text-xs text-slate-400">
                Scope (comma-separated targets)
              </label>
              <input
                className="input"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="10.10.10.0/24, target.example.com"
              />
            </div>
            <button className="btn">Create</button>
          </form>
        </Card>
      )}

      <Card>
        {loading ? (
          <Spinner label="Loading engagements..." />
        ) : items.length === 0 ? (
          <EmptyState message="No engagements yet." />
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                <th className="th">Name</th>
                <th className="th">Scope</th>
                <th className="th">Findings</th>
                <th className="th">Hosts</th>
                <th className="th"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td className="td">
                    <Link className="text-sky-400 hover:underline" to={`/engagements/${e.id}`}>
                      {e.name}
                    </Link>
                  </td>
                  <td className="td text-slate-400">{e.scope.join(", ")}</td>
                  <td className="td">{e.findings}</td>
                  <td className="td">{e.hosts}</td>
                  <td className="td text-right">
                    {canDelete && (
                      <button
                        className="text-xs text-red-400 hover:underline"
                        onClick={() => remove(e.id)}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

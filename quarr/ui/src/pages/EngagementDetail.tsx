import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, auth, Finding } from "../api";
import { Card, EmptyState, ErrorState, SeverityBadge, Spinner } from "../components";

type Tab = "hosts" | "findings" | "timeline" | "evidence" | "report";

export default function EngagementDetail() {
  const { id = "" } = useParams();
  const [tab, setTab] = useState<Tab>("findings");
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.getEngagement(id).then(setDetail).catch((e) => setError(e.message));
  }, [id]);

  if (error) return <ErrorState message={error} />;
  if (!detail) return <Spinner label="Loading engagement..." />;

  const tabs: Tab[] = ["hosts", "findings", "timeline", "evidence", "report"];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{detail.name}</h1>
          <p className="text-xs text-slate-500">Scope: {(detail.scope || []).join(", ")}</p>
        </div>
        {(auth.role === "operator" || auth.role === "admin") && (
          <Link className="btn" to={`/engagements/${id}/live`}>
            Live Console
          </Link>
        )}
      </div>

      <div className="flex gap-2 border-b border-slate-800">
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-2 text-sm capitalize ${
              tab === t ? "border-b-2 border-sky-400 text-sky-400" : "text-slate-400"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "hosts" && <HostsTab id={id} />}
      {tab === "findings" && <FindingsTab id={id} />}
      {tab === "timeline" && <TimelineTab id={id} />}
      {tab === "evidence" && <EvidenceTab id={id} />}
      {tab === "report" && <ReportTab id={id} />}
    </div>
  );
}

function HostsTab({ id }: { id: string }) {
  const [hosts, setHosts] = useState<any[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.getHosts(id).then((d) => setHosts(d.hosts)).catch((e) => setErr(e.message));
  }, [id]);
  if (err) return <ErrorState message={err} />;
  if (hosts.length === 0) return <EmptyState message="No hosts discovered." />;
  return (
    <Card>
      <table className="w-full">
        <thead>
          <tr><th className="th">Address</th><th className="th">Hostname</th><th className="th">Services</th></tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.address}>
              <td className="td">{h.address}</td>
              <td className="td">{h.hostname || "-"}</td>
              <td className="td text-slate-400">
                {(h.services || []).map((s: any) => `${s.port}/${s.protocol} ${s.name || ""}`).join(", ")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function FindingsTab({ id }: { id: string }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [err, setErr] = useState("");
  const canEdit = auth.role === "operator" || auth.role === "admin";

  const load = () =>
    api.getFindings(id).then((d) => setFindings(d.findings)).catch((e) => setErr(e.message));
  useEffect(() => {
    load();
  }, [id]);

  const setStatus = async (fid: string, status: string) => {
    await api.updateFinding(id, fid, { status });
    load();
  };

  if (err) return <ErrorState message={err} />;
  if (findings.length === 0) return <EmptyState message="No findings." />;
  return (
    <Card>
      <table className="w-full">
        <thead>
          <tr>
            <th className="th">Severity</th>
            <th className="th">Title</th>
            <th className="th">Asset</th>
            <th className="th">Status</th>
            <th className="th">Conf</th>
          </tr>
        </thead>
        <tbody>
          {findings
            .slice()
            .sort((a, b) => sevRank(b.severity) - sevRank(a.severity))
            .map((f) => (
              <tr key={f.id}>
                <td className="td"><SeverityBadge severity={f.severity} /></td>
                <td className="td">{f.title}</td>
                <td className="td text-slate-400">{f.asset}</td>
                <td className="td">
                  {canEdit ? (
                    <select
                      className="rounded bg-slate-900 px-1 py-0.5 text-xs"
                      value={f.status}
                      onChange={(e) => setStatus(f.id, e.target.value)}
                    >
                      {["observation", "hypothesis", "detected", "validating", "confirmed", "dismissed", "reported"].map(
                        (s) => (
                          <option key={s} value={s}>{s}</option>
                        )
                      )}
                    </select>
                  ) : (
                    f.status
                  )}
                </td>
                <td className="td">{f.confidence}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </Card>
  );
}

function TimelineTab({ id }: { id: string }) {
  const [events, setEvents] = useState<any[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.getTimeline(id).then((d) => setEvents(d.events)).catch((e) => setErr(e.message));
  }, [id]);
  if (err) return <ErrorState message={err} />;
  if (events.length === 0) return <EmptyState message="No timeline events." />;
  return (
    <Card>
      <ul className="space-y-1 text-sm">
        {events.map((e, i) => (
          <li key={i} className="flex gap-3">
            <span className="text-slate-500">{e.ts}</span>
            <span className="rounded bg-slate-700 px-2 text-xs">{e.kind}</span>
            <span>{e.detail}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function EvidenceTab({ id }: { id: string }) {
  const [data, setData] = useState<{ evidence: any[]; chain_verified: boolean } | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.getEvidence(id).then(setData).catch((e) => setErr(e.message));
  }, [id]);
  if (err) return <ErrorState message={err} />;
  if (!data) return <Spinner />;
  if (data.evidence.length === 0) return <EmptyState message="No evidence collected." />;
  return (
    <Card>
      <p className={`mb-2 text-xs ${data.chain_verified ? "text-emerald-400" : "text-red-400"}`}>
        Chain of custody: {data.chain_verified ? "verified ✓" : "TAMPERED ✗"}
      </p>
      <table className="w-full">
        <thead>
          <tr><th className="th">ID</th><th className="th">Tool</th><th className="th">Description</th><th className="th">Integrity</th></tr>
        </thead>
        <tbody>
          {data.evidence.map((ev) => (
            <tr key={ev.id}>
              <td className="td">{ev.id}</td>
              <td className="td">{ev.source_tool}</td>
              <td className="td text-slate-400">{ev.description}</td>
              <td className="td">{ev.tampered ? "✗" : "✓"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function ReportTab({ id }: { id: string }) {
  const [type, setType] = useState("executive");
  const [content, setContent] = useState("");
  const [err, setErr] = useState("");

  const preview = async () => {
    try {
      const r = await api.report(id, type);
      setContent(r.content);
    } catch (e: any) {
      setErr(e.message);
    }
  };

  return (
    <Card>
      <div className="mb-3 flex items-center gap-2">
        <select className="rounded bg-slate-900 px-2 py-1 text-sm" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="executive">Executive</option>
          <option value="technical">Technical</option>
        </select>
        <button className="btn" onClick={preview}>Preview</button>
        <a className="btn" href={api.reportDownloadUrl(id, "html", type)} target="_blank" rel="noreferrer">HTML</a>
        <a className="btn" href={api.reportDownloadUrl(id, "pdf", type)} target="_blank" rel="noreferrer">PDF</a>
        <a className="btn" href={api.reportDownloadUrl(id, "json", type)} target="_blank" rel="noreferrer">JSON</a>
      </div>
      {err && <ErrorState message={err} />}
      {content && (
        <pre className="max-h-[500px] overflow-auto whitespace-pre-wrap rounded bg-slate-950 p-3 text-xs">
          {content}
        </pre>
      )}
    </Card>
  );
}

function sevRank(s: string): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0;
}

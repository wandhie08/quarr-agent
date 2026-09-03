import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { auth } from "../api";
import { Card } from "../components";

interface LogLine {
  kind: string;
  text: string;
}

interface ApprovalReq {
  tool: string;
  target: string | null;
  risk: string;
}

export default function LiveConsole() {
  const { id = "" } = useParams();
  const [connected, setConnected] = useState(false);
  const [log, setLog] = useState<LogLine[]>([]);
  const [query, setQuery] = useState("");
  const [approval, setApproval] = useState<ApprovalReq | null>(null);
  const [running, setRunning] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  const append = (kind: string, text: string) =>
    setLog((l) => [...l, { kind, text }]);

  useEffect(() => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${location.host}/ws/live?token=${encodeURIComponent(
      auth.access || ""
    )}&engagement=${encodeURIComponent(id)}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      let msg: any;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      switch (msg.type) {
        case "connected":
          setConnected(true);
          append("system", "Live console connected.");
          break;
        case "status":
          append("status", msg.data);
          break;
        case "approval_request":
          setApproval({ tool: msg.tool, target: msg.target, risk: msg.risk });
          break;
        case "result":
          append("result", msg.data);
          setRunning(false);
          break;
        case "error":
          append("error", msg.data);
          setRunning(false);
          break;
      }
    };
    ws.onclose = () => {
      setConnected(false);
      append("system", "Connection closed.");
    };
    return () => ws.close();
  }, [id]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [log]);

  const run = () => {
    if (!query.trim() || !wsRef.current) return;
    append("query", query);
    wsRef.current.send(JSON.stringify({ type: "run", query }));
    setRunning(true);
    setQuery("");
  };

  const respond = (approved: boolean) => {
    wsRef.current?.send(JSON.stringify({ type: "approval_response", approved }));
    setApproval(null);
    append("system", approved ? "Approved dangerous tool." : "Denied dangerous tool.");
  };

  const color: Record<string, string> = {
    system: "text-slate-500",
    status: "text-sky-300",
    query: "text-emerald-300",
    result: "text-slate-100",
    error: "text-red-400",
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Live Console</h1>
        <span className={`text-xs ${connected ? "text-emerald-400" : "text-red-400"}`}>
          {connected ? "● connected" : "○ disconnected"}
        </span>
      </div>

      <Card>
        <div className="h-[420px] overflow-auto rounded bg-slate-950 p-3 font-mono text-xs">
          {log.length === 0 && <span className="text-slate-600">Waiting for commands…</span>}
          {log.map((l, i) => (
            <div key={i} className={color[l.kind] || "text-slate-300"}>
              <span className="text-slate-600">[{l.kind}]</span> {l.text}
            </div>
          ))}
          <div ref={logEndRef} />
        </div>

        <div className="mt-3 flex gap-2">
          <input
            className="input"
            placeholder="Enter an objective (e.g. discover hosts on 10.10.10.0/24)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            disabled={!connected || running}
          />
          <button className="btn" onClick={run} disabled={!connected || running}>
            {running ? "Running…" : "Run"}
          </button>
        </div>
      </Card>

      {approval && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="card w-96 space-y-3">
            <h2 className="text-lg font-bold text-amber-400">Approval Required</h2>
            <p className="text-sm">
              The agent wants to run a <b>{approval.risk.toUpperCase()}</b> risk tool:
            </p>
            <div className="rounded bg-slate-950 p-2 text-sm">
              <div>Tool: <b>{approval.tool}</b></div>
              <div>Target: {approval.target || "-"}</div>
            </div>
            <div className="flex justify-end gap-2">
              <button className="rounded bg-slate-700 px-3 py-1.5 text-sm" onClick={() => respond(false)}>
                Deny
              </button>
              <button className="btn" onClick={() => respond(true)}>
                Approve
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

import { ReactNode } from "react";

export function SeverityBadge({ severity }: { severity: string }) {
  const s = ["critical", "high", "medium", "low", "info"].includes(severity)
    ? severity
    : "info";
  const color: Record<string, string> = {
    critical: "bg-sev-critical",
    high: "bg-sev-high",
    medium: "bg-sev-medium text-black",
    low: "bg-sev-low",
    info: "bg-sev-info",
  };
  return <span className={`badge ${color[s]}`}>{s.toUpperCase()}</span>;
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="card">
      {title && <h2 className="mb-2 text-sm font-semibold text-emerald-400">{title}</h2>}
      {children}
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400" />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">
      {message}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return <div className="p-4 text-sm text-slate-500">{message}</div>;
}

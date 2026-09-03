// Typed API client with JWT auth, auto-refresh, and 401 handling.

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  role: string;
  username: string;
}

export interface EngagementSummary {
  id: string;
  name: string;
  scope: string[];
  findings: number;
  hosts: number;
  tools_run: number;
  saved_at?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  asset: string;
  description?: string;
  remediation?: string;
  evidence_count?: number;
}

const ACCESS_KEY = "quarr_access";
const REFRESH_KEY = "quarr_refresh";
const ROLE_KEY = "quarr_role";
const USER_KEY = "quarr_user";

export const auth = {
  get access() {
    return localStorage.getItem(ACCESS_KEY);
  },
  get refresh() {
    return localStorage.getItem(REFRESH_KEY);
  },
  get role() {
    return localStorage.getItem(ROLE_KEY) || "";
  },
  get username() {
    return localStorage.getItem(USER_KEY) || "";
  },
  set(data: LoginResponse) {
    localStorage.setItem(ACCESS_KEY, data.access_token);
    localStorage.setItem(REFRESH_KEY, data.refresh_token);
    localStorage.setItem(ROLE_KEY, data.role);
    localStorage.setItem(USER_KEY, data.username);
  },
  setAccess(token: string) {
    localStorage.setItem(ACCESS_KEY, token);
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(ROLE_KEY);
    localStorage.removeItem(USER_KEY);
  },
  get isAuthenticated() {
    return !!localStorage.getItem(ACCESS_KEY);
  },
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function tryRefresh(): Promise<boolean> {
  const refresh = auth.refresh;
  if (!refresh) return false;
  const resp = await fetch("/api/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!resp.ok) return false;
  const data = await resp.json();
  auth.setAccess(data.access_token);
  return true;
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  retry = true
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (auth.access) headers["Authorization"] = `Bearer ${auth.access}`;

  const resp = await fetch(path, { ...options, headers });

  if (resp.status === 401 && retry) {
    const refreshed = await tryRefresh();
    if (refreshed) return request<T>(path, options, false);
    auth.clear();
    throw new ApiError(401, "Session expired");
  }
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const body = await resp.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(resp.status, detail);
  }
  const ct = resp.headers.get("content-type") || "";
  return (ct.includes("application/json") ? await resp.json() : await resp.text()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<{ username: string; role: string }>("/api/auth/me"),
  listEngagements: () =>
    request<{ engagements: EngagementSummary[] }>("/api/engagements"),
  createEngagement: (name: string, allowed_targets: string[]) =>
    request<{ id: string; name: string }>("/api/engagements", {
      method: "POST",
      body: JSON.stringify({ name, allowed_targets }),
    }),
  deleteEngagement: (id: string) =>
    request<{ deleted: string }>(`/api/engagements/${id}`, { method: "DELETE" }),
  getEngagement: (id: string) => request<any>(`/api/engagements/${id}`),
  getHosts: (id: string) => request<{ hosts: any[] }>(`/api/engagements/${id}/hosts`),
  getFindings: (id: string) =>
    request<{ findings: Finding[] }>(`/api/engagements/${id}/findings`),
  updateFinding: (id: string, fid: string, upd: Record<string, unknown>) =>
    request(`/api/engagements/${id}/findings/${fid}`, {
      method: "PATCH",
      body: JSON.stringify(upd),
    }),
  dedup: (id: string, dryRun: boolean) =>
    request<{ merged: number; groups: string[][]; dry_run: boolean }>(
      `/api/engagements/${id}/dedup?dry_run=${dryRun}`,
      { method: "POST" }
    ),
  getTimeline: (id: string) =>
    request<{ events: any[] }>(`/api/engagements/${id}/timeline`),
  getToolHistory: (id: string) =>
    request<{ tool_history: any[] }>(`/api/engagements/${id}/tool-history`),
  getEvidence: (id: string) =>
    request<{ evidence: any[]; chain_verified: boolean }>(
      `/api/engagements/${id}/evidence`
    ),
  report: (id: string, type: string) =>
    request<{ type: string; content: string }>(`/api/engagements/${id}/report`, {
      method: "POST",
      body: JSON.stringify({ type }),
    }),
  reportDownloadUrl: (id: string, fmt: string, type: string) =>
    `/api/engagements/${id}/report/download?fmt=${fmt}&type=${type}`,
};

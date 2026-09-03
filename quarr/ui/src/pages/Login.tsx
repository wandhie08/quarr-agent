import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, auth } from "../api";
import { ErrorState } from "../components";

export default function Login() {
  const nav = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await api.login(username, password);
      auth.set(data);
      nav("/");
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900 text-slate-100">
      <form onSubmit={submit} className="card w-80 space-y-4">
        <h1 className="text-center text-xl font-bold text-sky-400">QUARR</h1>
        <p className="text-center text-xs text-slate-500">Cyber Operations Console</p>
        {error && <ErrorState message={error} />}
        <div>
          <label className="mb-1 block text-xs text-slate-400">Username</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">Password</label>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button className="btn w-full" disabled={loading}>
          {loading ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}

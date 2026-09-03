import { Navigate, Route, Routes, Link, useNavigate } from "react-router-dom";
import { auth } from "./api";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Engagements from "./pages/Engagements";
import EngagementDetail from "./pages/EngagementDetail";
import LiveConsole from "./pages/LiveConsole";

function RequireAuth({ children }: { children: JSX.Element }) {
  if (!auth.isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

function Layout({ children }: { children: JSX.Element }) {
  const nav = useNavigate();
  const logout = () => {
    auth.clear();
    nav("/login");
  };
  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      <header className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-6 py-3">
        <div className="flex items-center gap-6">
          <Link to="/" className="text-lg font-bold text-sky-400">
            QUARR
          </Link>
          <nav className="flex gap-4 text-sm">
            <Link to="/" className="hover:text-sky-400">Dashboard</Link>
            <Link to="/engagements" className="hover:text-sky-400">Engagements</Link>
          </nav>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span>
            {auth.username} <span className="rounded bg-slate-700 px-2 py-0.5 text-xs">{auth.role}</span>
          </span>
          <button className="text-slate-400 hover:text-red-400" onClick={logout}>
            Logout
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-6xl p-6">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Layout><Dashboard /></Layout>
          </RequireAuth>
        }
      />
      <Route
        path="/engagements"
        element={
          <RequireAuth>
            <Layout><Engagements /></Layout>
          </RequireAuth>
        }
      />
      <Route
        path="/engagements/:id"
        element={
          <RequireAuth>
            <Layout><EngagementDetail /></Layout>
          </RequireAuth>
        }
      />
      <Route
        path="/engagements/:id/live"
        element={
          <RequireAuth>
            <Layout><LiveConsole /></Layout>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

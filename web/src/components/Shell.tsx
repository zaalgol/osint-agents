import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { get, type InvestigationSummary, type Job } from "../api";
import { Badge, Spinner } from "./ui";

interface Meta { active_jobs: number; review_open: number }

export function Shell() {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => get<InvestigationSummary[]>("/api/investigations"), refetchInterval: 15_000 });
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => get<Meta>("/api/meta"), refetchInterval: 5_000 });
  const running = useQuery({
    queryKey: ["jobs", "running"],
    queryFn: async () => (await get<Job[]>("/api/jobs")).filter((j) => j.status === "running"),
    refetchInterval: 4_000,
  });

  const toggleTheme = () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("theme", root.dataset.theme); } catch { /* ignore */ }
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">◎</span> OSINT Workbench</div>
        <NavLink to="/" end className="nav-link">Investigations</NavLink>
        <NavLink to="/new" className="nav-link">＋ New investigation</NavLink>
        <NavLink to="/search" className="nav-link">Search entities</NavLink>
        <NavLink to="/review" className="nav-link">
          Review {meta.data && meta.data.review_open > 0 && <span className="count">{meta.data.review_open}</span>}
        </NavLink>
        <NavLink to="/sources" className="nav-link">Sources &amp; grading</NavLink>
        <NavLink to="/jobs" className="nav-link">
          Jobs {meta.data && meta.data.active_jobs > 0 && <span className="count">{meta.data.active_jobs}</span>}
        </NavLink>
        <NavLink to="/system" className="nav-link">System</NavLink>
        <div className="nav-section">Investigations</div>
        {invs.data?.filter((i) => i.status !== "archived").map((i) => (
          <NavLink key={i.id} to={`/inv/${i.id}`} className="nav-link nav-inv" title={i.focus ?? i.name}>
            <span className="nav-inv">{i.name}</span>
            {i.profile === "anonymous" && <Badge tone="tor">Tor</Badge>}
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <button className="small ghost" onClick={toggleTheme}>◐ Theme</button>
        </div>
      </aside>
      <div className="main">
        <div className="topbar">
          <form className="search" onSubmit={(e) => { e.preventDefault(); if (q.trim()) nav(`/search?q=${encodeURIComponent(q.trim())}`); }}>
            <input placeholder="Search entities in all investigations (name, alias, handle, wallet…)" value={q} onChange={(e) => setQ(e.target.value)} />
          </form>
          <div className="row" style={{ marginLeft: "auto" }}>
            {running.data && running.data.length > 0 && (
              <NavLink to="/jobs" className="row small"><Spinner /> {running.data.length} running: {running.data[0].label}</NavLink>
            )}
          </div>
        </div>
        <Outlet />
      </div>
    </div>
  );
}

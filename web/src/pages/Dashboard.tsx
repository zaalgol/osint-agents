import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, type InvestigationSummary } from "../api";
import { Badge, Empty, ErrorBox, Loading, fmtTime } from "../components/ui";

export function Dashboard() {
  const q = useQuery({ queryKey: ["investigations"], queryFn: () => get<InvestigationSummary[]>("/api/investigations") });
  const [showArchived, setShowArchived] = useState(false);
  const archived = (q.data ?? []).filter((i) => i.status === "archived").length;
  const shown = (q.data ?? []).filter((i) => showArchived || i.status !== "archived");
  return (
    <div className="page">
      <div className="spread">
        <div>
          <h1>Investigations</h1>
          <div className="muted">Each investigation is a scope over one shared knowledge base, so entities connect across cases.</div>
        </div>
        <div className="row">
          {archived > 0 && <label className="check small"><input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} /> show {archived} archived</label>}
          <Link to="/new" className="btn primary">＋ New investigation</Link>
        </div>
      </div>
      <div className="gap-top">
        {q.isLoading && <Loading />}
        <ErrorBox error={q.error} />
        {q.data?.length === 0 && <Empty>No investigations yet. <Link to="/new">Create the first one</Link>.</Empty>}
        <div className="grid grid-3">
          {shown.map((i) => (
            <Link key={i.id} to={`/inv/${i.id}`} className="card" style={{ color: "inherit", textDecoration: "none", opacity: i.status === "archived" ? 0.6 : 1 }}>
              <div className="spread">
                <strong style={{ fontSize: 15 }}>{i.name}</strong>
                <div className="row">
                  {i.status === "archived" && <Badge>archived</Badge>}
                  {i.profile === "anonymous" && <Badge tone="tor">Tor</Badge>}
                  {i.open_tasks > 0 && <Badge tone="accent">{i.open_tasks} queued</Badge>}
                  {i.failed_tasks > 0 && <Badge tone="bad">{i.failed_tasks} failed</Badge>}
                  {i.review_open > 0 && <Badge tone="warn">{i.review_open} to review</Badge>}
                </div>
              </div>
              <div className="muted small" style={{ margin: "6px 0 10px", minHeight: 40 }}>{i.focus ?? "No focus set"}</div>
              <div className="stats small">
                {([["artifact", "artifacts"], ["document", "documents"], ["entity", "entities"], ["relation", "relations"], ["event", "events"]] as const).map(([k, label]) => (
                  <div key={k} className="stat"><span className="n" style={{ fontSize: 16 }}>{i.counts[k] ?? 0}</span><span className="l">{label}</span></div>
                ))}
              </div>
              <div className="muted small gap-top">#{i.id} · created {fmtTime(i.created)}</div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, type TimelineEvent } from "../api";
import { Badge, Empty, ErrorBox, Loading } from "../components/ui";
import { EvidenceList } from "../components/EvidenceList";

export function TimelineTab({ inv }: { inv: number }) {
  const q = useQuery({ queryKey: ["inv", inv, "timeline"], queryFn: () => get<TimelineEvent[]>(`/api/inv/${inv}/timeline`) });
  const [type, setType] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const types = useMemo(() => [...new Set((q.data ?? []).map((e) => e.type))].sort(), [q.data]);
  const rows = (q.data ?? []).filter((e) => !type || e.type === type);
  const undated = rows.filter((e) => !e.time);
  const dated = rows.filter((e) => e.time);

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data?.length) return <Empty>No events extracted yet.</Empty>;

  const item = (e: TimelineEvent) => (
    <div key={e.event_id} className="card">
      <div className="spread">
        <div className="row">
          <strong>{e.time ?? "undated"}</strong>
          <Badge>{e.type.replace(/_/g, " ")}</Badge>
          {e.support && (e.support.independent_sources > 1
            ? <Badge tone="ok">{e.support.independent_sources} independent sources</Badge>
            : <Badge tone="warn">single source</Badge>)}
          {e.reports > 1 && <Badge tone="accent">{e.reports} reports of this incident</Badge>}
        </div>
        <button className="small ghost" onClick={() => setOpen(open === e.event_id ? null : e.event_id)}>
          {open === e.event_id ? "Hide" : "Show"} evidence ({e.evidence.length})
        </button>
      </div>
      <div style={{ margin: "6px 0" }}>{e.description}</div>
      <div className="chips">
        {e.location && <span className="chip" style={{ paddingRight: 9 }}>📍 {e.location}</span>}
        {e.participants.map((p) => (
          <Link key={`${p.entity_id}-${p.role}`} className="chip" style={{ paddingRight: 9 }} to={`/entity/${p.entity_id}?inv=${inv}`}>
            {p.name} <span className="muted">· {p.role}</span>
          </Link>
        ))}
      </div>
      {open === e.event_id && <div className="gap-top"><EvidenceList inv={inv} markers={e.evidence} /></div>}
    </div>
  );

  return (
    <div className="stack">
      <div className="row">
        <select style={{ maxWidth: 240 }} value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">all event types</option>
          {types.map((t) => <option key={t}>{t}</option>)}
        </select>
        <span className="muted small">{dated.length} dated, {undated.length} undated</span>
      </div>
      {dated.map(item)}
      {undated.length > 0 && <h3 className="gap-top">Undated</h3>}
      {undated.map(item)}
    </div>
  );
}

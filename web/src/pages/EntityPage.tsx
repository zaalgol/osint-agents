import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { get, type EntityDetail } from "../api";
import { Badge, ErrorBox, Loading, TypeChip } from "../components/ui";
import { EvidenceList } from "../components/EvidenceList";

export function EntityPage() {
  const { id } = useParams();
  const [sp] = useSearchParams();
  const inv = Number(sp.get("inv") ?? 0);
  const q = useQuery({ queryKey: ["entity", id, inv], queryFn: () => get<EntityDetail>(`/api/entity/${id}?inv=${inv}`) });
  const [open, setOpen] = useState<string | null>(null);
  const e = q.data;

  return (
    <div className="page">
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      {e && (
        <div className="stack">
          <div>
            <div className="row"><h1>{e.name}</h1><TypeChip type={e.type} />{e.strong_key && <code>{e.strong_key}</code>}</div>
            <div className="row small">
              <span className="muted">In:</span>
              {e.investigations.map((i) => <Link key={i.id} to={`/inv/${i.id}`}><Badge tone={i.id === inv ? "accent" : undefined}>{i.name}</Badge></Link>)}
              {e.investigations.length > 1 && <Badge tone="ok">appears in {e.investigations.length} investigations</Badge>}
            </div>
          </div>
          <div className="grid grid-2">
            <div className="card">
              <h3>Aliases ({e.alias_count})</h3>
              <div className="chips">{e.aliases.map((a) => <span key={a} className="chip" style={{ paddingRight: 9 }}>{a}</span>)}</div>
            </div>
            <div className="card">
              <h3>Attributes</h3>
              {Object.keys(e.attributes ?? {}).length === 0 ? <div className="muted small">None (run Enrich for sanctions, RDAP, geocoding, wallets).</div> : (
                <pre className="small mono" style={{ whiteSpace: "pre-wrap", margin: 0, maxHeight: 260, overflowY: "auto" }}>{JSON.stringify(e.attributes, null, 1)}</pre>
              )}
            </div>
          </div>
          <div className="card">
            <h3>Relations ({e.relations.length})</h3>
            <table>
              <tbody>
                {e.relations.map((r) => {
                  const key = `r${r.relation_id}`;
                  return (
                    <Fragment key={key}>
                      <tr>
                        <td className="small">{r.direction === "out" ? <><strong>{e.name}</strong> → {r.type.replace(/_/g, " ")}</> : <>← {r.type.replace(/_/g, " ")}</>}</td>
                        <td><Link to={`/entity/${r.other.entity_id}?inv=${inv}`}>{r.other.name}</Link> <TypeChip type={r.other.type} /></td>
                        <td>{r.support && (r.support.independent_sources > 1
                          ? <Badge tone="ok">{r.support.independent_sources} sources</Badge> : <Badge tone="warn">single source</Badge>)}</td>
                        <td><button className="small ghost" onClick={() => setOpen(open === key ? null : key)}>evidence ({r.evidence.length})</button></td>
                      </tr>
                      {open === key && <tr><td colSpan={4}><EvidenceList inv={inv} markers={r.evidence} preloaded={e.evidence_detail} /></td></tr>}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="card">
            <h3>Events ({e.events.length})</h3>
            {e.events.map((v) => {
              const key = `v${v.event_id}`;
              return (
                <div key={key} style={{ padding: "8px 0", borderBottom: "1px solid var(--border)" }}>
                  <div className="row"><strong>{v.time ?? "undated"}</strong><Badge>{v.type}</Badge><Badge tone="accent">{v.role}</Badge>
                    <button className="small ghost" onClick={() => setOpen(open === key ? null : key)}>evidence ({v.evidence.length})</button></div>
                  <div>{v.description}</div>
                  {open === key && <EvidenceList inv={inv} markers={v.evidence} preloaded={e.evidence_detail} />}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

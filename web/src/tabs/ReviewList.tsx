import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, post, type CrossLink, type ReviewItem } from "../api";
import { Badge, Empty, ErrorBox, Loading, useToast } from "../components/ui";

const KIND_HELP: Record<string, string> = {
  sanctions_match: "Possible sanctions listing. Accept only after checking identifiers (DOB, nationality, aliases).",
  resolution_candidate: "Possible duplicate entities. Accept to merge (reversible).",
  resolution_pair: "Possible duplicate entities. Accept to merge (reversible).",
  contradiction: "Sources disagree. Accept = acknowledged (both versions stay); reject = not a real contradiction.",
  finding_revision: "Claude proposes changing a finding. Accept to apply it.",
  media_metadata: "An image carries EXIF metadata (maybe GPS or camera). A lead, and it can identify people.",
  quote_not_found: "An extracted quote wasn't found in the source. Can only be dismissed.",
  weak_citation: "The quote doesn't clearly support the fact. Can only be dismissed.",
  blocked_source: "A site blocked collection. Dismiss when seen.",
  integrity_alert: "Evidence integrity problem. Investigate, then dismiss.",
};
const DISMISS_ONLY = new Set(["quote_not_found", "weak_citation", "ontology", "unresolved", "blocked_source", "enrichment", "integrity_alert"]);

export function ReviewList({ inv }: { inv?: number }) {
  const qc = useQueryClient();
  const toast = useToast();
  const key = inv ? ["inv", inv, "review"] : ["review"];
  const q = useQuery({
    queryKey: key,
    queryFn: () => get<{ items: ReviewItem[]; links?: CrossLink[]; total?: number }>(inv ? `/api/inv/${inv}/review` : "/api/review"),
  });
  const [kind, setKind] = useState("");
  const [notes, setNotes] = useState<Record<number, string>>({});
  const decide = useMutation({
    mutationFn: (v: { what: "item" | "link"; id: number; decision: "accept" | "reject"; target?: number }) =>
      post(`/api/review/${v.what}/${v.id}`, { decision: v.decision, note: notes[v.id], target: v.target }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: key }); qc.invalidateQueries({ queryKey: ["meta"] }); },
    onError: (e: Error) => toast(e.message, true),
  });
  const [bulk, setBulk] = useState<{ done: number; total: number } | null>(null);
  const dismissAll = async (rows: ReviewItem[]) => {
    if (!window.confirm(`Dismiss all ${rows.length} shown "${kind.replace(/_/g, " ")}" items? Each decision is recorded.`)) return;
    setBulk({ done: 0, total: rows.length });
    let failed = 0;
    for (let i = 0; i < rows.length; i++) {
      try { await post(`/api/review/item/${rows[i].id}`, { decision: "reject", note: "bulk dismiss (GUI)" }); }
      catch { failed++; }
      setBulk({ done: i + 1, total: rows.length });
    }
    setBulk(null);
    qc.invalidateQueries({ queryKey: key });
    qc.invalidateQueries({ queryKey: ["meta"] });
    toast(`Dismissed ${rows.length - failed} item(s)` + (failed ? `, ${failed} failed` : ""), failed > 0);
  };
  const kinds = useMemo(() => {
    const c: Record<string, number> = {};
    for (const i of q.data?.items ?? []) c[i.kind] = (c[i.kind] ?? 0) + 1;
    return c;
  }, [q.data]);

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const items = (q.data?.items ?? []).filter((i) => !kind || i.kind === kind);
  const links = q.data?.links ?? [];
  if (!items.length && !links.length && !kind) return <Empty>Nothing to review. 🎉</Empty>;

  return (
    <div className="stack">
      <div className="row">
        <button className={`small ${!kind ? "primary" : ""}`} onClick={() => setKind("")}>all ({q.data?.items.length})</button>
        {Object.entries(kinds).map(([k, n]) => (
          <button key={k} className={`small ${kind === k ? "primary" : ""}`} onClick={() => setKind(k)}>{k.replace(/_/g, " ")} ({n})</button>
        ))}
        {q.data?.total !== undefined && q.data.total > (q.data?.items.length ?? 0) && (
          <span className="muted small">showing {q.data.items.length} of {q.data.total}; decide some to see more</span>
        )}
      </div>
      {kind && DISMISS_ONLY.has(kind) && items.length > 1 && (
        <div className="notice row small">
          These items can only be dismissed.
          <button className="small" disabled={bulk !== null} onClick={() => dismissAll(items)}>
            {bulk ? `Dismissing ${bulk.done}/${bulk.total}…` : `Dismiss all ${items.length} shown`}
          </button>
        </div>
      )}
      {links.length > 0 && !kind && (
        <div className="card">
          <h3>Cross-investigation link candidates</h3>
          {links.map((l) => (
            <div key={l.link_id} className="spread" style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
              <div>
                <Link to={`/inv/${l.other_investigation.id}`}>{l.other_investigation.name}</Link> via {l.via.name ?? l.via.description ?? l.via.type}
                <span className="muted small"> · {l.tier} · score {l.score.toFixed(2)}</span>
              </div>
              <div className="row">
                <button className="small primary" onClick={() => decide.mutate({ what: "link", id: l.link_id, decision: "accept" })}>Confirm</button>
                <button className="small" onClick={() => decide.mutate({ what: "link", id: l.link_id, decision: "reject" })}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      )}
      {items.map((i) => <ReviewCard key={i.id} item={i} note={notes[i.id] ?? ""}
        setNote={(n) => setNotes({ ...notes, [i.id]: n })}
        decide={(decision, target) => decide.mutate({ what: "item", id: i.id, decision, target })}
        busy={decide.isPending} showInv={!inv} />)}
    </div>
  );
}

function ReviewCard({ item, note, setNote, decide, busy, showInv }: {
  item: ReviewItem; note: string; setNote: (n: string) => void;
  decide: (d: "accept" | "reject", target?: number) => void; busy: boolean; showInv: boolean;
}) {
  const p = item.payload;
  const candidates = (p.candidates as { entity_id: number; name: string; type?: string; score?: number }[] | undefined) ?? [];
  const [target, setTarget] = useState<number | undefined>(candidates[0]?.entity_id);
  return (
    <div className="card">
      <div className="spread">
        <div className="row">
          <Badge tone="warn">{item.kind.replace(/_/g, " ")}</Badge>
          <span className="mono small">#{item.id}</span>
          {showInv && item.investigation_id && <Link className="small" to={`/inv/${item.investigation_id}/review`}>{item.investigation ?? `investigation ${item.investigation_id}`}</Link>}
        </div>
      </div>
      <div style={{ margin: "6px 0" }}>{item.reason}</div>
      {KIND_HELP[item.kind] && <div className="muted small">{KIND_HELP[item.kind]}</div>}
      {typeof p.list_entry === "string" && <div className="quote small">{p.list_entry}</div>}
      {typeof p.quote === "string" && <div className="quote small">“{p.quote}”</div>}
      {typeof p.finding_text === "string" && <div className="quote small">{p.finding_text}</div>}
      {(typeof p.a_description === "string" || typeof p.b_description === "string") && (
        <div className="grid grid-2 small"><div><strong>A</strong> {String(p.a_description ?? "")}</div><div><strong>B</strong> {String(p.b_description ?? "")}</div></div>
      )}
      {Array.isArray(p.names) && <div className="small">{(p.names as string[]).join(" ↔ ")}</div>}
      {p.exif !== undefined && <pre className="small mono" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(p.exif, null, 1)}</pre>}
      {typeof p.entity_id === "number" && <div className="small"><Link to={`/entity/${p.entity_id}`}>entity {p.entity_id}</Link></div>}
      {candidates.length > 1 && (
        <label className="field small gap-top">Merge into
          <select value={target} onChange={(e) => setTarget(Number(e.target.value))}>
            {candidates.map((c) => <option key={c.entity_id} value={c.entity_id}>{c.name} ({c.entity_id}{c.score ? `, ${c.score}` : ""})</option>)}
          </select>
        </label>
      )}
      <div className="row gap-top">
        <input style={{ maxWidth: 360 }} placeholder="Note (optional, recorded)" value={note} onChange={(e) => setNote(e.target.value)} />
        {!DISMISS_ONLY.has(item.kind) && <button className="small primary" disabled={busy} onClick={() => decide("accept", target)}>Accept</button>}
        <button className="small" disabled={busy} onClick={() => decide("reject")}>{DISMISS_ONLY.has(item.kind) ? "Dismiss" : "Reject"}</button>
      </div>
    </div>
  );
}

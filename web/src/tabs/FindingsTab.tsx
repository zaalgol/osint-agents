import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, markerId, type Finding, type ProofNode } from "../api";
import { Badge, Empty, ErrorBox, JobButton, Loading, Modal, fmtTime } from "../components/ui";
import { EvidenceList } from "../components/EvidenceList";

interface Contradiction { events: number[]; issue: string; a: string; b: string; status: string; evidence_a: string[]; evidence_b: string[] }

const STATUS_TONE: Record<string, "ok" | "warn" | "bad" | "accent"> = {
  observed: "ok", reported: "accent", inferred: "warn", assessed: "warn",
};

export function FindingsTab({ inv }: { inv: number }) {
  const q = useQuery({
    queryKey: ["inv", inv, "findings"],
    queryFn: () => get<{ findings: Finding[]; contradictions: Contradiction[] }>(`/api/inv/${inv}/findings`),
  });
  const [explain, setExplain] = useState<number | null>(null);
  const [revise, setRevise] = useState<Finding | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const findings = q.data?.findings ?? [];
  return (
    <div className="stack">
      <div className="spread">
        <div className="muted small">Findings are recorded by Claude (or analysts) with an epistemic status and proof: evidence for observed/reported, a proof tree for inferred/assessed.</div>
        <div className="row">
          <JobButton action="analyze" inv={inv} primary>Analyze again</JobButton>
          <JobButton action="red_team" inv={inv}>Red team</JobButton>
        </div>
      </div>
      {findings.length === 0 && <Empty>No findings yet. Run Analyze.</Empty>}
      {findings.map((f) => (
        <div key={f.marker} className="card" style={{ opacity: f.status === "withdrawn" ? 0.55 : 1 }}>
          <div className="spread">
            <div className="row">
              <span className="mono">{f.marker}</span>
              <Badge tone={STATUS_TONE[f.epistemic_status]}>{f.epistemic_status}</Badge>
              <Badge>{f.kind}</Badge>
              <Badge tone={f.confidence >= 0.7 ? "ok" : f.confidence < 0.4 ? "warn" : undefined}>confidence {Math.round(f.confidence * 100)}%</Badge>
              {f.status !== "active" && <Badge tone="bad">{f.status}</Badge>}
              <span className="muted small">by {f.created_by}</span>
            </div>
            <div className="row">
              <button className="small" onClick={() => setExplain(markerId(f.marker))}>Proof tree</button>
              <button className="small" onClick={() => setOpen(open === f.marker ? null : f.marker)}>Evidence ({f.evidence.length})</button>
              <button className="small ghost" onClick={() => setRevise(f)}>Revise</button>
            </div>
          </div>
          <div style={{ marginTop: 6 }}>{f.text}</div>
          {open === f.marker && <div className="gap-top"><EvidenceList inv={inv} markers={f.evidence} /></div>}
        </div>
      ))}
      {(q.data?.contradictions.length ?? 0) > 0 && (
        <div className="card">
          <h3>Contradictions</h3>
          {q.data!.contradictions.map((c) => (
            <div key={c.events.join("-")} style={{ marginBottom: 12 }}>
              <div className="row"><Badge tone={c.status === "open" ? "warn" : undefined}>{c.status}</Badge> {c.issue}</div>
              <div className="grid grid-2 small gap-top">
                <div><strong>A</strong> {c.a}</div><div><strong>B</strong> {c.b}</div>
              </div>
            </div>
          ))}
        </div>
      )}
      {explain !== null && <ExplainModal inv={inv} fid={explain} onClose={() => setExplain(null)} />}
      {revise && <ReviseModal inv={inv} f={revise} onClose={() => setRevise(null)} />}
    </div>
  );
}

function ExplainModal({ inv, fid, onClose }: { inv: number; fid: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ["explain", fid], queryFn: () => get<ProofNode>(`/api/finding/${fid}/explain`) });
  return (
    <Modal title={`Proof tree for F:${fid}`} onClose={onClose}>
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      {q.data && <ul className="tree" style={{ borderLeft: "none", paddingLeft: 0 }}><ProofItem n={q.data} inv={inv} /></ul>}
    </Modal>
  );
}

function ProofItem({ n, inv }: { n: ProofNode; inv: number }) {
  let head;
  if (n.type === "evidence") {
    head = n.missing ? <span className="error small">E:{n.id} missing</span> : (
      <div>
        <div className="quote">“{n.quote}”</div>
        {n.translation && <div className="small muted">EN: {n.translation}</div>}
        <div className="small muted row">
          <span className="mono">E:{n.id}</span>
          {n.url?.startsWith("http") ? <a href={n.url} target="_blank" rel="noreferrer noopener" className="wrap-anywhere">{n.url}</a> : <span>{n.url}</span>}
          <span>captured {fmtTime(n.captured)}</span>
          <span className="mono">{n.sha256?.slice(0, 16)}…</span>
        </div>
      </div>
    );
  } else if (n.type === "inference") {
    head = <span className="muted small">└ derived by <em>{n.method}</em> ({n.by})</span>;
  } else if (n.type === "finding") {
    head = <div><strong>F:{n.id}</strong> <Badge>{n.epistemic_status}</Badge> <Badge>{Math.round((n.confidence ?? 0) * 100)}%</Badge> {n.text}</div>;
  } else {
    head = <div><strong>{n.type} {n.id}</strong> {n.text}</div>;
  }
  return (
    <li>
      {head}
      {n.children && n.children.length > 0 && (
        <ul className="tree">{n.children.map((c, i) => <ProofItem key={`${c.type}-${c.id}-${i}`} n={c} inv={inv} />)}</ul>
      )}
    </li>
  );
}

function ReviseModal({ inv, f, onClose }: { inv: number; f: Finding; onClose: () => void }) {
  const [confidence, setConfidence] = useState(Math.round(f.confidence * 100));
  const [reason, setReason] = useState("");
  const [withdraw, setWithdraw] = useState(false);
  return (
    <Modal title={`Revise ${f.marker}`} onClose={onClose}>
      <div className="stack">
        <div>{f.text}</div>
        <label className="check"><input type="checkbox" checked={withdraw} onChange={(e) => setWithdraw(e.target.checked)} /> Withdraw (shown to be wrong)</label>
        {!withdraw && (
          <label className="field">New confidence: {confidence}%
            <input type="range" min={0} max={100} value={confidence} onChange={(e) => setConfidence(Number(e.target.value))} />
          </label>
        )}
        <label className="field">Reason (what evidence changes it) *<textarea value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        <div className="muted small">History is kept. See also <Link to={`/inv/${inv}/review`}>Review</Link> for Claude's proposed revisions.</div>
        <div className="row" onClick={() => reason.trim() && setTimeout(onClose, 50)}>
          <JobButton action="revise" inv={inv} primary
            params={{ finding_id: markerId(f.marker), reason, withdraw, confidence: confidence / 100 }}>
            Save revision
          </JobButton>
        </div>
      </div>
    </Modal>
  );
}

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, type Artifact } from "../api";
import { Badge, Empty, ErrorBox, JobButton, Loading, Modal, fmtBytes, fmtTime } from "../components/ui";

const CAPTURE_LABEL: Record<string, string> = {
  raw: "raw", warc: "WARC", screenshot_png: "screenshot", pdf_render: "PDF", rendered_html: "DOM",
  media_original: "media", archive_org: "archive",
};

export function EvidenceTab({ inv }: { inv: number }) {
  const q = useQuery({ queryKey: ["inv", inv, "evidence"], queryFn: () => get<{ artifacts: Artifact[] }>(`/api/inv/${inv}/evidence`) });
  const [filter, setFilter] = useState("");
  const [platform, setPlatform] = useState("");
  const [shot, setShot] = useState<number | null>(null);
  const [purge, setPurge] = useState<Artifact | null>(null);
  const platforms = useMemo(() => [...new Set((q.data?.artifacts ?? []).map((a) => a.platform ?? "web"))].sort(), [q.data]);
  const rows = (q.data?.artifacts ?? []).filter((a) =>
    (!platform || (a.platform ?? "web") === platform) &&
    (!filter || `${a.url} ${a.platform_id ?? ""} ${a.sha256}`.toLowerCase().includes(filter.toLowerCase())));

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data?.artifacts.length) return <Empty>No evidence captured yet.</Empty>;
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <input style={{ maxWidth: 360 }} placeholder="Filter by URL, platform id or hash…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <select style={{ maxWidth: 180 }} value={platform} onChange={(e) => setPlatform(e.target.value)}>
          <option value="">all platforms</option>
          {platforms.map((p) => <option key={p}>{p}</option>)}
        </select>
        <span className="muted small">{rows.length} artifact(s). Captured pages are shown inert (no scripts).</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>#</th><th>source</th><th>captured</th><th>route</th><th>proof</th><th></th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.id}</td>
                <td style={{ maxWidth: 520 }}>
                  <div className="wrap-anywhere">
                    {a.url?.startsWith("http") ? <a href={a.url} target="_blank" rel="noreferrer noopener">{a.url}</a> : a.url}
                  </div>
                  <div className="row small muted">
                    {a.platform && <Badge>{a.platform}</Badge>}
                    {a.source && <Badge title={`Source ${a.source.locator}: reliability ${a.source.grade}`}>{a.source.grade} · {a.source.locator}</Badge>}
                    {a.mime && <span>{a.mime}</span>}
                    <span>{fmtBytes(a.size)}</span>
                    {a.status && a.status >= 400 && <Badge tone="bad">HTTP {a.status}</Badge>}
                    {a.blocked && <Badge tone="bad" title="the source refused us; kept as proof">blocked: {a.blocked}</Badge>}
                    {a.posted && <span>posted {fmtTime(a.posted)}</span>}
                  </div>
                  <div className="mono small muted" title="SHA-256">{a.sha256.slice(0, 24)}…</div>
                </td>
                <td className="small">{fmtTime(a.captured)}</td>
                <td>{a.route && <Badge tone={a.route.includes("vpn") ? "warn" : a.route.includes("proxy") ? "tor" : undefined}>{a.route}</Badge>}</td>
                <td className="small">
                  <div className="row" style={{ gap: 4 }}>
                    {a.document && <Link to={`/doc/${a.document}`}>text</Link>}
                    {a.captures.map((c) => c.kind === "screenshot_png"
                      ? <button key={c.id} className="linkish" onClick={() => setShot(c.id)}>screenshot</button>
                      : <a key={c.id} href={`/capture/${c.id}`} target="_blank" rel="noreferrer noopener">{CAPTURE_LABEL[c.kind] ?? c.kind}</a>)}
                  </div>
                </td>
                <td><button className="small ghost danger" title="Permanently delete this content (contamination procedure)" onClick={() => setPurge(a)}>purge</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {shot !== null && (
        <Modal title="Screenshot" onClose={() => setShot(null)}>
          <img src={`/capture/${shot}`} alt="capture screenshot" style={{ maxWidth: "100%" }} />
        </Modal>
      )}
      {purge && <PurgeDialog inv={inv} art={purge} onClose={() => setPurge(null)} />}
    </div>
  );
}

function PurgeDialog({ inv, art, onClose }: { inv: number; art: Artifact; onClose: () => void }) {
  const [reason, setReason] = useState("");
  return (
    <Modal title={`Purge artifact ${art.id}`} onClose={onClose}>
      <div className="stack">
        <div className="error small">This permanently deletes the stored files and blanks extracted text and quotes. The hashes are blocklisted so the content is refused if seen again. Use it for CSAM, malware or unlawful material.</div>
        <div className="small wrap-anywhere muted">{art.url}</div>
        <label className="field">Reason (recorded in the custody chain)<input value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        <div className="row">
          {reason.trim() ? (
            <span onClick={onClose}><JobButton action="purge" inv={inv} params={{ artifact_id: art.id, reason }}
              confirm="Permanently delete this content? This can't be undone.">Purge permanently</JobButton></span>
          ) : <button disabled>Purge permanently</button>}
          <button onClick={onClose}>Cancel</button>
        </div>
      </div>
    </Modal>
  );
}

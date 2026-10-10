import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get } from "../api";
import { Badge, Empty, ErrorBox, JobButton, Loading, fmtBytes, fmtTime } from "../components/ui";

interface Report { id: number; title: string; status: string; created: string; check: Record<string, unknown> | null }
interface FileRow { name: string; size: number; modified: string }

export function ReportsTab({ inv }: { inv: number }) {
  const reports = useQuery({ queryKey: ["inv", inv, "reports"], queryFn: () => get<Report[]>(`/api/inv/${inv}/reports`), refetchInterval: 10_000 });
  const files = useQuery({ queryKey: ["files"], queryFn: () => get<FileRow[]>("/api/files"), refetchInterval: 10_000 });
  const [view, setView] = useState<number | null>(null);
  const [formats, setFormats] = useState<string[]>(["stix"]);
  const [redact, setRedact] = useState(true);
  const mine = (files.data ?? []).filter((f) => f.name.includes(`inv${inv}-`));

  return (
    <div className="stack">
      <div className="grid grid-2">
        <div className="card">
          <div className="spread"><h3>Reports</h3><JobButton action="report" inv={inv} primary>Claude: write report</JobButton></div>
          <div className="muted small">Every claim must cite [E:n]/[F:n] markers; the citation gate checks markers, hashes and support before a report is final.</div>
          {reports.isLoading && <Loading />}
          <ErrorBox error={reports.error} />
          {reports.data?.length === 0 && <Empty>No reports yet.</Empty>}
          <table><tbody>
            {reports.data?.map((r) => (
              <tr key={r.id}>
                <td className="mono">#{r.id}</td>
                <td><button className="ghost" style={{ padding: 0, color: "var(--accent)" }} onClick={() => setView(r.id)}>{r.title}</button></td>
                <td><Badge tone={r.status === "final" ? "ok" : r.status === "failed" ? "bad" : "warn"}>{r.status}</Badge></td>
                <td className="small muted">{fmtTime(r.created)}</td>
                <td><a href={`/report/${r.id}`} target="_blank" rel="noreferrer">open</a></td>
              </tr>
            ))}
          </tbody></table>
        </div>
        <div className="card stack">
          <h3>Evidence bundle</h3>
          <div className="muted small">A zip with the cited captures, hashes, signatures, timestamp proofs, custody log and a standalone <code>verify.py</code> anyone can run.</div>
          <label className="check"><input type="checkbox" checked={redact} onChange={(e) => setRedact(e.target.checked)} /> Blur faces in screenshots (drops PDF/DOM captures)</label>
          <div className="row">
            <JobButton action="bundle" inv={inv} params={{ redact_faces: redact }}>Bundle all evidence</JobButton>
            {reports.data?.[0] && <JobButton action="bundle" inv={inv} params={{ redact_faces: redact, report_id: reports.data[0].id }}>Bundle for report #{reports.data[0].id}</JobButton>}
          </div>
          <h3 className="gap-top">Export</h3>
          <div className="row">
            {["stix", "ftm", "gexf"].map((f) => (
              <label key={f} className="check"><input type="checkbox" checked={formats.includes(f)}
                onChange={(e) => setFormats(e.target.checked ? [...formats, f] : formats.filter((x) => x !== f))} />
                {f === "stix" ? "STIX 2.1" : f === "ftm" ? "FollowTheMoney" : "GEXF (Gephi)"}</label>
            ))}
          </div>
          <div><JobButton action="export" inv={inv} params={{ formats }}>Export</JobButton></div>
        </div>
      </div>
      <div className="card">
        <h3>Files for this investigation</h3>
        {mine.length === 0 ? <div className="muted small">Bundles and exports appear here when their job finishes.</div> : (
          <table><tbody>
            {mine.map((f) => (
              <tr key={f.name}><td><a href={`/files/${encodeURIComponent(f.name)}`}>{f.name}</a></td><td className="small">{fmtBytes(f.size)}</td><td className="small muted">{fmtTime(f.modified)}</td></tr>
            ))}
          </tbody></table>
        )}
      </div>
      {view !== null && (
        <div className="card">
          <div className="spread"><h3>Report #{view}</h3><button className="small" onClick={() => setView(null)}>Close</button></div>
          <iframe title={`report ${view}`} src={`/report/${view}`} sandbox="" style={{ width: "100%", height: "75vh", border: "1px solid var(--border)", borderRadius: 6, background: "#fff" }} />
        </div>
      )}
    </div>
  );
}

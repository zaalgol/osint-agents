import { useQuery } from "@tanstack/react-query";
import { get, type Plugin } from "../api";
import { Badge, ErrorBox, JobButton, Loading, fmtBytes, fmtTime } from "../components/ui";

interface Check { component: string; ok: boolean; detail: string }
interface Tor { running: boolean; is_tor: boolean | null; exit_ip: string | null; bootstrapped: number; detail: string }
interface FileRow { name: string; size: number; modified: string }

export function SystemPage() {
  const doctor = useQuery({ queryKey: ["doctor"], queryFn: () => get<Check[]>("/api/system/doctor"), staleTime: 60_000 });
  const tor = useQuery({ queryKey: ["tor"], queryFn: () => get<Tor>("/api/system/tor"), refetchInterval: 15_000 });
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: () => get<Plugin[]>("/api/plugins") });
  const files = useQuery({ queryKey: ["files"], queryFn: () => get<FileRow[]>("/api/files") });

  return (
    <div className="page stack">
      <h1>System</h1>
      <div className="grid grid-2">
        <div className="card">
          <div className="spread"><h3>Health</h3><button className="small" onClick={() => doctor.refetch()} disabled={doctor.isFetching}>{doctor.isFetching ? "Checking…" : "Re-check"}</button></div>
          {doctor.isLoading && <Loading what="Checking components" />}
          <ErrorBox error={doctor.error} />
          <table><tbody>
            {doctor.data?.map((c) => (
              <tr key={c.component}><td><strong>{c.component}</strong></td><td>{c.ok ? <Badge tone="ok">ok</Badge> : <Badge tone="bad">FAIL</Badge>}</td><td className="small wrap-anywhere">{c.detail}</td></tr>
            ))}
          </tbody></table>
        </div>
        <div className="stack">
          <div className="card">
            <h3>Tor (anonymous investigations)</h3>
            {tor.data && (
              <div className="row">
                {tor.data.running ? <Badge tone={tor.data.is_tor ? "tor" : "bad"}>{tor.data.is_tor ? "running · exits via Tor" : "running · NOT via Tor"}</Badge> : <Badge>not running</Badge>}
                {tor.data.exit_ip && <span className="mono small">exit {tor.data.exit_ip}</span>}
              </div>
            )}
            <div className="row gap-top">
              <JobButton action="tor_start">Start Tor</JobButton>
              <JobButton action="tor_stop">Stop Tor</JobButton>
            </div>
          </div>
          <div className="card">
            <h3>Evidence and maintenance</h3>
            <div className="row">
              <JobButton action="verify" title="Re-hash all evidence; check custody chain and manifests">Verify evidence</JobButton>
              <JobButton action="seal" title="Merkle manifest + signature + trusted timestamps">Seal now</JobButton>
              <JobButton action="snapshot">Snapshot (backup)</JobButton>
              <JobButton action="graph_sync">Rebuild graph</JobButton>
              <JobButton action="daemon_once" title="Run schedules that are due">Run due schedules</JobButton>
            </div>
          </div>
        </div>
      </div>
      <div className="card">
        <h3>Plugins</h3>
        <table>
          <thead><tr><th>kind</th><th>name</th><th>version</th><th>description</th></tr></thead>
          <tbody>
            {plugins.data?.map((p) => (
              <tr key={`${p.kind}-${p.name}`}><td>{p.kind}</td><td><strong>{p.name}</strong> {p.requires_account && <Badge tone="warn">needs account: disabled</Badge>}</td><td className="mono small">{p.version}</td><td className="small">{p.description}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>Exports and bundles</h3>
        {files.data?.length === 0 && <div className="muted small">None yet.</div>}
        <table><tbody>
          {files.data?.map((f) => (
            <tr key={f.name}><td><a href={`/files/${encodeURIComponent(f.name)}`}>{f.name}</a></td><td className="small">{fmtBytes(f.size)}</td><td className="small muted">{fmtTime(f.modified)}</td></tr>
          ))}
        </tbody></table>
      </div>
    </div>
  );
}

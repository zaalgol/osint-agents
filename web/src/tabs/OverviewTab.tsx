import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, post, type InvestigationStatus, type Job } from "../api";
import { Badge, ErrorBox, JobButton, JobStatus, Stat, fmtTime, useToast } from "../components/ui";

const STATUSES = ["pending", "running", "done", "failed", "blocked"];

interface Overview { top_entities: { entity_id: number; name: string; type: string; links: number }[] }

export function OverviewTab({ inv, status }: { inv: number; status: InvestigationStatus }) {
  const k = status.knowledge;
  const jobs = useQuery({ queryKey: ["jobs", inv], queryFn: () => get<Job[]>(`/api/jobs?inv=${inv}`), refetchInterval: 4_000 });
  const overview = useQuery({ queryKey: ["inv", inv, "overview"], queryFn: () => get<Overview>(`/api/inv/${inv}/overview`) });
  const runningQueue = jobs.data?.some((j) => j.status === "running" && j.queue_worker);
  const pending = Object.values(status.tasks).reduce((n, t) => n + (t.pending ?? 0) + (t.running ?? 0), 0);

  return (
    <div className="grid grid-2">
      <div className="card">
        <h3>Knowledge</h3>
        <div className="stats">
          <Stat n={k.artifact ?? 0} label="artifacts" to={`/inv/${inv}/evidence`} />
          <Stat n={k.document ?? 0} label="documents" to={`/inv/${inv}/evidence`} />
          <Stat n={k.entity ?? 0} label="entities" to={`/inv/${inv}/entities`} />
          <Stat n={k.relation ?? 0} label="relations" to={`/inv/${inv}/graph`} />
          <Stat n={k.event ?? 0} label="events" to={`/inv/${inv}/timeline`} />
          <Stat n={k.review_open ?? 0} label="to review" to={`/inv/${inv}/review`} />
        </div>
        <h3 className="gap-top">Most connected</h3>
        <div className="chips">
          {overview.data?.top_entities?.slice(0, 12).map((e) => (
            <Link key={e.entity_id} className="chip" style={{ paddingRight: 9 }} to={`/entity/${e.entity_id}?inv=${inv}`}>{e.name}</Link>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="spread"><h3>Collection queue</h3>
          {runningQueue ? <Badge tone="accent">processing</Badge> : pending > 0 ? <Badge tone="warn">{pending} waiting: press Run</Badge> : <Badge tone="ok">idle</Badge>}
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>task</th>{STATUSES.map((s) => <th key={s} className="right">{s}</th>)}</tr></thead>
            <tbody>
              {Object.entries(status.tasks).map(([type, c]) => (
                <tr key={type}><td>{type}</td>{STATUSES.map((s) => <td key={s} className="right">{c[s] ?? ""}</td>)}</tr>
              ))}
              {Object.keys(status.tasks).length === 0 && <tr><td colSpan={6} className="muted">No tasks yet: queue collection in the Collect tab.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="row gap-top">
          <JobButton action="run" inv={inv} primary>▶ Run</JobButton>
          <JobButton action="resume" inv={inv} params={{ retry_failed: true }}>Retry failed</JobButton>
          <JobButton action="refresh" inv={inv} params={{ since: "week" }} title="Re-run searches and feeds for new material">Refresh sources</JobButton>
          <JobButton action="enrich" inv={inv} title="Sanctions, RDAP, geocoding, BTC">Enrich</JobButton>
          <JobButton action="reextract" inv={inv} params={{ role: "agent_heavy" }} title="Re-extract with the accurate 27B model (slow)">Re-extract (accurate)</JobButton>
        </div>
      </div>

      <div className="card">
        <h3>Claude analysis</h3>
        <div className="muted small">Runs on your Claude subscription. Claude only sees extracted records and short quotes.</div>
        <div className="row gap-top">
          <JobButton action="plan" inv={inv} params={{ run: true }}>Plan collection</JobButton>
          <JobButton action="analyze" inv={inv} primary>Analyze</JobButton>
          <JobButton action="assess" inv={inv}>Threat assessment</JobButton>
          <JobButton action="red_team" inv={inv}>Red team</JobButton>
          <JobButton action="link" inv={inv} title="Confirm or reject cross-investigation links">Confirm links</JobButton>
          <JobButton action="report" inv={inv}>Write report</JobButton>
        </div>
        <div className="row gap-top">
          <JobButton action="corroborate" inv={inv}>Corroborate</JobButton>
          <JobButton action="er" inv={inv}>Entity resolution</JobButton>
        </div>
      </div>

      <NetworkAndSchedule inv={inv} status={status} />

      <div className="card">
        <h3>Recent jobs</h3>
        {jobs.data?.length === 0 && <div className="muted">None yet.</div>}
        <table><tbody>
          {jobs.data?.slice(0, 8).map((j) => (
            <tr key={j.id}><td><Link to={`/jobs/${j.id}`}>#{j.id}</Link></td><td>{j.label}</td><td><JobStatus status={j.status} /></td><td className="muted small">{fmtTime(j.started_at)}</td></tr>
          ))}
        </tbody></table>
      </div>

      {status.failed.length > 0 && (
        <div className="card">
          <h3>Failed tasks</h3>
          <table><tbody>
            {status.failed.map((t) => (
              <tr key={t.id}><td className="mono">#{t.id}</td><td>{t.type}:{t.plugin}</td><td className="small wrap-anywhere">{t.error}</td></tr>
            ))}
          </tbody></table>
        </div>
      )}

      <div className="card">
        <h3>Seed</h3>
        <dl className="small" style={{ margin: 0 }}>
          {(["queries", "urls", "feeds"] as const).map((key) => (status.seed[key]?.length ?? 0) > 0 && (
            <div key={key}><dt className="muted">{key}</dt><dd className="wrap-anywhere" style={{ margin: "0 0 6px" }}>{status.seed[key]!.join(" · ")}</dd></div>
          ))}
          <dt className="muted">created</dt><dd style={{ margin: 0 }}>{fmtTime(status.created)}</dd>
        </dl>
      </div>
    </div>
  );
}

function NetworkAndSchedule({ inv, status }: { inv: number; status: InvestigationStatus }) {
  const qc = useQueryClient();
  const toast = useToast();
  const sch = status.schedule;
  const [every, setEvery] = useState(sch ? `${sch.every_minutes % 1440 === 0 ? sch.every_minutes / 1440 + "d" : sch.every_minutes % 60 === 0 ? sch.every_minutes / 60 + "h" : sch.every_minutes + "m"}` : "6h");
  const [since, setSince] = useState(sch?.time_range ?? "week");
  const [analyze, setAnalyze] = useState(sch?.analyze ?? false);
  const [role, setRole] = useState(sch?.extract_role ?? "");
  const refresh = () => qc.invalidateQueries({ queryKey: ["inv", inv] });

  const profile = useMutation({
    mutationFn: (p: string) => post(`/api/inv/${inv}/network`, { profile: p }),
    onSuccess: () => { refresh(); toast("Network profile changed"); },
    onError: (e: Error) => toast(e.message, true),
  });
  const schedule = useMutation({
    mutationFn: (enabled: boolean) => post<{ next_run_at: string }>(`/api/inv/${inv}/schedule`,
      { every, since, analyze, extract_role: role || null, enabled }),
    onSuccess: (r) => { refresh(); toast(`Schedule saved; next run ${fmtTime(r.next_run_at)}`); },
    onError: (e: Error) => toast(e.message, true),
  });

  return (
    <div className="card">
      <h3>Network profile</h3>
      <div className="row">
        <label className="check"><input type="radio" checked={status.profile === "standard"} onChange={() => profile.mutate("standard")} />
          Standard <span className="muted small">(direct, then VPN when blocked, then browser)</span></label>
      </div>
      <div className="row">
        <label className="check"><input type="radio" checked={status.profile === "anonymous"}
          onChange={() => window.confirm("Route all of this investigation's collection through Tor? Runs refuse to start if Tor isn't working.") && profile.mutate("anonymous")} />
          Anonymous <span className="muted small">(Tor only, fails closed)</span></label>
      </div>
      <h3 className="gap-top">Schedule</h3>
      {sch ? (
        <div className="small muted">
          {sch.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>} next {fmtTime(sch.next_run_at)} · last {fmtTime(sch.last_run_at)}
        </div>
      ) : <div className="small muted">No schedule. Scheduled refreshes are run by <code>osint daemon</code> (or System → Run due schedules).</div>}
      <div className="grid gap-top" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <label className="field">Every<input value={every} onChange={(e) => setEvery(e.target.value)} placeholder="30m, 6h, 1d" /></label>
        <label className="field">Search window
          <select value={since} onChange={(e) => setSince(e.target.value)}>
            <option>day</option><option>week</option><option>month</option><option>year</option>
          </select>
        </label>
        <label className="field">Extraction model
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">default (fast)</option><option value="agent_heavy">accurate (27B)</option>
          </select>
        </label>
        <label className="check" style={{ alignSelf: "end" }}><input type="checkbox" checked={analyze} onChange={(e) => setAnalyze(e.target.checked)} /> Claude analysis when new data</label>
      </div>
      <div className="row gap-top">
        <button className="primary" onClick={() => schedule.mutate(true)} disabled={schedule.isPending}>Save schedule</button>
        {sch?.enabled && <button onClick={() => schedule.mutate(false)}>Disable</button>}
      </div>
      <ErrorBox error={schedule.error} />
    </div>
  );
}

import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { get, post, type Job } from "../api";
import { Empty, ErrorBox, JobStatus, Loading, fmtTime, useToast } from "../components/ui";

export function JobsPage() {
  const q = useQuery({ queryKey: ["jobs"], queryFn: () => get<Job[]>("/api/jobs"), refetchInterval: 3_000 });
  return (
    <div className="page">
      <h1>Jobs</h1>
      <div className="muted">Long operations run in the background as <code>osint</code> commands; their output is kept.</div>
      <div className="card gap-top table-wrap">
        {q.isLoading && <Loading />}
        <ErrorBox error={q.error} />
        {q.data?.length === 0 && <Empty>No jobs yet.</Empty>}
        <table>
          <thead><tr><th>#</th><th>job</th><th>investigation</th><th>status</th><th>started</th><th>finished</th></tr></thead>
          <tbody>
            {q.data?.map((j) => (
              <tr key={j.id}>
                <td><Link to={`/jobs/${j.id}`}>#{j.id}</Link></td>
                <td><Link to={`/jobs/${j.id}`}>{j.label}</Link></td>
                <td>{j.investigation_id ? <Link to={`/inv/${j.investigation_id}`}>#{j.investigation_id}</Link> : "—"}</td>
                <td><JobStatus status={j.status} /></td>
                <td className="small">{fmtTime(j.started_at)}</td>
                <td className="small">{fmtTime(j.finished_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function JobPage() {
  const { id } = useParams();
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: ["job", Number(id)],
    queryFn: () => get<Job>(`/api/jobs/${id}`),
    refetchInterval: (s) => (s.state.data?.status === "running" ? 1500 : false),
  });
  const cancel = useMutation({
    mutationFn: () => post(`/api/jobs/${id}/cancel`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["job", Number(id)] }); toast("Cancelling: tasks go back to the queue"); },
    onError: (e: Error) => toast(e.message, true),
  });
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = logRef.current;
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 120) el.scrollTop = el.scrollHeight;
  }, [q.data?.log]);
  const j = q.data;
  return (
    <div className="page">
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      {j && (
        <div className="stack">
          <div className="spread">
            <div>
              <div className="row"><h1>#{j.id} {j.label}</h1><JobStatus status={j.status} /></div>
              <div className="muted small">
                started {fmtTime(j.started_at)}{j.finished_at && ` · finished ${fmtTime(j.finished_at)}`}{j.exit_code !== null && ` · exit ${j.exit_code}`}
                {j.investigation_id && <> · <Link to={`/inv/${j.investigation_id}`}>investigation #{j.investigation_id}</Link></>}
              </div>
            </div>
            {j.status === "running" && <button className="danger" onClick={() => cancel.mutate()} disabled={cancel.isPending}>Cancel (pause)</button>}
          </div>
          {j.status === "lost" && (
            <div className="card muted small">
              The GUI was restarted (or stopped) while this job ran, so it can no longer follow it. The log below ends where
              the GUI stopped watching. Everything it finished is saved; unfinished tasks go back to the queue.
              {j.investigation_id && <> Check the investigation's <Link to={`/inv/${j.investigation_id}`}>Overview</Link>, and press Run there to continue if nothing else is processing it.</>}
            </div>
          )}
          <div ref={logRef} className="log">{j.log || "(no output yet)"}</div>
        </div>
      )}
    </div>
  );
}

import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, type Job } from "../api";
import { Badge, ErrorBox, Spinner, fmtTime, useStartJob } from "../components/ui";

interface ClaudeJob {
  id: number; job: string; model: string; status: string; turns: number | null;
  input_tokens: number | null; output_tokens: number | null; duration_ms: number | null;
  created: string; finished: string | null; error: string | null; text: string | null;
}

// Strips the trailing JSON summary block that jobs end with.
const answerText = (t: string) => { const cut = t.lastIndexOf("```json"); return cut > 0 ? t.slice(0, cut).trim() : t; };

export function AskTab({ inv }: { inv: number }) {
  const [question, setQuestion] = useState("");
  const [jobId, setJobId] = useState<number | null>(null);
  const start = useStartJob();
  const job = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => get<Job>(`/api/jobs/${jobId}`),
    enabled: jobId !== null,
    refetchInterval: (q) => (q.state.data?.status === "running" ? 2000 : false),
  });
  const history = useQuery({
    queryKey: ["inv", inv, "claude-jobs", job.data?.status],
    queryFn: () => get<ClaudeJob[]>(`/api/inv/${inv}/claude-jobs`),
  });
  const [open, setOpen] = useState<number | null>(null);

  return (
    <div className="stack">
      <div className="card stack">
        <h3>Ask about this investigation</h3>
        <div className="muted small">Claude answers read-only from the knowledge base (all investigations), citing evidence markers.</div>
        <textarea value={question} onChange={(e) => setQuestion(e.target.value)}
          placeholder="Which channels claimed the October attacks, and do other sources corroborate them?" />
        <div className="row">
          <button className="primary" disabled={!question.trim() || start.isPending || job.data?.status === "running"}
            onClick={() => start.mutate({ action: "ask", investigation_id: inv, params: { question } }, { onSuccess: (j) => setJobId(j.id) })}>
            {(start.isPending || job.data?.status === "running") && <Spinner />} Ask Claude
          </button>
          {jobId && <Link to={`/jobs/${jobId}`} className="small">job {jobId}</Link>}
        </div>
        {job.data?.status === "running" && <div className="muted small">Claude is working; this usually takes 30 s to a few minutes.</div>}
        {job.data && job.data.status !== "running" && (
          job.data.status === "done"
            ? <div className="quote" style={{ borderLeftColor: "var(--ok)" }}>{answerText(job.data.log?.split("\n").slice(1).join("\n") ?? "")}</div>
            : <ErrorBox error={`The job ${job.data.status}. See the log.`} />
        )}
      </div>
      <div className="card">
        <h3>Claude job history</h3>
        <table>
          <thead><tr><th>#</th><th>job</th><th>model</th><th>status</th><th>tokens in/out</th><th>when</th><th></th></tr></thead>
          <tbody>
            {history.data?.map((j) => (
              <Fragment key={j.id}>
                <tr>
                  <td className="mono">{j.id}</td><td>{j.job}</td><td>{j.model}</td>
                  <td><Badge tone={j.status === "done" ? "ok" : j.status === "running" ? "accent" : "bad"}>{j.status}</Badge></td>
                  <td className="small">{j.input_tokens ?? "—"} / {j.output_tokens ?? "—"}</td>
                  <td className="small">{fmtTime(j.created)}</td>
                  <td>{(j.text || j.error) && <button className="small ghost" onClick={() => setOpen(open === j.id ? null : j.id)}>{open === j.id ? "hide" : "show"}</button>}</td>
                </tr>
                {open === j.id && (
                  <tr key={`${j.id}-text`}><td colSpan={7}>
                    {j.error && <div className="error small">{j.error}</div>}
                    {j.text && <div className="doc-text small">{answerText(j.text)}</div>}
                  </td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

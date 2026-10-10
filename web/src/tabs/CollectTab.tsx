import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post, upload, type Plugin } from "../api";
import { SchemaForm, defaults } from "../components/SchemaForm";
import { ErrorBox, Loading, Spinner, useToast } from "../components/ui";

const HIDDEN = new Set(["echo"]);   // test plugin

export function CollectTab({ inv }: { inv: number }) {
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: () => get<Plugin[]>("/api/plugins") });
  const collectors = (plugins.data ?? []).filter((p) => p.kind === "collector" && !HIDDEN.has(p.name));
  const [name, setName] = useState<string>("");
  const current = collectors.find((c) => c.name === name) ?? collectors[0];
  const [params, setParams] = useState<Record<string, unknown>>({});
  const [runNow, setRunNow] = useState(true);
  const qc = useQueryClient();
  const toast = useToast();

  useEffect(() => { if (current?.schema) setParams(defaults(current.schema)); }, [current?.name]); // eslint-disable-line react-hooks/exhaustive-deps

  const queue = useMutation({
    mutationFn: () => post<{ task: number; created: boolean; job?: number; job_error?: string }>(
      `/api/inv/${inv}/collect`, { plugin: current!.name, params, run: runNow }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["inv", inv] });
      toast(`Task ${r.task} ${r.created ? "queued" : "was already queued"}` + (r.job ? `; job ${r.job} running` : ""));
      if (r.job_error) toast(r.job_error, true);
    },
  });

  if (plugins.isLoading) return <Loading />;
  return (
    <div className="grid grid-2">
      <div className="card">
        <h3>Queue a collector</h3>
        <div className="muted small">Public sources only; account-based collectors are refused. Each collector's form comes from its parameter schema.</div>
        <div className="row gap-top" style={{ gap: 6 }}>
          {collectors.map((c) => (
            <button key={c.name} className={`small ${c.name === current?.name ? "primary" : ""}`} onClick={() => setName(c.name)}>{c.name}</button>
          ))}
        </div>
        {current && (
          <div className="gap-top stack">
            <div className="small muted">{current.description} <span className="mono">v{current.version}</span></div>
            {current.schema && <SchemaForm schema={current.schema} value={params} onChange={setParams} />}
            <label className="check"><input type="checkbox" checked={runNow} onChange={(e) => setRunNow(e.target.checked)} /> Run the queue right away</label>
            <ErrorBox error={queue.error} />
            <div><button className="primary" disabled={queue.isPending} onClick={() => queue.mutate()}>{queue.isPending && <Spinner />} Queue {current.name}</button></div>
          </div>
        )}
      </div>
      <div className="stack">
        <UploadCard inv={inv} />
        <div className="card small">
          <h3>Tips</h3>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            <li><strong>telegram_public</strong>: public channels via the t.me/s web preview; photos are captured and OCRed.</li>
            <li><strong>paste</strong>: paste URLs, or queries searched on paste sites through SearXNG.</li>
            <li><strong>wayback</strong>: deleted pages from the Internet Archive.</li>
            <li><strong>youtube</strong>: captions, or Whisper transcription when there are none.</li>
            <li>Enrichers (sanctions, RDAP, geocoding, BTC) run from Overview → Enrich.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function UploadCard({ inv }: { inv: number }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [url, setUrl] = useState("");
  const [note, setNote] = useState("");
  const toast = useToast();
  const qc = useQueryClient();
  const send = useMutation({
    mutationFn: async () => {
      const files = Array.from(fileRef.current?.files ?? []);
      if (!files.length) throw new Error("choose a file");
      const out = [];
      for (const f of files) {
        const form = new FormData();
        form.append("file", f);
        if (url) form.append("url", url);
        if (note) form.append("note", note);
        out.push(await upload<{ artifact: number; created: boolean; parse_queued: boolean }>(`/api/inv/${inv}/upload`, form));
      }
      return out;
    },
    onSuccess: (rs) => {
      qc.invalidateQueries({ queryKey: ["inv", inv] });
      toast(`${rs.length} file(s) stored as evidence` + (rs.some((r) => r.parse_queued) ? "; parsing queued (press Run)" : ""));
      if (fileRef.current) fileRef.current.value = "";
    },
  });
  return (
    <div className="card stack">
      <h3>Add your own evidence</h3>
      <div className="muted small">Files are hashed, stored write-once and logged in the custody chain. Images and scanned PDFs get EXIF + OCR.</div>
      <input type="file" multiple ref={fileRef} />
      <label className="field">Where it came from (URL, optional)<input value={url} onChange={(e) => setUrl(e.target.value)} /></label>
      <label className="field">Note (optional)<input value={note} onChange={(e) => setNote(e.target.value)} /></label>
      <ErrorBox error={send.error} />
      <div><button className="primary" onClick={() => send.mutate()} disabled={send.isPending}>{send.isPending && <Spinner />} Upload</button></div>
    </div>
  );
}

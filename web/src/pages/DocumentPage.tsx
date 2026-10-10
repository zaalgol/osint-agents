import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { get } from "../api";
import { Badge, ErrorBox, Loading } from "../components/ui";

interface Doc {
  id: number; title: string | null; lang: string | null; text: string; translated_text: string | null;
  extractor: string; meta: { ocr?: { machine_read: boolean; model: string; caution: string }; exif?: Record<string, unknown> };
  artifact: { id: number; url: string; sha256: string };
}

export function DocumentPage() {
  const { id } = useParams();
  const q = useQuery({ queryKey: ["doc", id], queryFn: () => get<Doc>(`/api/document/${id}`) });
  const [find, setFind] = useState("");
  const [translated, setTranslated] = useState(false);
  const d = q.data;
  const text = translated && d?.translated_text ? d.translated_text : d?.text ?? "";
  const parts = find.trim().length >= 2 ? text.split(new RegExp(`(${find.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi")) : [text];

  return (
    <div className="page">
      {q.isLoading && <Loading />}
      <ErrorBox error={q.error} />
      {d && (
        <div className="stack">
          <div>
            <h1>{d.title ?? `Document ${d.id}`}</h1>
            <div className="row small muted">
              {d.artifact.url.startsWith("http") ? <a href={d.artifact.url} target="_blank" rel="noreferrer noopener" className="wrap-anywhere">{d.artifact.url}</a> : <span>{d.artifact.url}</span>}
              {d.lang && <Badge>{d.lang}</Badge>}
              <span className="mono">{d.extractor}</span>
              <span className="mono">sha256 {d.artifact.sha256.slice(0, 16)}…</span>
            </div>
          </div>
          {d.meta.ocr && <div className="notice small">Machine-read text ({d.meta.ocr.model}): {d.meta.ocr.caution}.</div>}
          {d.meta.exif && Object.keys(d.meta.exif).length > 2 && (
            <div className="card small"><h3>EXIF</h3><pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(d.meta.exif, null, 1)}</pre></div>
          )}
          <div className="row">
            <input style={{ maxWidth: 300 }} placeholder="Find in text…" value={find} onChange={(e) => setFind(e.target.value)} />
            {d.translated_text && <label className="check"><input type="checkbox" checked={translated} onChange={(e) => setTranslated(e.target.checked)} /> show English translation</label>}
          </div>
          <div className="card doc-text" dir="auto">
            {parts.map((p, i) => i % 2 === 1 ? <mark key={i}>{p}</mark> : <span key={i}>{p}</span>)}
          </div>
        </div>
      )}
    </div>
  );
}

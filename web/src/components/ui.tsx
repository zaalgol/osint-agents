import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { post, type EvidenceItem, type Job } from "../api";

// ---------------------------------------------------------------- toasts

interface Toast { id: number; text: ReactNode; bad?: boolean }
const ToastCtx = createContext<(text: ReactNode, bad?: boolean) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: ReactNode, bad = false) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, bad }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), bad ? 9000 : 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.bad ? "bad" : ""}`}>{t.text}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

// ---------------------------------------------------------------- small pieces

export function Spinner() {
  return <span className="spinner" aria-label="loading" />;
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <div className="empty"><Spinner /> {what}…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="error">{error instanceof Error ? error.message : String(error)}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Badge({ children, tone, title }: { children: ReactNode; tone?: "ok" | "warn" | "bad" | "tor" | "accent"; title?: string }) {
  return <span className={`badge ${tone ?? ""}`} title={title}>{children}</span>;
}

export function Stat({ n, label, to }: { n: ReactNode; label: string; to?: string }) {
  const body = <><span className="n">{n}</span><span className="l">{label}</span></>;
  return to ? <Link className="stat" to={to}>{body}</Link> : <div className="stat">{body}</div>;
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id}
          className={`tab ${value === t.id ? "active" : ""}`} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [onClose]);
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true">
        <div className="spread" style={{ marginBottom: 12 }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <button className="ghost" onClick={onClose} aria-label="close">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export const fmtTime = (iso?: string | null) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";

export const fmtBytes = (n: number) =>
  n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;

export const TYPE_COLORS: Record<string, string> = {
  person: "#2f6fde", organization: "#1d8a4c", armed_group: "#c6363c", location: "#b7791f",
  online_account: "#7b4bd8", channel: "#9b59b6", domain: "#0e9aa7", url: "#0e9aa7",
  email: "#d35400", phone: "#d35400", crypto_wallet: "#e67e22", vehicle: "#7f8c8d",
  weapon: "#8e44ad", document: "#95a5a6", media_file: "#95a5a6", ip_address: "#16a085",
};
export const typeColor = (t: string) => TYPE_COLORS[t] ?? "#6c7a89";

export function TypeChip({ type }: { type: string }) {
  return (
    <span className="badge" style={{ color: typeColor(type), borderColor: typeColor(type) + "66" }}>
      {type.replace(/_/g, " ")}
    </span>
  );
}

const RELIABILITY: Record<string, string> = {
  A: "completely reliable", B: "usually reliable", C: "fairly reliable",
  D: "not usually reliable", E: "unreliable", F: "reliability cannot be judged",
};
const CREDIBILITY: Record<string, string> = {
  "1": "confirmed by other sources", "2": "probably true", "3": "possibly true",
  "4": "doubtful", "5": "improbable", "6": "truth cannot be judged",
};

export function Admiralty({ code }: { code?: string }) {
  if (!code) return null;
  const [r, c] = [code[0], code.slice(1)];
  const tone = c === "4" || c === "5" || r === "E" || r === "D" ? "bad" : r <= "B" && c === "1" ? "ok" : undefined;
  return (
    <Badge tone={tone} title={`Source: ${RELIABILITY[r] ?? r}. Information: ${CREDIBILITY[c] ?? (c || "—")}.`}>
      {code}
    </Badge>
  );
}

export function EvidenceQuote({ ev }: { ev: EvidenceItem }) {
  if (ev.error) return <div className="error small">{ev.marker}: {ev.error}</div>;
  return (
    <div>
      <div className={`quote ${ev.machine_read ? "machine" : ""}`}>“{ev.quote}”</div>
      {ev.quote_translated && <div className="small muted">EN: {ev.quote_translated}</div>}
      <div className="row small muted">
        <span className="mono">{ev.marker}</span>
        <Admiralty code={ev.admiralty} />
        {ev.machine_read && <Badge tone="warn" title="OCR or speech-to-text: wording may be misread">machine-read</Badge>}
        {ev.verified === false && <Badge tone="warn">unverified quote</Badge>}
        {ev.url && <a href={ev.url} target="_blank" rel="noreferrer noopener" className="wrap-anywhere">{ev.title || ev.url}</a>}
        {ev.posted_at && <span>posted {fmtTime(ev.posted_at)}</span>}
        <span>captured {fmtTime(ev.captured_at)}</span>
        {ev.document_id && <Link to={`/doc/${ev.document_id}`}>document</Link>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- jobs

export function useStartJob() {
  const qc = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: (v: { action: string; investigation_id?: number | null; params?: Record<string, unknown> }) =>
      post<Job>("/api/jobs", v),
    onSuccess: (job) => {
      qc.invalidateQueries({ queryKey: ["jobs"] });
      toast(<span>Started <Link to={`/jobs/${job.id}`}>job {job.id}</Link>: {job.label}</span>);
    },
    onError: (e: Error) => toast(e.message, true),
  });
}

export function JobButton({ action, inv, params, children, primary, confirm, title }: {
  action: string; inv?: number | null; params?: Record<string, unknown>; children: ReactNode;
  primary?: boolean; confirm?: string; title?: string;
}) {
  const start = useStartJob();
  return (
    <button className={primary ? "primary" : ""} disabled={start.isPending} title={title}
      onClick={() => {
        if (confirm && !window.confirm(confirm)) return;
        start.mutate({ action, investigation_id: inv ?? null, params });
      }}>
      {start.isPending && <Spinner />} {children}
    </button>
  );
}

export function JobStatus({ status }: { status: Job["status"] }) {
  const tone = status === "done" ? "ok" : status === "failed" || status === "lost" ? "bad"
    : status === "cancelled" ? "warn" : "accent";
  return <Badge tone={tone}>{status === "running" && <Spinner />}{status}</Badge>;
}

// ---------------------------------------------------------------- list input

export function ListInput({ value, onChange, placeholder }: {
  value: string[]; onChange: (v: string[]) => void; placeholder?: string;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const parts = draft.split("\n").map((s) => s.trim()).filter(Boolean);
    if (parts.length) onChange([...value, ...parts.filter((p) => !value.includes(p))]);
    setDraft("");
  };
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="row" style={{ flexWrap: "nowrap" }}>
        <input value={draft} placeholder={placeholder} onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
          onPaste={(e) => {
            const t = e.clipboardData.getData("text");
            if (t.includes("\n")) { e.preventDefault(); setDraft(t); setTimeout(add, 0); }
          }} />
        <button type="button" onClick={add}>Add</button>
      </div>
      {value.length > 0 && (
        <div className="chips">
          {value.map((v) => (
            <span key={v} className="chip">
              <span className="wrap-anywhere">{v}</span>
              <button type="button" aria-label={`remove ${v}`} onClick={() => onChange(value.filter((x) => x !== v))}>✕</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

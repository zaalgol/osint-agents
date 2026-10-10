import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { post } from "../api";
import { ErrorBox, ListInput, Spinner, useToast } from "../components/ui";

interface Created { id: number; tasks: number; job?: number | null; job_error?: string }

export function NewInvestigation() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const [f, setF] = useState({
    name: "", focus: "", lang: "", time_range: "", max_results: 10, max_fetches: 200,
    anonymous: false, plan: true, run: true,
  });
  const [queries, setQueries] = useState<string[]>([]);
  const [urls, setUrls] = useState<string[]>([]);
  const [feeds, setFeeds] = useState<string[]>([]);
  const create = useMutation({
    mutationFn: () => post<Created>("/api/investigations", { ...f, queries, urls, feeds }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["investigations"] });
      if (r.job_error) toast(r.job_error, true);
      else if (r.job) toast(`Investigation created; job ${r.job} started`);
      nav(`/inv/${r.id}`);
    },
  });
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF({ ...f, [k]: v });
  const nothing = !f.plan && queries.length + urls.length + feeds.length === 0;

  return (
    <div className="page" style={{ maxWidth: 900 }}>
      <h1>New investigation</h1>
      <div className="muted">Describe the goal. Claude can plan multilingual searches, or you can give queries, URLs and feeds yourself, or both.</div>
      <form className="card gap-top stack" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        <label className="field">Name *
          <input required value={f.name} placeholder="e.g. redsea-2026" onChange={(e) => set("name", e.target.value)} />
        </label>
        <label className="field">Focus
          <span className="hint">What this investigation is about: actors, region, period, key questions.</span>
          <textarea value={f.focus} placeholder="Houthi attacks on Red Sea shipping since 2025: actors, targets, claims, funding"
            onChange={(e) => set("focus", e.target.value)} />
        </label>
        <label className="check"><input type="checkbox" checked={f.plan} onChange={(e) => set("plan", e.target.checked)} />
          <span>Let Claude plan the collection <span className="muted small">(key questions + multilingual queries and sources; needs a focus)</span></span>
        </label>
        <div className="grid grid-2">
          <label className="field">Search queries <ListInput value={queries} onChange={setQueries} placeholder="Houthi ship attack" /></label>
          <label className="field">URLs to capture <ListInput value={urls} onChange={setUrls} placeholder="https://…" /></label>
          <label className="field">RSS/Atom feeds <ListInput value={feeds} onChange={setFeeds} placeholder="https://…/feed.xml" /></label>
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", alignContent: "start" }}>
            <label className="field">Search language
              <input value={f.lang} placeholder="en, ar, ru…" onChange={(e) => set("lang", e.target.value)} />
            </label>
            <label className="field">Time range
              <select value={f.time_range} onChange={(e) => set("time_range", e.target.value)}>
                <option value="">any</option><option>day</option><option>week</option><option>month</option><option>year</option>
              </select>
            </label>
            <label className="field">Results per query
              <input type="number" min={1} max={100} value={f.max_results} onChange={(e) => set("max_results", Number(e.target.value))} />
            </label>
            <label className="field">Fetch cap
              <input type="number" min={1} value={f.max_fetches} onChange={(e) => set("max_fetches", Number(e.target.value))} />
            </label>
          </div>
        </div>
        <label className="check"><input type="checkbox" checked={f.anonymous} onChange={(e) => set("anonymous", e.target.checked)} />
          <span><strong>Anonymous</strong>: all collection through Tor, never a direct connection <span className="muted small">(fails closed if Tor isn't running)</span></span>
        </label>
        <label className="check"><input type="checkbox" checked={f.run} onChange={(e) => set("run", e.target.checked)} />
          <span>Start collecting right away</span>
        </label>
        <ErrorBox error={create.error} />
        {nothing && <div className="notice small">Add at least one query, URL or feed, or let Claude plan.</div>}
        <div className="row">
          <button className="primary" type="submit" disabled={create.isPending || !f.name.trim() || nothing || (f.plan && !f.focus.trim())}>
            {create.isPending && <Spinner />} Create investigation
          </button>
        </div>
      </form>
    </div>
  );
}

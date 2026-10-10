import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post, type Source } from "../api";
import { ErrorBox, Loading, useToast } from "../components/ui";

const GRADES: [string, string][] = [
  ["A", "completely reliable"], ["B", "usually reliable"], ["C", "fairly reliable"],
  ["D", "not usually reliable"], ["E", "unreliable"], ["F", "cannot be judged"],
];

export function SourcesPage() {
  const [q, setQ] = useState("");
  const rows = useQuery({ queryKey: ["sources", q], queryFn: () => get<Source[]>(`/api/sources?q=${encodeURIComponent(q)}`), placeholderData: (p) => p });
  return (
    <div className="page">
      <h1>Sources &amp; grading</h1>
      <div className="muted">
        Admiralty source reliability (A–F). Each citation shows it as the letter of its code (e.g. <strong>B1</strong>); the digit comes from corroboration.
        Unknown sources stay F.
      </div>
      <div className="row gap-top">
        <input style={{ maxWidth: 360 }} placeholder="Filter (reuters.com, t.me/…)" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted small">{rows.data?.length ?? 0} sources, most used first</span>
      </div>
      <div className="card gap-top table-wrap">
        {rows.isLoading && <Loading />}
        <ErrorBox error={rows.error} />
        <table>
          <thead><tr><th>source</th><th>kind</th><th className="right">artifacts</th><th>grade</th><th>note</th></tr></thead>
          <tbody>{rows.data?.map((s) => <SourceRow key={s.id} s={s} />)}</tbody>
        </table>
      </div>
    </div>
  );
}

function SourceRow({ s }: { s: Source }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [note, setNote] = useState(s.note ?? "");
  const grade = useMutation({
    mutationFn: (g: string) => post(`/api/sources/${s.id}/grade`, { grade: g, note: note === s.note ? "" : note }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["sources"] }); toast(`${s.locator} graded`); },
    onError: (e: Error) => toast(e.message, true),
  });
  return (
    <tr>
      <td className="wrap-anywhere"><strong>{s.locator}</strong></td>
      <td className="small">{s.kind.replace(/_/g, " ")}</td>
      <td className="right">{s.artifacts}</td>
      <td>
        <select style={{ width: 210 }} value={s.grade} onChange={(e) => grade.mutate(e.target.value)} disabled={grade.isPending}>
          {GRADES.map(([g, d]) => <option key={g} value={g}>{g} · {d}</option>)}
        </select>
      </td>
      <td><input value={note} placeholder="why (optional)" onChange={(e) => setNote(e.target.value)}
        onBlur={() => note !== (s.note ?? "") && grade.mutate(s.grade)} /></td>
    </tr>
  );
}

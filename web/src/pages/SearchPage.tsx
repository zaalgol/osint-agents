import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { get } from "../api";
import { Badge, Empty, ErrorBox, Loading, TypeChip } from "../components/ui";

interface Hit { entity_id: number; name: string; type: string; aliases: string[]; investigations: { id: number; name: string }[] }

export function SearchPage() {
  const [sp, setSp] = useSearchParams();
  const query = sp.get("q") ?? "";
  const [draft, setDraft] = useState(query);
  const q = useQuery({ queryKey: ["search", query], queryFn: () => get<Hit[]>(`/api/search?q=${encodeURIComponent(query)}`), enabled: query.length >= 2 });
  return (
    <div className="page">
      <h1>Search entities</h1>
      <div className="muted">Names, aliases, handles, wallets and more, across every investigation (normalized and transliterated).</div>
      <form className="row gap-top" onSubmit={(e) => { e.preventDefault(); setSp({ q: draft }); }}>
        <input style={{ maxWidth: 480 }} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="e.g. Ansar Allah, @channel, bc1q…" autoFocus />
        <button className="primary">Search</button>
      </form>
      <div className="gap-top">
        {q.isLoading && <Loading />}
        <ErrorBox error={q.error} />
        {q.data?.length === 0 && <Empty>No entity matches “{query}”.</Empty>}
        {q.data && q.data.length > 0 && (
          <div className="card table-wrap">
            <table>
              <thead><tr><th>entity</th><th>type</th><th>aliases</th><th>investigations</th></tr></thead>
              <tbody>
                {q.data.map((h) => (
                  <tr key={h.entity_id}>
                    <td><Link to={`/entity/${h.entity_id}?inv=${h.investigations[0]?.id ?? 0}`}>{h.name}</Link></td>
                    <td><TypeChip type={h.type} /></td>
                    <td className="small">{h.aliases.slice(0, 6).join(" · ")}</td>
                    <td className="row">{h.investigations.map((i) => <Link key={i.id} to={`/inv/${i.id}`}><Badge>{i.name}</Badge></Link>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

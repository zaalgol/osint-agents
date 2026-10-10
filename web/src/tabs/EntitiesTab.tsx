import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get } from "../api";
import { Badge, Empty, ErrorBox, Loading, TypeChip } from "../components/ui";

interface Row { id: number; name: string; type: string; mentions: number; investigations: number; strong_key: string | null; sanctions: boolean }
interface Meta { ontology: { entity_types: string[] } }

export function EntitiesTab({ inv }: { inv: number }) {
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => get<Meta>("/api/meta") });
  const rows = useQuery({
    queryKey: ["inv", inv, "entities", q, type],
    queryFn: () => get<Row[]>(`/api/inv/${inv}/entities?q=${encodeURIComponent(q)}&type=${type}&limit=1000`),
    placeholderData: (prev) => prev,
  });
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <input style={{ maxWidth: 320 }} placeholder="Filter by name…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select style={{ maxWidth: 200 }} value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">all types</option>
          {meta.data?.ontology.entity_types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <span className="muted small">{rows.data?.length ?? 0} shown, most mentioned first</span>
      </div>
      {rows.isLoading && <Loading />}
      <ErrorBox error={rows.error} />
      {rows.data?.length === 0 && <Empty>No entities match.</Empty>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>name</th><th>type</th><th className="right">mentions</th><th>also in</th><th>identifier</th></tr></thead>
          <tbody>
            {rows.data?.map((e) => (
              <tr key={e.id}>
                <td><Link to={`/entity/${e.id}?inv=${inv}`}>{e.name}</Link> {e.sanctions && <Badge tone="bad">sanctions</Badge>}</td>
                <td><TypeChip type={e.type} /></td>
                <td className="right">{e.mentions}</td>
                <td>{e.investigations > 1 ? <Badge tone="accent">{e.investigations - 1} other investigation(s)</Badge> : ""}</td>
                <td className="mono small wrap-anywhere">{e.strong_key ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { get, type CrossLink } from "../api";
import { Badge, Empty, ErrorBox, JobButton, Loading, TypeChip } from "../components/ui";

interface Shared { entity_id: number; name: string; type: string; other_investigations: number[] }
interface Players {
  players: { entity_id: number; name: string; type: string; degree: number; betweenness: number; community: number }[];
  communities: { id: number; size: number; members: string[] }[];
}

export function LinksTab({ inv }: { inv: number }) {
  const links = useQuery({ queryKey: ["inv", inv, "links"], queryFn: () => get<{ links: CrossLink[]; shared: Shared[] }>(`/api/inv/${inv}/links`) });
  const players = useQuery({ queryKey: ["inv", inv, "players"], queryFn: () => get<Players>(`/api/inv/${inv}/key-players`), retry: 0 });
  const names = useQuery({ queryKey: ["investigations"], queryFn: () => get<{ id: number; name: string }[]>("/api/investigations") });
  const invName = (id: number) => names.data?.find((i) => i.id === id)?.name ?? `#${id}`;

  return (
    <div className="grid grid-2">
      <div className="card">
        <div className="spread"><h3>Links to other investigations</h3><JobButton action="link" inv={inv}>Claude: confirm links</JobButton></div>
        {links.isLoading && <Loading />}
        <ErrorBox error={links.error} />
        {links.data?.links.length === 0 && <Empty>No cross-investigation links yet.</Empty>}
        {links.data?.links.map((l) => (
          <div key={l.link_id} style={{ padding: "8px 0", borderBottom: "1px solid var(--border)" }}>
            <div className="row">
              <Link to={`/inv/${l.other_investigation.id}`}><strong>{l.other_investigation.name}</strong></Link>
              <Badge tone={l.status === "confirmed" ? "ok" : l.status === "rejected" ? "bad" : "warn"}>{l.status}</Badge>
              <Badge>{l.tier}</Badge>
              <span className="muted small">score {l.score.toFixed(2)}</span>
            </div>
            <div className="small">
              via {l.via.type === "entity"
                ? <Link to={`/entity/${l.via.id}?inv=${inv}`}>{l.via.name}</Link>
                : l.via.description ?? `${l.via.type} ${l.via.id}`}
            </div>
            {l.explanation && <div className="small muted">{l.explanation}</div>}
          </div>
        ))}
      </div>
      <div className="card">
        <h3>Shared entities</h3>
        {links.data?.shared.length === 0 && <Empty>No entities shared with other investigations.</Empty>}
        <table><tbody>
          {links.data?.shared.map((s) => (
            <tr key={s.entity_id}>
              <td><Link to={`/entity/${s.entity_id}?inv=${inv}`}>{s.name}</Link></td>
              <td><TypeChip type={s.type} /></td>
              <td className="small">{s.other_investigations.map((i) => <Link key={i} to={`/inv/${i}`} style={{ marginRight: 8 }}>{invName(i)}</Link>)}</td>
            </tr>
          ))}
        </tbody></table>
      </div>
      <div className="card">
        <h3>Key players</h3>
        <div className="muted small">Betweenness = brokers connecting otherwise separate groups. Degree = hubs.</div>
        {players.isLoading && <Loading />}
        <ErrorBox error={players.error} />
        <table>
          <thead><tr><th>entity</th><th>type</th><th className="right">betweenness</th><th className="right">degree</th><th className="right">group</th></tr></thead>
          <tbody>
            {players.data?.players.map((p) => (
              <tr key={p.entity_id}>
                <td><Link to={`/entity/${p.entity_id}?inv=${inv}`}>{p.name}</Link></td>
                <td><TypeChip type={p.type} /></td>
                <td className="right">{p.betweenness.toFixed(3)}</td>
                <td className="right">{p.degree.toFixed(3)}</td>
                <td className="right">{p.community}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>Communities</h3>
        {players.data?.communities.map((c) => (
          <div key={c.id} style={{ marginBottom: 8 }}><Badge>group {c.id} · {c.size}</Badge> <span className="small">{c.members.join(", ")}</span></div>
        ))}
      </div>
    </div>
  );
}

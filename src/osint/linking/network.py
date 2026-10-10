"""Network analytics over the knowledge graph (NetworkX, computed from Postgres).

Key players: degree and betweenness centrality plus Louvain communities on the graph of
relations and shared event participation (entities that took part in the same event).
"""

from __future__ import annotations

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.storage.db import Entity, EventParticipant, InvestigationRef, Relation


def build_graph(s: Session, investigation_id: int | None = None) -> nx.Graph:
    g = nx.Graph()
    scope = None
    if investigation_id is not None:
        scope = set(s.scalars(select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == investigation_id,
            InvestigationRef.object_type == "entity")))
    names = {e.id: (e.canonical_name, e.type) for e in s.scalars(
        select(Entity).where(Entity.merged_into_id.is_(None)))}

    def ok(x: int) -> bool:
        return x in names and (scope is None or x in scope)

    for a, b, t in s.execute(select(Relation.src_entity_id, Relation.dst_entity_id, Relation.type)
                             .where(Relation.attributes["retracted"].is_(None))):
        if ok(a) and ok(b) and a != b:
            w = g.get_edge_data(a, b, {}).get("weight", 0) + 1
            g.add_edge(a, b, weight=w, kind=t)
    by_event: dict[int, list[int]] = {}
    for v, e in s.execute(select(EventParticipant.event_id, EventParticipant.entity_id)):
        if ok(e):
            by_event.setdefault(v, []).append(e)
    for members in by_event.values():
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if a != b:
                    w = g.get_edge_data(a, b, {}).get("weight", 0) + 0.5
                    g.add_edge(a, b, weight=w, kind="co-event")
    for n in g.nodes:
        g.nodes[n]["name"], g.nodes[n]["type"] = names[n]
    return g


def key_players(s: Session, investigation_id: int | None = None, top: int = 15) -> dict:
    g = build_graph(s, investigation_id)
    if g.number_of_nodes() == 0:
        return {"nodes": 0, "edges": 0, "players": [], "communities": []}
    degree = nx.degree_centrality(g)
    between = nx.betweenness_centrality(g, weight=None)
    comms = sorted(nx.community.louvain_communities(g, weight="weight", seed=7),
                   key=len, reverse=True)
    comm_of = {n: i for i, c in enumerate(comms) for n in c}
    players = sorted(g.nodes, key=lambda n: (between[n], degree[n]), reverse=True)[:top]
    return {
        "nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
        "players": [{"entity_id": n, "name": g.nodes[n]["name"], "type": g.nodes[n]["type"],
                     "degree": round(degree[n], 3), "betweenness": round(between[n], 3),
                     "community": comm_of[n]} for n in players],
        "communities": [{"id": i, "size": len(c),
                         "members": [g.nodes[n]["name"] for n in sorted(
                             c, key=lambda n: -degree[n])[:8]]}
                        for i, c in enumerate(comms[:10])],
        "note": "betweenness = brokers connecting otherwise separate parts of the network",
    }

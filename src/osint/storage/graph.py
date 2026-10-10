"""Neo4j graph projection + graph analytics.

Neo4j is a *projection* of Postgres, never the source of truth. ``sync_graph`` rebuilds
it completely (correct after merges, merge undos and new links). Model:

  (:Investigation {pg_id, name})
  (:Entity {pg_id, name, type, strong_key})-[:IN]->(:Investigation)
  (:Entity)-[:REL {pg_id, type, confidence, sources}]->(:Entity)
  (:Entity)-[:PARTICIPATED {role}]->(:Event {pg_id, type, time, description})
  (:Event)-[:AT]->(:Entity)        (location)
  (:Investigation)-[:LINKED {pg_id, via_type, via_id, tier, score}]->(:Investigation)
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from neo4j import Driver, GraphDatabase
from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.core.config import Neo4jSettings, Settings

SCHEMA = [
    "CREATE CONSTRAINT entity_pg_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.pg_id IS UNIQUE",
    "CREATE CONSTRAINT event_pg_id IF NOT EXISTS FOR (n:Event) REQUIRE n.pg_id IS UNIQUE",
    (
        "CREATE CONSTRAINT investigation_pg_id IF NOT EXISTS "
        "FOR (n:Investigation) REQUIRE n.pg_id IS UNIQUE"
    ),
    "CREATE INDEX entity_type IF NOT EXISTS FOR (n:Entity) ON (n.type)",
    "CREATE INDEX entity_name IF NOT EXISTS FOR (n:Entity) ON (n.name)",
    "CREATE INDEX event_time IF NOT EXISTS FOR (n:Event) ON (n.time)",
]
BATCH = 1000
WRITE_CLAUSE = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|FOREACH)\b|"
    r"\bCALL\s+(dbms|db\.(create|drop)|apoc\.(create|merge|refactor|periodic|load|export))",
    re.IGNORECASE)


def make_driver(settings: Settings | Neo4jSettings) -> Driver:
    n = settings.neo4j if isinstance(settings, Settings) else settings
    return GraphDatabase.driver(n.uri, auth=(n.user, n.password))


def ensure_schema(driver: Driver) -> None:
    with driver.session() as s:
        for stmt in SCHEMA:
            s.run(stmt)


def _batches(rows: list[dict]) -> Iterable[list[dict]]:
    for i in range(0, len(rows), BATCH):
        yield rows[i:i + BATCH]


def sync_graph(session: Session, driver: Driver) -> dict[str, int]:
    from osint.storage.db import (
        CrossLink,
        Entity,
        Event,
        EventParticipant,
        Investigation,
        InvestigationRef,
        Relation,
        SupportStats,
    )

    invs = [{"id": i, "name": n} for i, n in session.execute(
        select(Investigation.id, Investigation.name))]
    ents = [{"id": e.id, "name": e.canonical_name, "type": e.type, "key": e.strong_key}
            for e in session.scalars(select(Entity).where(Entity.merged_into_id.is_(None)))]
    live = {e["id"] for e in ents}
    refs = [{"e": o, "i": i} for i, o in session.execute(
        select(InvestigationRef.investigation_id, InvestigationRef.object_id).where(
            InvestigationRef.object_type == "entity")) if o in live]
    support = {(t, i): n for t, i, n in session.execute(
        select(SupportStats.target_type, SupportStats.target_id,
               SupportStats.independent_sources))}
    rels = [{"id": r.id, "a": r.src_entity_id, "b": r.dst_entity_id, "type": r.type,
             "conf": r.confidence, "src": support.get(("relation", r.id), 0)}
            for r in session.scalars(select(Relation).where(
                Relation.attributes["retracted"].is_(None)))
            if r.src_entity_id in live and r.dst_entity_id in live]
    events = [{"id": e.id, "type": e.type, "time": e.time.isoformat() if e.time else None,
               "desc": e.description, "loc": e.location_entity_id}
              for e in session.scalars(select(Event))]
    parts = [{"v": v, "e": e, "role": r} for v, e, r in session.execute(
        select(EventParticipant.event_id, EventParticipant.entity_id, EventParticipant.role))
        if e in live]
    links = [{"id": c.id, "a": c.investigation_a, "b": c.investigation_b, "vt": c.via_type,
              "vi": c.via_id, "tier": c.tier, "score": c.score}
             for c in session.scalars(select(CrossLink).where(CrossLink.status == "confirmed"))]

    with driver.session() as s:
        s.run("MATCH (n) WHERE n:Entity OR n:Event OR n:Investigation DETACH DELETE n")
        for b in _batches(invs):
            s.run("UNWIND $rows AS r CREATE (:Investigation {pg_id: r.id, name: r.name})", rows=b)
        for b in _batches(ents):
            s.run("UNWIND $rows AS r CREATE (:Entity {pg_id: r.id, name: r.name, type: r.type, "
                  "strong_key: r.key})", rows=b)
        for b in _batches(refs):
            s.run("UNWIND $rows AS r MATCH (e:Entity {pg_id: r.e}), (i:Investigation {pg_id: r.i}) "
                  "CREATE (e)-[:IN]->(i)", rows=b)
        for b in _batches(rels):
            s.run("UNWIND $rows AS r MATCH (a:Entity {pg_id: r.a}), (b:Entity {pg_id: r.b}) "
                  "CREATE (a)-[:REL {pg_id: r.id, type: r.type, confidence: r.conf, "
                  "sources: r.src}]->(b)", rows=b)
        for b in _batches(events):
            s.run("UNWIND $rows AS r CREATE (:Event {pg_id: r.id, type: r.type, time: r.time, "
                  "description: r.desc})", rows=b)
            s.run("UNWIND $rows AS r WITH r WHERE r.loc IS NOT NULL "
                  "MATCH (v:Event {pg_id: r.id}), (l:Entity {pg_id: r.loc}) CREATE (v)-[:AT]->(l)",
                  rows=b)
        for b in _batches(parts):
            s.run("UNWIND $rows AS r MATCH (e:Entity {pg_id: r.e}), (v:Event {pg_id: r.v}) "
                  "CREATE (e)-[:PARTICIPATED {role: r.role}]->(v)", rows=b)
        for b in _batches(links):
            s.run("UNWIND $rows AS r MATCH (a:Investigation {pg_id: r.a}), "
                  "(b:Investigation {pg_id: r.b}) CREATE (a)-[:LINKED {pg_id: r.id, "
                  "via_type: r.vt, via_id: r.vi, tier: r.tier, score: r.score}]->(b)", rows=b)
    return {"investigations": len(invs), "entities": len(ents), "relations": len(rels),
            "events": len(events), "participations": len(parts), "links": len(links)}


def read_query(driver: Driver, cypher: str, params: dict | None = None,
               limit: int = 200) -> list[dict]:
    """Run a read-only Cypher query (read transaction + write-clause guard)."""
    if WRITE_CLAUSE.search(cypher):
        raise ValueError("only read queries are allowed (MATCH/OPTIONAL MATCH/WITH/RETURN, "
                         "read procedures)")

    def work(tx):
        return [r.data() for r in tx.run(cypher, **(params or {})).fetch(limit)]

    with driver.session() as s:
        return s.execute_read(work)


def shortest_path(driver: Driver, a: int, b: int, max_hops: int = 6) -> list[dict]:
    hops = max(1, min(int(max_hops), 10))
    q = (f"MATCH (a:Entity {{pg_id: $a}}), (b:Entity {{pg_id: $b}}), "
         f"p = shortestPath((a)-[:REL|PARTICIPATED*..{hops}]-(b)) "
         "RETURN [n IN nodes(p) | coalesce(n.name, n.type + ': ' + n.description)] AS nodes, "
         "[n IN nodes(p) | n.pg_id] AS ids, "
         "[r IN relationships(p) | coalesce(r.type, 'participated:' + r.role)] AS edges, "
         "[r IN relationships(p) | r.pg_id] AS relation_ids")
    return read_query(driver, q, {"a": a, "b": b}, limit=1)

"""Corroboration (independent-source counting) and contradiction detection.

Independence: two documents are NOT independent if they are near-duplicates (syndicated
wire copy, reposts: embedding cosine >= DUP_SIM) or come from the same outlet (same
host). The independent-source count for a relation/event is the number of such groups
among the documents that cite it. Twenty sites reposting one Telegram post count as one.

Contradictions (events): same event type, shared participants, near-identical
description (the same incident), but dates more than DATE_TOLERANCE_DAYS apart. Both
events get each other in support_stats.contradicted_by, and a review item is opened.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from osint.storage.db import (
    Artifact,
    Document,
    Event,
    EventParticipant,
    EvidenceLink,
    InvestigationRef,
    ReviewItem,
    SupportStats,
)

DUP_SIM = 0.93
SAME_INCIDENT_SIM = 0.86
DATE_TOLERANCE_DAYS = 2
CLUSTER_SIM = 0.88          # same incident reported twice: same type, within a day


class _UF:
    def __init__(self):
        self.p: dict = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb, key=str)] = min(ra, rb, key=str)


@dataclass
class CorroborationReport:
    documents: int = 0
    origin_clusters: int = 0
    targets: int = 0
    single_source: int = 0
    contradictions: int = 0
    incident_clusters: int = 0
    clustered_events: int = 0


def cluster_events(s: Session) -> tuple[int, int]:
    """Group events that are the same real-world incident: same type, dates within one
    day (or the same day for undated-to-day precision), near-identical description.
    Contradictions (same incident, dates further apart) are handled separately."""
    uf = _UF()
    for a, b in s.execute(text(
        "SELECT a.id, b.id FROM event a JOIN event b ON b.id > a.id AND b.type = a.type "
        "WHERE a.embedding IS NOT NULL AND b.embedding IS NOT NULL "
        "AND a.time IS NOT NULL AND b.time IS NOT NULL "
        "AND abs(extract(epoch FROM (a.time - b.time))) <= 86400 "
        "AND 1 - (a.embedding <=> b.embedding) >= :sim"), {"sim": CLUSTER_SIM}):
        uf.union(a, b)
    groups: dict[int, list[int]] = {}
    for x in list(uf.p):
        groups.setdefault(uf.find(x), []).append(x)
    s.execute(text("UPDATE event SET cluster_id = NULL WHERE cluster_id IS NOT NULL"))
    clustered = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        canon = min(members)
        clustered += len(members)
        s.execute(Event.__table__.update().where(Event.id.in_(members)).values(cluster_id=canon))
    return sum(1 for m in groups.values() if len(m) > 1), clustered


def cluster_documents(s: Session) -> dict[int, int]:
    """Assign Document.origin_cluster (= smallest doc id of its near-duplicate group)."""
    uf = _UF()
    docs = s.execute(select(Document.id, Document.embedding.is_not(None))).all()
    for d, _ in docs:
        uf.find(d)
    for a, b in s.execute(text(
        "SELECT a.id, b.id FROM document a JOIN LATERAL ("
        "  SELECT id, embedding FROM document b WHERE b.id <> a.id AND b.embedding IS NOT NULL "
        "  ORDER BY b.embedding <=> a.embedding LIMIT 5) b ON true "
        "WHERE a.embedding IS NOT NULL AND 1 - (a.embedding <=> b.embedding) >= :sim"),
            {"sim": DUP_SIM}):
        uf.union(a, b)
    clusters = {d: uf.find(d) for d, _ in docs}
    for d, c in clusters.items():
        s.execute(Document.__table__.update().where(Document.id == d).values(origin_cluster=c))
    return clusters


def update_support(s: Session, clusters: dict[int, int]) -> tuple[int, int]:
    rows = s.execute(
        select(EvidenceLink.target_type, EvidenceLink.target_id, EvidenceLink.document_id,
               Artifact.final_url, Artifact.url)
        .join(Artifact, Artifact.id == EvidenceLink.artifact_id)
        .where(EvidenceLink.target_type.in_(["relation", "event"]))).all()
    # an incident cluster is corroborated by the citations of all its member events
    cluster = dict(s.execute(select(Event.id, Event.cluster_id).where(
        Event.cluster_id.is_not(None))).all())
    members: dict[int, list[int]] = {}
    for eid, cid in cluster.items():
        members.setdefault(cid, []).append(eid)
    by_target: dict[tuple[str, int], list] = {}
    for tt, tid, doc, furl, url in rows:
        host = (urlsplit(furl or url or "").hostname or "").removeprefix("www.")
        key = (tt, cluster.get(tid, tid) if tt == "event" else tid)
        by_target.setdefault(key, []).append((doc, host))
    single = 0
    for (tt, tid), items in by_target.items():
        uf = _UF()
        hosts: dict[str, object] = {}
        for doc, host in items:
            key = ("c", clusters.get(doc, doc)) if doc else ("h", host)
            uf.find(key)
            if host:
                if host in hosts:
                    uf.union(key, hosts[host])
                else:
                    hosts[host] = key
        groups = {uf.find(("c", clusters.get(d, d)) if d else ("h", h)) for d, h in items}
        n = len(groups)
        single += int(n == 1)
        targets = members.get(tid, [tid]) if tt == "event" else [tid]
        for target in targets:
            s.execute(pg_insert(SupportStats).values(
                target_type=tt, target_id=target, citations=len(items),
                documents=len({d for d, _ in items if d}), domains=len({h for _, h in items if h}),
                independent_sources=n,
                origin_clusters=sorted({clusters.get(d, d) for d, _ in items if d}),
            ).on_conflict_do_update(index_elements=["target_type", "target_id"], set_={
                "citations": len(items), "documents": len({d for d, _ in items if d}),
                "domains": len({h for _, h in items if h}), "independent_sources": n,
                "origin_clusters": sorted({clusters.get(d, d) for d, _ in items if d}),
                "updated_at": text("now()")}))
    return len(by_target), single


def find_contradictions(s: Session, investigation_id: int | None = None) -> int:
    q = select(Event).where(Event.time.is_not(None), Event.embedding.is_not(None),
                            Event.time_precision.in_(["day", "exact"]))
    if investigation_id is not None:
        q = q.where(Event.id.in_(select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == investigation_id,
            InvestigationRef.object_type == "event")))
    events = s.scalars(q).all()
    found = 0
    for e in events:
        pairs = s.execute(text(
            "SELECT b.id, 1 - (a.embedding <=> b.embedding) AS sim FROM event a, event b "
            "WHERE a.id = :id AND b.id <> a.id AND b.type = a.type AND b.time IS NOT NULL "
            "AND b.embedding IS NOT NULL AND b.time_precision IN ('day', 'exact') "
            "AND abs(extract(epoch FROM (a.time - b.time))) > :tol * 86400 "
            "AND 1 - (a.embedding <=> b.embedding) >= :sim"),
            {"id": e.id, "tol": DATE_TOLERANCE_DAYS, "sim": SAME_INCIDENT_SIM}).all()
        mine = set(s.scalars(select(EventParticipant.entity_id).where(
            EventParticipant.event_id == e.id)))
        for other_id, sim in pairs:
            if other_id < e.id:
                continue  # each pair once
            theirs = set(s.scalars(select(EventParticipant.entity_id).where(
                EventParticipant.event_id == other_id)))
            if mine and theirs and not (mine & theirs):
                continue
            other = s.get(Event, other_id)
            exists = s.scalar(select(ReviewItem.id).where(
                ReviewItem.kind == "contradiction",
                ReviewItem.payload["a"].as_integer() == e.id,
                ReviewItem.payload["b"].as_integer() == other_id))
            if exists:
                continue
            found += 1
            for a, b in ((e.id, other_id), (other_id, e.id)):
                s.execute(pg_insert(SupportStats).values(
                    target_type="event", target_id=a, contradicted_by=[b])
                    .on_conflict_do_update(index_elements=["target_type", "target_id"], set_={
                        "contradicted_by": text(
                            "(SELECT array_agg(DISTINCT x) FROM unnest("
                            "support_stats.contradicted_by || ARRAY[:b]::bigint[]) x)"
                        ).bindparams(b=b)}))
            s.add(ReviewItem(
                investigation_id=investigation_id, kind="contradiction",
                reason=(f"same {e.type} reported on {e.time:%Y-%m-%d} and "
                        f"{other.time:%Y-%m-%d} (similarity {sim:.2f})"),
                payload={"a": e.id, "b": other_id, "a_description": e.description,
                         "b_description": other.description, "similarity": round(sim, 3)},
                created_by="corroboration"))
    return found


def corroborate(s: Session, investigation_id: int | None = None) -> CorroborationReport:
    clusters = cluster_documents(s)
    n_inc, n_ev = cluster_events(s)
    targets, single = update_support(s, clusters)
    return CorroborationReport(
        documents=len(clusters), origin_clusters=len(set(clusters.values())),
        targets=targets, single_source=single,
        contradictions=find_contradictions(s, investigation_id),
        incident_clusters=n_inc, clustered_events=n_ev)

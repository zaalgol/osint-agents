"""Cross-investigation link candidates (hard + soft). Claude confirms them with proof.

hard  the same (resolved) entity is referenced by two investigations. The score depends
      on how distinctive the entity is: a wallet or account means a lot; a country
      means almost nothing.
soft  near-identical events in two investigations (same incident or same MO), and
      entity pairs that resolution judged "unsure" across investigations.

Candidates are stored in cross_link (status=candidate, one row per pair and via-object).
The link_investigations Claude job confirms them (status=confirmed requires an evidence
link or inference, enforced by a DB trigger) or rejects them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from osint.core.ontology import Ontology
from osint.storage.db import CrossLink, Entity, Event, InvestigationRef, ReviewItem

TYPE_WEIGHT = {"person": 0.9, "organization": 0.8, "armed_group": 0.85, "location": 0.25,
               "weapon": 0.4, "vehicle": 0.6, "document": 0.7}
MIN_SCORE = 0.5
EVENT_SIM = 0.86
EVENT_WINDOW_DAYS = 30


@dataclass
class LinkReport:
    hard: int = 0
    soft: int = 0
    skipped_low: int = 0
    pairs: set[tuple[int, int]] = field(default_factory=set)


def _weight(onto: Ontology, etype: str) -> float:
    if etype in onto.strong_identifier_types():
        return 1.0
    for t in [etype, *onto._ancestors(onto.entity_types, etype)]:
        if t in TYPE_WEIGHT:
            return TYPE_WEIGHT[t]
    return 0.5


def _add(s: Session, rep: LinkReport, a: int, b: int, via_type: str, via_id: int, tier: str,
         score: float, explanation: str) -> None:
    a, b = min(a, b), max(a, b)
    res = s.execute(pg_insert(CrossLink).values(
        investigation_a=a, investigation_b=b, via_type=via_type, via_id=via_id, tier=tier,
        score=round(score, 3), explanation=explanation, status="candidate")
        .on_conflict_do_nothing(constraint="uq_cross_link_via").returning(CrossLink.id))
    if res.scalar() is not None:
        rep.pairs.add((a, b))
        if tier == "hard":
            rep.hard += 1
        else:
            rep.soft += 1


def generate_candidates(s: Session, onto: Ontology, min_score: float = MIN_SCORE) -> LinkReport:
    rep = LinkReport()

    # hard: entities shared by investigations
    rows = s.execute(
        select(Entity.id, Entity.type, Entity.canonical_name,
               func.array_agg(InvestigationRef.investigation_id.distinct()))
        .join(InvestigationRef, (InvestigationRef.object_type == "entity")
              & (InvestigationRef.object_id == Entity.id))
        .where(Entity.merged_into_id.is_(None))
        .group_by(Entity.id).having(func.count(InvestigationRef.investigation_id.distinct()) > 1))
    for eid, etype, name, invs in rows:
        w = _weight(onto, etype)
        if w < min_score:
            rep.skipped_low += 1
            continue
        for a, b in combinations(sorted(invs), 2):
            _add(s, rep, a, b, "entity", eid, "hard", w,
                 f"{etype} '{name}' appears in both investigations")

    # soft: near-identical events across investigations
    event_inv = dict(s.execute(
        select(InvestigationRef.object_id, func.array_agg(InvestigationRef.investigation_id))
        .where(InvestigationRef.object_type == "event").group_by(InvestigationRef.object_id)).all())
    for e in s.scalars(select(Event).where(Event.embedding.is_not(None))):
        for other, sim in s.execute(text(
            "SELECT b.id, 1 - (a.embedding <=> b.embedding) FROM event a, event b "
            "WHERE a.id = :id AND b.id > a.id AND b.embedding IS NOT NULL AND b.type = a.type "
            "AND (a.time IS NULL OR b.time IS NULL OR "
            "     abs(extract(epoch FROM (a.time - b.time))) <= :win * 86400) "
            "AND 1 - (a.embedding <=> b.embedding) >= :sim"),
                {"id": e.id, "win": EVENT_WINDOW_DAYS, "sim": EVENT_SIM}):
            for a in event_inv.get(e.id, []):
                for b in event_inv.get(other, []):
                    if a != b:
                        _add(s, rep, a, b, "event", min(e.id, other), "soft", float(sim) * 0.8,
                             f"similar {e.type} events {e.id} and {other} (similarity {sim:.2f})")

    # soft: unsure resolution pairs that span investigations
    for r in s.scalars(select(ReviewItem).where(ReviewItem.kind == "resolution_pair",
                                                ReviewItem.status == "open")):
        ia = set(s.scalars(select(InvestigationRef.investigation_id).where(
            InvestigationRef.object_type == "entity",
            InvestigationRef.object_id == r.payload["a"])))
        ib = set(s.scalars(select(InvestigationRef.investigation_id).where(
            InvestigationRef.object_type == "entity",
            InvestigationRef.object_id == r.payload["b"])))
        for a in ia:
            for b in ib - {a}:
                _add(s, rep, a, b, "entity", int(r.payload["a"]), "soft",
                     float(r.payload.get("score", 0.6)) * 0.8,
                     f"possibly the same entity: {r.payload.get('names')}")
    return rep

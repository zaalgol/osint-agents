"""Reversible entity merges.

A merge repoints the loser's aliases, mentions, relations, event roles and investigation
refs to the winner, and records every moved row id in entity_merge.moved, so
``undo_merge`` can put each one back. The loser row is kept (merged_into_id = winner):
nothing is deleted, so provenance survives merges and their undo.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from osint.storage.db import (
    Entity,
    EntityAlias,
    EntityMerge,
    Event,
    EventParticipant,
    InvestigationRef,
    Mention,
    Relation,
)


class MergeError(RuntimeError):
    pass


def canonical(s: Session, entity_id: int) -> int:
    seen = set()
    cur = entity_id
    while True:
        nxt = s.scalar(select(Entity.merged_into_id).where(Entity.id == cur))
        if nxt is None or cur in seen:
            return cur
        seen.add(cur)
        cur = nxt


def link_count(s: Session, entity_id: int) -> int:
    rel = s.scalar(select(func.count()).where(or_(Relation.src_entity_id == entity_id,
                                                   Relation.dst_entity_id == entity_id)))
    ev = s.scalar(select(func.count()).where(EventParticipant.entity_id == entity_id))
    men = s.scalar(select(func.count()).where(Mention.entity_id == entity_id))
    return (rel or 0) + (ev or 0) + (men or 0)


def choose_winner(s: Session, a: int, b: int) -> tuple[int, int]:
    """The better-connected entity survives (ties: the older one)."""
    la, lb = link_count(s, a), link_count(s, b)
    if la > lb or (la == lb and a < b):
        return a, b
    return b, a


def merge_entities(s: Session, winner_id: int, loser_id: int, *, method: str, score: float | None,
                   rationale: str | None, decided_by: str) -> EntityMerge:
    winner_id, loser_id = canonical(s, winner_id), canonical(s, loser_id)
    if winner_id == loser_id:
        raise MergeError("entities are already the same")
    winner, loser = s.get(Entity, winner_id), s.get(Entity, loser_id)
    if winner is None or loser is None:
        raise MergeError("unknown entity")
    if winner.strong_key and loser.strong_key and winner.strong_key != loser.strong_key:
        raise MergeError("different strong identifiers can't be the same entity")

    moved: dict[str, list] = {}

    # aliases (skip ones the winner already has: unique (entity_id, alias, lang))
    have = set(s.execute(select(EntityAlias.alias, EntityAlias.lang).where(
        EntityAlias.entity_id == winner_id)).all())
    ids = [a.id for a in s.scalars(select(EntityAlias).where(EntityAlias.entity_id == loser_id))
           if (a.alias, a.lang) not in have]
    if ids:
        s.execute(update(EntityAlias).where(EntityAlias.id.in_(ids)).values(entity_id=winner_id))
    moved["alias"] = ids

    def repoint(model, col, key="id") -> list[int]:
        ids = list(s.scalars(select(getattr(model, key)).where(col == loser_id)))
        if ids:
            s.execute(update(model).where(getattr(model, key).in_(ids)).values({col.key: winner_id}))
        return ids

    moved["mention"] = repoint(Mention, Mention.entity_id)
    moved["relation_src"] = repoint(Relation, Relation.src_entity_id)
    moved["relation_dst"] = repoint(Relation, Relation.dst_entity_id)
    moved["event_location"] = repoint(Event, Event.location_entity_id)

    # event roles: composite PK (event, entity, role); skip duplicates
    parts = s.execute(select(EventParticipant.event_id, EventParticipant.role).where(
        EventParticipant.entity_id == loser_id)).all()
    wparts = set(s.execute(select(EventParticipant.event_id, EventParticipant.role).where(
        EventParticipant.entity_id == winner_id)).all())
    mv = [(e, r) for e, r in parts if (e, r) not in wparts]
    for e, r in mv:
        s.execute(update(EventParticipant).where(
            EventParticipant.event_id == e, EventParticipant.entity_id == loser_id,
            EventParticipant.role == r).values(entity_id=winner_id))
    moved["event_participant"] = [list(x) for x in mv]

    # the winner joins every investigation the loser was in (refs inserted, not moved)
    inv_ids = s.scalars(select(InvestigationRef.investigation_id).where(
        InvestigationRef.object_type == "entity", InvestigationRef.object_id == loser_id)).all()
    added = []
    for inv in inv_ids:
        res = s.execute(pg_insert(InvestigationRef).values(
            investigation_id=inv, object_type="entity", object_id=winner_id,
            added_by=f"merge:{decided_by}").on_conflict_do_nothing().returning(
            InvestigationRef.investigation_id))
        if res.scalar() is not None:
            added.append(inv)
    moved["ref_added"] = added

    loser.merged_into_id = winner_id
    winner.embedding = None  # names/aliases changed: re-embed
    winner.confidence = max(winner.confidence, loser.confidence)
    m = EntityMerge(winner_id=winner_id, loser_id=loser_id, method=method, score=score,
                    rationale=rationale, decided_by=decided_by, moved=moved)
    s.add(m)
    s.flush()
    return m


def undo_merge(s: Session, merge_id: int) -> EntityMerge:
    m = s.get(EntityMerge, merge_id)
    if m is None or m.reverted_at is not None:
        raise MergeError("no such active merge")
    later = s.scalar(select(EntityMerge.id).where(
        EntityMerge.id > m.id, EntityMerge.reverted_at.is_(None),
        or_(EntityMerge.winner_id.in_([m.winner_id, m.loser_id]),
            EntityMerge.loser_id.in_([m.winner_id, m.loser_id]))))
    if later:
        raise MergeError(f"undo merge {later} first (it builds on this one)")
    w, lo, mv = m.winner_id, m.loser_id, m.moved or {}

    def back(model, col, ids, key="id"):
        if ids:
            s.execute(update(model).where(getattr(model, key).in_(ids)).values({col.key: lo}))

    back(EntityAlias, EntityAlias.entity_id, mv.get("alias"))
    back(Mention, Mention.entity_id, mv.get("mention"))
    back(Relation, Relation.src_entity_id, mv.get("relation_src"))
    back(Relation, Relation.dst_entity_id, mv.get("relation_dst"))
    back(Event, Event.location_entity_id, mv.get("event_location"))
    for e, r in mv.get("event_participant", []):
        s.execute(update(EventParticipant).where(
            EventParticipant.event_id == e, EventParticipant.entity_id == w,
            EventParticipant.role == r).values(entity_id=lo))
    for inv in mv.get("ref_added", []):
        s.execute(InvestigationRef.__table__.delete().where(
            InvestigationRef.investigation_id == inv, InvestigationRef.object_type == "entity",
            InvestigationRef.object_id == w))
    s.get(Entity, lo).merged_into_id = None
    s.get(Entity, w).embedding = None
    m.reverted_at = datetime.now(UTC)
    return m

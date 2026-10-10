"""Human review decisions (from the CLI or the UI).

Principles:
  * A human decision never turns an unverifiable quote into a fact: items about missing
    or weak quotes can only be dismissed (re-checked automatically by `review --recheck`)
  * Accepting a sanctions match writes the relation with the verbatim list entry as its
    citation and the human as its author
  * Every decision is recorded on the item: who, when, note
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from osint.storage.db import (
    CrossLink,
    Document,
    Entity,
    EventParticipant,
    EvidenceLink,
    InvestigationRef,
    Relation,
    ReviewItem,
)

DISMISS_ONLY = {"quote_not_found", "weak_citation", "ontology", "unresolved", "blocked_source",
                "enrichment", "integrity_alert"}


class ReviewError(ValueError):
    pass


def _stamp(item: ReviewItem, status: str, actor: str, note: str | None, **extra) -> None:
    item.status = status
    item.payload = {**(item.payload or {}), "decision": {
        "status": status, "by": actor, "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "note": note, **extra}}


def decide(s: Session, app, review_id: int, decision: str, actor: str,
           note: str | None = None, target: int | None = None) -> dict:
    if decision not in ("accept", "reject"):
        raise ReviewError("decision must be accept or reject")
    item = s.get(ReviewItem, review_id)
    if item is None:
        raise ReviewError(f"no review item {review_id}")
    if item.status != "open":
        raise ReviewError(f"review item {review_id} is already {item.status}")
    kind, p = item.kind, item.payload or {}

    if decision == "reject":
        if kind == "contradiction":
            _clear_contradiction(s, p["a"], p["b"])
        _stamp(item, "rejected", actor, note)
        return {"review": review_id, "status": "rejected"}

    if kind in DISMISS_ONLY:
        raise ReviewError(f"'{kind}' items can't be accepted: an unverifiable or rejected "
                          "extraction does not become a fact by vote. Reject (dismiss) it, or "
                          "run `osint review --recheck` after fixing the cause.")

    if kind in ("resolution_pair", "resolution_candidate"):
        from osint.resolution.merge import choose_winner, merge_entities

        a = p.get("a") or p.get("entity_id")
        b = target or p.get("b") or (p.get("candidates") or [None])[0]
        if not a or not b:
            raise ReviewError("which entity? pass target=<entity id>")
        if kind == "resolution_candidate" and len(p.get("candidates", [])) > 1 and target is None:
            raise ReviewError(f"several candidates {p['candidates']}: pass target=<entity id>")
        w, lo = choose_winner(s, int(a), int(b))
        m = merge_entities(s, w, lo, method="human", score=None, rationale=note or "analyst merge",
                           decided_by=actor)
        _stamp(item, "accepted", actor, note, merge_id=m.id)
        return {"review": review_id, "status": "accepted", "merge_id": m.id}

    if kind == "sanctions_match":
        rel_id = _accept_sanctions(s, app, item, actor)
        _stamp(item, "accepted", actor, note, relation_id=rel_id)
        return {"review": review_id, "status": "accepted", "relation_id": rel_id}

    if kind == "contradiction":
        _stamp(item, "accepted", actor, note)   # acknowledged: both versions stay visible
        return {"review": review_id, "status": "accepted"}

    raise ReviewError(f"no accept action for '{kind}'")


def _accept_sanctions(s: Session, app, item: ReviewItem, actor: str) -> int:
    from osint.core.models import EntityRef, ExtractedRelation, ExtractionResult
    from osint.extraction.writer import ExtractionWriter

    p = item.payload
    doc = s.get(Document, p.get("document_id"))
    ent = s.get(Entity, p.get("entity_id"))
    line = p.get("list_entry")
    if doc is None or ent is None or not line or line not in doc.text:
        raise ReviewError("the list entry is not available in a captured document")
    from osint.core.models import ExtractedEntity
    from osint.resolution.resolver import add_ref

    authority = "UN Security Council" if line.startswith("UN ") else "US Treasury OFAC"
    # people resolve within the investigation by alias: make sure this exact entity is
    # in scope and findable under its name, so the relation lands on it (not a namesake)
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from osint.storage.db import EntityAlias
    from osint.text.normalize import name_key

    add_ref(s, item.investigation_id, "entity", ent.id, actor)
    s.execute(pg_insert(EntityAlias).values(
        entity_id=ent.id, alias=ent.canonical_name, alias_norm=name_key(ent.canonical_name),
        alias_type="name", lang="und").on_conflict_do_nothing(constraint="uq_alias"))
    w = ExtractionWriter(s, app.ontology, item.investigation_id, doc, actor=actor)
    w.write(ExtractionResult(entities=[
        ExtractedEntity(name=ent.canonical_name, type=ent.type, quote=ent.canonical_name),
        # the authority's name may not appear verbatim in the line: cite the line itself
        ExtractedEntity(name=authority, type="organization", quote=line),
    ], relations=[ExtractedRelation(
        type="designated_by", src=EntityRef(name=ent.canonical_name, type=ent.type),
        dst=EntityRef(name=authority, type="organization"), quote=line, confidence=0.8)]))
    if w.stats.relations + w.stats.relations_reused == 0:
        raise ReviewError("could not write the relation (see review queue)")
    s.flush()
    return s.scalar(select(EvidenceLink.target_id).where(
        EvidenceLink.target_type == "relation", EvidenceLink.document_id == doc.id,
        EvidenceLink.quote_original == line).order_by(EvidenceLink.id.desc()).limit(1))


def _clear_contradiction(s: Session, a: int, b: int) -> None:
    for x, y in ((a, b), (b, a)):
        s.execute(text("UPDATE support_stats SET contradicted_by = array_remove(contradicted_by, "
                       ":y) WHERE target_type = 'event' AND target_id = :x"), {"x": x, "y": y})


def decide_link(s: Session, app, link_id: int, decision: str, actor: str,
                note: str | None = None) -> dict:
    """Human decision on a cross-investigation link candidate."""
    from osint.analyst.tools import AnalystTools

    c = s.get(CrossLink, link_id)
    if c is None:
        raise ReviewError(f"no cross link {link_id}")
    tools = AnalystTools(app.session_factory, app.ontology, app.registry, app.raw_store,
                         c.investigation_a, actor=actor)
    if decision == "reject":
        return tools.reject_cross_link(link_id, note or "rejected by analyst")
    if decision != "confirm":
        raise ReviewError("decision must be confirm or reject")
    evidence = _link_evidence(s, c)
    if not evidence:
        raise ReviewError("no citations found on both sides to support this link")
    return tools.confirm_cross_link(link_id, note or "confirmed by analyst", evidence)


def _link_evidence(s: Session, c: CrossLink, per_side: int = 2) -> list[int]:
    """Citations mentioning the linking entity/event, from each investigation's documents."""
    out = []
    for inv in (c.investigation_a, c.investigation_b):
        docs = select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == inv, InvestigationRef.object_type == "document")
        if c.via_type == "entity":
            rels = select(Relation.id).where(or_(Relation.src_entity_id == c.via_id,
                                                 Relation.dst_entity_id == c.via_id))
            evs = select(EventParticipant.event_id).where(EventParticipant.entity_id == c.via_id)
            cond = or_((EvidenceLink.target_type == "relation") & EvidenceLink.target_id.in_(rels),
                       (EvidenceLink.target_type == "event") & EvidenceLink.target_id.in_(evs))
        else:
            cond = (EvidenceLink.target_type == "event") & (EvidenceLink.target_id == c.via_id)
        out += list(s.scalars(select(EvidenceLink.id).where(
            cond, EvidenceLink.document_id.in_(docs)).limit(per_side)))
    return out

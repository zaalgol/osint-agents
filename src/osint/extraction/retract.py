"""Retracting relations without deleting history.

Citations are append-only, so a wrong relation is not deleted. It is *retracted*: it
gets attributes.retracted = {reason, by, at}, stays in the database for the record,
and is filtered out of tools, the graph, the UI and exports (``active``).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.core.ontology import Ontology
from osint.storage.db import CitationRetraction, EvidenceLink, Relation


def active():
    """SQL filter: relations that are not retracted."""
    return Relation.attributes["retracted"].is_(None)


def retract(s: Session, relation_id: int, reason: str, by: str) -> Relation:
    r = s.get(Relation, relation_id)
    if r is None:
        raise ValueError(f"no relation {relation_id}")
    r.attributes = {**(r.attributes or {}),
                    "retracted": {"reason": reason, "by": by,
                                  "at": datetime.now(UTC).isoformat(timespec="seconds")}}
    return r


def unretract(s: Session, relation_id: int) -> Relation:
    r = s.get(Relation, relation_id)
    if r is None:
        raise ValueError(f"no relation {relation_id}")
    attrs = dict(r.attributes or {})
    attrs.pop("retracted", None)
    r.attributes = attrs
    return r


def valid_citation():
    """SQL filter: evidence links that have not been retracted."""
    return EvidenceLink.id.not_in(select(CitationRetraction.evidence_link_id))


def retract_citation(s: Session, evidence_id: int, reason: str, by: str) -> dict:
    """Retract one citation; a relation/event left without valid citations is retracted too."""
    ev = s.get(EvidenceLink, evidence_id)
    if ev is None:
        raise ValueError(f"no evidence link {evidence_id}")
    if s.get(CitationRetraction, evidence_id) is None:
        s.add(CitationRetraction(evidence_link_id=evidence_id, reason=reason, retracted_by=by))
        s.flush()
    left = s.scalar(select(EvidenceLink.id).where(
        EvidenceLink.target_type == ev.target_type, EvidenceLink.target_id == ev.target_id,
        valid_citation()).limit(1))
    out = {"citation": evidence_id, "target": f"{ev.target_type}:{ev.target_id}",
           "remaining_valid_citations": left is not None}
    if left is None and ev.target_type == "relation":
        retract(s, ev.target_id, f"all citations retracted ({reason})", by)
        out["relation_retracted"] = True
    return out


def cleanup_disallowed(s: Session, onto: Ontology, by: str = "cleanup") -> list[int]:
    """Retract LLM-extracted relations of types the extractor may no longer produce."""
    allowed = set(onto.extractable_relations())
    out = []
    for r in s.scalars(select(Relation).where(active(), Relation.type.not_in(allowed),
                                              Relation.created_by.like("extractor:%"))):
        retract(s, r.id, f"type {r.type!r} is not extractable (enrichment-only)", by)
        out.append(r.id)
    return out

"""Extraction writer: the gate between extractors and the knowledge base.

For each extracted item:
  1. ontology check (types, relation endpoints)
  2. quote verification against the document text (osint.extraction.quotes)
  3. entity resolution
  4. write the object + an evidence_link holding the *document's own text* at the
     matched span (never the LLM's version of the quote), quote_verified = true

Anything that fails goes to review_item, so nothing is silently dropped and nothing
unverified gets into the graph. All writes happen in the caller's transaction, where
the DB's deferred proof triggers check every relation/event has its citation at commit.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.core.models import EntityRef, ExtractionResult
from osint.core.ontology import Ontology, OntologyError
from osint.evidence import custody
from osint.extraction.quotes import QuoteIndex, QuoteMatch
from osint.resolution.resolver import Resolver, add_ref
from osint.storage.db import (
    Claim,
    Document,
    Entity,
    Event,
    EventParticipant,
    EvidenceLink,
    Mention,
    Relation,
    ReviewItem,
)
from osint.text.normalize import name_key


@dataclass
class WriteStats:
    relevant: bool = True
    entities: int = 0
    entities_created: int = 0
    mentions: int = 0
    relations: int = 0
    relations_reused: int = 0
    events: int = 0
    events_reused: int = 0
    claims: int = 0
    citations: int = 0
    rejected: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


_TIME = re.compile(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?")


def parse_time(value: str | None) -> tuple[datetime | None, str | None]:
    if not value:
        return None, None
    m = _TIME.match(value.strip())
    if not m:
        return None, None
    y, mo, d, hh, mm, ss = m.groups()
    try:
        dt = datetime(int(y), int(mo or 1), int(d or 1), int(hh or 0), int(mm or 0),
                      int(ss or 0), tzinfo=UTC)
    except ValueError:
        return None, None
    precision = "exact" if hh else "day" if d else "month" if mo else "year"
    return dt, precision


class ExtractionWriter:
    def __init__(self, session: Session, ontology: Ontology, investigation_id: int,
                 document: Document, actor: str):
        self.s = session
        self.onto = ontology
        self.inv = investigation_id
        self.doc = document
        self.actor = actor
        self.qi = QuoteIndex(document.text)
        self.resolver = Resolver(session, ontology, investigation_id, actor)
        self.stats = WriteStats()
        self._by_name: dict[str, Entity] = {}

    # ------------------------------------------------------------------ public

    def write(self, result: ExtractionResult, chunk_start: int | None = None) -> WriteStats:
        if not result.relevant:
            self.stats.relevant = False
            return self.stats
        for e in result.entities:
            self._entity(e.name, e.type, e.quote, e.attributes, result.language, chunk_start)
        for r in result.relations:
            self._relation(r, chunk_start)
        for ev in result.events:
            self._event(ev, result.language, chunk_start)
        return self.stats

    def finish(self, extractor: str) -> None:
        self.stats.entities_created = self.resolver.created
        custody.append(self.s, "extracted", self.actor, self.doc.artifact_id,
                       {"document_id": self.doc.id, "text_sha256": self.doc.text_sha256,
                        "extractor": extractor, **self.stats.as_dict()})

    # ------------------------------------------------------------------ helpers

    def _review(self, kind: str, reason: str, payload: dict) -> None:
        self.stats.rejected += 1
        self.s.add(ReviewItem(investigation_id=self.inv, kind=kind, reason=reason,
                              payload=payload, document_id=self.doc.id, created_by=self.actor))

    def _verify(self, quote: str, near: int | None, what: str, payload: dict) -> QuoteMatch | None:
        m = self.qi.find(quote, near=near)
        if m is None:
            self._review("quote_not_found", f"{what}: quote not found in document text",
                         {**payload, "quote": quote})
        return m

    def _cite(self, target_type: str, target_id: int, m: QuoteMatch,
              translated: str | None = None) -> None:
        exists = self.s.scalar(select(EvidenceLink.id).where(
            EvidenceLink.target_type == target_type, EvidenceLink.target_id == target_id,
            EvidenceLink.document_id == self.doc.id, EvidenceLink.char_start == m.start,
            EvidenceLink.char_end == m.end))
        if exists:
            return
        self.s.add(EvidenceLink(
            target_type=target_type, target_id=target_id, artifact_id=self.doc.artifact_id,
            document_id=self.doc.id, quote_original=m.text(self.doc.text),
            quote_translated=translated or None,
            translator=self.actor if translated else None,
            char_start=m.start, char_end=m.end, quote_verified=True,
            verified_at=datetime.now(UTC), created_by=f"{self.actor}#{m.method}",
        ))
        self.stats.citations += 1

    def _entity(self, name: str, etype: str, quote: str | None, attributes: dict | None,
                lang: str | None, near: int | None) -> Entity | None:
        key = name_key(name)
        if etype not in self.onto.entity_types:
            self._review("ontology", f"unknown entity type {etype!r}",
                         {"name": name, "type": etype})
            return None
        cached = self._by_name.get(key)
        if cached is not None and self.resolver.root(cached.type) == self.resolver.root(etype):
            return cached
        spans = self.qi.occurrences(name)
        if not spans and quote:
            # the name may be inflected/abbreviated; accept if the quote is verifiable
            m = self.qi.find(quote, near=near)
            spans = [(m.start, m.end)] if m else []
        if not spans:
            self._review("quote_not_found", "entity name/quote not found in document text",
                         {"name": name, "type": etype, "quote": quote})
            return None
        try:
            ent = self.resolver.resolve(name, etype, lang=lang,
                                        source_artifact_id=self.doc.artifact_id,
                                        attributes=attributes or None)
        except (OntologyError, ValueError) as e:
            self._review("ontology", str(e), {"name": name, "type": etype})
            return None
        self.stats.entities += 1
        self._by_name[key] = ent
        existing = set(self.s.execute(
            select(Mention.char_start, Mention.char_end).where(
                Mention.entity_id == ent.id, Mention.document_id == self.doc.id)).all())
        for s, e in spans:
            if (s, e) in existing:
                continue
            ctx = self.doc.text[max(0, s - 120):e + 120]
            self.s.add(Mention(entity_id=ent.id, document_id=self.doc.id, char_start=s,
                               char_end=e, surface=self.doc.text[s:e], context=ctx,
                               confidence=0.8, extractor=self.actor))
            self.stats.mentions += 1
        return ent

    def _ref(self, ref: EntityRef, near: int | None) -> Entity | None:
        return self._by_name.get(name_key(ref.name)) or self._entity(
            ref.name, ref.type, None, None, None, near)

    def _relation(self, r, near: int | None) -> None:
        payload = r.model_dump()
        if r.type not in self.onto.relation_types:
            self._review("ontology", f"unknown relation type {r.type!r}", payload)
            return
        m = self._verify(r.quote, near, f"relation {r.type}", payload)
        if m is None:
            return
        weak = self._weak_relation_quote(m.text(self.doc.text), r)
        if weak:
            self._review("weak_citation", f"relation {r.type}: {weak}", payload)
            return
        src, dst = self._ref(r.src, near), self._ref(r.dst, near)
        if src is None or dst is None:
            self._review("unresolved", "relation endpoint could not be resolved", payload)
            return
        if src.id == dst.id:
            return
        try:
            self.onto.check_relation(r.type, src.type, dst.type)
        except OntologyError as e:
            self._review("ontology", str(e), payload)
            return
        if r.stance in ("denied", "speculative"):
            self._claim(r, src, dst, m)
            return
        rel = self.s.scalar(select(Relation).where(
            Relation.type == r.type, Relation.src_entity_id == src.id,
            Relation.dst_entity_id == dst.id))
        if rel is None:
            rel = Relation(type=r.type, src_entity_id=src.id, dst_entity_id=dst.id,
                           confidence=r.confidence, created_by=self.actor,
                           attributes={"stance": r.stance} if r.stance == "reported" else {})
            self.s.add(rel)
            self.s.flush()
            self.stats.relations += 1
        else:
            rel.confidence = max(rel.confidence, r.confidence)
            self.stats.relations_reused += 1
        self._cite("relation", rel.id, m, r.quote_en)
        add_ref(self.s, self.inv, "relation", rel.id, self.actor)

    def _claim(self, r, src: Entity, dst: Entity, m: QuoteMatch) -> None:
        """A denied or speculative relation is recorded as a cited claim, not as a fact."""
        stance = {"denied": "denies", "speculative": "speculates"}[r.stance]
        claim = self.s.scalar(select(Claim).where(
            Claim.subject_type == "entity", Claim.subject_id == src.id,
            Claim.predicate == r.type, Claim.object_type == "entity",
            Claim.object_id == dst.id, Claim.stance == stance))
        if claim is None:
            claim = Claim(subject_type="entity", subject_id=src.id, predicate=r.type,
                          object_type="entity", object_id=dst.id, stance=stance,
                          confidence=r.confidence, created_by=self.actor)
            self.s.add(claim)
            self.s.flush()
            self.stats.claims += 1
        self._cite("claim", claim.id, m, r.quote_en)
        add_ref(self.s, self.inv, "claim", claim.id, self.actor)

    @staticmethod
    def _weak_relation_quote(quote: str, r) -> str | None:
        """A relation's quote must be a statement, not just a name: at least 3 words, and
        it must mention one of the two entities (a pronoun can stand for the other)."""
        if len(quote.split()) < 3:
            return "quote is too short to state a relation"
        q = name_key(quote)
        names = [name_key(r.src.name), name_key(r.dst.name)]
        if not any(n and (n in q or all(t in q.split() for t in n.split())) for n in names):
            return "quote mentions neither entity"
        return None

    def _event(self, ev, lang: str | None, near: int | None) -> None:
        payload = ev.model_dump()
        if ev.type not in self.onto.event_types:
            self._review("ontology", f"unknown event type {ev.type!r}", payload)
            return
        m = self._verify(ev.quote, near, f"event {ev.type}", payload)
        if m is None:
            return
        # same event, same evidence span (e.g. re-extraction): reuse instead of duplicating
        event = self.s.scalar(
            select(Event).join(EvidenceLink, (EvidenceLink.target_type == "event")
                               & (EvidenceLink.target_id == Event.id))
            .where(Event.type == ev.type, EvidenceLink.document_id == self.doc.id,
                   EvidenceLink.char_start == m.start, EvidenceLink.char_end == m.end))
        if event is not None:
            self.stats.events_reused += 1
            add_ref(self.s, self.inv, "event", event.id, self.actor)
            return
        when, precision = parse_time(ev.time)
        loc = None
        if ev.location:
            loc = self._ref(EntityRef(name=ev.location, type="location"), near)
        event = Event(type=ev.type, time=when, time_precision=precision,
                      location_entity_id=loc.id if loc else None, description=ev.description,
                      attributes={"lang": lang} if lang else {}, confidence=ev.confidence,
                      created_by=self.actor)
        self.s.add(event)
        self.s.flush()
        roles = set(self.onto.event_roles(ev.type))
        seen: set[tuple[int, str]] = set()
        for p in ev.participants:
            ent = self._ref(p, near)
            if ent is None:
                continue
            role = p.role if p.role in roles else f"other:{p.role}"[:64]
            if (ent.id, role) not in seen:
                seen.add((ent.id, role))
                self.s.add(EventParticipant(event_id=event.id, entity_id=ent.id, role=role))
        self._cite("event", event.id, m, getattr(ev, "quote_en", None))
        add_ref(self.s, self.inv, "event", event.id, self.actor)
        self.stats.events += 1

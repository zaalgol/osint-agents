"""Fuzzy entity resolution: block -> score -> decide (auto / LLM judge / human review).

Candidates come from three blocks:
  * embedding nearest neighbours (bge-m3, multilingual: "Houthis" ~ "Iran-aligned Houthi
    rebels" ~ "الحوثيون")
  * transliterated name similarity (anyascii + rapidfuzz: "Sana'a" ~ "Sanaa" ~ "صنعاء")
  * open resolution_candidate review items (person namesakes found during extraction)

Decision rules (conservative):
  * strong-identifier types are never fuzzy-merged (different keys = different identifiers)
  * score >= auto_threshold and not a person: merge automatically
  * score >= judge_threshold, or any person pair: the local LLM judges with context
    (aliases, relations, events, mention snippets). "same" with enough confidence: merge;
    "different": remember the decision; "unsure": human review item
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Literal

from anyascii import anyascii
from pydantic import BaseModel, Field
from rapidfuzz import fuzz
from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from osint.core.context import App
from osint.resolution.merge import choose_winner, merge_entities
from osint.storage.db import (
    Entity,
    EntityAlias,
    Event,
    EventParticipant,
    InvestigationRef,
    Mention,
    Relation,
    ReviewItem,
)
from osint.text.normalize import name_key

PERSON = {"person"}


class SameEntity(BaseModel):
    same_entity: Literal["yes", "no", "unsure"]
    confidence: float = Field(ge=0, le=1)
    reason: str


JUDGE_SYSTEM = """You decide whether two records in an intelligence knowledge base refer to \
the SAME real-world entity. Names may be in different scripts, transliterations, \
abbreviations or descriptive forms ("Houthis" = "Ansar Allah" = "Iran-aligned Houthi rebels"). \
Use the aliases, relations, events and text snippets. Be strict with people: a shared \
common name is NOT enough, so require matching context (roles, organizations, places, \
events). A broader group and one of its sub-units are different entities. Answer "unsure" \
when the evidence doesn't decide it."""


@dataclass
class Candidate:
    a: int
    b: int
    type_a: str
    type_b: str
    name_sim: float = 0.0
    emb_sim: float = 0.0
    neighbor_jaccard: float = 0.0
    sources: set[str] = field(default_factory=set)

    @property
    def score(self) -> float:
        base = 0.55 * self.name_sim + 0.45 * self.emb_sim
        if self.name_sim >= 0.97 or self.emb_sim >= 0.97:
            base = max(base, 0.9)
        return min(1.0, base + 0.15 * self.neighbor_jaccard)


@dataclass
class ERReport:
    candidates: int = 0
    auto_merged: list[int] = field(default_factory=list)
    llm_merged: list[int] = field(default_factory=list)
    judged_different: int = 0
    sent_to_review: int = 0
    below_threshold: int = 0
    would_auto: int = 0       # decisions (also filled on dry runs)
    would_llm: int = 0
    details: list[dict] = field(default_factory=list)


def ascii_key(name: str) -> str:
    return " ".join(name_key(anyascii(name)).split())


def name_similarity(x: str, y: str) -> float:
    """Token-set similarity, plus containment: every token of the shorter name appears
    (fuzzily, so plurals and inflections still count) in the longer one, as in
    "Houthis" in "Iran-aligned Houthi rebels". Containment caps at 0.85: it qualifies a
    pair for the LLM judge but never auto-merges it ("Riyadh" vs "Riyadh airport")."""
    base = fuzz.token_set_ratio(x, y) / 100
    short, long_ = sorted((x.split(), y.split()), key=len)
    if short and len(short) < len(long_) and all(
            max(fuzz.ratio(t, u) for u in long_) >= 85 for t in short if len(t) >= 3):
        base = max(base, 0.85)
    return base


class EntityResolver:
    def __init__(self, app: App, llm=None, *, auto_threshold: float = 0.93,
                 judge_threshold: float = 0.72, judge_confidence: float = 0.8,
                 knn: int = 6, min_emb: float = 0.78, judge_role: str = "agent"):
        self.app = app
        self.llm = llm
        self.auto = auto_threshold
        self.judge_at = judge_threshold
        self.judge_conf = judge_confidence
        self.knn = knn
        self.min_emb = min_emb
        self.role = judge_role
        onto = app.ontology
        self.strong = onto.strong_identifier_types()

    def root(self, t: str) -> str:
        chain = self.app.ontology._ancestors(self.app.ontology.entity_types, t)
        return chain[-1] if chain else t

    # ------------------------------------------------------------------ blocking

    def _scope_ids(self, s: Session, investigation_id: int | None) -> list[int]:
        q = select(Entity.id).where(Entity.merged_into_id.is_(None))
        if investigation_id is not None:
            q = q.where(Entity.id.in_(select(InvestigationRef.object_id).where(
                InvestigationRef.investigation_id == investigation_id,
                InvestigationRef.object_type == "entity")))
        return list(s.scalars(q))

    def candidates(self, s: Session, investigation_id: int | None) -> dict[tuple[int, int], Candidate]:
        ents = {e.id: e for e in s.scalars(select(Entity).where(Entity.merged_into_id.is_(None)))}
        scope = [i for i in self._scope_ids(s, investigation_id) if ents[i].type not in self.strong]
        aliases: dict[int, set[str]] = {}
        for eid, alias in s.execute(select(EntityAlias.entity_id, EntityAlias.alias)):
            if eid in ents:
                aliases.setdefault(eid, set()).add(alias)
        keys = {eid: {ascii_key(a) for a in al} | {ascii_key(ents[eid].canonical_name)}
                for eid, al in aliases.items()}
        cands: dict[tuple[int, int], Candidate] = {}

        def add(a: int, b: int, source: str) -> Candidate | None:
            if a == b or a not in ents or b not in ents:
                return None
            ta, tb = ents[a].type, ents[b].type
            if ta in self.strong or tb in self.strong or self.root(ta) != self.root(tb):
                return None
            key = (min(a, b), max(a, b))
            c = cands.get(key)
            if c is None:
                c = cands[key] = Candidate(key[0], key[1], ents[key[0]].type, ents[key[1]].type)
            c.sources.add(source)
            return c

        # 1. embeddings: nearest neighbours within the type family
        for eid in scope:
            if ents[eid].embedding is None:
                continue
            fam = [t for t in self.app.ontology.entity_types if self.root(t) == self.root(ents[eid].type)]
            rows = s.execute(text(
                "SELECT id, 1 - (embedding <=> (SELECT embedding FROM entity WHERE id = :id)) AS sim "
                "FROM entity WHERE id <> :id AND merged_into_id IS NULL AND embedding IS NOT NULL "
                "AND type = ANY(:fam) ORDER BY embedding <=> (SELECT embedding FROM entity "
                "WHERE id = :id) LIMIT :k"), {"id": eid, "fam": fam, "k": self.knn})
            for other, sim in rows:
                if sim >= self.min_emb and (c := add(eid, other, "embedding")):
                    c.emb_sim = max(c.emb_sim, float(sim))

        # 2. transliterated names (blocked by first letter of each key token)
        index: dict[tuple[str, str], set[int]] = {}
        for eid, ks in keys.items():
            for k in ks:
                for tok in k.split():
                    if len(tok) >= 3:
                        index.setdefault((self.root(ents[eid].type), tok[:3]), set()).add(eid)
        for eid in scope:
            fam = self.root(ents[eid].type)
            pool = set()
            for k in keys.get(eid, ()):
                for tok in k.split():
                    pool |= index.get((fam, tok[:3]), set())
            for other in pool:
                if other == eid:
                    continue
                sim = max((name_similarity(x, y) for x in keys.get(eid, ())
                           for y in keys.get(other, ())), default=0.0)
                if sim >= 0.85 and (c := add(eid, other, "name")):
                    c.name_sim = max(c.name_sim, sim)

        # 3. namesake review items from extraction
        q = select(ReviewItem).where(ReviewItem.kind == "resolution_candidate",
                                     ReviewItem.status == "open")
        if investigation_id is not None:
            q = q.where(ReviewItem.investigation_id == investigation_id)
        for r in s.scalars(q):
            for other in r.payload.get("candidates", []):
                add(int(r.payload["entity_id"]), int(other), "namesake")

        # fill the missing similarity components for every candidate
        for c in cands.values():
            if not c.name_sim:
                c.name_sim = max((name_similarity(x, y) for x in keys.get(c.a, ())
                                  for y in keys.get(c.b, ())), default=0.0)
            if not c.emb_sim and ents[c.a].embedding is not None and ents[c.b].embedding is not None:
                c.emb_sim = float(s.scalar(text(
                    "SELECT 1 - (a.embedding <=> b.embedding) FROM entity a, entity b "
                    "WHERE a.id = :a AND b.id = :b"), {"a": c.a, "b": c.b}) or 0)
            na, nb = self._neighbors(s, c.a), self._neighbors(s, c.b)
            if na or nb:
                c.neighbor_jaccard = len(na & nb) / len(na | nb)
        return cands

    def _neighbors(self, s: Session, eid: int) -> set[int]:
        out = set()
        for a, b in s.execute(select(Relation.src_entity_id, Relation.dst_entity_id).where(
                or_(Relation.src_entity_id == eid, Relation.dst_entity_id == eid),
                Relation.attributes["retracted"].is_(None))):
            out |= {a, b}
        events = select(EventParticipant.event_id).where(EventParticipant.entity_id == eid)
        out |= set(s.scalars(select(EventParticipant.entity_id).where(
            EventParticipant.event_id.in_(events))))
        out.discard(eid)
        return out

    # ------------------------------------------------------------------ judging

    def _profile(self, s: Session, eid: int) -> str:
        e = s.get(Entity, eid)
        aliases = sorted(set(s.scalars(select(EntityAlias.alias).where(
            EntityAlias.entity_id == eid).limit(15))))
        other = Entity.__table__.alias("o")
        rels = s.execute(select(Relation.type, other.c.canonical_name).join(
            other, other.c.id == Relation.dst_entity_id).where(Relation.src_entity_id == eid)
            .limit(6)).all() + s.execute(select(Relation.type, other.c.canonical_name).join(
                other, other.c.id == Relation.src_entity_id).where(Relation.dst_entity_id == eid)
                .limit(6)).all()
        evs = s.execute(select(Event.description, EventParticipant.role).join(
            EventParticipant, EventParticipant.event_id == Event.id)
            .where(EventParticipant.entity_id == eid).limit(4)).all()
        ctx = s.scalars(select(Mention.context).where(Mention.entity_id == eid).limit(3)).all()
        invs = sorted(set(s.scalars(select(InvestigationRef.investigation_id).where(
            InvestigationRef.object_type == "entity", InvestigationRef.object_id == eid))))
        lines = [f"type: {e.type}", f"name: {e.canonical_name}",
                 f"aliases: {', '.join(aliases)}", f"investigations: {invs}"]
        lines += [f"relation: {t} -> {n}" for t, n in rels]
        lines += [f"event ({r}): {d}" for d, r in evs]
        lines += [f"text: …{(c or '').strip()[:300]}…" for c in ctx]
        return "\n".join(lines)

    async def judge(self, s: Session, c: Candidate) -> SameEntity:
        prompt = (f"RECORD A (id {c.a})\n{self._profile(s, c.a)}\n\n"
                  f"RECORD B (id {c.b})\n{self._profile(s, c.b)}")
        return await self.llm.chat_json(self.role, JUDGE_SYSTEM, prompt, SameEntity)

    def _decided(self, s: Session, c: Candidate) -> bool:
        """Has an analyst/LLM already said these two are different (or is review open)?"""
        rows = s.scalars(select(ReviewItem).where(
            ReviewItem.kind == "resolution_pair",
            ReviewItem.payload["a"].as_integer() == c.a,
            ReviewItem.payload["b"].as_integer() == c.b))
        return any(r.status in ("rejected", "open") for r in rows)

    # ------------------------------------------------------------------ main

    async def run(self, investigation_id: int | None = None, use_llm: bool = True,
                  dry_run: bool = False, max_judgements: int = 200) -> ERReport:
        rep = ERReport()
        with self.app.session_factory() as s:
            cands = sorted(self.candidates(s, investigation_id).values(),
                           key=lambda c: -c.score)
        rep.candidates = len(cands)
        judged = 0
        for c in cands:
            with self.app.session_factory() as s, s.begin():
                ea, eb = s.get(Entity, c.a), s.get(Entity, c.b)
                if ea.merged_into_id or eb.merged_into_id or self._decided(s, c):
                    continue
                person = self.root(c.type_a) in PERSON
                detail = {"a": c.a, "b": c.b, "names": [ea.canonical_name, eb.canonical_name],
                          "score": round(c.score, 3), "name_sim": round(c.name_sim, 3),
                          "emb_sim": round(c.emb_sim, 3), "via": sorted(c.sources)}
                if c.score >= self.auto and not person:
                    detail["decision"] = "auto-merge"
                    if not dry_run:
                        w, lo = choose_winner(s, c.a, c.b)
                        m = merge_entities(s, w, lo, method="er:auto", score=c.score,
                                           rationale=str(detail), decided_by="er:auto")
                        rep.auto_merged.append(m.id)
                elif (c.score >= self.judge_at or "namesake" in c.sources) and use_llm \
                        and self.llm is not None and judged < max_judgements:
                    judged += 1
                    v = await self.judge(s, c)
                    detail.update(decision=f"llm:{v.same_entity}", confidence=v.confidence,
                                  reason=v.reason)
                    if v.same_entity == "yes" and v.confidence >= self.judge_conf:
                        if not dry_run:
                            w, lo = choose_winner(s, c.a, c.b)
                            m = merge_entities(s, w, lo, method="er:llm", score=c.score,
                                               rationale=v.reason, decided_by="er:llm")
                            rep.llm_merged.append(m.id)
                    elif v.same_entity == "no" and v.confidence >= self.judge_conf:
                        rep.judged_different += 1
                        if not dry_run:
                            self._record(s, c, "rejected", f"judged different: {v.reason}", detail)
                    else:
                        rep.sent_to_review += 1
                        if not dry_run:
                            self._record(s, c, "open", f"unsure ({v.confidence:.2f}): {v.reason}",
                                         detail)
                elif c.score >= self.judge_at or "namesake" in c.sources:
                    rep.sent_to_review += 1
                    detail["decision"] = "review"
                    if not dry_run:
                        self._record(s, c, "open", "needs judgement (no LLM)", detail)
                else:
                    rep.below_threshold += 1
                    detail["decision"] = "below-threshold"
                rep.details.append(detail)
            await asyncio.sleep(0)
        decisions = [d.get("decision", "") for d in rep.details]
        rep.would_auto = decisions.count("auto-merge")
        rep.would_llm = decisions.count("llm:yes")
        return rep

    def _record(self, s: Session, c: Candidate, status: str, reason: str, detail: dict) -> None:
        s.add(ReviewItem(kind="resolution_pair", reason=reason[:2000], status=status,
                         payload={"a": c.a, "b": c.b, **detail}, created_by="er"))

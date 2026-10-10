"""Basic entity resolution (Phase 1: exact + normalized).

Rules, from safest to riskiest:
  1. Strong identifiers (email, phone, wallet, domain, URL, handle) match globally on
     their canonical key. This is what connects investigations automatically.
  2. Non-person names (organizations, groups, places, ...) match globally on the
     normalized name within the same type family (armed_group ~ organization).
  3. People match on normalized name only *within the current investigation*. Two
     "Mohammed Ali"s in different cases are not assumed to be the same person: a
     resolution_candidate review item is recorded for the Phase 3 resolver or an analyst.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from osint.core.ontology import Ontology, OntologyError
from osint.resolution.normalize import name_key, strong_key
from osint.storage.db import Entity, EntityAlias, InvestigationRef, ReviewItem

PERSON_SCOPED = {"person"}


@dataclass
class Resolver:
    session: Session
    ontology: Ontology
    investigation_id: int
    actor: str
    _cache: dict[tuple[str, str], int] = field(default_factory=dict)
    created: int = 0
    matched: int = 0

    def root(self, etype: str) -> str:
        chain = self.ontology._ancestors(self.ontology.entity_types, etype)
        return chain[-1] if chain else etype

    def family(self, etype: str) -> list[str]:
        r = self.root(etype)
        return [t for t in self.ontology.entity_types if self.root(t) == r]

    def resolve(self, name: str, etype: str, *, lang: str | None = None,
                source_artifact_id: int | None = None,
                attributes: dict | None = None) -> Entity:
        name = " ".join(name.split())
        if etype not in self.ontology.entity_types:
            raise OntologyError(f"unknown entity type {etype!r}")
        if not name:
            raise ValueError("empty entity name")

        skey = strong_key(etype, name, self.ontology)
        nkey = name_key(name)
        cache_key = (etype if skey else self.root(etype), skey or nkey)
        if cache_key in self._cache:
            ent = self.session.get(Entity, self._cache[cache_key])
        elif skey:
            ent = self._by_strong_key(etype, skey)
        else:
            ent = self._by_name(etype, nkey)

        if ent is None:
            ent = self._create(etype, name, skey, attributes)
            self.created += 1
            if etype in PERSON_SCOPED or self.root(etype) in PERSON_SCOPED:
                self._flag_namesakes(ent, nkey)
        else:
            self.matched += 1
            if attributes:
                ent.attributes = {**attributes, **(ent.attributes or {})}
        self._cache[cache_key] = ent.id
        self._alias(ent, name, nkey, lang, source_artifact_id)
        self.ref(ent.id)
        return ent

    # ------------------------------------------------------------------ lookups

    def _by_strong_key(self, etype: str, skey: str) -> Entity | None:
        return self.session.scalar(
            select(Entity).where(Entity.type == etype, Entity.strong_key == skey,
                                 Entity.merged_into_id.is_(None))
        )

    def _by_name(self, etype: str, nkey: str) -> Entity | None:
        q = (
            select(Entity)
            .join(EntityAlias, EntityAlias.entity_id == Entity.id)
            .where(EntityAlias.alias_norm == nkey, Entity.type.in_(self.family(etype)),
                   Entity.merged_into_id.is_(None))
            .order_by(Entity.id)
            .limit(1)
        )
        if etype in PERSON_SCOPED or self.root(etype) in PERSON_SCOPED:
            q = q.join(InvestigationRef, (InvestigationRef.object_type == "entity")
                       & (InvestigationRef.object_id == Entity.id)
                       & (InvestigationRef.investigation_id == self.investigation_id))
        return self.session.scalar(q)

    def _create(self, etype: str, name: str, skey: str | None, attributes) -> Entity:
        ent = Entity(type=etype, canonical_name=name, strong_key=skey,
                     attributes=attributes or {})
        if skey is None:
            self.session.add(ent)
            self.session.flush()
            return ent
        try:
            with self.session.begin_nested():  # concurrent workers may race on strong keys
                self.session.add(ent)
                self.session.flush()
            return ent
        except IntegrityError:
            existing = self._by_strong_key(etype, skey)
            if existing is None:
                raise
            return existing

    def _alias(self, ent: Entity, alias: str, nkey: str, lang, source_artifact_id) -> None:
        self.session.execute(
            pg_insert(EntityAlias)
            # "und" (undetermined) not NULL: NULLs never collide in a unique constraint
            .values(entity_id=ent.id, alias=alias, alias_norm=nkey, alias_type="name",
                    lang=lang or "und", source_artifact_id=source_artifact_id)
            .on_conflict_do_nothing(constraint="uq_alias")
        )

    def ref(self, entity_id: int, object_type: str = "entity") -> None:
        add_ref(self.session, self.investigation_id, object_type, entity_id, self.actor)

    def _flag_namesakes(self, ent: Entity, nkey: str) -> None:
        others = self.session.scalars(
            select(Entity.id)
            .join(EntityAlias, EntityAlias.entity_id == Entity.id)
            .where(EntityAlias.alias_norm == nkey, Entity.type.in_(self.family(ent.type)),
                   Entity.id != ent.id, Entity.merged_into_id.is_(None))
            .distinct()
            .limit(20)
        ).all()
        if others:
            self.session.add(ReviewItem(
                investigation_id=self.investigation_id, kind="resolution_candidate",
                reason=f"{ent.type} {ent.canonical_name!r} has namesakes in other investigations",
                payload={"entity_id": ent.id, "candidates": list(others), "method": "name_key"},
                created_by=self.actor,
            ))


def add_ref(session: Session, investigation_id: int, object_type: str, object_id: int,
            actor: str) -> None:
    session.execute(
        pg_insert(InvestigationRef)
        .values(investigation_id=investigation_id, object_type=object_type,
                object_id=object_id, added_by=actor)
        .on_conflict_do_nothing()
    )

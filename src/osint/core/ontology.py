"""Ontology: entity/relation/event types loaded from YAML.

The base file and plugin fragments are merged additively. A fragment may add new
types, but redefining an existing one is an error, so plugins can't silently change
meaning for data already stored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SECTIONS = ("entity_types", "relation_types", "event_types")


class OntologyError(ValueError):
    pass


@dataclass
class Ontology:
    entity_types: dict[str, dict[str, Any]] = field(default_factory=dict)
    relation_types: dict[str, dict[str, Any]] = field(default_factory=dict)
    event_types: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_reliability: list[str] = field(default_factory=list)
    information_credibility: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(cls, paths: list[Path]) -> Ontology:
        onto = cls()
        for p in paths:
            onto.merge(yaml.safe_load(Path(p).read_text(encoding="utf-8")) or {}, origin=str(p))
        onto.validate()
        return onto

    def merge(self, fragment: dict[str, Any], origin: str = "<fragment>") -> None:
        for section in SECTIONS:
            target: dict[str, dict[str, Any]] = getattr(self, section)
            for name, spec in (fragment.get(section) or {}).items():
                spec = spec or {}
                if name in target and target[name] != spec:
                    raise OntologyError(f"{origin}: {section}.{name} already defined differently")
                target[name] = spec
        for key in ("source_reliability", "information_credibility"):
            if key in fragment and not getattr(self, key):
                setattr(self, key, [str(v) for v in fragment[key]])

    def validate(self) -> None:
        for section in SECTIONS:
            types: dict[str, dict[str, Any]] = getattr(self, section)
            for name, spec in types.items():
                parent = spec.get("parent")
                if parent and parent not in types:
                    raise OntologyError(f"{section}.{name}: unknown parent {parent!r}")
                self._ancestors(types, name)  # raises on cycles
        for name, spec in self.relation_types.items():
            for end in ("from", "to"):
                for t in spec.get(end) or []:
                    if t not in self.entity_types:
                        raise OntologyError(f"relation_types.{name}.{end}: unknown entity type {t!r}")

    # ------------------------------------------------------------------ queries

    @staticmethod
    def _ancestors(types: dict[str, dict[str, Any]], name: str) -> list[str]:
        chain, seen = [], {name}
        cur = types[name].get("parent")
        while cur:
            if cur in seen:
                raise OntologyError(f"inheritance cycle at {name!r}")
            seen.add(cur)
            chain.append(cur)
            cur = types[cur].get("parent")
        return chain

    def entity_is_a(self, type_: str, ancestor: str) -> bool:
        if type_ not in self.entity_types:
            return False
        return type_ == ancestor or ancestor in self._ancestors(self.entity_types, type_)

    def strong_identifier_types(self) -> set[str]:
        return {
            n for n in self.entity_types
            if self._inherited(self.entity_types, n, "strong_identifier")
        }

    def _inherited(self, types: dict[str, dict[str, Any]], name: str, key: str) -> Any:
        for t in [name, *self._ancestors(types, name)]:
            if key in types[t]:
                return types[t][key]
        return None

    def check_relation(self, rel_type: str, src_type: str, dst_type: str) -> None:
        """Raise OntologyError if the relation is not allowed between these entity types."""
        if rel_type not in self.relation_types:
            raise OntologyError(f"unknown relation type {rel_type!r}")
        for end, etype in (("from", src_type), ("to", dst_type)):
            allowed = self._inherited(self.relation_types, rel_type, end)
            if allowed and not any(self.entity_is_a(etype, a) for a in allowed):
                raise OntologyError(f"{rel_type}: {etype!r} not allowed as {end!r} ({allowed})")

    def extractable_relations(self) -> list[str]:
        """Relation types the extraction LLM may produce (excludes enrichment-only types)."""
        return [n for n, spec in self.relation_types.items()
                if spec.get("extractable", True) and n != "same_as"]

    def event_roles(self, event_type: str) -> list[str]:
        if event_type not in self.event_types:
            raise OntologyError(f"unknown event type {event_type!r}")
        return list(self._inherited(self.event_types, event_type, "roles") or [])

"""Enrichment contract and persistence.

An enricher looks up one entity in an outside source (RDAP, OpenStreetMap, a block
explorer, sanctions lists) and returns:
  captures    the source responses, each persisted with the full proof bundle
  facts_text  a human-readable summary derived *only* from those responses; it becomes a
              derived artifact + document, so every citation quotes it verbatim
  extraction  relations/entities to add, with quotes taken from facts_text
  attributes  stored on the entity under attributes[<enricher>] with the artifact id
  reviews     things a human must confirm (e.g. a sanctions name match on a person)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select

from osint.core.models import CapturedItem, CaptureMeta, ExtractionResult
from osint.evidence import custody
from osint.evidence.capture import persist_item
from osint.extraction.writer import ExtractionWriter
from osint.resolution.resolver import add_ref
from osint.storage.db import Document, Entity, EntityAlias, ReviewItem


class EntityView(BaseModel):
    id: int
    type: str
    name: str
    strong_key: str | None = None
    aliases: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


@dataclass
class EnrichmentResult:
    captures: list[CapturedItem] = field(default_factory=list)
    facts_text: str | None = None
    extraction: ExtractionResult | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    reviews: list[dict] = field(default_factory=list)
    skipped: str | None = None          # why nothing was looked up


def entity_view(s, entity_id: int) -> EntityView:
    e = s.get(Entity, entity_id)
    aliases = sorted(set(s.scalars(select(EntityAlias.alias).where(EntityAlias.entity_id == e.id))))
    return EntityView(id=e.id, type=e.type, name=e.canonical_name, strong_key=e.strong_key,
                      aliases=aliases, attributes=e.attributes or {})


def persist_enrichment(s, app, investigation_id: int, entity_id: int, enricher_ident: str,
                       enricher_name: str, res: EnrichmentResult) -> dict:
    """Store captures, the derived facts document, the extraction and attributes."""
    store = app.raw_store
    shas = []
    for item in res.captures:
        art, _ = persist_item(s, store, item, actor=enricher_ident)
        add_ref(s, investigation_id, "artifact", art.id, enricher_ident)
        shas.append(art.sha256)
    out: dict[str, Any] = {"captures": len(shas)}
    doc_id = None
    if res.facts_text:
        meta = CaptureMeta(url=f"enrichment://{enricher_name}/entity/{entity_id}",
                           collector=enricher_ident, platform=f"enrichment:{enricher_name}",
                           extra={"derived_from": shas, "entity_id": entity_id})
        art, _ = persist_item(s, store, CapturedItem(data=res.facts_text.encode("utf-8"),
                                                     meta=meta, mime="text/plain"),
                              actor=enricher_ident)
        add_ref(s, investigation_id, "artifact", art.id, enricher_ident)
        text = res.facts_text
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        doc = s.scalar(select(Document).where(Document.artifact_id == art.id,
                                              Document.text_sha256 == sha))
        if doc is None:
            doc = Document(artifact_id=art.id, extractor=enricher_ident, text=text,
                           text_sha256=sha, title=f"{enricher_name} enrichment",
                           meta={"derived_from": shas})
            s.add(doc)
            s.flush()
            custody.append(s, "derived", enricher_ident, art.id,
                           {"document_id": doc.id, "derived_from": shas})
        add_ref(s, investigation_id, "document", doc.id, enricher_ident)
        doc_id = doc.id
        if res.extraction is not None:
            w = ExtractionWriter(s, app.ontology, investigation_id, doc, actor=enricher_ident)
            w.write(res.extraction)
            w.finish(enricher_ident)
            out.update(relations=w.stats.relations, rejected=w.stats.rejected)
    if res.attributes:
        e = s.get(Entity, entity_id)
        attrs = dict(e.attributes or {})
        attrs[enricher_name] = {**res.attributes, "source_document": doc_id,
                                "enriched_at": datetime.now(UTC).isoformat(timespec="seconds")}
        e.attributes = attrs
        out["attributes"] = sorted(res.attributes)
    for r in res.reviews:
        s.add(ReviewItem(investigation_id=investigation_id, kind=r.get("kind", "enrichment"),
                         reason=r["reason"][:2000], payload={**r, "entity_id": entity_id,
                                                             "document_id": doc_id},
                         document_id=doc_id, created_by=enricher_ident))
    out["reviews"] = len(res.reviews)
    return out

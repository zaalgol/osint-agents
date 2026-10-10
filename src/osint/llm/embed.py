"""Fill missing embeddings (bge-m3, multilingual) for entities, documents and events.

Used for fuzzy entity resolution, near-duplicate (syndication) detection and soft
cross-investigation links. Runs locally on the GPU, so it costs no Claude quota.
"""

from __future__ import annotations

from sqlalchemy import select

from osint.core.context import App
from osint.storage.db import Entity, EntityAlias, Event, InvestigationRef

DOC_CHARS = 2000


def entity_text(s, e: Entity) -> str:
    aliases = s.scalars(select(EntityAlias.alias).where(EntityAlias.entity_id == e.id).limit(12))
    alias_list = sorted(set(aliases) - {e.canonical_name})
    tail = f"; also known as: {', '.join(alias_list)}" if alias_list else ""
    return f"{e.type.replace('_', ' ')}: {e.canonical_name}{tail}"


def event_text(e: Event) -> str:
    when = e.time.date().isoformat() if e.time else "undated"
    return f"{e.type.replace('_', ' ')} ({when}): {e.description}"


def _scope(q, model, investigation_id: int | None, object_type: str):
    if investigation_id is None:
        return q
    return q.where(model.id.in_(select(InvestigationRef.object_id).where(
        InvestigationRef.investigation_id == investigation_id,
        InvestigationRef.object_type == object_type)))


async def embed_missing(app: App, llm, investigation_id: int | None = None,
                        kinds: tuple[str, ...] = ("entity", "document", "event"),
                        batch: int = 32) -> dict[str, int]:
    from osint.storage.db import Document

    done: dict[str, int] = {}
    specs = {
        "entity": (Entity, lambda s, x: entity_text(s, x), Entity.merged_into_id.is_(None)),
        "document": (Document, lambda s, x: f"{x.title or ''}\n{x.text[:DOC_CHARS]}", None),
        "event": (Event, lambda s, x: event_text(x), None),
    }
    for kind in kinds:
        model, to_text, extra = specs[kind]
        done[kind] = 0
        while True:
            with app.session_factory() as s, s.begin():
                q = select(model).where(model.embedding.is_(None))
                if extra is not None:
                    q = q.where(extra)
                rows = s.scalars(_scope(q, model, investigation_id, kind)
                                 .order_by(model.id).limit(batch)).all()
                if not rows:
                    break
                vectors = await llm.embed([to_text(s, r) for r in rows])
                for r, v in zip(rows, vectors, strict=True):
                    r.embedding = v
                done[kind] += len(rows)
    return done

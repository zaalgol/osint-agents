"""Ingest raw bytes as evidence: raw store → artifact row → raw capture → custody entry.

Collectors call this (through the context) instead of writing files themselves, so every
artifact automatically gets hashes, a capture record and a custody entry.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.core.models import CaptureMeta
from osint.evidence import custody
from osint.storage.db import Artifact, Capture
from osint.storage.raw_store import RawStore


def ingest_bytes(
    session: Session,
    store: RawStore,
    data: bytes,
    meta: CaptureMeta,
    actor: str,
    mime: str | None = None,
    source_id: int | None = None,
    fetched_at: datetime | None = None,
) -> tuple[Artifact, bool]:
    """Store bytes as an artifact. Returns (artifact, created).

    Content already stored isn't duplicated. Seeing it again is still logged in the
    custody chain ("observed_again"), which records that the content was still online
    at that time.
    """
    blob = store.put_bytes(data)
    fetched = (fetched_at or datetime.now(UTC)).astimezone(UTC)
    existing = session.scalar(select(Artifact).where(Artifact.sha256 == blob.sha256))
    if existing is not None:
        custody.append(
            session, "observed_again", actor, existing.id,
            {"url": meta.url, "fetched_at": fetched.isoformat()},
        )
        return existing, False

    art = Artifact(
        sha256=blob.sha256,
        sha512=blob.sha512,
        size=blob.size,
        path=blob.path,
        source_id=source_id,
        mime=mime,
        url=meta.url,
        final_url=meta.final_url,
        http_status=meta.http_status,
        platform_id=meta.platform_id,
        posted_at=meta.posted_at,
        fetched_at_utc=fetched,
        capture_meta=meta.model_dump(mode="json", exclude_none=True),
    )
    session.add(art)
    session.flush()
    session.add(
        Capture(artifact_id=art.id, kind="raw", sha256=blob.sha256, sha512=blob.sha512,
                path=blob.path)
    )
    custody.append(
        session, "captured", actor, art.id,
        {"sha256": blob.sha256, "sha512": blob.sha512, "size": blob.size, "url": meta.url},
        at_utc=fetched,
    )
    return art, True

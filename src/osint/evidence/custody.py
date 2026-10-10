"""Hash-chained chain-of-custody log.

entry_hash = sha256(prev_hash || canonical_json(entry fields)). Every entry commits to
the entire history before it, so changing, deleting or reordering any entry breaks
verification from that point on. One global chain also proves the order of actions
across artifacts. Appends take a transaction-level advisory lock, so concurrent
workers can't fork the chain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from osint.storage.db import CustodyLog

GENESIS = "0" * 64
_LOCK_KEY = 0x0517_C057  # pg_advisory_xact_lock key reserved for the custody chain


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _ts(at: datetime) -> str:
    if at.tzinfo is None:
        raise ValueError("custody timestamps must be timezone-aware")
    return at.astimezone(UTC).isoformat(timespec="microseconds")


def compute_entry_hash(
    prev_hash: str,
    artifact_id: int | None,
    action: str,
    actor: str,
    at_utc: datetime,
    details: dict[str, Any],
) -> str:
    payload = canonical_json(
        {
            "artifact_id": artifact_id,
            "action": action,
            "actor": actor,
            "at_utc": _ts(at_utc),
            "details": details,
        }
    )
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def append(
    session: Session,
    action: str,
    actor: str,
    artifact_id: int | None = None,
    details: dict[str, Any] | None = None,
    at_utc: datetime | None = None,
) -> CustodyLog:
    """Append an entry within the caller's transaction (the lock is held until commit)."""
    details = json.loads(canonical_json(details or {}))  # normalize to what JSONB will store
    at = (at_utc or datetime.now(UTC)).astimezone(UTC)
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
    prev = session.scalar(select(CustodyLog.entry_hash).order_by(CustodyLog.seq.desc()).limit(1))
    prev = prev or GENESIS
    entry = CustodyLog(
        artifact_id=artifact_id,
        action=action,
        actor=actor,
        at_utc=at,
        details=details,
        prev_hash=prev,
        entry_hash=compute_entry_hash(prev, artifact_id, action, actor, at, details),
    )
    session.add(entry)
    session.flush()
    return entry


@dataclass
class ChainReport:
    entries: int
    ok: bool
    first_bad_seq: int | None = None
    problem: str | None = None


def verify_chain(session: Session, batch: int = 5000) -> ChainReport:
    prev, count, last_seq = GENESIS, 0, -1
    while True:
        rows = session.scalars(
            select(CustodyLog).where(CustodyLog.seq > last_seq).order_by(CustodyLog.seq).limit(batch)
        ).all()
        if not rows:
            return ChainReport(entries=count, ok=True)
        for e in rows:
            if e.prev_hash != prev:
                return ChainReport(count, False, e.seq, "prev_hash does not match previous entry")
            expected = compute_entry_hash(
                prev, e.artifact_id, e.action, e.actor, e.at_utc, e.details
            )
            if e.entry_hash != expected:
                return ChainReport(count, False, e.seq, "entry_hash mismatch (entry altered)")
            prev, count, last_seq = e.entry_hash, count + 1, e.seq

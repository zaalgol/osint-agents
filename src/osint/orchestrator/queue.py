"""Durable task queue on Postgres (SELECT ... FOR UPDATE SKIP LOCKED).

All state lives in the task table, so a crash or Ctrl+C loses nothing: ``reclaim``
returns tasks whose heartbeat has expired to pending, and their saved checkpoints let
collectors continue where they stopped.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from osint.core.models import TaskSpec
from osint.storage.db import Task

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


def params_hash(params: dict) -> str:
    return hashlib.sha256(
        json.dumps(params, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def enqueue(session: Session, spec: TaskSpec) -> tuple[int, bool]:
    """Idempotent: the same (investigation, type, plugin+params) is only queued once.

    Returns (task_id, created).
    """
    phash = params_hash({"plugin": spec.plugin, **spec.params})
    stmt = (
        pg_insert(Task)
        .values(investigation_id=spec.investigation_id, type=spec.type, plugin=spec.plugin,
                params=spec.params, params_hash=phash, priority=spec.priority,
                depends_on=spec.depends_on, status="pending", attempts=0, max_attempts=3,
                checkpoint={})
        .on_conflict_do_nothing(constraint="uq_task_idempotent")
        .returning(Task.id)
    )
    new_id = session.scalar(stmt)
    if new_id is not None:
        return new_id, True
    existing = session.scalar(select(Task.id).where(
        Task.investigation_id == spec.investigation_id, Task.type == spec.type,
        Task.params_hash == phash))
    return existing, False


CLAIM_SQL = text("""
UPDATE task SET status = 'running', worker = :worker, attempts = attempts + 1,
       heartbeat_at = now(), started_at = coalesce(started_at, now()), error = NULL
WHERE id = (
    SELECT t.id FROM task t
    WHERE t.investigation_id = :inv AND t.status = 'pending' AND t.type = ANY(:types)
      AND NOT EXISTS (SELECT 1 FROM task d
                      WHERE d.id = ANY(t.depends_on) AND d.status <> 'done')
    ORDER BY t.priority, t.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id
""")


def claim(session: Session, investigation_id: int, types: list[str],
          worker: str = WORKER_ID) -> Task | None:
    task_id = session.scalar(CLAIM_SQL, {"worker": worker, "inv": investigation_id,
                                         "types": types})
    return session.get(Task, task_id) if task_id is not None else None


def heartbeat(session: Session, task_id: int, checkpoint: dict | None = None) -> None:
    values: dict = {"heartbeat_at": func.now()}
    if checkpoint is not None:
        values["checkpoint"] = checkpoint
    session.execute(update(Task).where(Task.id == task_id).values(**values))


def complete(session: Session, task_id: int, result: dict | None = None,
             checkpoint: dict | None = None) -> None:
    values: dict = {"status": "done", "finished_at": func.now(), "result": result or {},
                    "heartbeat_at": func.now()}
    if checkpoint is not None:
        values["checkpoint"] = checkpoint
    session.execute(update(Task).where(Task.id == task_id).values(**values))


def fail(session: Session, task_id: int, error: str) -> str:
    """Retry if attempts remain; otherwise mark failed and block dependents."""
    t = session.get(Task, task_id)
    if t is None:
        return "missing"
    t.error = error[:4000]
    t.heartbeat_at = datetime.now(UTC)
    if t.attempts < t.max_attempts:
        t.status = "pending"
        t.priority = t.priority + 5  # let other work go first
        return "retry"
    t.status = "failed"
    t.finished_at = datetime.now(UTC)
    session.execute(text("""
        UPDATE task SET status = 'blocked', error = 'dependency ' || :tid || ' failed'
        WHERE investigation_id = :inv AND status = 'pending' AND :tid = ANY(depends_on)
    """), {"tid": t.id, "inv": t.investigation_id})
    return "failed"


def release(session: Session, task_id: int) -> None:
    """Give a task back without counting the attempt (graceful shutdown)."""
    session.execute(update(Task).where(Task.id == task_id, Task.status == "running").values(
        status="pending", attempts=Task.attempts - 1, worker=None))


def reclaim(session: Session, investigation_id: int, stale_after: timedelta | None) -> int:
    """Return running tasks with an expired heartbeat (or all, if stale_after=None) to pending."""
    q = update(Task).where(Task.investigation_id == investigation_id, Task.status == "running")
    if stale_after is not None:
        q = q.where(Task.heartbeat_at < datetime.now(UTC) - stale_after)
    return session.execute(q.values(status="pending", worker=None)).rowcount or 0


def retry_failed(session: Session, investigation_id: int) -> int:
    n = session.execute(update(Task).where(
        Task.investigation_id == investigation_id, Task.status.in_(["failed", "blocked"])
    ).values(status="pending", attempts=0, error=None)).rowcount or 0
    return n


def counts(session: Session, investigation_id: int) -> dict[tuple[str, str], int]:
    rows = session.execute(
        select(Task.type, Task.status, func.count()).where(
            Task.investigation_id == investigation_id).group_by(Task.type, Task.status))
    return {(t, s): n for t, s, n in rows}


def active(session: Session, investigation_id: int, types: list[str],
           running_only: bool = False) -> bool:
    """Any pending/running (or only running) task of these types?"""
    statuses = ["running"] if running_only else ["pending", "running"]
    return bool(session.scalar(select(func.count()).where(
        Task.investigation_id == investigation_id, Task.type.in_(types),
        Task.status.in_(statuses))))


def has_open_work(session: Session, investigation_id: int) -> bool:
    return bool(session.scalar(select(func.count()).where(
        Task.investigation_id == investigation_id, Task.status.in_(["pending", "running"]))))


# ---------------------------------------------------------------------- one runner per queue

RUNNER_LOCK = 4242                    # advisory-lock class id; the object id is the investigation


class RunnerLock:
    """At most one runner per investigation, across processes (CLI, GUI jobs, daemon).

    A session-level Postgres advisory lock on a dedicated connection. Postgres drops it
    when the connection closes, so a crashed or killed runner never blocks the queue.
    Two runners would double GPU and RAM use, and `resume` reclaims running tasks,
    which would steal the other runner's work.
    """

    def __init__(self, session_factory, investigation_id: int) -> None:
        self.engine = session_factory.kw["bind"]
        self.inv_id = investigation_id
        self.conn = None

    def acquire(self) -> str | None:
        """None if we hold the lock now; otherwise who holds it."""
        conn = self.engine.connect()
        conn.execute(text("SELECT set_config('application_name', :n, false)"),
                     {"n": f"osint runner pid {os.getpid()}"})
        got = conn.scalar(text("SELECT pg_try_advisory_lock(:c, :i)"),
                          {"c": RUNNER_LOCK, "i": self.inv_id})
        conn.commit()                 # the lock is session-level: it outlives the transaction
        if got:
            self.conn = conn
            return None
        holder = runner_holder(conn, self.inv_id) or "another process"
        conn.close()
        return holder

    def release(self) -> None:
        if self.conn is not None:
            self.conn.execute(text("SELECT pg_advisory_unlock(:c, :i)"),
                              {"c": RUNNER_LOCK, "i": self.inv_id})
            self.conn.commit()
            self.conn.close()
            self.conn = None


def runner_holder(session_or_conn, investigation_id: int) -> str | None:
    """Who is processing this investigation's queue right now (None if nobody)."""
    return session_or_conn.scalar(text("""
        SELECT coalesce(nullif(a.application_name, ''), 'pid ' || l.pid)
        FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'advisory' AND l.classid = :c AND l.objid = :i
          AND l.objsubid = 2 AND l.granted
        LIMIT 1"""), {"c": RUNNER_LOCK, "i": investigation_id})

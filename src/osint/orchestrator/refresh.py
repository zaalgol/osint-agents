"""Incremental refresh, scheduled runs, and snapshots.

refresh   re-arms the investigation's refreshable collectors (searxng, rss): done tasks
          go back to pending with checkpoints the collector prepares for a refresh
          (rss keeps its seen entries; search starts over, optionally narrowed to a
          recent time_range). Pages already captured are not fetched again: the web
          follow-ups are idempotent per URL.
daemon    runs due schedules: refresh -> run -> post-run (embed, corroborate, link
          candidates, graph) -> optional Claude analyze when the knowledge changed.
snapshot  pg_dump + raw evidence store + manifests/keys + config, with a SHA-256 list.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select, update

from osint.core.config import project_home
from osint.core.context import App
from osint.core.plugins import PluginError
from osint.storage.db import Schedule, Task

log = logging.getLogger(__name__)


def refresh(app: App, investigation_id: int, time_range: str | None = None) -> int:
    n = 0
    with app.session_factory() as s, s.begin():
        tasks = s.scalars(select(Task).where(Task.investigation_id == investigation_id,
                                             Task.type == "collect",
                                             Task.status.in_(["done", "failed"]))).all()
        for t in tasks:
            try:
                cls = app.registry.get("collector", t.plugin)
            except PluginError:
                log.warning("refresh: collector %r is not installed; skipping task %s",
                            t.plugin, t.id)
                continue
            if not getattr(cls, "refreshable", False):
                continue
            cp = cls().on_refresh(dict(t.checkpoint or {}))
            if time_range:
                cp["time_range"] = time_range
            s.execute(update(Task).where(Task.id == t.id).values(
                status="pending", attempts=0, error=None, checkpoint=cp, finished_at=None))
            n += 1
    return n


def parse_every(text: str) -> int:
    """'30m', '6h', '1d' -> minutes."""
    text = text.strip().lower()
    unit = text[-1]
    value = int(text[:-1])
    factor = {"m": 1, "h": 60, "d": 1440}.get(unit)
    if factor is None or value <= 0:
        raise ValueError("use e.g. 30m, 6h or 1d")
    return value * factor


def set_schedule(app: App, investigation_id: int, every_minutes: int, time_range: str | None,
                 analyze: bool, enabled: bool = True, extract_role: str | None = None) -> Schedule:
    with app.session_factory() as s, s.begin():
        sch = s.scalar(select(Schedule).where(Schedule.investigation_id == investigation_id))
        now = datetime.now(UTC)
        if sch is None:
            sch = Schedule(investigation_id=investigation_id, every_minutes=every_minutes,
                           next_run_at=now)
            s.add(sch)
        sch.every_minutes, sch.time_range, sch.analyze, sch.enabled = (
            every_minutes, time_range, analyze, enabled)
        sch.extract_role = extract_role
        s.flush()
        s.expunge(sch)
        return sch


def due_schedules(app: App) -> list[Schedule]:
    with app.session_factory() as s:
        rows = s.scalars(select(Schedule).where(Schedule.enabled.is_(True),
                                                Schedule.next_run_at <= datetime.now(UTC))).all()
        for r in rows:
            s.expunge(r)
        return list(rows)


def reextract(app: App, investigation_id: int, role: str, only_relevant: bool = True) -> int:
    """Queue extraction again for the investigation's documents with another model role.

    Results merge into the existing knowledge: the writer reuses identical relations and
    events (adding citations) and adds what the better model finds. With only_relevant,
    documents the earlier run judged irrelevant are skipped.
    """
    from osint.core.models import TaskSpec
    from osint.orchestrator import queue
    from osint.storage.db import InvestigationRef

    n = 0
    with app.session_factory() as s, s.begin():
        docs = s.scalars(select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == investigation_id,
            InvestigationRef.object_type == "document")).all()
        skip = set()
        if only_relevant:
            for t in s.scalars(select(Task).where(Task.investigation_id == investigation_id,
                                                  Task.type == "extract", Task.status == "done")):
                if (t.result or {}).get("relevant") is False:
                    skip.add(int(t.params["document_id"]))
        for d in docs:
            if d in skip:
                continue
            _, created = queue.enqueue(s, TaskSpec(
                investigation_id=investigation_id, type="extract", plugin="extract",
                params={"document_id": d, "role": role}, priority=85))
            n += int(created)
    return n


def finish_schedule(app: App, schedule_id: int, result: dict) -> None:
    with app.session_factory() as s, s.begin():
        sch = s.get(Schedule, schedule_id)
        now = datetime.now(UTC)
        sch.last_run_at = now
        sch.next_run_at = now + timedelta(minutes=sch.every_minutes)
        sch.last_result = result


# --------------------------------------------------------------------------- snapshot


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(app: App, include_raw: bool = True) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = app.settings.data_path / "snapshots" / ts
    out.mkdir(parents=True, exist_ok=True)
    pg = app.settings.postgres
    dump = out / "postgres.dump"
    with open(dump, "wb") as f:
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "postgres", "pg_dump", "-U", pg.user, "-Fc",
             pg.database], stdout=f, stderr=subprocess.PIPE, cwd=str(project_home()),
            check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"pg_dump failed: {proc.stderr.decode(errors='replace')[:500]}")
    files = [dump]
    if include_raw and app.raw_store.root.is_dir():
        raw_zip = out / "raw.zip"
        with zipfile.ZipFile(raw_zip, "w", zipfile.ZIP_STORED, allowZip64=True) as z:
            for p in app.raw_store.root.rglob("*"):
                if p.is_file() and not p.name.startswith(".incoming"):
                    z.write(p, p.relative_to(app.settings.data_path).as_posix())
        files.append(raw_zip)
    for sub in ("manifests",):
        src = app.settings.data_path / sub
        if src.is_dir():
            shutil.copytree(src, out / sub)
            files += [p for p in (out / sub).rglob("*") if p.is_file()]
    cfg = out / "config"
    shutil.copytree(project_home() / "config", cfg,
                    ignore=shutil.ignore_patterns("*.local.yaml", "keys"))
    files += [p for p in cfg.rglob("*") if p.is_file()]
    listing = {p.relative_to(out).as_posix(): _sha256(p) for p in files}
    (out / "snapshot.json").write_text(json.dumps(
        {"created": ts, "files": listing,
         "restore": "pg_restore -U osint -d osint --clean postgres.dump; unzip raw.zip into "
                    "data/; then `osint graph-sync` (Neo4j is rebuilt from Postgres)"},
        indent=2), encoding="utf-8")
    return out

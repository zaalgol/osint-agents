"""Periodic integrity check: re-hash evidence, verify the custody chain and sealed manifests.

Run daily by `osint daemon`. Failures open an integrity_alert review item; the last
result is kept in data/state/integrity.json.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from osint.core.context import App
from osint.evidence.custody import verify_chain
from osint.evidence.seal import verify_manifests
from osint.storage.db import Artifact, Capture, ReviewItem
from osint.storage.raw_store import IntegrityError

EVERY = timedelta(hours=24)


def state_path(app: App) -> Path:
    return app.settings.data_path / "state" / "integrity.json"


def last_result(app: App) -> dict | None:
    p = state_path(app)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def due(app: App) -> bool:
    last = last_result(app)
    if last is None:
        return True
    return datetime.fromisoformat(last["checked_at"]) + EVERY <= datetime.now(UTC)


def run_integrity_check(app: App) -> dict:
    problems: list[str] = []
    files = 0
    from osint.evidence.purge import purged_hashes

    with app.session_factory() as s:
        gone = purged_hashes(s)              # deleted on purpose (custody "purged")
        for sha256, sha512 in s.execute(select(Artifact.sha256, Artifact.sha512)).yield_per(500):
            if sha256 in gone:
                continue
            files += 1
            try:
                app.raw_store.verify(sha256, sha512)
            except IntegrityError as e:
                problems.append(str(e))
        for sha256, sha512 in s.execute(select(Capture.sha256, Capture.sha512).where(
                Capture.sha256.is_not(None))).yield_per(500):
            if sha256 in gone:
                continue
            files += 1
            try:
                app.raw_store.verify(sha256, sha512)
            except IntegrityError as e:
                problems.append(f"capture: {e}")
        chain = verify_chain(s)
    if not chain.ok:
        problems.append(f"custody chain broken at seq {chain.first_bad_seq}: {chain.problem}")
    for m in verify_manifests(app):
        problems += [f"manifest {m.manifest_id}: {p}" for p in m.problems]
    result = {"checked_at": datetime.now(UTC).isoformat(timespec="seconds"), "ok": not problems,
              "files": files, "custody_entries": chain.entries, "problems": problems[:200]}
    p = state_path(app)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=1), encoding="utf-8")
    if problems:
        with app.session_factory() as s, s.begin():
            s.add(ReviewItem(kind="integrity_alert", reason=f"{len(problems)} integrity problem(s): "
                             + "; ".join(problems[:3]), payload=result,
                             created_by="integrity-check"))
    return result

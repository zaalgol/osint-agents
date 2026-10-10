"""Creating investigations and queueing collection: shared by the CLI and the web GUI."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from osint.core.models import TaskSpec
from osint.orchestrator import queue


class InvestigationError(ValueError):
    pass


def create_investigation(a, name: str, focus: str | None = None, queries: list[str] | None = None,
                         urls: list[str] | None = None, feeds: list[str] | None = None,
                         lang: str | None = None, time_range: str | None = None,
                         max_results: int = 10, max_fetches: int = 200,
                         anonymous: bool = False, plan: bool = False) -> tuple[int, int]:
    """Create the investigation and queue its seed tasks. Returns (id, tasks queued)."""
    from osint.storage.db import Investigation

    name = (name or "").strip()
    queries = [q.strip() for q in queries or [] if q.strip()]
    urls = [u.strip() for u in urls or [] if u.strip()]
    feeds = [f.strip() for f in feeds or [] if f.strip()]
    if not name:
        raise InvestigationError("a name is required")
    if not (queries or urls or feeds or plan):
        raise InvestigationError("give at least one query, URL or feed, or let Claude plan")
    if plan and not focus:
        raise InvestigationError("planning needs a focus (what Claude should plan for)")
    with a.session_factory() as s, s.begin():
        if s.scalar(select(Investigation.id).where(Investigation.name == name)):
            raise InvestigationError(f"investigation {name!r} already exists")
        inv = Investigation(name=name, seed={"focus": focus, "queries": queries, "urls": urls,
                                             "feeds": feeds, "lang": lang,
                                             "time_range": time_range},
                            config={"max_fetches": max_fetches,
                                    "network_profile": "anonymous" if anonymous else "standard"})
        s.add(inv)
        s.flush()
        specs = []
        if queries:
            specs.append(TaskSpec(investigation_id=inv.id, type="collect", plugin="searxng",
                                  params={"queries": queries, "max_results": max_results,
                                          "language": lang, "time_range": time_range}))
        if urls:
            specs.append(TaskSpec(investigation_id=inv.id, type="collect", plugin="web",
                                  params={"urls": urls, "found_via": "seed"}, priority=90))
        if feeds:
            specs.append(TaskSpec(investigation_id=inv.id, type="collect", plugin="rss",
                                  params={"feeds": feeds}))
        for spec in specs:
            queue.enqueue(s, spec)
        return inv.id, len(specs)


def set_archived(a, investigation_id: int, archived: bool) -> str:
    """Archive (hide, stop schedules) or restore an investigation. Nothing is deleted:
    its evidence and knowledge stay in the shared knowledge base."""
    from osint.storage.db import Investigation, Schedule

    with a.session_factory() as s, s.begin():
        inv = s.get(Investigation, investigation_id)
        if inv is None:
            raise InvestigationError(f"no investigation {investigation_id}")
        inv.status = "archived" if archived else "active"
        if archived and (sch := s.scalar(select(Schedule).where(
                Schedule.investigation_id == investigation_id))):
            sch.enabled = False
        return inv.status


def queue_collection(a, investigation_id: int, plugin: str, params: dict[str, Any],
                     priority: int = 100) -> tuple[int, bool]:
    """Validate and queue a collector task (account-based sources are refused)."""
    from pydantic import ValidationError

    from osint.core.plugins import PluginError, check_collector_allowed

    try:
        cls = a.registry.get("collector", plugin)
        check_collector_allowed(cls, a.settings)
        cls.params_schema.model_validate(params)
    except (PluginError, ValidationError) as e:
        raise InvestigationError(str(e)) from None
    with a.session_factory() as s, s.begin():
        return queue.enqueue(s, TaskSpec(investigation_id=investigation_id, type="collect",
                                         plugin=plugin, params=params, priority=priority))

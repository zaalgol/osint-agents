"""Local web GUI (Starlette + a React single-page app). Binds to 127.0.0.1 only.

* The React app (web/, built into ui/static/) is served at /; client-side routes fall
  back to index.html, which carries a per-server CSRF token in <meta name="csrf">.
* JSON API under /api. Every write (POST) needs that token and a localhost Origin, so
  other sites in the browser can't drive the system.
* Long operations (runs, Claude jobs, exports) are background jobs (ui/jobs.py).
* Captured web content is hostile by default: captured HTML is served as text/plain (or
  a sandbox CSP that blocks scripts) with nosniff, and only image/PDF captures render
  inline.
"""

from __future__ import annotations

import mimetypes
import secrets
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from osint.analyst.tools import AnalystTools, ToolError
from osint.core.context import App
from osint.storage.db import (
    Artifact,
    Capture,
    ClaudeJob,
    Document,
    Entity,
    EventParticipant,
    Investigation,
    InvestigationRef,
    Mention,
    Relation,
    Report,
    ReviewItem,
    Schedule,
    Source,
    Task,
)
from osint.ui.jobs import JobError, JobManager

HERE = Path(__file__).parent
STATIC = HERE / "static"
SAFE_INLINE = {"screenshot_png": "image/png", "pdf_render": "application/pdf"}
HARDEN = {"X-Content-Type-Options": "nosniff",
          "Content-Security-Policy": "sandbox; default-src 'none'; img-src 'self' data:",
          "Referrer-Policy": "no-referrer"}
SPA_CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
           "frame-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'")
MAX_UPLOAD = 200 * 1024 * 1024
REVIEW_FIELDS = ("names", "score", "list_entry", "a_description", "finding_text", "old", "new",
                 "withdraw", "b_description", "host", "quote", "name", "type", "candidates",
                 "entity_id", "a", "b", "artifact_id", "exif", "authority", "revision_id")


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def create_app(app: App | None = None, jobs: JobManager | None = None) -> Starlette:
    a = app or App()
    S = a.session_factory
    csrf = secrets.token_urlsafe(32)
    jm = jobs or JobManager(a.settings.data_path)

    def runner_of(inv_id: int) -> str | None:
        from osint.orchestrator import queue

        with S() as s:
            return queue.runner_holder(s, inv_id)

    jm.busy_check = runner_of      # a run started in a terminal also holds the queue

    def write_allowed(req: Request) -> bool:
        origin = req.headers.get("origin") or req.headers.get("referer") or ""
        local = origin.startswith(("http://127.0.0.1:", "http://localhost:"))
        return local and secrets.compare_digest(req.headers.get("x-csrf-token", ""), csrf)

    def forbidden() -> JSONResponse:
        return JSONResponse({"error": "forbidden: missing CSRF token or non-local origin"},
                            status_code=403)

    def bad(msg: str, code: int = 400) -> JSONResponse:
        return JSONResponse({"error": msg}, status_code=code)

    def tools(inv: int) -> AnalystTools:
        return AnalystTools(S, a.ontology, a.registry, a.raw_store, inv, actor="ui",
                            neo4j=a.settings.neo4j)

    def inv_exists(inv: int) -> bool:
        with S() as s:
            return s.get(Investigation, inv) is not None

    async def body(req: Request) -> dict:
        try:
            data = await req.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ SPA

    def spa_page() -> Response:
        index = STATIC / "index.html"
        if not index.exists():
            return HTMLResponse("<h1>GUI not built</h1><p>Run <code>npm install</code> and "
                                "<code>npm run build</code> in <code>web/</code>.</p>"
                                f'<meta name="csrf" content="{csrf}">', status_code=200)
        page = index.read_text(encoding="utf-8").replace("__CSRF__", csrf)
        return HTMLResponse(page, headers={"Content-Security-Policy": SPA_CSP,
                                           "X-Content-Type-Options": "nosniff",
                                           "Referrer-Policy": "no-referrer"})

    async def index(_: Request) -> Response:
        return spa_page()

    async def spa_fallback(req: Request) -> Response:
        path = req.path_params.get("path", "")
        if path.startswith(("api/", "capture/", "document/", "report/", "files/")):
            return bad("not found", 404)
        return spa_page()

    # ------------------------------------------------------------------ meta / system

    async def meta(_: Request) -> Response:
        with S() as s:
            review_open = s.scalar(select(func.count()).where(ReviewItem.status == "open"))
        return JSONResponse({"active_jobs": jm.active(), "review_open": review_open,
                             "ontology": {"entity_types": sorted(a.ontology.entity_types),
                                          "relation_types": sorted(a.ontology.relation_types),
                                          "event_types": sorted(a.ontology.event_types)}})

    async def doctor(_: Request) -> Response:
        import asyncio

        from osint.core.doctor import run_checks

        results = await asyncio.to_thread(run_checks)
        return JSONResponse([{"component": n, "ok": ok, "detail": d} for n, ok, d in results])

    async def tor_status(_: Request) -> Response:
        import asyncio

        from osint.net import tor

        st = await asyncio.to_thread(tor.status, a.settings)
        return JSONResponse({"running": st.running, "is_tor": st.is_tor, "exit_ip": st.exit_ip,
                             "bootstrapped": st.bootstrapped, "detail": st.detail})

    async def plugins(_: Request) -> Response:
        out = []
        for cls, origin in a.registry.list():
            row = {"kind": cls.kind, "name": cls.name, "version": cls.version,
                   "description": cls.description, "origin": origin}
            if getattr(cls, "params_schema", None) is not None:
                row["schema"] = cls.params_schema.model_json_schema()
            if getattr(cls, "requires_account", False):
                row["requires_account"] = True
            if getattr(cls, "entity_types", None):
                row["entity_types"] = sorted(cls.entity_types)
            out.append(row)
        return JSONResponse(out)

    # ------------------------------------------------------------------ investigations

    async def investigations(_: Request) -> Response:
        with S() as s:
            out = []
            for inv in s.scalars(select(Investigation).order_by(Investigation.id.desc())):
                counts = dict(s.execute(select(InvestigationRef.object_type, func.count()).where(
                    InvestigationRef.investigation_id == inv.id).group_by(
                    InvestigationRef.object_type)).all())
                open_tasks = s.scalar(select(func.count()).where(
                    Task.investigation_id == inv.id, Task.status.in_(["pending", "running"])))
                failed = s.scalar(select(func.count()).where(
                    Task.investigation_id == inv.id, Task.status == "failed"))
                review_open = s.scalar(select(func.count()).where(
                    ReviewItem.investigation_id == inv.id, ReviewItem.status == "open"))
                out.append({"id": inv.id, "name": inv.name, "status": inv.status,
                            "focus": (inv.seed or {}).get("focus"),
                            "created": inv.created_at.isoformat(), "counts": counts,
                            "open_tasks": open_tasks, "failed_tasks": failed,
                            "review_open": review_open,
                            "profile": (inv.config or {}).get("network_profile", "standard")})
        return JSONResponse(out)

    async def create_investigation(req: Request) -> Response:
        from osint.orchestrator.investigations import InvestigationError
        from osint.orchestrator.investigations import create_investigation as create

        if not write_allowed(req):
            return forbidden()
        b = await body(req)
        try:
            inv_id, n = create(a, b.get("name", ""), b.get("focus") or None, b.get("queries"),
                               b.get("urls"), b.get("feeds"), b.get("lang") or None,
                               b.get("time_range") or None, int(b.get("max_results") or 10),
                               int(b.get("max_fetches") or 200), bool(b.get("anonymous")),
                               bool(b.get("plan")))
        except (InvestigationError, ValueError) as e:
            return bad(str(e))
        job = None
        try:
            if b.get("plan"):
                job = jm.start("plan", inv_id, {"run": bool(b.get("run"))})
            elif b.get("run"):
                job = jm.start("run", inv_id, {})
        except JobError as e:
            return JSONResponse({"id": inv_id, "tasks": n, "job_error": str(e)})
        return JSONResponse({"id": inv_id, "tasks": n, "job": job.id if job else None})

    async def inv_status(req: Request) -> Response:
        from osint.orchestrator import queue

        inv_id = int(req.path_params["inv"])
        with S() as s:
            inv = s.get(Investigation, inv_id)
            if inv is None:
                return bad("no such investigation", 404)
            counts = queue.counts(s, inv_id)
            tasks: dict[str, dict[str, int]] = {}
            for (typ, st), n in counts.items():
                tasks.setdefault(typ, {})[st] = n
            refs = dict(s.execute(select(InvestigationRef.object_type, func.count()).where(
                InvestigationRef.investigation_id == inv_id).group_by(
                InvestigationRef.object_type)).all())
            review_open = s.scalar(select(func.count()).where(
                ReviewItem.investigation_id == inv_id, ReviewItem.status == "open"))
            failed = [{"id": t.id, "type": t.type, "plugin": t.plugin, "error": (t.error or "")[:500],
                       "attempts": t.attempts}
                      for t in s.scalars(select(Task).where(Task.investigation_id == inv_id,
                                                            Task.status == "failed")
                                         .order_by(Task.id.desc()).limit(20))]
            sch = s.scalar(select(Schedule).where(Schedule.investigation_id == inv_id))
            schedule = None if sch is None else {
                "every_minutes": sch.every_minutes, "time_range": sch.time_range,
                "analyze": sch.analyze, "extract_role": sch.extract_role, "enabled": sch.enabled,
                "last_run_at": _iso(sch.last_run_at), "next_run_at": _iso(sch.next_run_at),
                "last_result": sch.last_result}
            return JSONResponse({
                "id": inv.id, "name": inv.name, "status": inv.status, "seed": inv.seed or {},
                "config": inv.config or {}, "created": inv.created_at.isoformat(),
                "profile": (inv.config or {}).get("network_profile", "standard"),
                "tasks": tasks, "knowledge": {**refs, "review_open": review_open},
                "failed": failed, "schedule": schedule,
                "runner": queue.runner_holder(s, inv_id)})

    async def overview(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        return JSONResponse(tools(inv).investigation_overview(inv))

    async def collect(req: Request) -> Response:
        from osint.orchestrator.investigations import InvestigationError, queue_collection

        if not write_allowed(req):
            return forbidden()
        inv = int(req.path_params["inv"])
        b = await body(req)
        if not inv_exists(inv):
            return bad("no such investigation", 404)
        try:
            tid, created = queue_collection(a, inv, b.get("plugin", ""), b.get("params") or {},
                                            int(b.get("priority") or 100))
        except InvestigationError as e:
            return bad(str(e))
        out = {"task": tid, "created": created}
        if b.get("run"):
            try:
                out["job"] = jm.start("run", inv, {}).id
            except JobError as e:
                out["job_error"] = str(e)
        return JSONResponse(out)

    async def set_network(req: Request) -> Response:
        from osint.net.profile import PROFILES

        if not write_allowed(req):
            return forbidden()
        inv = int(req.path_params["inv"])
        profile = (await body(req)).get("profile")
        if profile not in PROFILES:
            return bad(f"profile must be one of {PROFILES}")
        with S() as s, s.begin():
            row = s.get(Investigation, inv)
            if row is None:
                return bad("no such investigation", 404)
            row.config = {**(row.config or {}), "network_profile": profile}
        return JSONResponse({"profile": profile})

    async def archive(req: Request) -> Response:
        from osint.orchestrator.investigations import InvestigationError, set_archived

        if not write_allowed(req):
            return forbidden()
        try:
            st = set_archived(a, int(req.path_params["inv"]),
                              bool((await body(req)).get("archived", True)))
        except InvestigationError as e:
            return bad(str(e), 404)
        return JSONResponse({"status": st})

    async def set_schedule(req: Request) -> Response:
        from osint.orchestrator.refresh import parse_every
        from osint.orchestrator.refresh import set_schedule as do_set

        if not write_allowed(req):
            return forbidden()
        inv = int(req.path_params["inv"])
        b = await body(req)
        try:
            sch = do_set(a, inv, parse_every(b.get("every") or "6h"), b.get("since") or None,
                         bool(b.get("analyze")), enabled=bool(b.get("enabled", True)),
                         extract_role=b.get("extract_role") or None)
        except ValueError as e:
            return bad(str(e))
        return JSONResponse({"next_run_at": _iso(sch.next_run_at), "enabled": sch.enabled})

    async def upload(req: Request) -> Response:
        from osint.core.models import CapturedItem, CaptureMeta, TaskSpec
        from osint.evidence.capture import persist_item
        from osint.evidence.parse import should_parse
        from osint.orchestrator import queue
        from osint.resolution.resolver import add_ref
        from osint.storage.raw_store import BlockedContent

        if not write_allowed(req):
            return forbidden()
        inv = int(req.path_params["inv"])
        if not inv_exists(inv):
            return bad("no such investigation", 404)
        form = await req.form(max_part_size=MAX_UPLOAD)
        f = form.get("file")
        if f is None or not hasattr(f, "read"):
            return bad("no file")
        data = await f.read()
        if len(data) > MAX_UPLOAD:
            return bad("file too large (200 MB max)")
        name = Path(f.filename or "upload.bin").name
        mime = f.content_type if f.content_type not in (None, "", "application/octet-stream") \
            else mimetypes.guess_type(name)[0]
        url = (form.get("url") or "").strip() or f"upload://{name}"
        meta = CaptureMeta(url=url, collector="user:ui", platform="upload",
                           extra={"original_filename": name, "note": form.get("note") or None})
        try:
            with S() as s, s.begin():
                art, created = persist_item(s, a.raw_store, CapturedItem(
                    data=data, meta=meta, mime=mime or "application/octet-stream"), actor="user:ui")
                add_ref(s, inv, "artifact", art.id, "user:ui")
                parse = should_parse(mime, a.settings.media.ocr)
                if parse:
                    queue.enqueue(s, TaskSpec(investigation_id=inv, type="parse", plugin="parse",
                                              params={"artifact_id": art.id}, priority=50))
                return JSONResponse({"artifact": art.id, "created": created, "sha256": art.sha256,
                                     "parse_queued": parse})
        except BlockedContent as e:
            return bad(str(e), 422)

    # ------------------------------------------------------------------ knowledge

    async def entities(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        q = (req.query_params.get("q") or "").strip()
        typ = req.query_params.get("type") or None
        limit = min(int(req.query_params.get("limit", 300)), 2000)
        with S() as s:
            ids = select(InvestigationRef.object_id).where(
                InvestigationRef.investigation_id == inv, InvestigationRef.object_type == "entity")
            mentions = (select(func.count()).select_from(Mention)
                        .where(Mention.entity_id == Entity.id).scalar_subquery())
            stmt = (select(Entity, mentions.label("m"))
                    .where(Entity.id.in_(ids), Entity.merged_into_id.is_(None))
                    .order_by(mentions.desc(), Entity.canonical_name).limit(limit))
            if q:
                stmt = stmt.where(Entity.canonical_name.ilike(f"%{q}%"))
            if typ:
                stmt = stmt.where(Entity.type == typ)
            shared = dict(s.execute(
                select(InvestigationRef.object_id, func.count(InvestigationRef.investigation_id.distinct()))
                .where(InvestigationRef.object_type == "entity", InvestigationRef.object_id.in_(ids))
                .group_by(InvestigationRef.object_id)).all())
            out = [{"id": e.id, "name": e.canonical_name, "type": e.type, "mentions": m,
                    "investigations": shared.get(e.id, 1), "strong_key": e.strong_key,
                    "sanctions": bool((e.attributes or {}).get("sanctions"))}
                   for e, m in s.execute(stmt)]
        return JSONResponse(out)

    async def search(req: Request) -> Response:
        q = (req.query_params.get("q") or "").strip()
        if len(q) < 2:
            return JSONResponse([])
        return JSONResponse(tools(0).search_entities(q, req.query_params.get("type") or None,
                                                      limit=50))

    async def graph(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        with S() as s:
            ent_ids = select(InvestigationRef.object_id).where(
                InvestigationRef.investigation_id == inv, InvestigationRef.object_type == "entity")
            ents = s.scalars(select(Entity).where(Entity.id.in_(ent_ids),
                                                  Entity.merged_into_id.is_(None))).all()
            live = {e.id for e in ents}
            nodes = [{"data": {"id": f"e{e.id}", "label": e.canonical_name, "type": e.type,
                               "eid": e.id}} for e in ents]
            edges = [{"data": {"id": f"r{r.id}", "source": f"e{r.src_entity_id}",
                               "target": f"e{r.dst_entity_id}", "label": r.type, "rid": r.id}}
                     for r in s.scalars(select(Relation).where(
                         Relation.src_entity_id.in_(live), Relation.dst_entity_id.in_(live),
                         Relation.attributes["retracted"].is_(None)))]
            pairs: dict[int, list[int]] = {}
            for ev, e in s.execute(select(EventParticipant.event_id, EventParticipant.entity_id)
                                   .where(EventParticipant.entity_id.in_(live))):
                pairs.setdefault(ev, []).append(e)
            for ev, members in pairs.items():
                for i, x in enumerate(members):
                    for y in members[i + 1:]:
                        edges.append({"data": {"id": f"v{ev}-{x}-{y}", "source": f"e{x}",
                                               "target": f"e{y}", "label": "same event",
                                               "event": ev}})
        return JSONResponse({"nodes": nodes, "edges": edges})

    async def entity(req: Request) -> Response:
        eid = int(req.path_params["eid"])
        inv = int(req.query_params.get("inv", "0") or 0)
        t = tools(inv or 1)
        try:
            data = t.get_entity(eid)
        except ToolError as e:
            return bad(str(e), 404)
        markers = {int(m[3:-1]) for r in data["relations"] for m in r["evidence"]}
        markers |= {int(m[3:-1]) for v in data["events"] for m in v["evidence"]}
        data["evidence_detail"] = {e["marker"]: e for e in t.get_evidence(sorted(markers)[:60])}
        return JSONResponse(data)

    async def timeline(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        return JSONResponse(tools(inv).timeline(inv, limit=500))

    async def findings(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        t = tools(inv)
        return JSONResponse({"findings": t.list_findings(inv), "links": t.cross_links(inv),
                             "contradictions": t.contradictions(inv)})

    async def explain(req: Request) -> Response:
        return JSONResponse(_explain(S, int(req.path_params["fid"])))

    async def evidence_detail(req: Request) -> Response:
        ids = [int(x) for x in (req.query_params.get("ids") or "").split(",") if x.strip().isdigit()]
        inv = int(req.query_params.get("inv", "0") or 0)
        return JSONResponse(tools(inv or 1).get_evidence(ids[:100]))

    async def key_players(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        try:
            return JSONResponse(tools(inv).key_players(inv, 20))
        except Exception as e:  # noqa: BLE001 - graph may be empty
            return bad(f"{type(e).__name__}: {e}")

    async def links(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        t = tools(inv)
        return JSONResponse({"links": t.cross_links(inv, limit=200),
                             "shared": t.shared_entities(inv, 100)})

    async def reports(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        with S() as s:
            rows = [{"id": r.id, "title": r.title, "status": r.status,
                     "created": r.created_at.isoformat(),
                     "check": (r.verification or {}).get("summary")}
                    for r in s.scalars(select(Report).where(Report.investigation_id == inv)
                                       .order_by(Report.id.desc()))]
        return JSONResponse(rows)

    async def report_html(req: Request) -> Response:
        from osint.reports.render import render_report

        rid = int(req.path_params["rid"])
        with S() as s:
            r = s.get(Report, rid)
            if r is None:
                return Response("not found", status_code=404)
            paths = render_report(s, r, a.settings.data_path / "reports" / f"inv-{r.investigation_id}")
        # our own rendering (escaped markdown); still no scripts allowed
        return HTMLResponse(paths["html"].read_text(encoding="utf-8"), headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff"})

    async def claude_jobs(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        with S() as s:
            rows = [{"id": j.id, "job": j.job, "model": j.model, "status": j.status,
                     "turns": j.num_turns, "input_tokens": j.input_tokens,
                     "output_tokens": j.output_tokens, "duration_ms": j.duration_ms,
                     "created": _iso(j.created_at), "finished": _iso(j.finished_at),
                     "error": (j.error or "")[:500] or None,
                     "text": (j.result_text or "")[:20000] or None}
                    for j in s.scalars(select(ClaudeJob).where(ClaudeJob.investigation_id == inv)
                                       .order_by(ClaudeJob.id.desc()).limit(100))]
        return JSONResponse(rows)

    async def evidence(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        with S() as s:
            arts = s.scalars(select(Artifact).where(Artifact.id.in_(select(
                InvestigationRef.object_id).where(InvestigationRef.investigation_id == inv,
                                                  InvestigationRef.object_type == "artifact")))
                .order_by(Artifact.id.desc()).limit(1000)).all()
            sources = {src.id: src for src in s.scalars(select(Source).where(
                Source.id.in_({x.source_id for x in arts if x.source_id})))}
            out = []
            for art in arts:
                caps = s.execute(select(Capture.id, Capture.kind).where(
                    Capture.artifact_id == art.id)).all()
                doc = s.scalar(select(Document.id).where(Document.artifact_id == art.id).limit(1))
                ex = (art.capture_meta or {}).get("extra", {})
                src = sources.get(art.source_id)
                out.append({"id": art.id, "url": art.final_url or art.url, "mime": art.mime,
                            "platform": (art.capture_meta or {}).get("platform"),
                            "platform_id": art.platform_id,
                            "captured": art.fetched_at_utc.isoformat(),
                            "posted": _iso(art.posted_at), "status": art.http_status,
                            "sha256": art.sha256, "size": art.size, "document": doc,
                            "route": ex.get("route"), "blocked": ex.get("blocked"),
                            "source": {"id": src.id, "locator": src.locator, "kind": src.kind,
                                       "grade": src.reliability} if src else None,
                            "captures": [{"id": i, "kind": k} for i, k in caps]})
            review = [{"id": r.id, "kind": r.kind, "reason": r.reason}
                      for r in s.scalars(select(ReviewItem).where(
                          ReviewItem.investigation_id == inv, ReviewItem.status == "open")
                          .order_by(ReviewItem.id.desc()).limit(200))]
        return JSONResponse({"artifacts": out, "review": review})

    async def document_json(req: Request) -> Response:
        did = int(req.path_params["did"])
        with S() as s:
            d = s.get(Document, did)
            if d is None:
                return bad("not found", 404)
            art = s.get(Artifact, d.artifact_id)
            return JSONResponse({"id": d.id, "title": d.title, "lang": d.lang, "text": d.text,
                                 "translated_text": d.translated_text, "extractor": d.extractor,
                                 "meta": {k: v for k, v in (d.meta or {}).items()
                                          if k in ("ocr", "exif", "page_starts", "source")},
                                 "artifact": {"id": art.id, "url": art.final_url or art.url,
                                              "sha256": art.sha256}})

    # ------------------------------------------------------------------ review

    def _review_rows(s, where) -> list[dict]:
        return [{"id": r.id, "kind": r.kind, "reason": r.reason,
                 "investigation_id": r.investigation_id, "created": _iso(r.created_at),
                 "payload": {k: v for k, v in (r.payload or {}).items() if k in REVIEW_FIELDS}}
                for r in s.scalars(select(ReviewItem).where(ReviewItem.status == "open", where)
                                   .order_by(ReviewItem.kind, ReviewItem.id).limit(500))]

    async def review_list(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        t = tools(inv)
        with S() as s:
            items = _review_rows(s, (ReviewItem.investigation_id == inv)
                                 | (ReviewItem.investigation_id.is_(None)))
        return JSONResponse({"items": items, "links": t.cross_links(inv, "candidate")})

    async def review_all(_: Request) -> Response:
        with S() as s:
            items = _review_rows(s, True)
            names = dict(s.execute(select(Investigation.id, Investigation.name)).all())
            total = s.scalar(select(func.count()).where(ReviewItem.status == "open"))
        for i in items:
            i["investigation"] = names.get(i["investigation_id"])
        return JSONResponse({"items": items, "total": total})

    async def review_decide(req: Request) -> Response:
        from osint.review.actions import decide, decide_link

        if not write_allowed(req):
            return forbidden()
        b = await body(req)
        try:
            if req.path_params["what"] == "item":
                with S() as s, s.begin():
                    out = decide(s, a, int(req.path_params["id"]), b.get("decision", ""),
                                 actor="human:ui", note=b.get("note") or None,
                                 target=b.get("target"))
            else:
                with S() as s:
                    out = decide_link(s, a, int(req.path_params["id"]), b.get("decision", ""),
                                      actor="human:ui", note=b.get("note") or None)
        except ValueError as e:
            return bad(str(e))
        return JSONResponse(out)

    # ------------------------------------------------------------------ sources

    async def sources(req: Request) -> Response:
        inv = req.query_params.get("inv")
        q = (req.query_params.get("q") or "").strip().lower()
        with S() as s:
            stmt = (select(Source, func.count(Artifact.id)).join(Artifact, Artifact.source_id == Source.id)
                    .group_by(Source.id).order_by(func.count(Artifact.id).desc()).limit(1000))
            if inv:
                stmt = stmt.join(InvestigationRef, (InvestigationRef.object_type == "artifact")
                                 & (InvestigationRef.object_id == Artifact.id)
                                 & (InvestigationRef.investigation_id == int(inv)))
            if q:
                stmt = stmt.where(Source.locator.ilike(f"%{q}%"))
            rows = [{"id": src.id, "kind": src.kind, "locator": src.locator,
                     "grade": src.reliability, "note": src.reliability_note, "artifacts": n,
                     "first_seen": _iso(src.first_seen)} for src, n in s.execute(stmt)]
        return JSONResponse(rows)

    async def grade_source(req: Request) -> Response:
        from osint.evidence.sources import RELIABILITY

        if not write_allowed(req):
            return forbidden()
        b = await body(req)
        grade = (b.get("grade") or "").upper()
        if grade not in RELIABILITY:
            return bad("grade must be A-F")
        with S() as s, s.begin():
            src = s.get(Source, int(req.path_params["sid"]))
            if src is None:
                return bad("no such source", 404)
            src.reliability = grade
            src.reliability_note = (b.get("note") or "").strip() or RELIABILITY[grade]
            return JSONResponse({"id": src.id, "grade": grade, "note": src.reliability_note})

    # ------------------------------------------------------------------ jobs and files

    async def jobs_list(req: Request) -> Response:
        inv = req.query_params.get("inv")
        return JSONResponse(jm.list(int(inv) if inv else None))

    async def job_get(req: Request) -> Response:
        try:
            return JSONResponse(jm.get(int(req.path_params["jid"])))
        except JobError as e:
            return bad(str(e), 404)

    async def job_start(req: Request) -> Response:
        if not write_allowed(req):
            return forbidden()
        b = await body(req)
        inv = b.get("investigation_id")
        try:
            inv = int(inv) if inv not in (None, "") else None
            if inv is not None and not inv_exists(inv):
                return bad("no such investigation", 404)
            job = jm.start(str(b.get("action", "")), inv, b.get("params") or {})
        except (JobError, ValueError, TypeError) as e:
            return bad(str(e), 409 if "already" in str(e) else 400)
        return JSONResponse(jm.get(job.id))

    async def job_cancel(req: Request) -> Response:
        if not write_allowed(req):
            return forbidden()
        try:
            return JSONResponse(jm.cancel(int(req.path_params["jid"])))
        except JobError as e:
            return bad(str(e))

    def exports_dir() -> Path:
        return a.settings.data_path / "exports"

    async def files(_: Request) -> Response:
        d = exports_dir()
        rows = []
        if d.is_dir():
            for p in sorted(d.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:300]:
                if p.is_file():
                    st = p.stat()
                    rows.append({"name": p.name, "size": st.st_size,
                                 "modified": datetime.fromtimestamp(st.st_mtime, UTC).isoformat()})
        return JSONResponse(rows)

    async def file_download(req: Request) -> Response:
        name = Path(req.path_params["name"]).name           # no directories, no traversal
        path = exports_dir() / name
        if not path.is_file():
            return Response("not found", status_code=404)
        return FileResponse(path, media_type="application/octet-stream", filename=name,
                            headers={"X-Content-Type-Options": "nosniff"})

    # ------------------------------------------------------------------ raw evidence

    async def capture_file(req: Request) -> Response:
        cid = int(req.path_params["cid"])
        with S() as s:
            c = s.get(Capture, cid)
        if c is None or not c.path:
            return Response("not found", status_code=404)
        path = a.settings.data_path / c.path
        if not path.exists():
            return Response("content purged or missing", status_code=410)
        if c.kind in SAFE_INLINE:
            return FileResponse(path, media_type=SAFE_INLINE[c.kind], headers=HARDEN)
        # anything else (HTML, WARC, raw bodies) as inert text or a download
        if c.kind in ("rendered_html", "raw"):
            return Response(path.read_bytes(), media_type="text/plain; charset=utf-8",
                            headers=HARDEN)
        return FileResponse(path, media_type="application/octet-stream", headers=HARDEN,
                            filename=f"capture-{cid}-{c.kind}")

    async def document(req: Request) -> Response:
        did = int(req.path_params["did"])
        with S() as s:
            d = s.get(Document, did)
        if d is None:
            return Response("not found", status_code=404)
        return Response(d.text, media_type="text/plain; charset=utf-8", headers=HARDEN)

    routes = [
        Route("/", index),
        Route("/api/meta", meta),
        Route("/api/system/doctor", doctor),
        Route("/api/system/tor", tor_status),
        Route("/api/plugins", plugins),
        Route("/api/investigations", investigations),
        Route("/api/investigations", create_investigation, methods=["POST"]),
        Route("/api/inv/{inv:int}/status", inv_status),
        Route("/api/inv/{inv:int}/overview", overview),
        Route("/api/inv/{inv:int}/collect", collect, methods=["POST"]),
        Route("/api/inv/{inv:int}/network", set_network, methods=["POST"]),
        Route("/api/inv/{inv:int}/schedule", set_schedule, methods=["POST"]),
        Route("/api/inv/{inv:int}/archive", archive, methods=["POST"]),
        Route("/api/inv/{inv:int}/upload", upload, methods=["POST"]),
        Route("/api/inv/{inv:int}/entities", entities),
        Route("/api/inv/{inv:int}/graph", graph),
        Route("/api/inv/{inv:int}/timeline", timeline),
        Route("/api/inv/{inv:int}/findings", findings),
        Route("/api/inv/{inv:int}/key-players", key_players),
        Route("/api/inv/{inv:int}/links", links),
        Route("/api/inv/{inv:int}/reports", reports),
        Route("/api/inv/{inv:int}/claude-jobs", claude_jobs),
        Route("/api/inv/{inv:int}/evidence", evidence),
        Route("/api/inv/{inv:int}/review", review_list),
        Route("/api/review", review_all),
        Route("/api/review/{what:str}/{id:int}", review_decide, methods=["POST"]),
        Route("/api/search", search),
        Route("/api/entity/{eid:int}", entity),
        Route("/api/evidence", evidence_detail),
        Route("/api/finding/{fid:int}/explain", explain),
        Route("/api/document/{did:int}", document_json),
        Route("/api/sources", sources),
        Route("/api/sources/{sid:int}/grade", grade_source, methods=["POST"]),
        Route("/api/jobs", jobs_list),
        Route("/api/jobs", job_start, methods=["POST"]),
        Route("/api/jobs/{jid:int}", job_get),
        Route("/api/jobs/{jid:int}/cancel", job_cancel, methods=["POST"]),
        Route("/api/files", files),
        Route("/files/{name:str}", file_download),
        Route("/report/{rid:int}", report_html),
        Route("/capture/{cid:int}", capture_file),
        Route("/document/{did:int}", document),
    ]
    if (STATIC / "assets").is_dir():
        routes.append(Mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets"))
    routes.append(Route("/{path:path}", spa_fallback))
    return Starlette(routes=routes)


def _explain(S, finding_id: int, depth: int = 5) -> dict:
    """A finding's proof tree as JSON, down to the preserved quotes."""
    from osint.storage.db import Event as EventRow
    from osint.storage.db import (
        EvidenceLink,
        Finding,
        Inference,
        InferencePremise,
    )

    with S() as s:
        def evidence(ev_id: int) -> dict:
            row = s.execute(select(EvidenceLink, Artifact).join(
                Artifact, Artifact.id == EvidenceLink.artifact_id)
                .where(EvidenceLink.id == ev_id)).first()
            if row is None:
                return {"type": "evidence", "id": ev_id, "missing": True}
            ev, art = row
            return {"type": "evidence", "id": ev.id, "quote": ev.quote_original,
                    "translation": ev.quote_translated, "url": art.final_url or art.url,
                    "captured": art.fetched_at_utc.isoformat(), "sha256": art.sha256,
                    "artifact_id": art.id, "document_id": ev.document_id}

        def node(kind: str, oid: int, level: int) -> dict:
            if kind == "evidence":
                return evidence(oid)
            out: dict = {"type": kind, "id": oid}
            if kind == "finding":
                f = s.get(Finding, oid)
                if f is None:
                    return {**out, "missing": True}
                out |= {"text": f.text, "kind": f.kind, "status": f.status,
                        "epistemic_status": f.epistemic_status, "confidence": f.confidence}
            elif kind == "relation":
                r = s.get(Relation, oid)
                if r:
                    src, dst = s.get(Entity, r.src_entity_id), s.get(Entity, r.dst_entity_id)
                    out |= {"text": f"{src.canonical_name if src else r.src_entity_id} "
                                    f"—{r.type}→ {dst.canonical_name if dst else r.dst_entity_id}"}
            elif kind == "event":
                e = s.get(EventRow, oid)
                if e:
                    out |= {"text": f"{e.type}: {e.description}"}
            children = []
            if level < depth:
                for inf in s.scalars(select(Inference).where(Inference.conclusion_type == kind,
                                                             Inference.conclusion_id == oid)):
                    prem = [node(p.premise_type, p.premise_id, level + 1) for p in s.scalars(
                        select(InferencePremise).where(InferencePremise.inference_id == inf.id))]
                    children.append({"type": "inference", "id": inf.id, "method": inf.method,
                                     "by": inf.created_by, "children": prem})
            children += [evidence(i) for i in s.scalars(select(EvidenceLink.id).where(
                EvidenceLink.target_type == kind, EvidenceLink.target_id == oid))]
            return {**out, "children": children}

        return node("finding", finding_id, 0)

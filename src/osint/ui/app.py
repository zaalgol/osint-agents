"""Local web UI (Starlette). Binds to 127.0.0.1 only.

Captured web content is hostile by default: captured HTML is served as text/plain (or a
sandbox CSP that blocks scripts) with nosniff, and only image/PDF captures render
inline. The only writes are review decisions (POST), which require a per-server CSRF
token and a localhost Origin.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from sqlalchemy import func, select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from osint.analyst.tools import AnalystTools, ToolError
from osint.core.context import App
from osint.storage.db import (
    Artifact,
    Capture,
    Document,
    Entity,
    EventParticipant,
    Investigation,
    InvestigationRef,
    Relation,
    Report,
    ReviewItem,
    Task,
)

HERE = Path(__file__).parent
SAFE_INLINE = {"screenshot_png": "image/png", "pdf_render": "application/pdf"}
HARDEN = {"X-Content-Type-Options": "nosniff",
          "Content-Security-Policy": "sandbox; default-src 'none'; img-src 'self' data:",
          "Referrer-Policy": "no-referrer"}


def create_app(app: App | None = None) -> Starlette:
    a = app or App()
    S = a.session_factory
    csrf = secrets.token_urlsafe(32)

    def write_allowed(req: Request) -> bool:
        origin = req.headers.get("origin") or req.headers.get("referer") or ""
        local = origin.startswith(("http://127.0.0.1:", "http://localhost:"))
        return local and secrets.compare_digest(req.headers.get("x-csrf-token", ""), csrf)

    def tools(inv: int) -> AnalystTools:
        return AnalystTools(S, a.ontology, a.registry, a.raw_store, inv, actor="ui",
                            neo4j=a.settings.neo4j)

    async def index(_: Request) -> Response:
        page = (HERE / "index.html").read_text(encoding="utf-8").replace("__CSRF__", csrf)
        return HTMLResponse(page)

    async def review_list(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        t = tools(inv)
        with S() as s:
            items = [{"id": r.id, "kind": r.kind, "reason": r.reason,
                      "payload": {k: v for k, v in (r.payload or {}).items()
                                  if k in ("names", "score", "list_entry", "a_description",
                                           "b_description", "host", "quote", "name", "type",
                                           "candidates", "entity_id", "a", "b")}}
                     for r in s.scalars(select(ReviewItem).where(
                         ReviewItem.status == "open",
                         (ReviewItem.investigation_id == inv) | (ReviewItem.investigation_id.is_(None)))
                         .order_by(ReviewItem.kind, ReviewItem.id).limit(500))]
        return JSONResponse({"items": items, "links": t.cross_links(inv, "candidate")})

    async def review_decide(req: Request) -> Response:
        from osint.review.actions import decide, decide_link

        if not write_allowed(req):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        body = await req.json()
        try:
            if req.path_params["what"] == "item":
                with S() as s, s.begin():
                    out = decide(s, a, int(req.path_params["id"]), body.get("decision", ""),
                                 actor="human:ui", note=body.get("note") or None,
                                 target=body.get("target"))
            else:
                with S() as s:
                    out = decide_link(s, a, int(req.path_params["id"]), body.get("decision", ""),
                                      actor="human:ui", note=body.get("note") or None)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return JSONResponse(out)

    async def investigations(_: Request) -> Response:
        with S() as s:
            out = []
            for inv in s.scalars(select(Investigation).order_by(Investigation.id)):
                counts = dict(s.execute(select(InvestigationRef.object_type, func.count()).where(
                    InvestigationRef.investigation_id == inv.id).group_by(
                    InvestigationRef.object_type)).all())
                open_tasks = s.scalar(select(func.count()).where(
                    Task.investigation_id == inv.id, Task.status.in_(["pending", "running"])))
                out.append({"id": inv.id, "name": inv.name,
                            "focus": (inv.seed or {}).get("focus"),
                            "created": inv.created_at.isoformat(), "counts": counts,
                            "open_tasks": open_tasks})
        return JSONResponse(out)

    async def overview(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        return JSONResponse(tools(inv).investigation_overview(inv))

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
            pairs = {}
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
            return JSONResponse({"error": str(e)}, status_code=404)
        markers = {int(m[3:-1]) for r in data["relations"] for m in r["evidence"]}
        markers |= {int(m[3:-1]) for v in data["events"] for m in v["evidence"]}
        data["evidence_detail"] = {e["marker"]: e for e in t.get_evidence(sorted(markers)[:40])}
        return JSONResponse(data)

    async def timeline(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        return JSONResponse(tools(inv).timeline(inv, limit=300))

    async def findings(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        t = tools(inv)
        rows = t.list_findings(inv)
        return JSONResponse({"findings": rows, "links": t.cross_links(inv),
                             "contradictions": t.contradictions(inv)})

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

    async def evidence(req: Request) -> Response:
        inv = int(req.path_params["inv"])
        with S() as s:
            arts = s.scalars(select(Artifact).where(Artifact.id.in_(select(
                InvestigationRef.object_id).where(InvestigationRef.investigation_id == inv,
                                                  InvestigationRef.object_type == "artifact")))
                .order_by(Artifact.id.desc()).limit(500)).all()
            out = []
            for art in arts:
                caps = s.execute(select(Capture.id, Capture.kind).where(
                    Capture.artifact_id == art.id)).all()
                doc = s.scalar(select(Document.id).where(Document.artifact_id == art.id).limit(1))
                ex = (art.capture_meta or {}).get("extra", {})
                out.append({"id": art.id, "url": art.final_url or art.url, "mime": art.mime,
                            "platform": (art.capture_meta or {}).get("platform"),
                            "captured": art.fetched_at_utc.isoformat(),
                            "posted": art.posted_at.isoformat() if art.posted_at else None,
                            "sha256": art.sha256, "size": art.size, "document": doc,
                            "route": ex.get("route"), "blocked": ex.get("blocked"),
                            "captures": [{"id": i, "kind": k} for i, k in caps]})
            review = [{"id": r.id, "kind": r.kind, "reason": r.reason}
                      for r in s.scalars(select(ReviewItem).where(
                          ReviewItem.investigation_id == inv, ReviewItem.status == "open")
                          .order_by(ReviewItem.id.desc()).limit(200))]
        return JSONResponse({"artifacts": out, "review": review})

    async def capture_file(req: Request) -> Response:
        cid = int(req.path_params["cid"])
        with S() as s:
            c = s.get(Capture, cid)
        if c is None or not c.path:
            return Response("not found", status_code=404)
        path = a.settings.data_path / c.path
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
        Route("/api/investigations", investigations),
        Route("/api/inv/{inv:int}/overview", overview),
        Route("/api/inv/{inv:int}/graph", graph),
        Route("/api/inv/{inv:int}/timeline", timeline),
        Route("/api/inv/{inv:int}/findings", findings),
        Route("/api/inv/{inv:int}/reports", reports),
        Route("/api/inv/{inv:int}/evidence", evidence),
        Route("/api/entity/{eid:int}", entity),
        Route("/api/inv/{inv:int}/review", review_list),
        Route("/api/review/{what:str}/{id:int}", review_decide, methods=["POST"]),
        Route("/report/{rid:int}", report_html),
        Route("/capture/{cid:int}", capture_file),
        Route("/document/{did:int}", document),
    ]
    return Starlette(routes=routes)

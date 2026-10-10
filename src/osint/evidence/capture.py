"""Build a full capture bundle for a URL and persist bundles as evidence.

Bundle = raw body (the artifact) + WARC (request/response as received) + screenshot,
PDF render and rendered DOM (optional, via Playwright). Each file goes into the raw
store with SHA-256/512 hashes, gets a Capture row, and gets a custody entry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from osint.core.models import CapturedItem, CaptureKind, CaptureMeta, ExtraCapture
from osint.evidence import custody
from osint.evidence.ingest import ingest_bytes
from osint.evidence.warc import build_warc
from osint.storage.db import Artifact, Capture
from osint.storage.raw_store import RawStore

if TYPE_CHECKING:
    from osint.core.context import PluginContext


async def capture_url(
    ctx: PluginContext, url: str, collector: str, *, screenshot: bool | None = None,
    params: dict | None = None, platform: str | None = None,
) -> CapturedItem:
    if ctx.http is None:
        raise RuntimeError("no HTTP fetcher in context")
    res = await ctx.http.fetch(url, params=params)
    meta = CaptureMeta(
        url=url,
        final_url=res.final_url,
        http_status=res.status,
        resolved_ip=res.resolved_ip,
        user_agent=ctx.settings.network.user_agent,
        proxy=(ctx.settings.network.vpn_proxy if res.route == "vpn"
               else ctx.settings.network.proxy),
        collector=collector,
        platform=platform,
        extra={"redirects": res.redirects, "http_version": res.http_version,
               "fetched_at": res.fetched_at.isoformat(), "route": res.route,
               **({"blocked": res.blocked} if res.blocked else {}),
               **({"route_attempts": res.attempts} if res.attempts else {})},
    )
    extras = [ExtraCapture(kind=CaptureKind.WARC, data=build_warc(res), mime="application/warc")]

    want_shot = ctx.settings.evidence.screenshots if screenshot is None else screenshot
    is_html = (res.content_type or "").startswith(("text/html", "application/xhtml"))
    if want_shot and is_html and ctx.browser is not None and res.status < 400 \
            and not res.blocked:
        shot = await ctx.browser.capture(
            res.final_url, proxy=ctx.settings.network.vpn_proxy if res.route == "vpn" else None)
        meta.extra["browser_captured_at"] = shot.captured_at.isoformat()
        if shot.error:
            meta.extra["browser_error"] = shot.error
        if shot.screenshot_png:
            extras.append(ExtraCapture(kind=CaptureKind.SCREENSHOT_PNG, data=shot.screenshot_png,
                                       mime="image/png"))
        if shot.pdf:
            extras.append(ExtraCapture(kind=CaptureKind.PDF_RENDER, data=shot.pdf,
                                       mime="application/pdf"))
        if shot.rendered_html:
            extras.append(ExtraCapture(kind="rendered_html", data=shot.rendered_html,
                                       mime="text/html"))

    mime = res.content_type
    if res.charset:
        meta.extra["charset"] = res.charset
    # a block page is kept as evidence (it shows the source refused us) but not parsed
    return CapturedItem(data=res.body, meta=meta, mime=mime, extra_captures=extras,
                        parse=res.status < 400 and not res.blocked)


def persist_item(
    session: Session, store: RawStore, item: CapturedItem, actor: str,
    source_id: int | None = None,
) -> tuple[Artifact, bool]:
    """Store a captured item and its whole bundle in the caller's transaction."""
    art, created = ingest_bytes(session, store, item.data, item.meta, actor=actor,
                                mime=item.mime, source_id=source_id)
    for extra in item.extra_captures:
        blob = store.put_bytes(extra.data)
        kind = extra.kind.value if isinstance(extra.kind, CaptureKind) else str(extra.kind)
        cap = Capture(artifact_id=art.id, kind=kind, sha256=blob.sha256, sha512=blob.sha512,
                      path=blob.path)
        session.add(cap)
        session.flush()
        custody.append(session, "capture_added", actor, art.id,
                       {"capture_id": cap.id, "kind": kind, "sha256": blob.sha256,
                        "size": blob.size})
    return art, created


def meta_only(url: str, collector: str, **extra) -> CaptureMeta:
    return CaptureMeta(url=url, collector=collector, extra=extra)

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
    from osint.net.http import FetchError

    try:
        res = await ctx.http.fetch(url, params=params)
    except FetchError as e:
        # every HTTP route failed (e.g. anti-bot tarpits that hold connections open):
        # a real browser is the last resort for plain page URLs
        if ctx.browser is None or params:
            raise
        item = await _browser_route(ctx, url, [{"route": "http", "error": str(e)[:300]}],
                                    collector, platform)
        if item is None:
            raise
        return item
    meta = CaptureMeta(
        url=url,
        final_url=res.final_url,
        http_status=res.status,
        resolved_ip=res.resolved_ip,
        user_agent=ctx.settings.network.user_agent,
        proxy=(ctx.settings.network.vpn_proxy if res.route == "vpn"
               else None if res.route == "local" else ctx.settings.network.proxy),
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
            res.final_url, proxy=(ctx.settings.network.vpn_proxy if res.route == "vpn"
                                  else ctx.settings.network.browser_proxy
                                  or ctx.settings.network.proxy))
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
    if res.blocked and ctx.browser is not None:
        attempts = [*res.attempts, {"route": res.route, "error": f"blocked: {res.blocked}"}]
        via_browser = await _browser_route(ctx, url, attempts, collector, platform)
        if via_browser is not None:
            return via_browser
    # a block page is kept as evidence (it shows the source refused us) but not parsed
    return CapturedItem(data=res.body, meta=meta, mime=mime, extra_captures=extras,
                        parse=res.status < 400 and not res.blocked)


async def _browser_route(ctx: PluginContext, url: str, attempts: list[dict], collector: str,
                         platform: str | None) -> CapturedItem | None:
    """Last resort for sites that refuse non-browser clients: load the page in Chromium
    (through the VPN when one is configured). The browser's main-document response is the
    evidence; it gets its own WARC record."""
    from osint.net.http import FetchResult, block_reason

    net = ctx.settings.network
    # VPN when available; otherwise the configured proxy (Tor on the anonymous profile)
    vpn = (net.vpn_proxy if (net.vpn_fallback and net.vpn_proxy)
           else net.browser_proxy or net.proxy)
    bf = await ctx.browser.fetch(url, proxy=vpn)
    if bf.status is None or bf.status >= 400 or block_reason(bf.status, bf.body):
        return None
    route = ("browser+vpn" if vpn and vpn == net.vpn_proxy
             else "browser+proxy" if vpn else "browser")
    headers = [(k, v) for k, v in bf.response_headers if k.lower() != "content-encoding"]
    fr = FetchResult(url=url, final_url=bf.final_url or url, status=bf.status,
                     reason=bf.reason or "OK", http_version="HTTP/1.1",
                     request_headers=bf.request_headers, response_headers=headers,
                     wire_body=bf.body, body=bf.body, fetched_at=bf.capture.captured_at,
                     route=route)
    meta = CaptureMeta(
        url=url, final_url=fr.final_url, http_status=bf.status,
        user_agent=ctx.settings.network.user_agent, proxy=vpn, collector=collector,
        platform=platform,
        extra={"route": route, "fetched_at": fr.fetched_at.isoformat(),
               "route_attempts": attempts,
               "note": "HTTP clients were blocked; captured with a real browser"})
    extras = [ExtraCapture(kind=CaptureKind.WARC, data=build_warc(fr), mime="application/warc")]
    c = bf.capture
    if c.screenshot_png:
        extras.append(ExtraCapture(kind=CaptureKind.SCREENSHOT_PNG, data=c.screenshot_png,
                                   mime="image/png"))
    if c.pdf:
        extras.append(ExtraCapture(kind=CaptureKind.PDF_RENDER, data=c.pdf, mime="application/pdf"))
    if c.rendered_html:
        extras.append(ExtraCapture(kind="rendered_html", data=c.rendered_html, mime="text/html"))
    mime = next((v.split(";")[0].strip() for k, v in headers if k.lower() == "content-type"),
                "text/html")
    return CapturedItem(data=bf.body, meta=meta, mime=mime, extra_captures=extras, parse=True)


def persist_item(
    session: Session, store: RawStore, item: CapturedItem, actor: str,
    source_id: int | None = None,
) -> tuple[Artifact, bool]:
    """Store a captured item and its whole bundle in the caller's transaction.

    Every part is checked against the blocklist first, so a blocked item leaves nothing
    behind (raises BlockedContent before any write)."""
    for part in (item.data, *(x.data for x in item.extra_captures)):
        store.blocklist.check(part)
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

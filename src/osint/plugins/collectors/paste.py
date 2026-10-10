"""Paste sites (no account): capture pastes by URL, or find them through SearXNG.

The paste sites' own search/scraping APIs need accounts (Pastebin's scraping API needs
a PRO account and a whitelisted IP), so this collector doesn't use them:

* `urls`: each paste page is captured with proof (raw HTML, WARC, screenshot). Where
  the site has a raw endpoint, the raw text is captured too and is what gets parsed,
  because it keeps the original formatting (code, lists of handles, wallets).
* `queries`: each query is searched once per paste host through our own SearXNG
  (`<query> site:<host>`), and the paste URLs found are captured as above.

Pastes are often deleted quickly. The capture is the proof that a paste existed.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem, FollowUp
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url

# host -> (paste-id regex on the path, raw URL template); template None = no raw endpoint
HOSTS: dict[str, tuple[str, str | None]] = {
    "pastebin.com": (r"^/(?:raw/)?([A-Za-z0-9]{8})$", "https://pastebin.com/raw/{id}"),
    "paste.ee": (r"^/[pr]/([A-Za-z0-9]+)$", "https://paste.ee/r/{id}"),
    "dpaste.org": (r"^/([A-Za-z0-9]+)(?:/raw)?$", "https://dpaste.org/{id}/raw"),
    "rentry.co": (r"^/([A-Za-z0-9_-]+)$", None),
    "rentry.org": (r"^/([A-Za-z0-9_-]+)$", None),
    "justpaste.it": (r"^/([A-Za-z0-9_-]+)$", None),
    "controlc.com": (r"^/([A-Za-z0-9]+)$", None),
    "pastes.io": (r"^/([A-Za-z0-9_-]+)$", None),
    "gist.github.com": (r"^/([A-Za-z0-9_-]+/[0-9a-f]+)$",
                        "https://gist.githubusercontent.com/{id}/raw"),
}
SEARCH_HOSTS = ["pastebin.com", "rentry.co", "justpaste.it", "controlc.com", "paste.ee"]
NOT_PASTES = {"login", "signup", "archive", "trends", "faq", "tools", "doc_api", "pro",
              "contact", "dmca", "privacy", "terms", "night_mode", "search", "languages"}


def paste_ref(url: str) -> tuple[str, str, str | None] | None:
    """(host, paste id, raw URL or None) for a paste URL, else None."""
    u = urlsplit(url.strip())
    host = (u.hostname or "").removeprefix("www.")
    if host not in HOSTS:
        return None
    pattern, raw = HOSTS[host]
    m = re.match(pattern, u.path.rstrip("/") or "/")
    if not m or m.group(1).lower() in NOT_PASTES:
        return None
    pid = m.group(1)
    return host, pid, raw.format(id=pid) if raw else None


class PasteParams(BaseModel):
    urls: list[str] = Field(default_factory=list, description="Paste URLs")
    queries: list[str] = Field(default_factory=list,
                               description="Search terms; searched per paste host via SearXNG")
    hosts: list[str] = Field(default_factory=lambda: list(SEARCH_HOSTS))
    max_results: int = Field(10, ge=1, le=50, description="Paste URLs per query and host")
    found_via: str | None = None


class PasteCollector(Collector):
    name = "paste"
    description = "Paste sites (Pastebin, Rentry, JustPaste.it, ...) by URL or search; no account."
    params_schema = PasteParams
    refreshable = True

    def __init__(self) -> None:
        self._done: list[str] = []          # URLs / searches finished (resume)

    async def collect(self, params: PasteParams, ctx: PluginContext
                      ) -> AsyncIterator[CapturedItem | FollowUp]:
        for url in params.urls:
            if url in self._done:
                continue
            ref = paste_ref(url)
            if ref is None:                    # not a known paste host: plain web capture
                yield FollowUp(plugin="web", params={"urls": [url], "found_via": params.found_via})
            else:
                async for item in self._capture(ctx, url, ref, params.found_via):
                    yield item
            self._done.append(url)
        for query in params.queries:
            for host in params.hosts:
                key = f"search:{host}:{query}"
                if key in self._done:
                    continue
                qp: dict[str, Any] = {"q": f"{query} site:{host}", "format": "json",
                                      "categories": "general"}
                res = await capture_url(ctx, f"{ctx.settings.searxng.url}/search", self.ident,
                                        screenshot=False, params=qp, platform="searxng")
                res.parse = False
                res.meta.extra["query"] = qp["q"]
                yield res
                found = []
                if res.meta.http_status == 200:
                    try:
                        results = json.loads(res.data).get("results", [])
                    except ValueError:
                        results = []
                    for r in results:
                        u = (r.get("url") or "").strip()
                        if paste_ref(u) and u not in found:
                            found.append(u)
                if found:
                    yield FollowUp(plugin="paste", priority=110, params={
                        "urls": found[:params.max_results], "found_via": f"search:{qp['q']}"})
                self._done.append(key)

    async def _capture(self, ctx: PluginContext, url: str, ref: tuple, found_via: str | None):
        host, pid, raw_url = ref
        page = await capture_url(ctx, url, self.ident, platform="paste")
        page.meta.platform_id = f"paste:{host}:{pid}"
        page.meta.extra.update({"paste": {"host": host, "id": pid}, "found_via": found_via})
        if raw_url is None:
            yield page                          # no raw endpoint: parse the page itself
            return
        page.parse = False
        yield page
        raw = await capture_url(ctx, raw_url, self.ident, screenshot=False, platform="paste")
        if raw.meta.http_status != 200 or raw.meta.extra.get("blocked"):
            return
        raw.meta.platform_id = f"paste:{host}:{pid}:raw"
        raw.meta.extra.update({"paste": {"host": host, "id": pid, "page": url},
                               "found_via": found_via})
        raw.mime = "text/plain"
        raw.parse = True
        yield raw

    def checkpoint(self) -> dict[str, Any]:
        return {"done": self._done}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._done = list(checkpoint.get("done", []))

    def on_refresh(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        return {}                               # searches run again; known pastes dedupe by hash

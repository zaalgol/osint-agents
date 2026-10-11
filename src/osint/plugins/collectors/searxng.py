"""Search via self-hosted SearXNG.

The search response itself is stored as evidence (it proves what the search returned,
and when). Each result URL becomes a follow-up ``web`` fetch task.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem, FollowUp
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url

SKIP_SCHEMES = ("javascript:", "mailto:", "data:")


class SearxngParams(BaseModel):
    queries: list[str] = Field(min_length=1)
    max_results: int = Field(10, ge=1, le=100)    # per query
    pages: int = Field(1, ge=1, le=10)
    language: str | None = Field("all", description="all = every language (default), or a code: "
                          "en, ar, ru, fa...")
    time_range: str | None = None                 # day|week|month|year
    categories: str = "general,news"
    fetch_results: bool = True


class SearxngCollector(Collector):
    name = "searxng"
    description = "Metasearch via SearXNG; stores result pages and schedules fetches."
    params_schema = SearxngParams
    refreshable = True

    def __init__(self) -> None:
        self._pos = 0  # index into the (query, page) grid
        self._time_range: str | None = None  # refresh override ("day", "week", ...)

    async def collect(
        self, params: SearxngParams, ctx: PluginContext
    ) -> AsyncIterator[CapturedItem | FollowUp]:
        grid = [(q, p) for q in params.queries for p in range(1, params.pages + 1)]
        seen: set[str] = set()
        for i in range(self._pos, len(grid)):
            query, page = grid[i]
            qp: dict[str, Any] = {"q": query, "format": "json", "pageno": page,
                                  "categories": params.categories}
            # explicit, or SearXNG's "auto" would follow our Accept-Language (English)
            qp["language"] = params.language or "all"
            if self._time_range or params.time_range:
                qp["time_range"] = self._time_range or params.time_range
            item = await capture_url(ctx, f"{ctx.settings.searxng.url}/search", self.ident,
                                     screenshot=False, params=qp, platform="searxng")
            item.parse = False
            item.meta.extra["query"] = query
            item.meta.extra["page"] = page
            yield item

            if params.fetch_results and item.meta.http_status == 200:
                try:
                    results = json.loads(item.data).get("results", [])
                except ValueError:
                    results = []
                urls = []
                for r in results[: params.max_results]:
                    url = (r.get("url") or "").strip()
                    if url and not url.startswith(SKIP_SCHEMES) and url not in seen:
                        seen.add(url)
                        urls.append(url)
                for url in urls:
                    yield FollowUp(plugin="web", params={"urls": [url], "found_via":
                                                         f"searxng:{query}"}, priority=110)
            self._pos = i + 1

    def checkpoint(self) -> dict[str, Any]:
        cp: dict[str, Any] = {"pos": self._pos}
        if self._time_range:
            cp["time_range"] = self._time_range
        return cp

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._pos = int(checkpoint.get("pos", 0))
        self._time_range = checkpoint.get("time_range")

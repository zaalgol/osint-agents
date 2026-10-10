"""GDELT DOC 2.0: worldwide news search across 65+ languages (no key, no account).

The API response is captured as evidence, and each article URL becomes a follow-up
`web` fetch (deduplicated per URL, like searxng). Useful for broad, multilingual news
coverage of actors and events.
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

API = "https://api.gdeltproject.org/api/v2/doc/doc"


class GdeltParams(BaseModel):
    queries: list[str] = Field(min_length=1, description='GDELT syntax, e.g. "houthi" sourcelang:arabic')
    timespan: str = Field("1w", description="e.g. 24h, 1w, 3m")
    max_records: int = Field(50, ge=1, le=250)
    fetch_articles: bool = True


class GdeltCollector(Collector):
    name = "gdelt"
    description = "GDELT worldwide multilingual news search (no account)."
    params_schema = GdeltParams
    refreshable = True

    def __init__(self) -> None:
        self._pos = 0

    async def collect(self, params: GdeltParams, ctx: PluginContext
                      ) -> AsyncIterator[CapturedItem | FollowUp]:
        for i in range(self._pos, len(params.queries)):
            q = params.queries[i]
            item = await capture_url(ctx, API, self.ident, screenshot=False, platform="gdelt",
                                     params={"query": q, "mode": "artlist", "format": "json",
                                             "maxrecords": params.max_records,
                                             "timespan": params.timespan, "sort": "datedesc"})
            item.parse = False
            item.meta.extra["query"] = q
            yield item
            if params.fetch_articles and item.meta.http_status == 200:
                try:
                    arts = json.loads(item.data or b"{}").get("articles", [])
                except ValueError:
                    arts = []  # GDELT answers plain-text errors for bad queries
                for a in arts:
                    if a.get("url"):
                        yield FollowUp(plugin="web", priority=115, params={
                            "urls": [a["url"]], "found_via": f"gdelt:{q}"})
            self._pos = i + 1
        self._pos = 0

    def checkpoint(self) -> dict[str, Any]:
        return {"pos": self._pos}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._pos = int(checkpoint.get("pos", 0))

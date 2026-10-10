"""Generic web collector: fetch one or more URLs with the full proof bundle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url


class WebParams(BaseModel):
    urls: list[str] = Field(min_length=1)
    screenshot: bool | None = None       # None = follow settings.evidence.screenshots
    found_via: str | None = None         # provenance: search query, feed, parent URL


class WebCollector(Collector):
    name = "web"
    description = "Fetch URLs: raw body + WARC + screenshot/PDF/rendered DOM."
    params_schema = WebParams

    def __init__(self) -> None:
        self._done = 0

    async def collect(self, params: WebParams, ctx: PluginContext) -> AsyncIterator[CapturedItem]:
        for i in range(self._done, len(params.urls)):
            item = await capture_url(ctx, params.urls[i], self.ident, screenshot=params.screenshot)
            if params.found_via:
                item.meta.extra["found_via"] = params.found_via
            yield item
            self._done = i + 1

    def checkpoint(self) -> dict[str, Any]:
        return {"done": self._done}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._done = int(checkpoint.get("done", 0))

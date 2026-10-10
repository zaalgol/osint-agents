"""Wayback Machine: historical snapshots of a URL (deleted pages, changed statements).

The CDX index response is captured (proof of which snapshots existed), then each chosen
snapshot is fetched in raw form (``<ts>id_/<url>`` = the page as archived, without the
Wayback toolbar). The snapshot time becomes the artifact's posted_at. No account needed.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url

CDX = "https://web.archive.org/cdx/search/cdx"


class WaybackParams(BaseModel):
    urls: list[str] = Field(min_length=1)
    mode: Literal["latest", "earliest", "spread"] = "latest"
    max_snapshots: int = Field(3, ge=1, le=50, description="Per URL")
    from_date: str | None = Field(None, description="YYYYMMDD")
    to_date: str | None = Field(None, description="YYYYMMDD")


def pick(rows: list[list[str]], mode: str, n: int) -> list[list[str]]:
    if not rows:
        return []
    if mode == "latest":
        return rows[-n:][::-1]
    if mode == "earliest":
        return rows[:n]
    step = max(1, len(rows) // n)               # spread over the whole history
    return rows[::step][:n]


class WaybackCollector(Collector):
    name = "wayback"
    description = "Archived snapshots of URLs from the Internet Archive (no account)."
    params_schema = WaybackParams

    def __init__(self) -> None:
        self._done: list[str] = []

    async def collect(self, params: WaybackParams, ctx: PluginContext) -> AsyncIterator[CapturedItem]:
        for url in params.urls:
            q: dict[str, Any] = {"url": url, "output": "json", "filter": "statuscode:200",
                                 "collapse": "digest", "fl": "timestamp,original,mimetype,digest"}
            if params.from_date:
                q["from"] = params.from_date
            if params.to_date:
                q["to"] = params.to_date
            index = await capture_url(ctx, CDX, self.ident, screenshot=False, params=q,
                                      platform="wayback")
            index.parse = False
            index.meta.extra["looked_up"] = url
            yield index
            try:
                rows = json.loads(index.data or b"[]")[1:]
            except ValueError:
                rows = []
            for ts, original, mime, _digest in pick(rows, params.mode, params.max_snapshots):
                key = f"{ts}:{original}"
                if key in self._done:
                    continue
                snap = await capture_url(ctx, f"https://web.archive.org/web/{ts}id_/{original}",
                                         self.ident, platform="wayback")
                snap.meta.posted_at = datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
                snap.meta.platform_id = f"wayback:{ts}:{original}"
                snap.meta.extra.update({"archived_url": original, "archived_at": ts,
                                        "archived_mime": mime})
                yield snap
                self._done.append(key)

    def checkpoint(self) -> dict[str, Any]:
        return {"done": self._done[-2000:]}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._done = list(checkpoint.get("done", []))

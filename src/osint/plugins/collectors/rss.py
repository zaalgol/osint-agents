"""RSS/Atom collector: stores the feed as evidence and schedules fetches of new entries.

The checkpoint remembers which entry IDs were already scheduled, so ``osint refresh``
(and resume) only fetch new items.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import feedparser
from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem, FollowUp
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url

MAX_SEEN = 5000


class RssParams(BaseModel):
    feeds: list[str] = Field(min_length=1)
    max_entries: int = Field(50, ge=1, le=1000)   # per feed per run
    fetch_entries: bool = True


class RssCollector(Collector):
    name = "rss"
    description = "RSS/Atom feeds; stores the feed and schedules fetches of new entries."
    params_schema = RssParams
    refreshable = True

    def __init__(self) -> None:
        self._feed_pos = 0
        self._seen: list[str] = []

    async def collect(
        self, params: RssParams, ctx: PluginContext
    ) -> AsyncIterator[CapturedItem | FollowUp]:
        seen = set(self._seen)
        for i in range(self._feed_pos, len(params.feeds)):
            feed_url = params.feeds[i]
            item = await capture_url(ctx, feed_url, self.ident, screenshot=False, platform="rss")
            item.parse = False
            yield item

            parsed = feedparser.parse(item.data)
            new: list[tuple[str, str]] = []
            for e in parsed.entries[: params.max_entries]:
                key = e.get("id") or e.get("link")
                link = e.get("link")
                if key and link and key not in seen:
                    seen.add(key)
                    new.append((key, link))
            for key, link in new:
                # Mark seen right before yielding: the checkpoint persisted after this
                # follow-up then covers exactly the entries that were really scheduled.
                self._seen.append(key)
                if params.fetch_entries:
                    yield FollowUp(plugin="web", params={"urls": [link],
                                                         "found_via": f"rss:{feed_url}"},
                                   priority=110)
            self._feed_pos = i + 1
        self._feed_pos = 0  # a later refresh starts from the first feed again

    def checkpoint(self) -> dict[str, Any]:
        return {"feed_pos": self._feed_pos, "seen": self._seen[-MAX_SEEN:]}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._feed_pos = int(checkpoint.get("feed_pos", 0))
        self._seen = list(checkpoint.get("seen", []))

    def on_refresh(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        return {"feed_pos": 0, "seen": checkpoint.get("seen", [])}  # only new entries

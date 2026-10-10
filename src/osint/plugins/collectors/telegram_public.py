"""Public Telegram channels via the web preview (https://t.me/s/<channel>). No account.

This works only for channels that are public and have web preview enabled. Each preview
page is captured with full proof (raw HTML, WARC, screenshot). Each post on it becomes
a derived artifact (post text plus metadata) that records the page's SHA-256 it came
from, the post's permalink (t.me/<channel>/<id>) and its time. That way every
citation points to one post, while the page capture proves the post existed as shown.

Pagination walks back with ?before=<id> until max_posts or `since`. The checkpoint
keeps the newest post id per channel, so a refresh fetches only newer posts.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from lxml import html as lxml_html
from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem, CaptureMeta
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url

CHANNEL_RE = re.compile(r"^(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z0-9_]{4,})")


def channel_name(value: str) -> str:
    value = value.strip()
    m = CHANNEL_RE.match(value)
    name = m.group(1) if m else value.lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_]{4,}", name):
        raise ValueError(f"not a public channel name: {value!r}")
    return name


def parse_preview(html_bytes: bytes) -> tuple[dict, list[dict], int | None]:
    """Return (channel info, posts newest-last, before-id for the next older page)."""
    doc = lxml_html.fromstring(html_bytes)
    info = {
        "title": " ".join(doc.xpath('string(//div[contains(@class,"tgme_channel_info_header_title")])').split()) or None,
        "description": " ".join(doc.xpath('string(//div[contains(@class,"tgme_channel_info_description")])').split()) or None,
    }
    posts = []
    for node in doc.xpath('//div[contains(concat(" ", normalize-space(@class), " "), '
                          '" tgme_widget_message ") and @data-post]'):
        data_post = node.get("data-post")
        try:
            post_id = int(data_post.rsplit("/", 1)[1])
        except (ValueError, IndexError):
            continue
        text_nodes = node.xpath('.//div[contains(@class,"tgme_widget_message_text")]')
        text = ""
        if text_nodes:
            for br in text_nodes[0].xpath(".//br"):
                br.tail = "\n" + (br.tail or "")
            text = text_nodes[0].text_content().strip()
        times = node.xpath('.//a[contains(@class,"tgme_widget_message_date")]/time/@datetime')
        fwd = node.xpath('string(.//*[contains(@class,"tgme_widget_message_forwarded_from_name")])')
        views = node.xpath('string(.//span[contains(@class,"tgme_widget_message_views")])')
        links = [a for a in node.xpath('.//div[contains(@class,"tgme_widget_message_text")]//a/@href')
                 if a.startswith("http")]
        media = node.xpath('.//a[contains(@class,"tgme_widget_message_photo_wrap") or '
                           'contains(@class,"tgme_widget_message_video_player")]/@href')
        posts.append({"id": post_id, "data_post": data_post, "text": text,
                      "datetime": times[0] if times else None,
                      "forwarded_from": " ".join(fwd.split()) or None,
                      "views": views.strip() or None, "links": links, "media": media})
    more = doc.xpath('//a[contains(@class,"tme_messages_more")]/@data-before')
    before = int(more[0]) if more and more[0].isdigit() else None
    return info, sorted(posts, key=lambda p: p["id"]), before


class TelegramPublicParams(BaseModel):
    channels: list[str] = Field(min_length=1, description="Names, @names or t.me links")
    max_posts: int = Field(100, ge=1, le=5000, description="Per channel per run")
    since: str | None = Field(None, description="ISO date; stop at older posts")
    follow_links: bool = Field(False, description="Queue web fetches for links in posts")


class TelegramPublicCollector(Collector):
    name = "telegram_public"
    description = "Public Telegram channels via t.me/s web preview (no account)."
    params_schema = TelegramPublicParams
    refreshable = True

    def __init__(self) -> None:
        self._newest: dict[str, int] = {}   # channel -> newest post id stored
        self._pos = 0                       # channel index
        self._before: int | None = None     # pagination cursor within the channel
        self._count = 0

    async def collect(self, params: TelegramPublicParams, ctx: PluginContext
                      ) -> AsyncIterator[CapturedItem]:
        from osint.core.models import FollowUp

        since = datetime.fromisoformat(params.since).replace(tzinfo=UTC) if params.since else None
        channels = [channel_name(c) for c in params.channels]
        for i in range(self._pos, len(channels)):
            ch = channels[i]
            floor = self._newest.get(ch, 0)       # refresh: stop at what we already have
            newest_seen = floor
            while True:
                url = f"https://t.me/s/{ch}" + (f"?before={self._before}" if self._before else "")
                page = await capture_url(ctx, url, self.ident, platform="telegram")
                page.parse = False
                page.meta.platform_id = f"telegram:{ch}"
                info, posts, before = parse_preview(page.data) if page.meta.http_status == 200 \
                    else ({}, [], None)
                page.meta.extra["channel"] = {"name": ch, **info}
                yield page
                if not posts:
                    break
                stop = False
                for p in reversed(posts):     # newest first
                    if p["id"] <= floor:
                        stop = True
                        break
                    posted = datetime.fromisoformat(p["datetime"]) if p["datetime"] else None
                    if since and posted and posted < since:
                        stop = True
                        break
                    newest_seen = max(newest_seen, p["id"])
                    header = (f"Telegram channel: {info.get('title') or ch} (@{ch})\n"
                              f"Post: https://t.me/{p['data_post']}\n"
                              f"Posted: {p['datetime'] or 'unknown'}\n"
                              + (f"Forwarded from: {p['forwarded_from']}\n" if p["forwarded_from"] else "")
                              + "\n")
                    meta = CaptureMeta(
                        url=f"https://t.me/{p['data_post']}", final_url=page.meta.final_url,
                        collector=self.ident, platform="telegram",
                        platform_id=f"telegram:{p['data_post']}", posted_at=posted,
                        extra={"derived_from": {"sha256_page": _sha(page.data),
                                                "page_url": page.meta.final_url},
                               "views": p["views"], "links": p["links"], "media": p["media"],
                               "forwarded_from": p["forwarded_from"],
                               "post_json": json.dumps(p, ensure_ascii=False)})
                    yield CapturedItem(data=(header + p["text"]).encode("utf-8"), meta=meta,
                                       mime="text/plain", parse=bool(p["text"]))
                    if params.follow_links:
                        for link in p["links"][:5]:
                            yield FollowUp(plugin="web", params={
                                "urls": [link], "found_via": f"telegram:{p['data_post']}"},
                                priority=120)
                    self._count += 1
                    if self._count >= params.max_posts:
                        stop = True
                        break
                self._newest[ch] = max(self._newest.get(ch, 0), newest_seen)
                if stop or before is None:
                    break
                self._before = before
            self._pos, self._before, self._count = i + 1, None, 0
        self._pos = 0

    def checkpoint(self) -> dict[str, Any]:
        return {"newest": self._newest, "pos": self._pos, "before": self._before,
                "count": self._count}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._newest = dict(checkpoint.get("newest", {}))
        self._pos = int(checkpoint.get("pos", 0))
        self._before = checkpoint.get("before")
        self._count = int(checkpoint.get("count", 0))

    def on_refresh(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        return {"newest": checkpoint.get("newest", {})}   # only posts newer than stored


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()

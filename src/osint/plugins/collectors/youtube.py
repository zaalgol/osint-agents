"""YouTube: video metadata + captions (no account, no cookies, no video download).

yt-dlp only *resolves* the video: metadata and caption-track URLs. Everything kept as
evidence is fetched through our own fetcher, so it gets the normal proof bundle:
  * the watch page (raw HTML, WARC, screenshot)
  * the caption file (WebVTT, as served)
  * a derived transcript artifact: "[hh:mm:ss] line" text, so quotes verify and carry
    their position in the video
Channel and playlist URLs expand to their videos (follow-ups). If YouTube demands a
login or bot check, the task fails or is marked blocked. It never uses cookies.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem, CaptureMeta, FollowUp
from osint.core.plugins import Collector
from osint.evidence.capture import capture_url

VTT_TIME = re.compile(r"^(\d{2}):(\d{2}):(\d{2})[.,]\d{3}\s+-->")


class YoutubeParams(BaseModel):
    urls: list[str] = Field(min_length=1, description="Video, channel or playlist URLs")
    languages: list[str] = Field(default_factory=lambda: ["en", "ar", "fa", "ru", "fr"],
                                 description="Caption languages, in preference order")
    max_videos: int = Field(20, ge=1, le=500, description="Per channel/playlist")
    transcribe: bool | None = Field(None, description="Whisper when no captions "
                                                       "(None = settings.media)")


def vtt_to_transcript(vtt: str) -> str:
    """WebVTT -> '[hh:mm:ss] text' lines, de-duplicating rolling auto-captions."""
    out, last, stamp = [], "", None
    for line in vtt.splitlines():
        m = VTT_TIME.match(line)
        if m:
            stamp = f"{m.group(1)}:{m.group(2)}:{m.group(3)}"
            continue
        text = re.sub(r"<[^>]+>", "", line).strip()
        if not text or text.startswith(("WEBVTT", "Kind:", "Language:", "NOTE")) or text == last:
            continue
        last = text
        out.append(f"[{stamp or '00:00:00'}] {text}")
    return "\n".join(out)


def _download_audio(url: str, proxy: str | None) -> tuple[bytes | None, str, str]:
    """Best Opus/WebM audio (decodable by Chromium), no cookies. Returns (bytes, mime, url)."""
    import tempfile
    from pathlib import Path

    import yt_dlp

    with tempfile.TemporaryDirectory(prefix="osint-audio-") as tmp:
        opts = {"quiet": True, "no_warnings": True, "cookiefile": None,
                "format": "bestaudio[ext=webm]/bestaudio[acodec=opus]/bestaudio",
                "outtmpl": str(Path(tmp) / "%(id)s.%(ext)s")}
        if proxy:
            opts["proxy"] = proxy
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=True)
        files = list(Path(tmp).iterdir())
        if not files:
            return None, "", ""
        ext = files[0].suffix.lstrip(".")
        mime = {"webm": "audio/webm", "m4a": "audio/mp4", "ogg": "audio/ogg"}.get(ext, "audio/webm")
        return files[0].read_bytes(), mime, info.get("url") or url


def _resolve(url: str, proxy: str | None, flat: bool) -> dict:
    import yt_dlp

    opts = {"quiet": True, "no_warnings": True, "skip_download": True,
            "extract_flat": "in_playlist" if flat else False, "cookiefile": None,
            "noplaylist": not flat}
    if proxy:
        opts["proxy"] = proxy
    with yt_dlp.YoutubeDL(opts) as ydl:
        return ydl.extract_info(url, download=False)


class YoutubeCollector(Collector):
    name = "youtube"
    description = "YouTube video metadata and captions (no account, no cookies)."
    params_schema = YoutubeParams

    def __init__(self) -> None:
        self._done: list[str] = []

    async def collect(self, params: YoutubeParams, ctx: PluginContext
                      ) -> AsyncIterator[CapturedItem | FollowUp]:
        proxy = ctx.settings.network.proxy
        for url in params.urls:
            if url in self._done:
                continue
            info = await asyncio.to_thread(_resolve, url, proxy, True)
            if info.get("_type") in ("playlist", "multi_video") or info.get("entries"):
                for e in list(info.get("entries") or [])[: params.max_videos]:
                    vid = e.get("url") or e.get("id")
                    if vid:
                        full = vid if vid.startswith("http") else f"https://www.youtube.com/watch?v={vid}"
                        yield FollowUp(plugin="youtube", priority=115, params={
                            "urls": [full], "languages": params.languages})
                self._done.append(url)
                continue
            if info.get("_type") == "url":
                info = await asyncio.to_thread(_resolve, url, proxy, False)
            async for item in self._video(info, params, ctx):
                yield item
            self._done.append(url)

    async def _video(self, info: dict, params: YoutubeParams, ctx: PluginContext
                     ) -> AsyncIterator[CapturedItem]:
        vid = info["id"]
        watch = f"https://www.youtube.com/watch?v={vid}"
        page = await capture_url(ctx, watch, self.ident, platform="youtube")
        page.parse = False
        posted = None
        if info.get("timestamp"):
            posted = datetime.fromtimestamp(info["timestamp"], UTC)
        elif info.get("upload_date"):
            posted = datetime.strptime(info["upload_date"], "%Y%m%d").replace(tzinfo=UTC)
        meta_fields = {k: info.get(k) for k in ("title", "channel", "channel_id", "uploader",
                                                "duration", "view_count", "description",
                                                "tags", "categories", "language")}
        page.meta.platform_id = f"youtube:{vid}"
        page.meta.posted_at = posted
        page.meta.extra["video"] = meta_fields
        yield page

        tracks = {**(info.get("automatic_captions") or {}), **(info.get("subtitles") or {})}
        chosen = next((lang for lang in params.languages if lang in tracks), None)
        if chosen is None and tracks:
            chosen = min(tracks)
        if chosen is None:
            async for item in self._whisper(info, params, ctx, watch, posted, meta_fields):
                yield item
            return
        vtt_url = next((t["url"] for t in tracks[chosen] if t.get("ext") == "vtt"), None)
        if not vtt_url:
            return
        cap = await capture_url(ctx, vtt_url, self.ident, screenshot=False, platform="youtube")
        cap.parse = False
        cap.meta.platform_id = f"youtube:{vid}:captions:{chosen}"
        cap.meta.posted_at = posted
        yield cap
        transcript = vtt_to_transcript(cap.data.decode("utf-8", "replace"))
        if not transcript:
            return
        header = (f"YouTube video: {meta_fields['title']}\nChannel: {meta_fields['channel']}\n"
                  f"URL: {watch}\nPublished: {posted.isoformat() if posted else 'unknown'}\n"
                  f"Captions: {chosen} ({'auto' if chosen not in (info.get('subtitles') or {}) else 'uploaded'})\n\n")
        yield CapturedItem(
            data=(header + transcript).encode("utf-8"), mime="text/plain",
            meta=CaptureMeta(url=watch, collector=self.ident, platform="youtube",
                             platform_id=f"youtube:{vid}:transcript:{chosen}", posted_at=posted,
                             extra={"derived_from": {"sha256_captions": hashlib.sha256(cap.data).hexdigest(),
                                                     "captions_url": vtt_url},
                                    "video": meta_fields}))

    async def _whisper(self, info: dict, params: YoutubeParams, ctx: PluginContext, watch: str,
                       posted, meta_fields: dict) -> AsyncIterator[CapturedItem]:
        """No captions: keep the audio as evidence and transcribe it (machine transcription)."""
        media = ctx.settings.media
        want = params.transcribe if params.transcribe is not None else media.transcribe_missing_captions
        duration = info.get("duration") or 0
        if not want or duration > media.max_transcribe_minutes * 60:
            return
        try:
            from osint.media.transcribe import decode_audio, transcribe
        except ImportError:
            return  # media extra not installed
        audio, mime, audio_url = await asyncio.to_thread(_download_audio, info["webpage_url"],
                                                         ctx.settings.network.proxy)
        if not audio:
            return
        yield CapturedItem(
            data=audio, mime=mime, parse=False,
            meta=CaptureMeta(url=audio_url, collector=self.ident, platform="youtube",
                             platform_id=f"youtube:{info['id']}:audio", posted_at=posted,
                             extra={"source_page": watch, "duration_s": duration}))
        pcm = await decode_audio(audio, mime)
        tr = await asyncio.to_thread(transcribe, pcm, media.whisper_model, media.whisper_device)
        text = tr.as_text()
        if not text:
            return
        header = (f"YouTube video: {meta_fields['title']}\nChannel: {meta_fields['channel']}\n"
                  f"URL: {watch}\nPublished: {posted.isoformat() if posted else 'unknown'}\n"
                  f"Transcript: machine transcription ({tr.model}, language {tr.language}, "
                  f"p={tr.language_probability}); verify against the audio before quoting\n\n")
        yield CapturedItem(
            data=(header + text).encode("utf-8"), mime="text/plain",
            meta=CaptureMeta(url=watch, collector=self.ident, platform="youtube",
                             platform_id=f"youtube:{info['id']}:whisper:{tr.language}",
                             posted_at=posted,
                             extra={"derived_from": {"sha256_audio": hashlib.sha256(audio).hexdigest()},
                                    "transcriber": tr.model, "video": meta_fields}))

    def checkpoint(self) -> dict[str, Any]:
        return {"done": self._done[-2000:]}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._done = list(checkpoint.get("done", []))

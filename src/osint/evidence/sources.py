"""Sources and Admiralty grading (NATO AJP-2.1 / "Admiralty code").

Every captured artifact belongs to a source: a website (by host), a Telegram channel, a
YouTube channel, a paste site, an official list, or an enrichment service. The analyst
grades each source's **reliability** (A-F); unknown sources stay F ("cannot be judged"),
which is the honest default, not an insult.

**Information credibility** (1-6) is judged per fact, from the corroboration data:
  1 confirmed by other independent sources (>= 2 independent origins)
  4 doubtful (another source contradicts it)
  6 cannot be judged (single origin, no contradiction)
Grades 2, 3 and 5 need an analyst's judgement and aren't assigned automatically.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from osint.core.models import CaptureMeta

RELIABILITY = {
    "A": "completely reliable", "B": "usually reliable", "C": "fairly reliable",
    "D": "not usually reliable", "E": "unreliable", "F": "reliability cannot be judged",
}
CREDIBILITY = {
    "1": "confirmed by other sources", "2": "probably true", "3": "possibly true",
    "4": "doubtful", "5": "improbable", "6": "truth cannot be judged",
}
# defaults for sources whose nature is known; everything else starts at F
DEFAULT_GRADES = {
    ("enrichment", "sanctions"): ("A", "official issuing authorities' published lists"),
    ("enrichment", "rdap"): ("B", "registry data via RDAP"),
    ("enrichment", "btc"): ("B", "public blockchain data via an explorer"),
    ("enrichment", "geocode"): ("C", "geocoder candidates; places can be ambiguous"),
}
WAYBACK_RE = re.compile(r"^/web/\d+[a-z_]*/(.+)$")


def source_key(meta: CaptureMeta) -> tuple[str, str] | None:
    """(kind, locator) for a capture, or None for internal ones (our own search pages)."""
    platform = meta.platform or ""
    pid = meta.platform_id or ""
    url = meta.final_url or meta.url or ""
    if platform == "searxng":
        return None
    if platform.startswith("enrichment:"):
        return "enrichment", platform.split(":", 1)[1]
    if platform == "sanctions":
        return "official_list", (urlsplit(url).hostname or "unknown").removeprefix("www.")
    if platform == "telegram" and pid.startswith("telegram:"):
        channel = pid.split(":", 1)[1].split("/", 1)[0]
        return "telegram_channel", f"t.me/{channel.lower()}"
    if platform == "youtube":
        video = (meta.extra or {}).get("video") or {}
        if video.get("channel_id"):
            return "youtube_channel", f"youtube.com/channel/{video['channel_id']}"
    if platform == "paste" and pid.startswith("paste:"):
        return "paste_site", pid.split(":")[1]
    u = urlsplit(url)
    host = (u.hostname or "").lower().removeprefix("www.")
    if host == "web.archive.org" and (m := WAYBACK_RE.match(u.path)):
        host = (urlsplit(unquote(m.group(1))).hostname or host).lower().removeprefix("www.")
    if not host or host in ("localhost", "127.0.0.1"):
        return None
    return "website", host


def ensure_source(s: Session, meta: CaptureMeta) -> int | None:
    from osint.storage.db import Source

    key = source_key(meta)
    if key is None:
        return None
    kind, locator = key
    grade, note = DEFAULT_GRADES.get(key, ("F", None))
    s.execute(pg_insert(Source).values(kind=kind, locator=locator, platform=meta.platform,
                                       reliability=grade, reliability_note=note, policy={})
              .on_conflict_do_nothing(constraint="uq_source_kind_locator"))
    return s.scalar(select(Source.id).where(Source.kind == kind, Source.locator == locator))


def credibility(s: Session, target_type: str, target_id: int) -> str:
    from osint.storage.db import Claim, SupportStats

    if target_type == "claim" and (c := s.get(Claim, target_id)) is not None:
        return c.credibility
    st = s.get(SupportStats, (target_type, target_id))
    if st is None:
        return "6"
    if st.contradicted_by:
        return "4"
    return "1" if st.independent_sources >= 2 else "6"


def grade_of(s: Session, source_id: int | None) -> str:
    from osint.storage.db import Source

    src = s.get(Source, source_id) if source_id else None
    return src.reliability if src else "F"

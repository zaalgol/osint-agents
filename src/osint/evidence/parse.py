"""Turn artifacts into documents (plain text that citations point into).

The document text is frozen once written: citation offsets refer to it, and its
SHA-256 is stored so that `verify-report` can show the offsets still hold.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)

PARSER_VERSION = "parse@0.1.0"
HTML = ("text/html", "application/xhtml+xml")
NO_DOCUMENT = ("application/json", "application/rss+xml", "application/atom+xml",
               "application/xml", "text/xml", "image/", "video/", "audio/")


@dataclass
class ParsedDoc:
    text: str
    parser: str
    title: str | None = None
    lang: str | None = None
    published_at: datetime | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def text_sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


def should_parse(mime: str | None) -> bool:
    m = (mime or "").lower()
    return not any(m.startswith(p) for p in NO_DOCUMENT)


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def parse_html(data: bytes, url: str | None) -> ParsedDoc | None:
    import trafilatura

    doc = trafilatura.bare_extraction(
        data, url=url, with_metadata=True, favor_recall=True, include_comments=False,
        include_tables=True,
    )
    if doc is None:
        return None
    d = doc if isinstance(doc, dict) else doc.as_dict()
    text = (d.get("text") or "").strip()
    if not text:
        return None
    return ParsedDoc(
        text=text,
        parser=f"{PARSER_VERSION}/trafilatura",
        title=d.get("title"),
        lang=d.get("language"),
        published_at=_parse_date(d.get("date")),
        meta={k: d.get(k) for k in ("author", "sitename", "hostname", "description")
              if d.get(k)},
    )


def parse_pdf(data: bytes) -> ParsedDoc | None:
    import pymupdf

    parts, page_starts, pos = [], [], 0
    with pymupdf.open(stream=data, filetype="pdf") as pdf:
        meta = {k: v for k, v in (pdf.metadata or {}).items() if v}
        for page in pdf:
            t = page.get_text("text").strip()
            page_starts.append(pos)
            parts.append(t)
            pos += len(t) + 2  # "\n\n" separator
    text = "\n\n".join(parts).strip()
    if not text:
        return None  # scanned PDF: OCR comes with the media agent (Phase 4)
    return ParsedDoc(text=text, parser=f"{PARSER_VERSION}/pymupdf", title=meta.get("title"),
                     meta={"page_starts": page_starts, "pdf_meta": meta})


def parse_text(data: bytes, charset: str | None) -> ParsedDoc | None:
    for enc in [c for c in (charset, "utf-8", "cp1252", "latin-1") if c]:
        try:
            text = data.decode(enc).strip()
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        return None
    return ParsedDoc(text=text, parser=f"{PARSER_VERSION}/text") if text else None


def parse_artifact(
    data: bytes, mime: str | None, url: str | None, charset: str | None = None,
    rendered_html: bytes | None = None, min_chars: int = 200,
) -> ParsedDoc | None:
    m = (mime or "").lower()
    if m.startswith(HTML):
        doc = parse_html(data, url)
        # JS-heavy pages: the raw HTML is a shell; the browser-rendered DOM has the content
        if rendered_html and (doc is None or len(doc.text) < min_chars):
            rendered = parse_html(rendered_html, url)
            if rendered and len(rendered.text) > (len(doc.text) if doc else 0):
                rendered.parser += "+rendered"
                rendered.meta["source"] = "rendered_html"
                if doc is not None and doc.title:  # the served <title> beats in-page headings
                    rendered.title = doc.title
                doc = rendered
        return doc
    if m == "application/pdf" or data[:5] == b"%PDF-":
        return parse_pdf(data)
    if m.startswith("text/") or not m:
        return parse_text(data, charset)
    log.info("no parser for mime %s", mime)
    return None

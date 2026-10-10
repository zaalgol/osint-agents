"""Images and scanned PDFs: EXIF metadata and OCR with the local vision model.

EXIF (Pillow) gives camera, original timestamp, editing software and GPS position.
Most platforms strip it, but files people hand to the analyst often keep it.

OCR uses a vision-capable local model (role `vision`, by default qwen3.6:27b). It reads
Arabic, Cyrillic and handwriting better than classic OCR, but it is a model: it can
misread or, rarely, invent text. OCR documents are therefore tagged
`meta.ocr.machine_read = true`, and their parser name starts with `ocr:` so reviewers
and the report gate can tell transcribed text from text that was in the file.
"""

from __future__ import annotations

import io
import logging
import math
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

OCR_SYSTEM = (
    "You transcribe text from images for an evidence archive. Copy every piece of visible "
    "text exactly as written, in its original language and script. Keep line breaks. "
    "Do not translate, correct, summarize or describe the image. If a word is unreadable, "
    "write [illegible]. If there is no text, return an empty string."
)
MAX_SIDE = 1600


class OcrResult(BaseModel):
    text: str = Field(description="All visible text, verbatim, original script")
    language: str | None = Field(default=None, description="ISO 639-1 code of the main language")


def _ratio(v) -> float:
    try:
        return float(v[0]) / float(v[1]) if isinstance(v, tuple) else float(v)
    except (TypeError, ValueError, ZeroDivisionError):
        return float("nan")


def _gps(gps: dict) -> dict[str, float] | None:
    def deg(vals, ref):
        if not vals or len(vals) != 3:
            return None
        d, m, s = (_ratio(x) for x in vals)
        out = d + m / 60 + s / 3600
        return -out if ref in ("S", "W") else out

    lat = deg(gps.get(2), gps.get(1))
    lon = deg(gps.get(4), gps.get(3))
    if lat is None or lon is None or math.isnan(lat) or math.isnan(lon):
        return None
    out = {"lat": round(lat, 6), "lon": round(lon, 6)}
    if 6 in gps:
        alt = _ratio(gps[6])
        if not math.isnan(alt):
            out["alt_m"] = round(alt, 1)
    return out


def exif(data: bytes) -> dict[str, Any]:
    """Camera, timestamps, software and GPS from an image ({} if none or unreadable)."""
    from PIL import ExifTags, Image, UnidentifiedImageError

    try:
        with Image.open(io.BytesIO(data)) as im:
            raw = im.getexif()
            size = im.size
            fmt = im.format
    except (UnidentifiedImageError, OSError, ValueError):
        return {}
    out: dict[str, Any] = {"format": fmt, "width": size[0], "height": size[1]}
    if not raw:
        return out
    names = {v: k for k, v in ExifTags.TAGS.items()}
    fields = dict(raw.items())
    try:
        fields.update(raw.get_ifd(names["ExifOffset"]))
    except KeyError:
        pass
    for key in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Artist",
                "LensModel", "OffsetTimeOriginal"):
        v = fields.get(names.get(key, -1))
        if isinstance(v, str) and v.strip(" \x00"):
            out[key] = v.strip(" \x00")
    try:
        gps = _gps(dict(raw.get_ifd(names["GPSInfo"])))
    except KeyError:
        gps = None
    if gps:
        out["gps"] = gps
    return out


def to_png_for_vision(data: bytes) -> bytes | None:
    """Downscale (max side 1600 px) and re-encode as PNG; None if not an image."""
    from PIL import Image, ImageOps, UnidentifiedImageError

    try:
        with Image.open(io.BytesIO(data)) as im:
            im = ImageOps.exif_transpose(im)
            im.thumbnail((MAX_SIDE, MAX_SIDE))
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            buf = io.BytesIO()
            im.save(buf, "PNG")
            return buf.getvalue()
    except (UnidentifiedImageError, OSError, ValueError):
        return None


def pdf_pages_png(data: bytes, max_pages: int, dpi: int = 150) -> list[bytes]:
    import pymupdf

    out = []
    with pymupdf.open(stream=data, filetype="pdf") as pdf:
        for page in list(pdf)[:max_pages]:
            out.append(page.get_pixmap(dpi=dpi).tobytes("png"))
    return out


async def ocr_images(llm, role: str, pages: list[bytes]) -> tuple[str, list[int], str | None]:
    """OCR each page; returns (text, page_starts, language)."""
    parts, starts, pos, lang = [], [], 0, None
    for i, png in enumerate(pages):
        res = await llm.chat_json(role, OCR_SYSTEM,
                                  f"Transcribe all text in this image (page {i + 1}).",
                                  OcrResult, images=[png])
        t = res.text.strip()
        lang = lang or res.language
        starts.append(pos)
        parts.append(t)
        pos += len(t) + 2
    return "\n\n".join(parts).strip(), starts, lang


def ocr_meta(model: str, pages: int) -> dict:
    return {"machine_read": True, "method": "vision-llm", "model": model, "pages": pages,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
            "caution": "transcribed by a model; check quotes against the image"}

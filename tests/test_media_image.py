"""Images and scanned PDFs: EXIF metadata, OCR with the vision role, labelled as machine-read."""

from __future__ import annotations

import asyncio
import io
import json
import uuid

import httpx
import pytest
from PIL import Image
from sqlalchemy import select


def _jpeg_with_gps(seed: int = 0) -> bytes:
    im = Image.new("RGB", (64, 48), (seed % 255, 80, 120))
    exif = Image.Exif()
    exif[0x010F] = "TestCam"                     # Make
    exif[0x0110] = "Model X"                     # Model
    gps = exif.get_ifd(0x8825)
    gps.update({1: "N", 2: (15.0, 20.0, 30.0), 3: "E", 4: (44.0, 12.0, 0.0)})
    buf = io.BytesIO()
    im.save(buf, "JPEG", exif=exif)
    return buf.getvalue()


def test_exif_gps_and_camera():
    from osint.media.image import exif

    e = exif(_jpeg_with_gps())
    assert e["Make"] == "TestCam" and e["Model"] == "Model X"
    assert e["gps"] == {"lat": 15.341667, "lon": 44.2}
    assert exif(b"not an image") == {}


def test_vision_png_is_downscaled():
    from osint.media.image import MAX_SIDE, to_png_for_vision

    big = io.BytesIO()
    Image.new("RGB", (4000, 1000)).save(big, "PNG")
    out = Image.open(io.BytesIO(to_png_for_vision(big.getvalue())))
    assert max(out.size) == MAX_SIDE


def test_images_are_sent_to_ollama_base64():
    from osint.core.config import LocalModels, LocalRole
    from osint.llm.local import LocalLLM
    from osint.media.image import OcrResult

    bodies = []

    def handler(req):
        bodies.append(json.loads(req.content))
        return httpx.Response(200, json={"message": {"content": '{"text": "STOP", "language": "en"}'}})

    cfg = LocalModels(base_url="http://o.test/v1", roles={"vision": LocalRole(model="v")})
    out = asyncio.run(LocalLLM(cfg, transport=httpx.MockTransport(handler)).chat_json(
        "vision", "sys", "read", OcrResult, images=[b"\x89PNG fake"]))
    assert out.text == "STOP"
    assert bodies[0]["messages"][1]["images"] == ["iVBORyBmYWtl"]


@pytest.mark.integration
def test_image_artifact_is_ocred_labelled_and_exif_reviewed(pg_settings):
    from osint.core.context import App
    from osint.core.models import CaptureMeta, TaskSpec
    from osint.evidence.ingest import ingest_bytes
    from osint.orchestrator import queue
    from osint.orchestrator.runner import Runner
    from osint.storage.db import Document, Investigation, ReviewItem

    pg_settings.evidence.screenshots = False
    app = App(pg_settings)
    img = _jpeg_with_gps(uuid.uuid4().int)
    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"ocr-{uuid.uuid4().hex[:6]}")
        s.add(inv)
        s.flush()
        art, _ = ingest_bytes(s, app.raw_store, img, CaptureMeta(url="https://img.test/a.jpg"),
                              actor="t", mime="image/jpeg")
        queue.enqueue(s, TaskSpec(investigation_id=inv.id, type="parse", plugin="parse",
                                  params={"artifact_id": art.id}))
        inv_id, art_id = inv.id, art.id
    sent = []

    def llm(req):
        body = json.loads(req.content)
        sent.append(body)
        if "images" in body["messages"][-1]:
            text = "بيان رقم 7\nWe will strike the port at dawn."
            return httpx.Response(200, json={"message": {"content": json.dumps(
                {"text": text, "language": "ar"})}})
        return httpx.Response(200, json={"message": {"content": json.dumps(
            {"relevant": False, "relevance_reason": "test", "language": "ar"})}})

    async def go():
        async with app.services(llm_transport=httpx.MockTransport(llm), browser=False) as svc:
            return await Runner(app, inv_id, svc, on_event=lambda m: None).run()

    asyncio.run(go())
    with app.session_factory() as s:
        doc = s.scalar(select(Document).where(Document.artifact_id == art_id))
        assert doc.extractor.startswith("ocr:")
        assert doc.meta["ocr"]["machine_read"] is True and doc.lang == "ar"
        assert "strike the port" in doc.text and doc.meta["exif"]["gps"]["lat"] == 15.341667
        review = s.scalar(select(ReviewItem).where(ReviewItem.investigation_id == inv_id,
                                                   ReviewItem.kind == "media_metadata"))
        assert "GPS" in review.reason and review.payload["artifact_id"] == art_id
    assert sent[0]["messages"][-1]["images"]                  # the image went to the vision role

"""Contamination handling: hash blocklists refuse content before it is stored; purge removes it."""

from __future__ import annotations

import hashlib
import io
import uuid

import pytest
from sqlalchemy import select

from osint.core.models import CapturedItem, CaptureKind, CaptureMeta, ExtraCapture
from osint.storage.raw_store import BlockedContent


def _block(store, *lines: str, name: str = "list.txt") -> None:
    store.blocklist.dir.mkdir(parents=True, exist_ok=True)
    (store.blocklist.dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_blocklist_formats_and_refusal_before_disk(raw_store):
    bad1, bad2, bad3, ok = b"bad one", b"bad two", b"bad three", b"fine"
    _block(raw_store,
           "# hotline list",
           hashlib.md5(bad1).hexdigest() + "   # md5 entry",
           "SHA1:" + hashlib.sha1(bad2).hexdigest().upper(),
           hashlib.sha256(bad3).hexdigest(),
           "not-a-hash")
    assert len(raw_store.blocklist) == 3
    for data in (bad1, bad2, bad3):
        with pytest.raises(BlockedContent) as e:
            raw_store.put_bytes(data)
        assert e.value.list_name == "list.txt"
        assert not raw_store.exists(hashlib.sha256(data).hexdigest())
    with pytest.raises(BlockedContent):              # streamed input: hashed, then discarded
        raw_store.put_stream(io.BytesIO(bad3))
    assert not list(raw_store.root.glob(".incoming-*"))
    assert raw_store.exists(raw_store.put_bytes(ok).sha256)


def test_blocklist_reloads_when_a_list_is_added(raw_store):
    data = b"later known bad"
    raw_store.put_bytes(b"warm up")
    _block(raw_store, hashlib.sha256(data).hexdigest(), name="feed.txt")
    with pytest.raises(BlockedContent):
        raw_store.put_bytes(data)


def test_item_with_blocked_screenshot_leaves_nothing(raw_store, session_factory):
    from osint.evidence.capture import persist_item
    from osint.storage.db import Artifact

    page, shot = uuid.uuid4().bytes + b"page", uuid.uuid4().bytes + b"png"
    _block(raw_store, hashlib.sha256(shot).hexdigest())
    item = CapturedItem(data=page, meta=CaptureMeta(url="https://x.test/"), mime="text/html",
                        extra_captures=[ExtraCapture(kind=CaptureKind.SCREENSHOT_PNG, data=shot,
                                                     mime="image/png")])
    with session_factory() as s, s.begin(), pytest.raises(BlockedContent):
        persist_item(s, raw_store, item, actor="t")
    assert not raw_store.exists(hashlib.sha256(page).hexdigest())
    with session_factory() as s:
        assert s.scalar(select(Artifact).where(
            Artifact.sha256 == hashlib.sha256(page).hexdigest())) is None


@pytest.mark.integration
def test_purge_removes_content_keeps_record_and_blocks_return(pg_settings):
    from osint.core.context import App
    from osint.core.models import EntityRef, ExtractedRelation, ExtractionResult
    from osint.evidence.capture import persist_item
    from osint.evidence.custody import verify_chain
    from osint.evidence.integrity import run_integrity_check
    from osint.evidence.purge import PURGED, delete_files, purge_artifact
    from osint.extraction.writer import ExtractionWriter
    from osint.storage.db import CustodyLog, Document, EvidenceLink, Investigation

    app = App(pg_settings)
    tag = uuid.uuid4().hex[:6]
    text = f"Group{tag} Front is based in Hodeidah."
    page, shot = text.encode() + uuid.uuid4().bytes, uuid.uuid4().bytes + b"png"
    item = CapturedItem(data=page, meta=CaptureMeta(url="https://bad.test/"), mime="text/html",
                        extra_captures=[ExtraCapture(kind=CaptureKind.SCREENSHOT_PNG, data=shot,
                                                     mime="image/png")])
    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"purge-{tag}")
        s.add(inv)
        s.flush()
        art, _ = persist_item(s, app.raw_store, item, actor="t")
        d = Document(artifact_id=art.id, extractor="t", text=text,
                     text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(d)
        s.flush()
        ExtractionWriter(s, app.ontology, inv.id, d, actor="extractor:llm@0.1.0").write(
            ExtractionResult(relations=[ExtractedRelation(
                type="located_in", src=EntityRef(name=f"Group{tag} Front", type="armed_group"),
                dst=EntityRef(name="Hodeidah", type="location"),
                quote=f"Group{tag} Front is based in Hodeidah")]))
        art_id, doc_id = art.id, d.id

    with app.session_factory() as s, s.begin():
        out = purge_artifact(s, app.raw_store, art_id, reason="test: contaminated")
    assert delete_files(app.raw_store, out["files"]) == 2
    with app.session_factory() as s:
        assert s.get(Document, doc_id).text == PURGED
        quotes = set(s.scalars(select(EvidenceLink.quote_original)
                               .where(EvidenceLink.artifact_id == art_id)))
        assert quotes == {PURGED}
        entry = s.scalar(select(CustodyLog).where(CustodyLog.action == "purged",
                                                  CustodyLog.artifact_id == art_id))
        assert entry.details["reason"] == "test: contaminated"
        assert text not in str(entry.details)                  # custody keeps hashes, not content
        assert verify_chain(s).ok
    assert run_integrity_check(app)["ok"]                       # missing on purpose is not a problem
    with pytest.raises(BlockedContent):                          # never comes back
        app.raw_store.put_bytes(page)

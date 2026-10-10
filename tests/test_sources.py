"""Sources and Admiralty grading: every capture gets a source; credibility from corroboration."""

from __future__ import annotations

import uuid

import pytest

from osint.core.models import CapturedItem, CaptureMeta
from osint.evidence.sources import source_key


def test_source_keys():
    def key(**kw):
        return source_key(CaptureMeta(**kw))

    assert key(url="https://www.Reuters.com/world/x") == ("website", "reuters.com")
    assert key(url="https://t.me/s/chan", platform="telegram",
               platform_id="telegram:SomeChan/12") == ("telegram_channel", "t.me/somechan")
    assert key(url="https://pastebin.com/raw/x", platform="paste",
               platform_id="paste:pastebin.com:x:raw") == ("paste_site", "pastebin.com")
    assert key(url="https://web.archive.org/web/2020id_/https://www.example.org/a") == \
        ("website", "example.org")                                  # the original site
    assert key(url="enrichment://sanctions/entity/1", platform="enrichment:sanctions") == \
        ("enrichment", "sanctions")
    assert key(url="https://www.youtube.com/watch?v=x", platform="youtube",
               extra={"video": {"channel_id": "UC123"}}) == ("youtube_channel",
                                                             "youtube.com/channel/UC123")
    assert key(url="http://127.0.0.1:8888/search", platform="searxng") is None


@pytest.mark.integration
def test_capture_gets_source_and_citations_get_admiralty(pg_settings):
    import hashlib

    from sqlalchemy import select

    from osint.core.context import App
    from osint.core.models import EntityRef, ExtractedRelation, ExtractionResult
    from osint.evidence.capture import persist_item
    from osint.evidence.sources import credibility, grade_of
    from osint.extraction.writer import ExtractionWriter
    from osint.reports.render import _evidence_note
    from osint.storage.db import Document, EvidenceLink, Investigation, Source, SupportStats

    app = App(pg_settings)
    tag = uuid.uuid4().hex[:6]
    host = f"news-{tag}.test"
    text = f"Group{tag} Front is based in Hodeidah."
    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"src-{tag}")
        s.add(inv)
        s.flush()
        art, _ = persist_item(s, app.raw_store, CapturedItem(
            data=text.encode() + uuid.uuid4().bytes, meta=CaptureMeta(url=f"https://www.{host}/a"),
            mime="text/html"), actor="t")
        src = s.get(Source, art.source_id)
        assert (src.kind, src.locator, src.reliability) == ("website", host, "F")
        src.reliability = "B"
        d = Document(artifact_id=art.id, extractor="t", text=text,
                     text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(d)
        s.flush()
        ExtractionWriter(s, app.ontology, inv.id, d, actor="extractor:llm@0.1.0").write(
            ExtractionResult(relations=[ExtractedRelation(
                type="located_in", src=EntityRef(name=f"Group{tag} Front", type="armed_group"),
                dst=EntityRef(name="Hodeidah", type="location"),
                quote=f"Group{tag} Front is based in Hodeidah")]))
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.artifact_id == art.id))
        assert grade_of(s, art.source_id) == "B"
        assert credibility(s, ev.target_type, ev.target_id) == "6"        # single source
        s.add(SupportStats(target_type=ev.target_type, target_id=ev.target_id, citations=3,
                           documents=3, domains=3, independent_sources=3, origin_clusters=[],
                           contradicted_by=[]))
        s.flush()
        assert credibility(s, ev.target_type, ev.target_id) == "1"
        assert "Admiralty B1" in _evidence_note(s, ev.id)

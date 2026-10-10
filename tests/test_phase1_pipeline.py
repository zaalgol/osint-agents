"""Phase 1 integration tests: queue, extraction writer, and an end-to-end run with resume."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select, update

from osint.core.context import App
from osint.core.models import (
    CaptureMeta,
    EntityRef,
    ExtractedEntity,
    ExtractedEvent,
    ExtractedParticipant,
    ExtractedRelation,
    ExtractionResult,
    TaskSpec,
)
from osint.evidence import custody
from osint.evidence.ingest import ingest_bytes
from osint.extraction.writer import ExtractionWriter
from osint.orchestrator import queue
from osint.orchestrator.runner import Runner
from osint.storage.db import (
    Artifact,
    Capture,
    Document,
    Entity,
    Event,
    EventParticipant,
    EvidenceLink,
    Investigation,
    InvestigationRef,
    Relation,
    ReviewItem,
    RunLog,
    Task,
)

pytestmark = pytest.mark.integration


def _investigation(session_factory, **seed) -> int:
    with session_factory() as s, s.begin():
        inv = Investigation(name=f"t-{uuid.uuid4().hex[:8]}", seed=seed)
        s.add(inv)
        s.flush()
        return inv.id


# --------------------------------------------------------------------------- queue


def test_enqueue_is_idempotent_and_claim_respects_priority_and_deps(session_factory):
    inv = _investigation(session_factory)
    with session_factory() as s, s.begin():
        a, created = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect",
                                               plugin="web", params={"urls": ["u1"]}, priority=50))
        assert created
        assert queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="web",
                                         params={"urls": ["u1"]}))[1] is False
        b, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="web",
                                         params={"urls": ["u2"]}, priority=10, depends_on=[a]))
    with session_factory() as s, s.begin():
        first = queue.claim(s, inv, ["collect"])
        assert first.id == a  # b has better priority but depends on a
        assert queue.claim(s, inv, ["collect"]) is None
        queue.complete(s, a, {"ok": 1})
    with session_factory() as s, s.begin():
        assert queue.claim(s, inv, ["collect"]).id == b


def test_fail_retries_then_fails_and_blocks_dependents(session_factory):
    inv = _investigation(session_factory)
    with session_factory() as s, s.begin():
        a, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="parse", plugin="parse",
                                         params={"artifact_id": 1}))
        b, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="extract", plugin="extract",
                                         params={"document_id": 1}, depends_on=[a]))
    outcomes = []
    for _ in range(3):
        with session_factory() as s, s.begin():
            t = queue.claim(s, inv, ["parse"])
            outcomes.append(queue.fail(s, t.id, "boom"))
    assert outcomes == ["retry", "retry", "failed"]
    with session_factory() as s:
        assert s.get(Task, b).status == "blocked"
    with session_factory() as s, s.begin():
        assert queue.retry_failed(s, inv) == 2


def test_reclaim_stale_and_release(session_factory):
    inv = _investigation(session_factory)
    with session_factory() as s, s.begin():
        a, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="x",
                                         params={}))
        queue.claim(s, inv, ["collect"])
    with session_factory() as s, s.begin():
        assert queue.reclaim(s, inv, timedelta(seconds=90)) == 0  # heartbeat is fresh
        s.execute(update(Task).where(Task.id == a).values(
            heartbeat_at=datetime.now(UTC) - timedelta(minutes=5)))
        assert queue.reclaim(s, inv, timedelta(seconds=90)) == 1
    with session_factory() as s, s.begin():
        t = queue.claim(s, inv, ["collect"])
        assert t.attempts == 2
        queue.release(s, t.id)
    with session_factory() as s:
        t = s.get(Task, a)
        assert (t.status, t.attempts) == ("pending", 1)


# --------------------------------------------------------------------------- writer


TEXT = ("Abu Example, a commander of the Northern Front, announced on 1 March 2026 that the "
        "group carried out the attack in Testville. Donations were requested to "
        "recruit@front.example and wallet 0xAbCdEf0123456789aBcDeF0123456789AbCdEf01.")


def _document(session_factory, raw_store, text=TEXT) -> int:
    with session_factory() as s, s.begin():
        art, _ = ingest_bytes(s, raw_store, text.encode() + uuid.uuid4().bytes,
                              CaptureMeta(url="https://news.example/x"), actor="test")
        import hashlib

        doc = Document(artifact_id=art.id, extractor="test", text=text,
                       text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(doc)
        s.flush()
        return doc.id


def _result() -> ExtractionResult:
    return ExtractionResult(
        relevant=True, language="en",
        entities=[
            ExtractedEntity(name="Abu Example", type="person", quote="Abu Example, a commander"),
            ExtractedEntity(name="Northern Front", type="armed_group", quote="the Northern Front"),
            ExtractedEntity(name="recruit@front.example", type="email",
                            quote="recruit@front.example"),
            ExtractedEntity(name="Ghost Person", type="person", quote="Ghost Person said"),
        ],
        relations=[
            ExtractedRelation(type="member_of", src=EntityRef(name="Abu Example", type="person"),
                              dst=EntityRef(name="Northern Front", type="armed_group"),
                              quote="Abu Example, a commander of the Northern Front",
                              confidence=0.8),
            # paraphrased quote: must be rejected, not written
            ExtractedRelation(type="leader_of", src=EntityRef(name="Abu Example", type="person"),
                              dst=EntityRef(name="Northern Front", type="armed_group"),
                              quote="Abu Example leads the Northern Front"),
            # ontology violation: organization cannot be member_of a person
            ExtractedRelation(type="member_of",
                              src=EntityRef(name="Northern Front", type="armed_group"),
                              dst=EntityRef(name="Abu Example", type="person"),
                              quote="a commander of the Northern Front"),
        ],
        events=[ExtractedEvent(
            type="attack", description="The Northern Front carried out an attack in Testville.",
            time="2026-03-01", location="Testville",
            participants=[ExtractedParticipant(name="Northern Front", type="armed_group",
                                               role="perpetrator"),
                          ExtractedParticipant(name="Abu Example", type="person",
                                               role="spokesman")],
            quote="the group carried out the attack in Testville", confidence=0.7)],
    )


def test_writer_verifies_quotes_and_writes_cited_knowledge(session_factory, raw_store):
    inv = _investigation(session_factory)
    doc_id = _document(session_factory, raw_store)
    from pathlib import Path

    from osint.core.ontology import Ontology

    onto = Ontology.load([Path(__file__).resolve().parents[1] / "config/ontology.yaml"])
    with session_factory() as s, s.begin():
        w = ExtractionWriter(s, onto, inv, s.get(Document, doc_id), actor="test-extractor")
        w.write(_result(), chunk_start=0)
        w.finish("test-extractor")
        stats = w.stats

    assert stats.relations == 1 and stats.events == 1
    assert stats.rejected == 3  # ghost person, paraphrase, ontology violation
    with session_factory() as s:
        rel = s.scalar(select(Relation).join(EvidenceLink, (EvidenceLink.target_type == "relation")
                                             & (EvidenceLink.target_id == Relation.id))
                       .where(EvidenceLink.document_id == doc_id))
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.target_type == "relation",
                                                 EvidenceLink.target_id == rel.id))
        assert ev.quote_verified and ev.quote_original == TEXT[ev.char_start:ev.char_end]
        kinds = sorted(s.scalars(select(ReviewItem.kind).where(ReviewItem.document_id == doc_id)))
        assert kinds == ["ontology", "quote_not_found", "quote_not_found"]
        event = s.scalar(select(Event).join(EvidenceLink, (EvidenceLink.target_type == "event")
                                            & (EvidenceLink.target_id == Event.id))
                         .where(EvidenceLink.document_id == doc_id))
        assert event.time_precision == "day" and event.location_entity_id is not None
        roles = set(s.scalars(select(EventParticipant.role).where(
            EventParticipant.event_id == event.id)))
        assert roles == {"perpetrator", "other:spokesman"}
        assert custody.verify_chain(s).ok


def test_resolution_strong_keys_link_investigations_but_namesakes_do_not(session_factory,
                                                                         raw_store):
    from pathlib import Path

    from osint.core.ontology import Ontology

    onto = Ontology.load([Path(__file__).resolve().parents[1] / "config/ontology.yaml"])
    ids = {}
    for label in ("A", "B"):
        inv = _investigation(session_factory)
        doc_id = _document(session_factory, raw_store)
        with session_factory() as s, s.begin():
            w = ExtractionWriter(s, onto, inv, s.get(Document, doc_id), actor="t")
            w.write(_result())
            ids[label] = {e.type: e.id for e in w._by_name.values()}
    # strong identifier (email) and organization name: the same global entity in both
    assert ids["A"]["email"] == ids["B"]["email"]
    assert ids["A"]["armed_group"] == ids["B"]["armed_group"]
    # person with the same name in a different investigation: NOT merged, flagged instead
    assert ids["A"]["person"] != ids["B"]["person"]
    with session_factory() as s:
        cand = s.scalar(select(ReviewItem).where(
            ReviewItem.kind == "resolution_candidate",
            ReviewItem.payload["entity_id"].as_integer() == ids["B"]["person"]))
        assert cand is not None and ids["A"]["person"] in cand.payload["candidates"]


# --------------------------------------------------------------------------- end to end


PAGES = {
    "https://news.example/front-attack": (
        "<html><head><title>Front claims Testville attack</title></head><body><article>"
        "<h1>Front claims Testville attack</h1>"
        f"<p>{TEXT}</p>"
        "<p>Officials said the attack targeted a checkpoint. Analysts say the group has expanded"
        " its operations in the region over the past year, recruiting through messaging apps."
        "</p></article></body></html>"),
    "https://blog.example/other": (
        "<html><head><title>Cooking with lentils</title></head><body><article>"
        "<p>Lentils are a great source of protein. Soak them overnight and cook them slowly "
        "with onions, garlic and cumin for a warming winter soup that everyone will enjoy. "
        "Serve with bread and lemon. Red lentils cook faster than green ones and break down "
        "into a creamy texture, which makes them ideal for dal.</p></article></body></html>"),
    "https://seed.example/direct": (
        "<html><head><title>Statement</title></head><body><article>"
        "<p>In a statement, the Northern Front said its fighters would continue operations. "
        "The statement was distributed via the channel of commander Abu Example and repeated "
        "the group's demands. Security services said they were monitoring the situation "
        "closely across the province.</p></article></body></html>"),
}


class Streamed(httpx.AsyncByteStream):
    def __init__(self, data: bytes):
        self.data = data

    async def __aiter__(self):
        yield self.data


def web_handler(req: httpx.Request) -> httpx.Response:
    url = str(req.url)
    if req.url.path == "/search":
        results = [{"url": "https://news.example/front-attack", "title": "Front attack"},
                   {"url": "https://blog.example/other", "title": "Lentils"}]
        return httpx.Response(200, stream=Streamed(json.dumps({"results": results}).encode()),
                              headers={"Content-Type": "application/json"})
    page = PAGES.get(url.split("?")[0])
    if page is None:
        return httpx.Response(404, stream=Streamed(b"not found"),
                              headers={"Content-Type": "text/plain"})
    return httpx.Response(200, stream=Streamed(page.encode()),
                          headers={"Content-Type": "text/html; charset=utf-8"})


def llm_handler(req: httpx.Request) -> httpx.Response:
    """Fake local model: 'extracts' from the text it is given, quoting it verbatim."""
    body = json.loads(req.content)
    prompt = body["messages"][-1]["content"]
    text = re.search(r"=== TEXT START ===\n(.*)\n=== TEXT END ===", prompt, re.DOTALL).group(1)
    if "Lentils" in text:
        out = {"relevant": False, "relevance_reason": "cooking", "language": "en"}
    else:
        r = _result()
        keep = lambda q: q in text
        out = {"relevant": True, "relevance_reason": "attack claim", "language": "en",
               "entities": [e.model_dump() for e in r.entities if keep(e.quote)],
               "relations": [x.model_dump() for x in r.relations[:1] if keep(x.quote)],
               "events": [x.model_dump() for x in r.events if keep(x.quote)]}
    return httpx.Response(200, json={"message": {"content": json.dumps(out)},
                                     "prompt_eval_count": 1000, "eval_count": 200})


def _app(pg_settings) -> App:
    s = pg_settings
    s.evidence.screenshots = False
    s.network.per_host_interval_s = 0
    s.searxng.url = "https://searx.test"
    return App(s)


async def _run(app: App, inv: int) -> object:
    async with app.services(http_transport=httpx.MockTransport(web_handler),
                            llm_transport=httpx.MockTransport(llm_handler),
                            browser=False) as services:
        return await Runner(app, inv, services, net_workers=3, llm_workers=2,
                            on_event=lambda m: None).run()


def test_end_to_end_search_capture_parse_extract(pg_settings):
    app = _app(pg_settings)
    inv = _investigation(app.session_factory, focus="Northern Front attacks",
                         queries=["northern front attack"])
    with app.session_factory() as s, s.begin():
        queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="searxng",
                                  params={"queries": ["northern front attack"]}))
        queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="web",
                                  params={"urls": ["https://seed.example/direct"]}))

    summary = asyncio.run(_run(app, inv))
    with app.session_factory() as s:
        errors = s.scalars(select(Task.error).where(Task.investigation_id == inv,
                                                    Task.error.isnot(None))).all()
    assert summary.failed == 0 and summary.retried == 0, errors

    with app.session_factory() as s:
        statuses = set(s.scalars(select(Task.status).where(Task.investigation_id == inv)))
        assert statuses == {"done"}
        # 1 search JSON + 3 pages, each with a WARC capture
        arts = s.scalars(select(Artifact).join(Capture, Capture.artifact_id == Artifact.id)
                         .where(Capture.kind == "warc")).all()
        assert len({a.id for a in arts}) >= 4
        search = s.scalar(select(Artifact).where(Artifact.mime == "application/json"))
        assert search.capture_meta["extra"]["query"] == "northern front attack"
        # search JSON is evidence but not parsed; the 3 HTML pages became documents
        assert s.scalar(select(func.count(Document.id))) >= 3
        # scope to this investigation: the session-wide test DB holds other tests' data
        rel = s.scalar(select(Relation).join(
            InvestigationRef, (InvestigationRef.object_type == "relation")
            & (InvestigationRef.object_id == Relation.id)
            & (InvestigationRef.investigation_id == inv)).where(Relation.type == "member_of"))
        assert rel is not None
        cite = s.scalar(select(EvidenceLink).where(EvidenceLink.target_type == "relation",
                                                   EvidenceLink.target_id == rel.id,
                                                   EvidenceLink.document_id.isnot(None)))
        doc = s.get(Document, cite.document_id)
        assert doc.text[cite.char_start:cite.char_end] == cite.quote_original
        assert s.scalar(select(Entity).where(Entity.strong_key == "recruit@front.example"))
        assert s.scalar(select(func.count(RunLog.id)).where(RunLog.input_tokens == 1000)) >= 2
        assert custody.verify_chain(s).ok
        extract_results = s.scalars(select(Task.result).where(Task.investigation_id == inv,
                                                               Task.type == "extract")).all()
        assert any(r.get("relevant") is False for r in extract_results)  # the lentils page

    # every stored file re-hashes correctly
    with app.session_factory() as s:
        mine = select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == inv, InvestigationRef.object_type == "artifact")
        for sha256, sha512 in s.execute(select(Capture.sha256, Capture.sha512)
                                        .where(Capture.artifact_id.in_(mine))):
            app.raw_store.verify(sha256, sha512)


def test_resume_continues_from_checkpoint_after_crash(pg_settings):
    app = _app(pg_settings)
    inv = _investigation(app.session_factory, focus="resume test")
    urls = ["https://seed.example/direct", "https://news.example/front-attack"]
    with app.session_factory() as s, s.begin():
        tid, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="web",
                                           params={"urls": urls}))
        # simulate a crash: the task was running, had stored url[0], heartbeat went stale
        s.execute(update(Task).where(Task.id == tid).values(
            status="running", attempts=1, checkpoint={"done": 1},
            heartbeat_at=datetime.now(UTC) - timedelta(minutes=10)))

    seen: list[str] = []
    orig = web_handler

    def counting(req):
        seen.append(str(req.url))
        return orig(req)

    async def go():
        async with app.services(http_transport=httpx.MockTransport(counting),
                                llm_transport=httpx.MockTransport(llm_handler),
                                browser=False) as services:
            return await Runner(app, inv, services, on_event=lambda m: None).run()

    summary = asyncio.run(go())
    assert summary.failed == 0
    assert seen == [urls[1]]  # url[0] was not fetched again
    with app.session_factory() as s:
        t = s.get(Task, tid)
        assert t.status == "done" and t.checkpoint == {"done": 2}

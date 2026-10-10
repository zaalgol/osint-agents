"""Stance-aware extraction (denials -> claims), quote translations, Chromium audio decoding,
transcript formatting, face redaction."""

from __future__ import annotations

import asyncio
import hashlib
import io
import math
import struct
import uuid
import wave

import pytest
from sqlalchemy import select

from osint.core.models import (
    CaptureMeta,
    EntityRef,
    ExtractedEvent,
    ExtractedRelation,
    ExtractionResult,
)


@pytest.fixture
def app6(pg_settings):
    from osint.core.context import App

    pg_settings.evidence.screenshots = False
    return App(pg_settings)


def _doc(app, text):
    from osint.evidence.ingest import ingest_bytes
    from osint.resolution.resolver import add_ref
    from osint.storage.db import Document, Investigation

    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"p6-{uuid.uuid4().hex[:8]}")
        s.add(inv)
        s.flush()
        art, _ = ingest_bytes(s, app.raw_store, text.encode() + uuid.uuid4().bytes,
                              CaptureMeta(url="https://s.test/"), actor="t")
        d = Document(artifact_id=art.id, extractor="t", text=text,
                     text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(d)
        s.flush()
        add_ref(s, inv.id, "document", d.id, "t")
        return inv.id, d.id


@pytest.mark.integration
def test_denied_and_speculative_relations_become_claims_not_facts(app6):
    from osint.analyst.tools import AnalystTools
    from osint.extraction.writer import ExtractionWriter
    from osint.storage.db import Claim, Document, EvidenceLink, Relation

    tag = uuid.uuid4().hex[:5]
    a, b, c = f"Orin{tag} Front", f"Vale{tag} Cell", f"Kesh{tag} Group"
    text = (f"Officials denied that the {a} is affiliated with the {b}. "
            f"The {a} may be affiliated with the {c}, according to unconfirmed reports. "
            f"The {b} is affiliated with the {c}, police said.")
    inv, did = _doc(app6, text)
    ent = lambda n: EntityRef(name=n, type="armed_group")
    with app6.session_factory() as s, s.begin():
        w = ExtractionWriter(s, app6.ontology, inv, s.get(Document, did), actor="extractor:llm@0.2.0")
        w.write(ExtractionResult(relations=[
            ExtractedRelation(type="affiliated_with", src=ent(a), dst=ent(b), stance="denied",
                              quote=f"Officials denied that the {a} is affiliated with the {b}"),
            ExtractedRelation(type="affiliated_with", src=ent(a), dst=ent(c), stance="speculative",
                              quote=f"The {a} may be affiliated with the {c}"),
            ExtractedRelation(type="affiliated_with", src=ent(b), dst=ent(c), stance="reported",
                              quote=f"The {b} is affiliated with the {c}, police said",
                              quote_en="(translation test)")]))
        assert (w.stats.claims, w.stats.relations) == (2, 1)
    with app6.session_factory() as s:
        claims = {c.stance for c in s.scalars(select(Claim).where(Claim.created_by == "extractor:llm@0.2.0",
                                                                  Claim.predicate == "affiliated_with"))}
        assert {"denies", "speculates"} <= claims
        rels = s.scalars(select(Relation).join(EvidenceLink, (EvidenceLink.target_type == "relation")
                                               & (EvidenceLink.target_id == Relation.id))
                         .where(EvidenceLink.document_id == did)).all()
        assert len(rels) == 1 and rels[0].attributes == {"stance": "reported"}
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.target_type == "relation",
                                                 EvidenceLink.document_id == did))
        assert ev.quote_translated == "(translation test)" and ev.translator == "extractor:llm@0.2.0"
        a_id = rels[0].src_entity_id
        orin = s.scalar(select(Claim.subject_id).where(Claim.stance == "denies",
                                                       Claim.created_by == "extractor:llm@0.2.0"))
    t = AnalystTools(app6.session_factory, app6.ontology, app6.registry, app6.raw_store, inv)
    view = t.get_entity(orin)
    assert view["relations"] == []                      # the denial is not a relation...
    assert {c["stance"] for c in view["claims_not_facts"]} >= {"denies"}   # ...but visible
    assert a_id  # reported relation exists


def test_llm_schema_carries_stance_and_translation():
    import json
    from pathlib import Path

    from osint.core.ontology import Ontology
    from osint.plugins.extractors.llm import schema_for

    js = json.dumps(schema_for(Ontology.load([Path(__file__).resolve().parents[1] /
                                              "config/ontology.yaml"])).model_json_schema())
    assert "speculative" in js and "quote_en" in js


def test_eval_ignores_claims_when_scoring_relations():
    from pathlib import Path

    from osint.core.ontology import Ontology
    from osint.evals.extraction import load_gold, score_document

    onto = Ontology.load([Path(__file__).resolve().parents[1] / "config/ontology.yaml"])
    denial = {g["id"]: g for g in load_gold(Path(__file__).resolve().parents[1] /
                                            "evals/extraction/gold.jsonl")}["denial"]
    res = ExtractionResult(relevant=True, relations=[ExtractedRelation(
        type="affiliated_with", src=EntityRef(name="Crimson Dawn Brigade", type="armed_group"),
        dst=EntityRef(name="Lisbon", type="location"), stance="denied",
        quote="denied reports that the Crimson Dawn Brigade had any connection")])
    assert score_document(denial, res, onto).relations.fp == 0


# --------------------------------------------------------------------------- media


def _wav(seconds: float = 1.0) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(44100)
        w.writeframes(b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / 44100)))
                               for i in range(int(44100 * seconds))))
    return buf.getvalue()


def test_chromium_decodes_audio_to_16k_mono():
    pytest.importorskip("numpy")
    from osint.media.transcribe import decode_audio

    pcm = asyncio.run(decode_audio(_wav(2.0), "audio/wav"))
    assert abs(len(pcm) - 32000) <= 2 and pcm.dtype.name == "float32"
    assert 0.1 < float(abs(pcm).max()) < 0.5


def test_transcript_formatting():
    from osint.media.transcribe import Transcript

    t = Transcript("en", 0.9, [(0.4, 2.0, " hello "), (65.2, 70.0, "world"), (3700, 3701, "")],
                   "faster-whisper-small")
    assert t.as_text() == "[00:00:00] hello\n[00:01:05] world"


def test_face_redaction_on_faceless_image_and_model_pinning(tmp_path, monkeypatch):
    cv2 = pytest.importorskip("cv2")
    import numpy as np

    from osint.evidence import redact

    img = np.full((300, 500, 3), 240, dtype=np.uint8)
    cv2.putText(img, "no faces here", (20, 150), cv2.FONT_HERSHEY_SIMPLEX, 1.2, (0, 0, 0), 2)
    _ok, png = cv2.imencode(".png", img)
    # a tampered model download is refused
    monkeypatch.setattr(redact, "MODEL_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="pinned"):
        redact.model_path(tmp_path / "models")
    monkeypatch.undo()
    model = redact.model_path(tmp_path / "models")
    r = redact.redact_faces(png.tobytes(), model)
    assert r.regions == 0
    assert cv2.imdecode(np.frombuffer(r.data, np.uint8), cv2.IMREAD_COLOR).shape == (300, 500, 3)


def test_event_quote_translation_stored(app6):
    from osint.extraction.writer import ExtractionWriter
    from osint.storage.db import Document, EvidenceLink

    text = "Группировка взяла на себя ответственность за поджог склада в Мурманске."
    inv, did = _doc(app6, text)
    with app6.session_factory() as s, s.begin():
        ExtractionWriter(s, app6.ontology, inv, s.get(Document, did), actor="x").write(
            ExtractionResult(events=[ExtractedEvent(
                type="claim_of_responsibility", description="Group claimed the warehouse arson",
                quote="взяла на себя ответственность за поджог склада",
                quote_en="claimed responsibility for the warehouse arson")]))
    with app6.session_factory() as s:
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.document_id == did))
        assert ev.quote_original.startswith("взяла") and ev.quote_translated.startswith("claimed")


@pytest.mark.integration
def test_reextract_uses_heavy_model_and_schedule_keeps_role(app6):
    import json

    import httpx

    from osint.core.config import LocalRole
    from osint.core.models import TaskSpec
    from osint.orchestrator import queue
    from osint.orchestrator.refresh import reextract, set_schedule
    from osint.orchestrator.runner import Runner
    from osint.storage.db import Schedule, Task

    text = "The Teal Front attacked a depot in Harbor Town on 2026-05-01, police said. " * 4
    inv, _did = _doc(app6, text)
    _inv2, irrelevant = _doc(app6, "Lentil soup recipe with cumin and lemon. " * 8)
    with app6.session_factory() as s, s.begin():
        # pretend an earlier run judged the second doc irrelevant (it lives in inv2; move ref)
        from osint.resolution.resolver import add_ref
        add_ref(s, inv, "document", irrelevant, "t")
        t, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="extract", plugin="extract",
                                         params={"document_id": irrelevant}))
        s.get(Task, t).status, s.get(Task, t).result = "done", {"relevant": False}
    assert reextract(app6, inv, "agent_heavy") == 1          # irrelevant doc skipped
    assert reextract(app6, inv, "agent_heavy") == 0          # idempotent

    from osint.core.config import get_models_config
    roles = get_models_config().local.roles
    roles.setdefault("agent_heavy", LocalRole(model="qwen3.6:27b"))
    seen_models = []

    def llm(req):
        body = json.loads(req.content)
        seen_models.append(body["model"])
        return httpx.Response(200, json={"message": {"content": json.dumps(
            {"relevant": True, "relevance_reason": "x", "language": "en"})}})

    async def go():
        async with app6.services(llm_transport=httpx.MockTransport(llm), browser=False) as svc:
            return await Runner(app6, inv, svc, on_event=lambda m: None).run()

    asyncio.run(go())
    assert seen_models and set(seen_models) == {roles["agent_heavy"].model}
    sch = set_schedule(app6, inv, 360, "week", False, extract_role="agent_heavy")
    with app6.session_factory() as s:
        assert s.get(Schedule, sch.id).extract_role == "agent_heavy"


@pytest.mark.integration
def test_red_team_job_and_report_gating(app6):
    import sys
    from datetime import UTC, datetime, timedelta
    from pathlib import Path

    from osint.analyst.jobs import Analyst
    from osint.llm.claude_cli import ClaudeRunner
    from osint.storage.db import ClaudeJob, EvidenceLink, Finding

    root = Path(__file__).resolve().parents[1]
    runner = ClaudeRunner(app6, binary=[sys.executable, str(root / "tests" / "fake_claude.py")])
    a = Analyst(app6, runner=runner)
    inv, did = _doc(app6, "The Grey Front attacked the port on 1 May 2026, police said.")
    assert a.red_team(inv).extra["skipped"].startswith("no findings")
    with app6.session_factory() as s, s.begin():
        f = Finding(investigation_id=inv, kind="fact", text="x", confidence=0.6,
                    epistemic_status="reported", created_by="t")
        s.add(f)
        s.flush()
        from osint.storage.db import Document

        d = s.get(Document, did)
        s.add(EvidenceLink(target_type="finding", target_id=f.id, artifact_id=d.artifact_id,
                           document_id=did, quote_original="The Grey Front attacked the port",
                           quote_verified=True, created_by="t"))
    assert a.red_team_current(inv) is False
    out = a.red_team(inv)
    assert out.result is not None and not out.result.cached
    assert a.red_team_current(inv) is True
    with app6.session_factory() as s, s.begin():   # a newer analysis makes it stale again
        s.add(ClaudeJob(investigation_id=inv, job="analyze_investigation", model="x",
                        input_hash="h" * 64, status="done",
                        finished_at=datetime.now(UTC) + timedelta(minutes=1)))
    assert a.red_team_current(inv) is False


@pytest.mark.integration
def test_finding_revision_policy_and_withdrawn_findings_fail_gate(app6):
    from osint.analyst.revisions import RevisionError, propose_revision
    from osint.reports.verify import verify_report
    from osint.review.actions import decide
    from osint.storage.db import EvidenceLink, Finding, FindingRevision, ReviewItem

    inv, did = _doc(app6, "The Grey Front attacked the port on 1 May 2026, police said.")
    with app6.session_factory() as s, s.begin():
        from osint.storage.db import Document

        d = s.get(Document, did)
        f = Finding(investigation_id=inv, kind="assessment", text="Grey Front attacks ports",
                    confidence=0.7, epistemic_status="reported", created_by="t")
        s.add(f)
        s.flush()
        s.add(EvidenceLink(target_type="finding", target_id=f.id, artifact_id=d.artifact_id,
                           document_id=did, quote_original="The Grey Front attacked the port",
                           quote_verified=True, created_by="t"))
        fid = f.id
    with app6.session_factory() as s, s.begin():
        # analyst downgrade: applied at once
        r = propose_revision(s, fid, 0.4, "only one police source so far", "claude:red_team")
        assert r["status"] == "applied"
        # analyst upgrade: waits for a human
        up = propose_revision(s, fid, 0.9, "two more outlets confirm it", "claude:analyze")
        assert up["status"] == "proposed"
        # analyst withdrawal: waits for a human
        wd = propose_revision(s, fid, 0.0, "the report was retracted by the outlet",
                              "claude:red_team", withdraw=True)
        with pytest.raises(RevisionError, match="reason"):
            propose_revision(s, fid, 0.3, "meh", "claude:x")
    with app6.session_factory() as s:
        assert s.get(Finding, fid).confidence == 0.4
    with app6.session_factory() as s, s.begin():
        decide(s, app6, up["review_item"], "reject", "human:test")
        decide(s, app6, wd["review_item"], "accept", "human:test", note="outlet retracted")
    with app6.session_factory() as s:
        f = s.get(Finding, fid)
        assert f.status == "withdrawn" and f.confidence == 0.0
        statuses = sorted(r.status for r in s.scalars(select(FindingRevision).where(
            FindingRevision.finding_id == fid)))
        assert statuses == ["applied", "applied", "rejected"]
        assert s.scalar(select(ReviewItem.status).where(ReviewItem.id == wd["review_item"])) == "accepted"
    v = asyncio.run(verify_report(app6.session_factory, app6.raw_store, inv,
                                  f"The Grey Front attacked the port in May 2026 [F:{fid}]."))
    assert not v.ok and v.unresolved == 1


def test_memory_guard_pauses_until_ram_recovers(monkeypatch):
    import sys
    import types

    from osint.orchestrator.runner import Runner

    readings = iter([1, 1, 8])            # GB free: low, low, recovered

    def virtual_memory():
        return types.SimpleNamespace(available=next(readings) * 1024 ** 3)

    async def no_wait(_seconds):
        return None

    monkeypatch.setitem(sys.modules, "psutil", types.SimpleNamespace(virtual_memory=virtual_memory))
    monkeypatch.setattr(asyncio, "sleep", no_wait)
    r = Runner.__new__(Runner)          # only the guard is under test
    r.app = types.SimpleNamespace(settings=types.SimpleNamespace(
        concurrency=types.SimpleNamespace(min_free_ram_gb=3.0)))
    r._stop = asyncio.Event()
    r._mem_warned = False
    events: list[str] = []
    r.on_event = events.append
    asyncio.run(r._wait_for_memory())
    assert next(readings, None) is None   # all three readings consumed
    assert len([e for e in events if "low memory" in e]) == 1


def test_unload_all_asks_ollama_to_release_models():
    import json

    import httpx

    from osint.core.config import LocalModels, LocalRole
    from osint.llm.local import LocalLLM

    seen = []

    def handler(req):
        seen.append((req.url.path, json.loads(req.content)))
        return httpx.Response(200, json={})

    cfg = LocalModels(base_url="http://ollama.test/v1", roles={
        "agent": LocalRole(model="a:14b"), "agent_heavy": LocalRole(model="b:27b"),
        "embedding": LocalRole(model="a:14b")})
    llm = LocalLLM(cfg, transport=httpx.MockTransport(handler))
    done = asyncio.run(llm.unload_all())
    assert sorted(done) == ["a:14b", "b:27b"]
    assert all(p == "/api/generate" and b["keep_alive"] == 0 for p, b in seen)


@pytest.mark.integration
def test_extraction_resumes_from_the_next_chunk(app6):
    import json

    import httpx

    from osint.core.models import TaskSpec
    from osint.orchestrator import queue
    from osint.orchestrator.runner import Runner
    from osint.storage.db import Task

    app6.settings.extraction.chunk_chars = 300
    app6.settings.extraction.chunk_overlap = 0
    sentences = [f"Paragraph {i}: the Ash{i} Brigade operated near the river crossing." for i in range(15)]
    inv, did = _doc(app6, "\n\n".join(sentences))
    with app6.session_factory() as s, s.begin():
        tid, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="extract", plugin="extract",
                                           params={"document_id": did}))
    seen_chunks: list[str] = []
    fail_once = {"armed": True}

    def llm(req):
        prompt = json.loads(req.content)["messages"][-1]["content"]
        first = prompt.split("=== TEXT START ===\n")[1][:40]
        if len(seen_chunks) == 1 and fail_once["armed"]:
            fail_once["armed"] = False
            return httpx.Response(500, text="simulated crash")
        seen_chunks.append(first)
        return httpx.Response(200, json={"message": {"content": json.dumps(
            {"relevant": True, "relevance_reason": "x", "language": "en"})}})

    async def go():
        async with app6.services(llm_transport=httpx.MockTransport(llm), browser=False) as svc:
            return await Runner(app6, inv, svc, on_event=lambda m: None).run()

    asyncio.run(go())   # chunk 1 ok, chunk 2 fails -> retry resumes at chunk 2
    with app6.session_factory() as s:
        t = s.get(Task, tid)
        assert t.status == "done" and t.attempts == 2
        n_chunks = t.result["chunks"]
    assert n_chunks >= 3
    assert len(seen_chunks) == n_chunks           # every chunk extracted exactly once
    assert len(set(seen_chunks)) == n_chunks

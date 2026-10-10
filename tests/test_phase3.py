"""Phase 3: Merkle/timestamps/sealing/bundles, merges + ER, corroboration, linking, refresh."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import uuid
import zipfile

import httpx
import pytest
from sqlalchemy import select, text, update

from osint.core.context import App
from osint.core.models import CaptureMeta
from osint.evidence import merkle
from osint.evidence.timestamp import (
    OTS_MAGIC,
    build_tsq,
    stamp_opentimestamps,
    stamp_rfc3161,
    tsr_status,
)

# --------------------------------------------------------------------------- pure


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 9, 17])
def test_merkle_proofs_verify_and_detect_tampering(n):
    hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]
    root = merkle.root(hashes)
    for i, h in enumerate(hashes):
        path = merkle.proof(hashes, i)
        assert merkle.verify_proof(h, path, root)
        assert not merkle.verify_proof(hashlib.sha256(b"x").hexdigest(), path, root)
    if n > 1:
        assert merkle.root(list(reversed(hashes))) != root  # order matters


def test_rfc3161_request_encoding_and_status_parsing():
    digest = hashlib.sha256(b"manifest").digest()
    tsq = build_tsq(digest, nonce=12345)
    assert tsq[0] == 0x30 and digest in tsq
    assert bytes.fromhex("0609608648016503040201") in tsq  # sha256 OID
    granted = bytes.fromhex("3008") + bytes.fromhex("3003020100") + bytes.fromhex("0400")
    assert tsr_status(granted) == 0
    rejected = bytes.fromhex("30053003020102")
    assert tsr_status(rejected) == 2


def test_stamping_against_mock_authorities():
    digest = hashlib.sha256(b"m").digest()

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/tsr":
            body = bytes.fromhex("3003020100") + bytes([0x04, 32]) + digest
            return httpx.Response(200, content=bytes([0x30, len(body)]) + body)
        if req.url.path == "/digest":
            assert req.content == digest
            return httpx.Response(200, content=bytes.fromhex("f010aabb"))
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            r = await stamp_rfc3161(digest, c, "https://tsa.test/tsr", cert_urls=[])
            o = await stamp_opentimestamps(digest, c, ["https://cal.test"])
            return r, o

    r, o = asyncio.run(go())
    assert r.status == "complete" and digest in r.proof
    assert o[0].proof.startswith(OTS_MAGIC) and digest in o[0].proof and o[0].status == "pending"


def test_graph_read_guard():
    from osint.storage.graph import WRITE_CLAUSE

    assert WRITE_CLAUSE.search("MATCH (n) DETACH DELETE n")
    assert WRITE_CLAUSE.search("match (n) set n.x = 1")
    assert WRITE_CLAUSE.search("CALL apoc.create.node(['X'], {})")
    assert not WRITE_CLAUSE.search("MATCH (a:Entity)-[r:REL]->(b) RETURN a.name, r.type LIMIT 5")


# --------------------------------------------------------------------------- DB fixtures

pytestmark_db = pytest.mark.integration


@pytest.fixture
def app(pg_settings):
    pg_settings.evidence.screenshots = False
    pg_settings.evidence.timestamp_methods = []  # no network in tests
    return App(pg_settings)


def _inv(app, **seed) -> int:
    from osint.storage.db import Investigation

    with app.session_factory() as s, s.begin():
        i = Investigation(name=f"p3-{uuid.uuid4().hex[:8]}", seed=seed)
        s.add(i)
        s.flush()
        return i.id


def _doc(app, inv: int, text_: str, url: str) -> int:
    from osint.evidence.ingest import ingest_bytes
    from osint.resolution.resolver import add_ref
    from osint.storage.db import Document

    with app.session_factory() as s, s.begin():
        art, _ = ingest_bytes(s, app.raw_store, text_.encode() + uuid.uuid4().bytes,
                              CaptureMeta(url=url), actor="test")
        d = Document(artifact_id=art.id, extractor="t", text=text_,
                     text_sha256=hashlib.sha256(text_.encode()).hexdigest())
        s.add(d)
        s.flush()
        add_ref(s, inv, "document", d.id, "t")
        add_ref(s, inv, "artifact", art.id, "t")
        return d.id


def _extract(app, inv: int, doc_id: int, result):
    from osint.extraction.writer import ExtractionWriter
    from osint.storage.db import Document

    with app.session_factory() as s, s.begin():
        w = ExtractionWriter(s, app.ontology, inv, s.get(Document, doc_id), actor="t")
        w.write(result)
        return {k: e.id for k, e in w._by_name.items()}


def _vec(seed: int, noise: float = 0.0, base: int | None = None) -> list[float]:
    import random

    r = random.Random(base if base is not None else seed)
    v = [r.uniform(-1, 1) for _ in range(1024)]
    if noise:
        n = random.Random(seed)
        v = [x + n.uniform(-noise, noise) for x in v]
    return v


# --------------------------------------------------------------------------- merges + ER


@pytest.mark.integration
def test_merge_and_undo_round_trip(app):
    from osint.core.models import EntityRef, ExtractedEntity, ExtractedRelation, ExtractionResult
    from osint.resolution.merge import MergeError, merge_entities, undo_merge
    from osint.storage.db import Entity, EntityAlias, Mention, Relation

    inv = _inv(app)
    t = "Commander Zed leads the Red Hand. Later reports say Zed of Red Hand Group expanded."
    d = _doc(app, inv, t, "https://news.example/m")
    tag = uuid.uuid4().hex[:6]
    t = t.replace("Red Hand", f"Red Hand {tag}")
    d = _doc(app, inv, t, "https://news.example/m2")
    ids = _extract(app, inv, d, ExtractionResult(
        entities=[ExtractedEntity(name="Zed", type="person", quote="Zed"),
                  ExtractedEntity(name=f"Red Hand {tag}", type="armed_group", quote=f"Red Hand {tag}"),
                  ExtractedEntity(name=f"Red Hand {tag} Group", type="armed_group",
                                  quote=f"Red Hand {tag} Group")],
        relations=[ExtractedRelation(type="leader_of", src=EntityRef(name="Zed", type="person"),
                                     dst=EntityRef(name=f"Red Hand {tag}", type="armed_group"),
                                     quote=f"Commander Zed leads the Red Hand {tag}")]))
    a, b = sorted(v for k, v in ids.items() if "red hand" in k)
    with app.session_factory() as s, s.begin():
        m = merge_entities(s, a, b, method="test", score=1, rationale="t", decided_by="test")
        mid = m.id
    with app.session_factory() as s:
        assert s.get(Entity, b).merged_into_id == a
        aliases = set(s.scalars(select(EntityAlias.alias).where(EntityAlias.entity_id == a)))
        assert {f"Red Hand {tag}", f"Red Hand {tag} Group"} <= aliases
        assert s.scalar(select(Mention.id).where(Mention.entity_id == b)) is None
    with app.session_factory() as s, s.begin():
        with pytest.raises(MergeError):
            merge_entities(s, a, b, method="t", score=1, rationale="", decided_by="t")
        undo_merge(s, mid)
    with app.session_factory() as s:
        assert s.get(Entity, b).merged_into_id is None
        assert s.scalar(select(Mention.id).where(Mention.entity_id == b)) is not None
        assert s.scalar(select(Relation.id).where(Relation.dst_entity_id == a))  # untouched


@pytest.mark.integration
def test_er_merges_variants_via_judge_but_not_people_automatically(app):
    from osint.core.models import ExtractedEntity, ExtractionResult
    from osint.resolution.er import EntityResolver, SameEntity
    from osint.storage.db import Entity

    tag = uuid.uuid4().hex[:5]
    inv = _inv(app)
    t = (f"The Qx{tag} Movement and the Qx{tag} rebels clashed with police. "
         f"Analyst Mira Qx{tag} commented, as did Mira Qx{tag}.")
    d = _doc(app, inv, t, "https://er.example/1")
    ids = _extract(app, inv, d, ExtractionResult(entities=[
        ExtractedEntity(name=f"Qx{tag} Movement", type="armed_group", quote=f"Qx{tag} Movement"),
        ExtractedEntity(name=f"Qx{tag} rebels", type="armed_group", quote=f"Qx{tag} rebels")]))
    g1, g2 = sorted(ids.values())
    inv2 = _inv(app)
    d2 = _doc(app, inv2, t, "https://er.example/2")
    p1 = _extract(app, inv, d, ExtractionResult(entities=[
        ExtractedEntity(name=f"Mira Qx{tag}", type="person", quote=f"Mira Qx{tag}")]))
    p2 = _extract(app, inv2, d2, ExtractionResult(entities=[
        ExtractedEntity(name=f"Mira Qx{tag}", type="person", quote=f"Mira Qx{tag}")]))
    pa, pb = next(iter(p1.values())), next(iter(p2.values()))
    assert pa != pb  # people are investigation-scoped at extraction time
    with app.session_factory() as s, s.begin():
        for eid, v in ((g1, _vec(1, base=99)), (g2, _vec(2, 0.05, base=99)),
                       (pa, _vec(3, base=7)), (pb, _vec(4, 0.01, base=7))):
            s.execute(update(Entity).where(Entity.id == eid).values(embedding=v))

    calls = []

    class FakeLLM:
        async def chat_json(self, role, system, user, schema):
            calls.append(user)
            # judge on the records' names, not on snippets (which mention both groups)
            same = f"name: Qx{tag} Movement" in user and f"name: Qx{tag} rebels" in user
            return SameEntity(same_entity="yes" if same else "unsure", confidence=0.9,
                              reason="variant names" if same else "common name, no context")

    rep = asyncio.run(EntityResolver(app, FakeLLM()).run(inv))
    with app.session_factory() as s:
        merged = {s.get(Entity, g1).merged_into_id, s.get(Entity, g2).merged_into_id} - {None}
        assert merged, rep.details
        # the namesakes were judged (unsure) and sent to review, not merged
        assert s.get(Entity, pa).merged_into_id is None and s.get(Entity, pb).merged_into_id is None
    assert rep.sent_to_review >= 1


# --------------------------------------------------------------------------- corroboration


@pytest.mark.integration
def test_independent_sources_and_contradictions(app):
    from osint.core.models import (
        EntityRef,
        ExtractedEntity,
        ExtractedEvent,
        ExtractedParticipant,
        ExtractedRelation,
        ExtractionResult,
    )
    from osint.linking.corroboration import corroborate
    from osint.storage.db import Document, Event, ReviewItem, SupportStats

    tag = uuid.uuid4().hex[:5]
    inv = _inv(app)
    sentence = f"Kel{tag} is a member of the Vor{tag} Front."
    res = ExtractionResult(
        entities=[ExtractedEntity(name=f"Kel{tag}", type="person", quote=f"Kel{tag}"),
                  ExtractedEntity(name=f"Vor{tag} Front", type="armed_group",
                                  quote=f"Vor{tag} Front")],
        relations=[ExtractedRelation(type="member_of",
                                     src=EntityRef(name=f"Kel{tag}", type="person"),
                                     dst=EntityRef(name=f"Vor{tag} Front", type="armed_group"),
                                     quote=sentence[:-1])])
    docs = [_doc(app, inv, sentence, u) for u in (
        "https://a.example/1", "https://a.example/2",       # same outlet
        "https://b.example/x",                              # syndicated copy (same embedding)
        "https://c.example/y")]                             # independent
    for d in docs:
        _extract(app, inv, d, res)
    with app.session_factory() as s, s.begin():
        for d, v in zip(docs, [_vec(10), _vec(11), _vec(12, 0.01, base=10), _vec(13)],
                        strict=True):
            s.execute(update(Document).where(Document.id == d).values(embedding=v))

    ev = ExtractionResult(entities=res.entities, events=[ExtractedEvent(
        type="attack", description=f"Vor{tag} Front attack on the port", time="2026-03-01",
        participants=[ExtractedParticipant(name=f"Vor{tag} Front", type="armed_group",
                                           role="perpetrator")], quote=sentence[:-1])])
    _extract(app, inv, docs[0], ev)
    ev2 = ev.model_copy(deep=True)
    ev2.events[0].time = "2026-03-09"
    d5 = _doc(app, inv, sentence + " (second report)", "https://d.example/z")
    _extract(app, inv, d5, ev2)
    with app.session_factory() as s, s.begin():
        evs = s.scalars(select(Event).where(Event.description.contains(f"Vor{tag}"))).all()
        assert len(evs) == 2
        for e in evs:
            e.embedding = _vec(50, 0.01, base=50 + e.id % 1)

    with app.session_factory() as s, s.begin():
        rep = corroborate(s, inv)
    assert rep.contradictions >= 1
    with app.session_factory() as s:
        from osint.storage.db import EvidenceLink, Relation

        rel = s.scalar(select(Relation).join(EvidenceLink, (EvidenceLink.target_type == "relation")
                                             & (EvidenceLink.target_id == Relation.id))
                       .where(EvidenceLink.document_id == docs[0]))
        st = s.get(SupportStats, ("relation", rel.id))
        assert st.documents == 4 and st.independent_sources == 2  # a.example+b-copy, c.example
        c = s.scalar(select(ReviewItem).where(ReviewItem.kind == "contradiction",
                                              ReviewItem.payload["a"].as_integer().in_(
                                                  [e.id for e in evs])))
        assert c is not None and "2026-03-01" in c.reason and "2026-03-09" in c.reason


# --------------------------------------------------------------------------- linking


@pytest.mark.integration
def test_cross_link_candidates_confirm_and_reject(app):
    from osint.analyst.tools import AnalystTools, ToolError
    from osint.core.models import ExtractedEntity, ExtractionResult
    from osint.linking.linker import generate_candidates
    from osint.storage.db import CrossLink, EvidenceLink

    tag = uuid.uuid4().hex[:5]
    inv_a, inv_b = _inv(app), _inv(app)
    txt = f"The Ost{tag} Brigade operates near Lakeside{tag}. Wallet 0x{tag}00000000000000000000000000000000000."
    ents = [ExtractedEntity(name=f"Ost{tag} Brigade", type="armed_group", quote=f"Ost{tag} Brigade"),
            ExtractedEntity(name=f"Lakeside{tag}", type="location", quote=f"Lakeside{tag}")]
    da = _doc(app, inv_a, txt, "https://x.example/a")
    db_ = _doc(app, inv_b, txt, "https://y.example/b")
    _extract(app, inv_a, da, ExtractionResult(entities=ents))
    _extract(app, inv_b, db_, ExtractionResult(entities=ents))
    with app.session_factory() as s, s.begin():
        rep = generate_candidates(s, app.ontology)
    assert rep.hard >= 1 and rep.skipped_low >= 1  # the brigade links; the place does not
    with app.session_factory() as s:
        link = s.scalar(select(CrossLink).where(
            CrossLink.investigation_a == min(inv_a, inv_b),
            CrossLink.investigation_b == max(inv_a, inv_b)))
        assert link.status == "candidate" and link.tier == "hard"
        ev_ids = list(s.scalars(select(EvidenceLink.id).limit(1)))
    t = AnalystTools(app.session_factory, app.ontology, app.registry, app.raw_store, inv_a,
                     actor="claude:test")
    assert t.cross_links(inv_a)[0]["via"]["name"] == f"Ost{tag} Brigade"
    with pytest.raises(ToolError, match="evidence"):
        t.confirm_cross_link(link.id, "same brigade", [])
    t.confirm_cross_link(link.id, "same brigade in both cases", ev_ids)
    assert t.cross_links(inv_a, "confirmed")[0]["evidence"]
    other = AnalystTools(app.session_factory, app.ontology, app.registry, app.raw_store,
                         _inv(app), actor="claude:test")
    with pytest.raises(ToolError, match="no cross link"):
        other.reject_cross_link(link.id, "not mine")


# --------------------------------------------------------------------------- refresh


@pytest.mark.integration
def test_refresh_rearms_refreshable_collectors(app):
    from osint.core.models import TaskSpec
    from osint.orchestrator import queue
    from osint.orchestrator.refresh import refresh
    from osint.storage.db import Task

    inv = _inv(app)
    with app.session_factory() as s, s.begin():
        t_rss, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="rss",
                                             params={"feeds": ["https://f.example/rss"]}))
        t_web, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect", plugin="web",
                                             params={"urls": ["https://w.example"]}))
        t_sx, _ = queue.enqueue(s, TaskSpec(investigation_id=inv, type="collect",
                                            plugin="searxng", params={"queries": ["q"]}))
        s.execute(update(Task).where(Task.investigation_id == inv).values(
            status="done", checkpoint={"feed_pos": 1, "seen": ["a", "b"], "pos": 1, "done": 1}))
    assert refresh(app, inv, "week") == 2
    with app.session_factory() as s:
        rss, web, sx = s.get(Task, t_rss), s.get(Task, t_web), s.get(Task, t_sx)
        assert rss.status == "pending" and rss.checkpoint["seen"] == ["a", "b"]
        assert rss.checkpoint["feed_pos"] == 0
        assert sx.status == "pending" and sx.checkpoint == {"time_range": "week"}
        assert web.status == "done"


# --------------------------------------------------------------------------- seal + bundle


@pytest.mark.integration
def test_seal_bundle_standalone_verify_and_tamper_detection(app, tmp_path, monkeypatch):
    from osint.core.config import project_home
    from osint.evidence import seal as seal_mod
    from osint.evidence.bundle import build_bundle
    from osint.evidence.seal import seal, verify_manifests

    keys = tmp_path / "keys"
    monkeypatch.setattr(seal_mod, "KEY_DIR", keys)  # absolute path wins over project home
    inv = _inv(app)
    _doc(app, inv, "Sealed evidence text for the bundle test.", "https://seal.example/1")
    r = seal(app)
    assert r is not None and r.entries >= 1
    assert seal(app) is None  # nothing new
    assert all(c.ok for c in verify_manifests(app))
    assert (keys / "signing_ed25519.pem").exists() and project_home()

    out = build_bundle(app, inv)
    dest = tmp_path / "unzipped"
    with zipfile.ZipFile(out) as z:
        z.extractall(dest)
    meta = json.loads((dest / "bundle.json").read_text(encoding="utf-8"))
    assert meta["artifacts"] and all(e["inclusion"] for e in meta["custody"])
    proc = subprocess.run([sys.executable, "-I", str(dest / "verify.py"), str(dest)],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0 and "ALL CHECKS PASSED" in proc.stdout, proc.stdout
    raw = dest / meta["artifacts"][0]["raw_path"]
    raw.write_bytes(raw.read_bytes() + b"!")
    proc = subprocess.run([sys.executable, "-I", str(dest / "verify.py"), str(dest)],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1 and "FAIL" in proc.stdout

    # tampering with a sealed custody entry (even in maintenance mode) breaks the manifest
    with app.session_factory() as s, s.begin():
        s.execute(text("SET LOCAL osint.maintenance = 'on'"))
        s.execute(text("UPDATE custody_log SET actor = 'evil' WHERE seq = "
                       "(SELECT max(seq) FROM custody_log)"))
    assert any(not c.ok for c in verify_manifests(app))
    with app.session_factory() as s, s.begin():
        s.execute(text("SET LOCAL osint.maintenance = 'on'"))
        s.execute(text("UPDATE custody_log SET actor = 'test' WHERE actor = 'evil'"))


@pytest.mark.integration
def test_key_players(app):
    from osint.core.models import EntityRef, ExtractedEntity, ExtractedRelation, ExtractionResult
    from osint.linking.network import key_players

    tag = uuid.uuid4().hex[:5]
    inv = _inv(app)
    names = [f"Hub{tag}", f"Ann{tag}", f"Bob{tag}", f"Cy{tag}"]
    t = " ".join(f"{n} is affiliated with Hub{tag}." for n in names[1:])
    d = _doc(app, inv, t, "https://net.example/1")
    _extract(app, inv, d, ExtractionResult(
        entities=[ExtractedEntity(name=n, type="person", quote=n) for n in names],
        relations=[ExtractedRelation(type="affiliated_with",
                                     src=EntityRef(name=n, type="person"),
                                     dst=EntityRef(name=f"Hub{tag}", type="person"),
                                     quote=f"{n} is affiliated with Hub{tag}")
                   for n in names[1:]]))
    with app.session_factory() as s:
        r = key_players(s, inv)
    assert r["players"][0]["name"] == f"Hub{tag}" and r["nodes"] == 4

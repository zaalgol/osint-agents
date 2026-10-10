"""Phase 5: incident clusters, extraction eval scoring, health metrics, review decisions, CSRF,
integrity checks."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from osint.core.models import (
    CaptureMeta,
    EntityRef,
    ExtractedEntity,
    ExtractedEvent,
    ExtractedRelation,
    ExtractionResult,
)
from osint.core.ontology import Ontology

ONTO = Ontology.load([Path(__file__).resolve().parents[1] / "config/ontology.yaml"])


# --------------------------------------------------------------------------- eval scoring


def test_gold_set_is_well_formed():
    from osint.evals.extraction import load_gold

    gold = load_gold(Path(__file__).resolve().parents[1] / "evals/extraction/gold.jsonl")
    assert len(gold) >= 8 and {g["lang"] for g in gold} >= {"en", "ar", "ru", "fr"}
    for g in gold:
        for e in g["entities"]:
            assert e["type"] in ONTO.entity_types
            assert any(n in g["text"] for n in [e["name"], *e.get("aliases", [])]), (g["id"], e)
        for r in g["relations"]:
            assert r["type"] in ONTO.extractable_relations()
        for v in g["events"]:
            assert v["type"] in ONTO.event_types


def test_score_document_rewards_correct_and_punishes_overreach():
    from osint.evals.extraction import load_gold, score_document

    gold = {g["id"]: g for g in load_gold(Path(__file__).resolve().parents[1] / "evals/extraction/gold.jsonl")}
    g = gold["en-claim"]
    perfect = ExtractionResult(
        relevant=True,
        entities=[ExtractedEntity(name="Crimson Dawn Brigade", type="armed_group", quote="Crimson Dawn Brigade"),
                  ExtractedEntity(name="Farid Okonjo", type="person", quote="Farid Okonjo"),
                  ExtractedEntity(name="Port Varen", type="location", quote="Port Varen"),
                  ExtractedEntity(name="crimsondawn_media", type="channel", quote="@crimsondawn_media")],
        relations=[ExtractedRelation(type="leader_of", src=EntityRef(name="Farid Okonjo", type="person"),
                                     dst=EntityRef(name="Crimson Dawn Brigade", type="armed_group"),
                                     quote="led by commander Farid Okonjo"),
                   ExtractedRelation(type="operates", src=EntityRef(name="Crimson Dawn Brigade", type="armed_group"),
                                     dst=EntityRef(name="@crimsondawn_media", type="channel"),
                                     quote="its Telegram channel @crimsondawn_media")],
        events=[ExtractedEvent(type="attack", description="d", time="2026-03-14", quote="bombing of a police checkpoint in Port Varen"),
                ExtractedEvent(type="claim_of_responsibility", description="d", quote="claimed responsibility"),
                ExtractedEvent(type="threat", description="d", quote="warned of further attacks")])
    s = score_document(g, perfect, ONTO)
    assert (s.entities.f1, s.relations.f1, s.events.f1) == (1.0, 1.0, 1.0)
    assert s.quotes_verified == s.quotes_total
    # a relation drawn from a denial is a false positive; an invented quote is counted
    denial = gold["denial"]
    bad = ExtractionResult(relevant=True, relations=[ExtractedRelation(
        type="affiliated_with", src=EntityRef(name="Crimson Dawn Brigade", type="armed_group"),
        dst=EntityRef(name="Lisbon", type="location"), quote="the Brigade ran the Lisbon cell")])
    s2 = score_document(denial, bad, ONTO)
    assert s2.relations.fp == 1 and s2.relations.p == 0.0
    assert s2.quotes_verified == 0 and s2.quotes_total == 1
    # irrelevant text: judged relevant = wrong
    s3 = score_document(gold["irrelevant"], ExtractionResult(relevant=True), ONTO)
    assert not s3.relevant_ok


def test_multilingual_name_matching():
    from osint.evals.extraction import _names_match

    assert _names_match("Мурманске", "Мурманск")
    assert _names_match("جماعة سرايا الفجر", "سرايا الفجر")
    assert not _names_match("Port Varen", "Tallon")


# --------------------------------------------------------------------------- DB tests

pytestmark_db = pytest.mark.integration


@pytest.fixture
def app5(pg_settings):
    from osint.core.context import App

    pg_settings.evidence.screenshots = False
    pg_settings.evidence.timestamp_methods = []
    return App(pg_settings)


def _inv(app) -> int:
    from osint.storage.db import Investigation

    with app.session_factory() as s, s.begin():
        i = Investigation(name=f"p5-{uuid.uuid4().hex[:8]}")
        s.add(i)
        s.flush()
        return i.id


def _doc(app, inv, text, url="https://n.test/"):
    from osint.evidence.ingest import ingest_bytes
    from osint.resolution.resolver import add_ref
    from osint.storage.db import Document

    with app.session_factory() as s, s.begin():
        art, _ = ingest_bytes(s, app.raw_store, text.encode() + uuid.uuid4().bytes,
                              CaptureMeta(url=url + uuid.uuid4().hex[:6]), actor="t")
        d = Document(artifact_id=art.id, extractor="t", text=text,
                     text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(d)
        s.flush()
        add_ref(s, inv, "document", d.id, "t")
        add_ref(s, inv, "artifact", art.id, "t")
        return d.id


def _write(app, inv, doc_id, res):
    from osint.extraction.writer import ExtractionWriter
    from osint.storage.db import Document

    with app.session_factory() as s, s.begin():
        ExtractionWriter(s, app.ontology, inv, s.get(Document, doc_id), actor="t").write(res)


def _vec(base: int, noise: float = 0.0, seed: int = 0) -> list[float]:
    import random

    r, n = random.Random(base), random.Random(seed)
    return [r.uniform(-1, 1) + (n.uniform(-noise, noise) if noise else 0) for _ in range(1024)]


@pytest.mark.integration
def test_same_incident_reports_cluster_and_corroborate(app5):
    from osint.analyst.tools import AnalystTools
    from osint.linking.corroboration import corroborate
    from osint.storage.db import Event, SupportStats

    tag = uuid.uuid4().hex[:5]
    inv = _inv(app5)
    ids = []
    for host, day in (("https://a.test/", "2026-05-01"), ("https://b.test/", "2026-05-02")):
        text = f"Gunmen of the Zor{tag} Front attacked the Kelmar{tag} depot, officials said."
        d = _doc(app5, inv, text, host)
        _write(app5, inv, d, ExtractionResult(events=[ExtractedEvent(
            type="attack", description=f"Zor{tag} Front attacked the Kelmar{tag} depot", time=day,
            quote=f"Gunmen of the Zor{tag} Front attacked the Kelmar{tag} depot")]))
    with app5.session_factory() as s, s.begin():
        evs = s.scalars(select(Event).where(Event.description.contains(f"Kelmar{tag}"))
                        .order_by(Event.id)).all()
        assert len(evs) == 2
        for i, e in enumerate(evs):
            e.embedding = _vec(77, 0.01, seed=i)
        ids = [e.id for e in evs]
    with app5.session_factory() as s, s.begin():
        r = corroborate(s, inv)
    assert r.incident_clusters >= 1
    with app5.session_factory() as s:
        assert {s.get(Event, i).cluster_id for i in ids} == {min(ids)}
        assert s.get(SupportStats, ("event", ids[1])).independent_sources == 2
    rows = AnalystTools(app5.session_factory, app5.ontology, app5.registry, app5.raw_store,
                        inv).timeline(inv)
    mine = [r for r in rows if f"Kelmar{tag}" in r["description"]]
    assert len(mine) == 1 and mine[0]["reports"] == 2 and len(mine[0]["evidence"]) == 2


@pytest.mark.integration
def test_health_metrics(app5):
    from osint.evals.health import extraction_health

    inv = _inv(app5)
    d = _doc(app5, inv, "The Rho Front is led by Commander Vex in the hills.")
    _write(app5, inv, d, ExtractionResult(relations=[
        ExtractedRelation(type="leader_of", src=EntityRef(name="Commander Vex", type="person"),
                          dst=EntityRef(name="Rho Front", type="armed_group"),
                          quote="The Rho Front is led by Commander Vex"),
        ExtractedRelation(type="leader_of", src=EntityRef(name="Commander Vex", type="person"),
                          dst=EntityRef(name="Rho Front", type="armed_group"),
                          quote="Vex founded the Rho Front in 2019")]))
    with app5.session_factory() as s:
        h = extraction_health(s, inv)
    assert h["citations_accepted"] == 1 and h["rejected"]["quote_not_found"] == 1
    assert h["hallucinated_quote_rate"] == 0.5


@pytest.mark.integration
def test_review_decisions(app5):
    from osint.review.actions import ReviewError, decide
    from osint.storage.db import Entity, ReviewItem, SupportStats

    inv = _inv(app5)
    with app5.session_factory() as s, s.begin():
        a = Entity(type="armed_group", canonical_name=f"Alpha{uuid.uuid4().hex[:4]} Group")
        b = Entity(type="armed_group", canonical_name=f"Alpha{uuid.uuid4().hex[:4]} Grp")
        s.add_all([a, b])
        s.flush()
        pair = ReviewItem(investigation_id=inv, kind="resolution_pair", reason="unsure",
                          payload={"a": a.id, "b": b.id}, created_by="er")
        weak = ReviewItem(investigation_id=inv, kind="weak_citation", reason="weak",
                          payload={"quote": "Yemen"}, created_by="t")
        contra = ReviewItem(investigation_id=inv, kind="contradiction", reason="dates",
                            payload={"a": 900001, "b": 900002}, created_by="t")
        s.add_all([pair, weak, contra])
        s.add(SupportStats(target_type="event", target_id=900001, contradicted_by=[900002]))
        s.flush()
        ids = (pair.id, weak.id, contra.id, a.id, b.id)
    pid, wid, cid, a_id, b_id = ids
    with app5.session_factory() as s, s.begin():
        out = decide(s, app5, pid, "accept", "human:test", note="same group, two spellings")
    assert out["merge_id"]
    with app5.session_factory() as s:
        merged = {s.get(Entity, a_id).merged_into_id, s.get(Entity, b_id).merged_into_id} - {None}
        assert merged
        assert s.get(ReviewItem, pid).payload["decision"]["note"] == "same group, two spellings"
    with app5.session_factory() as s, s.begin(), pytest.raises(ReviewError, match="by vote"):
        decide(s, app5, wid, "accept", "human:test")
    with app5.session_factory() as s, s.begin():
        decide(s, app5, wid, "reject", "human:test")
        decide(s, app5, cid, "reject", "human:test", note="different incidents")
    with app5.session_factory() as s:
        assert s.get(SupportStats, ("event", 900001)).contradicted_by == []
        assert s.get(ReviewItem, wid).status == "rejected"
    with app5.session_factory() as s, s.begin(), pytest.raises(ReviewError, match="already"):
        decide(s, app5, wid, "reject", "human:test")


@pytest.mark.integration
def test_accepting_a_sanctions_match_writes_cited_relation(app5):
    from osint.enrichment.base import EnrichmentResult, persist_enrichment
    from osint.review.actions import decide
    from osint.storage.db import Entity, EvidenceLink, Relation, ReviewItem

    inv = _inv(app5)
    with app5.session_factory() as s, s.begin():
        e = Entity(type="person", canonical_name=f"Omar Test{uuid.uuid4().hex[:4]}")
        s.add(e)
        s.flush()
        eid, name = e.id, e.canonical_name
    line = f"OFAC SDN entry 9999 [SDGT]: {name.upper()}"
    res = EnrichmentResult(facts_text=f"Sanctions screening for: {name} (person)\n{line}",
                           reviews=[{"kind": "sanctions_match", "reason": "possible listing",
                                     "list_entry": line}])
    with app5.session_factory() as s, s.begin():
        persist_enrichment(s, app5, inv, eid, "enricher:sanctions@0.1.0", "sanctions", res)
        rid = s.scalar(select(ReviewItem.id).where(ReviewItem.kind == "sanctions_match",
                                                   ReviewItem.investigation_id == inv))
    with app5.session_factory() as s, s.begin():
        out = decide(s, app5, rid, "accept", "human:analyst", note="DOB and nationality match")
    with app5.session_factory() as s:
        rel = s.get(Relation, out["relation_id"])
        assert rel.type == "designated_by" and rel.src_entity_id == eid
        assert rel.created_by == "human:analyst"
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.target_type == "relation",
                                                 EvidenceLink.target_id == rel.id))
        assert ev.quote_original == line and ev.quote_verified


@pytest.mark.integration
def test_ui_review_writes_need_csrf_and_localhost(app5):
    from starlette.testclient import TestClient

    from osint.storage.db import ReviewItem
    from osint.ui.app import create_app

    inv = _inv(app5)
    with app5.session_factory() as s, s.begin():
        item = ReviewItem(investigation_id=inv, kind="blocked_source", reason="x",
                          payload={"host": "h"}, created_by="t")
        s.add(item)
        s.flush()
        iid = item.id
    c = TestClient(create_app(app5), base_url="http://127.0.0.1:8765")
    page = c.get("/").text
    token = page.split('name="csrf" content="')[1].split('"')[0]
    url = f"/api/review/item/{iid}"
    assert c.post(url, json={"decision": "reject"}).status_code == 403                  # no token
    assert c.post(url, json={"decision": "reject"}, headers={
        "X-CSRF-Token": token, "Origin": "http://evil.test"}).status_code == 403          # foreign origin
    ok = c.post(url, json={"decision": "reject"}, headers={
        "X-CSRF-Token": token, "Origin": "http://127.0.0.1:8765"})
    assert ok.status_code == 200 and ok.json()["status"] == "rejected"
    listing = c.get(f"/api/inv/{inv}/review").json()
    assert all(i["id"] != iid for i in listing["items"])


@pytest.mark.integration
def test_integrity_check_detects_tampering(app5):
    from osint.evidence.integrity import last_result, run_integrity_check
    from osint.storage.db import Artifact, ReviewItem

    inv = _inv(app5)
    _doc(app5, inv, "integrity test text")
    with app5.session_factory() as s:
        art = s.scalar(select(Artifact).order_by(Artifact.id.desc()).limit(1))
    path = app5.raw_store.path_for(art.sha256)
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    path.write_bytes(b"tampered")
    r = run_integrity_check(app5)
    assert not r["ok"] and any(art.sha256 in p for p in r["problems"])
    assert last_result(app5)["ok"] is False
    with app5.session_factory() as s:
        assert s.scalar(select(ReviewItem).where(ReviewItem.kind == "integrity_alert"))


@pytest.mark.integration
def test_accepted_eu_match_names_the_eu_and_unknown_lists_are_refused(app5):
    from osint.enrichment.base import EnrichmentResult, persist_enrichment
    from osint.review.actions import ReviewError, decide
    from osint.storage.db import Entity, Relation, ReviewItem

    inv = _inv(app5)
    with app5.session_factory() as s, s.begin():
        e = Entity(type="person", canonical_name=f"Ali Test{uuid.uuid4().hex[:4]}")
        s.add(e)
        s.flush()
        eid, name = e.id, e.canonical_name
    eu = f"EU consolidated financial sanctions list EU.1.2 [YEM]: {name}"
    odd = f"Some Other List 7: {name}"
    res = EnrichmentResult(facts_text=f"Sanctions screening for: {name} (person)\n{eu}\n{odd}",
                           reviews=[{"kind": "sanctions_match", "reason": "eu", "list_entry": eu},
                                    {"kind": "sanctions_match", "reason": "odd", "list_entry": odd}])
    with app5.session_factory() as s, s.begin():
        persist_enrichment(s, app5, inv, eid, "enricher:sanctions@0.1.0", "sanctions", res)
        ids = dict(s.execute(select(ReviewItem.reason, ReviewItem.id).where(
            ReviewItem.investigation_id == inv)).all())
    with app5.session_factory() as s, s.begin():
        out = decide(s, app5, ids["eu"], "accept", "human:analyst")
    with app5.session_factory() as s:
        rel = s.get(Relation, out["relation_id"])
        dst = s.get(Entity, rel.dst_entity_id)
        assert dst.canonical_name == "Council of the European Union"
    with app5.session_factory() as s, s.begin(), pytest.raises(ReviewError, match="unknown"):
        decide(s, app5, ids["odd"], "accept", "human:analyst")

"""Integration tests: the DB itself enforces immutable evidence and 'no claim without proof'."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from osint.core.models import CaptureMeta
from osint.evidence import custody
from osint.evidence.ingest import ingest_bytes
from osint.plugins.collectors.echo import EchoCollector
from osint.storage.db import (
    Artifact,
    CustodyLog,
    Entity,
    EvidenceLink,
    Finding,
    Inference,
    InferencePremise,
    Investigation,
    Relation,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def artifact_id(session_factory, raw_store):
    with session_factory() as s, s.begin():
        art, _ = ingest_bytes(s, raw_store, b"Abu X joined Group A in 2024.",
                              CaptureMeta(url="https://example.org/a"), actor="test")
        return art.id


@pytest.fixture
def entities(session_factory):
    with session_factory() as s, s.begin():
        p = Entity(type="person", canonical_name="Abu X")
        g = Entity(type="armed_group", canonical_name="Group A")
        s.add_all([p, g])
        s.flush()
        return p.id, g.id


@pytest.fixture
def investigation_id(session_factory):
    import uuid

    with session_factory() as s, s.begin():
        inv = Investigation(name=f"inv-{uuid.uuid4().hex[:6]}")
        s.add(inv)
        s.flush()
        return inv.id


def _commit_fails(session_factory, fn, match: str):
    with pytest.raises(DBAPIError, match=match), session_factory() as s, s.begin():
        fn(s)


# ------------------------------------------------------------------ evidence immutability


def test_ingest_dedups_and_logs_custody(session_factory, raw_store, artifact_id):
    with session_factory() as s, s.begin():
        again, created = ingest_bytes(s, raw_store, b"Abu X joined Group A in 2024.",
                                      CaptureMeta(url="https://mirror.example/a"), actor="test")
    assert not created and again.id == artifact_id
    with session_factory() as s:
        actions = s.scalars(select(CustodyLog.action).where(CustodyLog.artifact_id == artifact_id)
                            .order_by(CustodyLog.seq)).all()
        assert actions == ["captured", "observed_again"]
        assert custody.verify_chain(s).ok


@pytest.mark.parametrize("sql", [
    "UPDATE artifact SET url = 'https://evil' WHERE id = :id",
    "DELETE FROM artifact WHERE id = :id",
    "UPDATE capture SET path = 'x' WHERE artifact_id = :id",
    "UPDATE custody_log SET actor = 'someone-else' WHERE artifact_id = :id",
    "DELETE FROM custody_log WHERE artifact_id = :id",
    "TRUNCATE custody_log CASCADE",
])
def test_evidence_tables_are_append_only(session_factory, artifact_id, sql):
    _commit_fails(session_factory, lambda s: s.execute(text(sql), {"id": artifact_id}),
                  "append-only")


def test_custody_fork_rejected(session_factory, artifact_id):
    def forge(s):
        s.add(CustodyLog(artifact_id=artifact_id, action="x", actor="forger",
                         at_utc=s.scalar(text("SELECT now()")), details={},
                         prev_hash=custody.GENESIS, entry_hash="f" * 64))
        s.flush()

    _commit_fails(session_factory, forge, "custody chain fork")


def test_tampering_in_maintenance_mode_is_still_detected(session_factory, artifact_id):
    with session_factory() as s, s.begin():
        s.execute(text("SET LOCAL osint.maintenance = 'on'"))
        s.execute(text("UPDATE custody_log SET actor = 'tampered' WHERE artifact_id = :id"),
                  {"id": artifact_id})
    with session_factory() as s:
        report = custody.verify_chain(s)
    assert not report.ok and "altered" in report.problem
    # restore so later tests see a valid chain
    with session_factory() as s, s.begin():
        s.execute(text("SET LOCAL osint.maintenance = 'on'"))
        s.execute(text("UPDATE custody_log SET actor = 'test' WHERE actor = 'tampered'"))
    with session_factory() as s:
        assert custody.verify_chain(s).ok


# ------------------------------------------------------------------ no claim without proof


def test_relation_without_evidence_rejected_at_commit(session_factory, entities):
    p, g = entities

    def add(s):
        s.add(Relation(type="member_of", src_entity_id=p, dst_entity_id=g, created_by="t"))
        s.flush()  # insert succeeds; the deferred trigger fires at COMMIT

    _commit_fails(session_factory, add, "no proof")


def test_relation_with_citation_accepted(session_factory, entities, artifact_id):
    p, g = entities
    with session_factory() as s, s.begin():
        r = Relation(type="member_of", src_entity_id=p, dst_entity_id=g, created_by="t")
        s.add(r)
        s.flush()
        s.add(EvidenceLink(target_type="relation", target_id=r.id, artifact_id=artifact_id,
                           quote_original="Abu X joined Group A", char_start=0, char_end=20,
                           created_by="t"))
    with session_factory() as s:
        assert s.get(Relation, r.id) is not None


def test_citation_to_missing_target_rejected(session_factory, artifact_id):
    _commit_fails(
        session_factory,
        lambda s: (s.add(EvidenceLink(target_type="relation", target_id=999_999_999,
                                      artifact_id=artifact_id, quote_original="q",
                                      created_by="t")), s.flush()),
        "does not exist",
    )


def test_inferred_finding_needs_inference(session_factory, investigation_id, artifact_id):
    def add(s):
        f = Finding(investigation_id=investigation_id, kind="assessment", text="likely link",
                    confidence=0.6, epistemic_status="inferred", created_by="t")
        s.add(f)
        s.flush()
        # a citation alone isn't enough for an inferred finding
        s.add(EvidenceLink(target_type="finding", target_id=f.id, artifact_id=artifact_id,
                           quote_original="q", created_by="t"))
        s.flush()

    _commit_fails(session_factory, add, "requires a proof tree")


def test_inference_needs_premises(session_factory, investigation_id):
    def add(s):
        f = Finding(investigation_id=investigation_id, kind="assessment", text="t",
                    confidence=0.6, epistemic_status="assessed", created_by="t")
        s.add(f)
        s.flush()
        s.add(Inference(conclusion_type="finding", conclusion_id=f.id, method="m",
                        created_by="t"))
        s.flush()

    _commit_fails(session_factory, add, "no premises")


def test_full_proof_tree_accepted(session_factory, investigation_id, artifact_id, entities):
    p, g = entities
    with session_factory() as s, s.begin():
        r = Relation(type="member_of", src_entity_id=p, dst_entity_id=g, created_by="t")
        s.add(r)
        s.flush()
        ev = EvidenceLink(target_type="relation", target_id=r.id, artifact_id=artifact_id,
                          quote_original="Abu X joined Group A", created_by="t")
        s.add(ev)
        f = Finding(investigation_id=investigation_id, kind="assessment",
                    text="Abu X is likely an active Group A member", confidence=0.7,
                    epistemic_status="assessed", created_by="claude:analyze")
        s.add(f)
        s.flush()
        inf = Inference(conclusion_type="finding", conclusion_id=f.id,
                        method="single self-published source", created_by="claude:analyze")
        s.add(inf)
        s.flush()
        s.add_all([InferencePremise(inference_id=inf.id, premise_type="relation", premise_id=r.id),
                   InferencePremise(inference_id=inf.id, premise_type="evidence",
                                    premise_id=ev.id)])
    with session_factory() as s:
        assert s.get(Finding, f.id).epistemic_status == "assessed"


def test_echo_collector_end_to_end(session_factory, raw_store):
    c = EchoCollector()
    params = c.parse_params({"items": ["post one", "post two", "post one"]})

    async def run():
        ids = []
        async for item in c.collect(params, ctx=None):
            with session_factory() as s, s.begin():
                art, _ = ingest_bytes(s, raw_store, item.data, item.meta, actor=c.ident)
                ids.append(art.id)
        return ids

    ids = asyncio.run(run())
    assert ids[0] == ids[2] and ids[0] != ids[1]
    with session_factory() as s:
        art = s.get(Artifact, ids[0])
        assert art.capture_meta["collector"] == "collector:echo@0.1.0"
        assert raw_store.read_bytes(art.sha256) == b"post one"
        assert custody.verify_chain(s).ok

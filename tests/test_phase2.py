"""Phase 2: citation gate, analyst tools, MCP server, report rendering, Claude bridge."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from osint.analyst.tools import AnalystTools, ToolError
from osint.core.context import App
from osint.core.models import (
    CaptureMeta,
    EntityRef,
    ExtractedEntity,
    ExtractedEvent,
    ExtractedParticipant,
    ExtractedRelation,
    ExtractionResult,
)
from osint.evidence.ingest import ingest_bytes
from osint.extraction.writer import ExtractionWriter
from osint.reports.verify import SupportVerdict, is_exempt, split_sentences, verify_report
from osint.storage.db import (
    ClaudeJob,
    Document,
    EvidenceLink,
    Finding,
    Inference,
    Investigation,
    Report,
    Task,
)

ROOT = Path(__file__).resolve().parents[1]
TEXT = ("Abu Example, a commander of the Northern Front, announced on 1 March 2026 that the "
        "group carried out the attack in Testville. Officials said two people were killed.")


# --------------------------------------------------------------------------- pure functions


def test_split_sentences_handles_lists_tables_markers_and_code():
    md = """# Title

## Key judgements
- The Front is likely expanding [F:1].
- Attacks rose in March [E:2]. A second claim followed. [E:3]

| Date | Event |
|---|---|
| 2026-03-01 | Attack in Testville [E:2] |

```
code is ignored [E:999]
```

## Methodology and limitations
We used open sources only.
"""
    out = split_sentences(md)
    texts = [t for _, t in out]
    assert "The Front is likely expanding [F:1]." in texts
    assert "A second claim followed. [E:3]" in texts  # marker-only fragment re-attached
    assert any(t.startswith("2026-03-01 | Attack in Testville") for t in texts)
    assert not any("999" in t for t in texts)
    meth = [t for s, t in out if s.startswith("Methodology")]
    assert meth and is_exempt("Methodology and limitations", meth[0])
    assert is_exempt("Background", "Short line.")
    assert not is_exempt("Background", "The group attacked a checkpoint in the north.")


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def kb(pg_settings):
    """An investigation with one document, extracted knowledge and verified citations."""
    pg_settings.evidence.screenshots = False
    app = App(pg_settings)
    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"p2-{uuid.uuid4().hex[:8]}", seed={"focus": "Front"})
        s.add(inv)
        s.flush()
        art, _ = ingest_bytes(s, app.raw_store, TEXT.encode() + uuid.uuid4().bytes,
                              CaptureMeta(url="https://news.example/front"), actor="test")
        doc = Document(artifact_id=art.id, extractor="t", text=TEXT,
                       text_sha256=hashlib.sha256(TEXT.encode()).hexdigest(), title="Front")
        s.add(doc)
        s.flush()
        from osint.resolution.resolver import add_ref

        add_ref(s, inv.id, "document", doc.id, "t")
        add_ref(s, inv.id, "artifact", art.id, "t")
        w = ExtractionWriter(s, app.ontology, inv.id, doc, actor="t")
        w.write(ExtractionResult(
            entities=[ExtractedEntity(name="Abu Example", type="person", quote="Abu Example"),
                      ExtractedEntity(name="Northern Front", type="armed_group",
                                      quote="Northern Front")],
            relations=[ExtractedRelation(
                type="member_of", src=EntityRef(name="Abu Example", type="person"),
                dst=EntityRef(name="Northern Front", type="armed_group"),
                quote="Abu Example, a commander of the Northern Front")],
            events=[ExtractedEvent(
                type="attack", description="Attack in Testville", time="2026-03-01",
                participants=[ExtractedParticipant(name="Northern Front", type="armed_group",
                                                   role="perpetrator")],
                quote="the group carried out the attack in Testville")]))
        inv_id, art_sha = inv.id, art.sha256
    with app.session_factory() as s:
        evs = {e.target_type: e.id for e in s.scalars(select(EvidenceLink).where(
            EvidenceLink.document_id == doc.id))}
    tools = AnalystTools(app.session_factory, app.ontology, app.registry, app.raw_store, inv_id,
                         actor="claude:test", max_collection_requests=2)
    return {"app": app, "inv": inv_id, "rel_ev": evs["relation"], "event_ev": evs["event"],
            "tools": tools, "art_sha": art_sha}


async def fake_judge(claim: str, evidence: str) -> SupportVerdict:
    """Supported when the claim's key words appear in the evidence."""
    words = [w for w in claim.lower().replace(".", "").split() if len(w) > 4]
    hit = sum(w in evidence.lower() for w in words)
    if hit == len(words):
        return SupportVerdict(verdict="supported", missing="")
    return SupportVerdict(verdict="unsupported" if hit == 0 else "partial",
                          missing="words not in evidence")


# --------------------------------------------------------------------------- tools

pytestmark = pytest.mark.integration


def test_read_tools(kb):
    t = kb["tools"]
    ov = t.investigation_overview()
    assert ov["counts"]["relation"] == 1 and ov["counts"]["event"] == 1
    ents = t.search_entities("northern front")
    assert ents and ents[0]["type"] == "armed_group"
    e = t.get_entity(ents[0]["entity_id"])
    # the organization is global: other tests' (investigation-scoped) people relate to it too
    assert any(f"[E:{kb['rel_ev']}]" in r["evidence"] for r in e["relations"])
    assert e["events"][0]["type"] == "attack"
    nb = t.neighborhood([ents[0]["entity_id"]], hops=2)
    assert {n["name"] for n in nb["nodes"]} >= {"Abu Example", "Northern Front"}
    tl = t.timeline()
    assert tl[0]["time"].startswith("2026-03-01")
    # date filters are ISO dates, `end` inclusive (they used to fail as text comparisons)
    assert [e["event_id"] for e in t.timeline(start="2026-03-01", end="2026-03-01")] ==         [tl[0]["event_id"]]
    assert t.timeline(start="2026-03-02") == []
    with pytest.raises(ToolError):
        t.timeline(start="March 2026")
    ev = t.get_evidence([kb["rel_ev"], 999_999])
    assert ev[0]["quote"] == "Abu Example, a commander of the Northern Front"
    assert ev[0]["sha256"] == kb["art_sha"] and "context" in ev[0]
    assert ev[1]["error"] == "no such evidence"
    docs = t.search_documents("Testville")
    assert docs and "Testville" in docs[0]["snippet"]
    assert t.read_document(docs[0]["document_id"], 0, 50)["text"] == TEXT[:200]  # min 200


def test_add_finding_enforces_proof(kb):
    t = kb["tools"]
    f = t.add_finding("Abu Example is a commander of the Northern Front.", "fact", 0.8,
                      "reported", evidence_ids=[kb["rel_ev"]])
    with pytest.raises(ToolError, match="no claim without proof"):
        t.add_finding("Something.", "fact", 0.5, "observed")
    with pytest.raises(ToolError, match="unknown evidence"):
        t.add_finding("Something.", "fact", 0.5, "observed", evidence_ids=[999_999])
    with pytest.raises(ToolError, match="method"):
        t.add_finding("The Front is likely to attack again.", "assessment", 0.6, "assessed",
                      evidence_ids=[kb["event_ev"]])
    a = t.add_finding("The Front is likely to attack again.", "assessment", 0.6, "assessed",
                      evidence_ids=[kb["event_ev"]],
                      premises=[{"type": "finding", "id": f["finding_id"]}],
                      method="recent claimed attack plus command structure")
    assert a["marker"].startswith("[F:")
    with kb["app"].session_factory() as s:
        inf = s.scalar(select(Inference).where(Inference.conclusion_type == "finding",
                                               Inference.conclusion_id == a["finding_id"]))
        assert inf.method.startswith("recent claimed")
        cites = s.scalars(select(EvidenceLink).where(EvidenceLink.target_type == "finding",
                                                     EvidenceLink.target_id == f["finding_id"]))
        assert [c.quote_original for c in cites] == ["Abu Example, a commander of the Northern Front"]
    assert len(t.list_findings()) == 2


def test_request_collection_validates_and_budgets(kb):
    t = kb["tools"]
    with pytest.raises(ToolError, match="unknown collector"):
        t.request_collection("telegram_magic", {}, "x")
    with pytest.raises(ToolError, match="invalid params"):
        t.request_collection("searxng", {"queries": []}, "x")
    r = t.request_collection("searxng", {"queries": ["northern front"], "language": "ar"},
                             "Arabic coverage")
    assert r["queued"]
    t.request_collection("web", {"urls": ["https://example.org/a"]}, "primary source")
    with pytest.raises(ToolError, match="budget"):
        t.request_collection("web", {"urls": ["https://example.org/b"]}, "x")
    with kb["app"].session_factory() as s:
        task = s.get(Task, r["task_id"])
        assert task.params["_requested_by"] == "claude:test" and task.status == "pending"


def test_report_gate_and_rendering(kb):
    t = kb["tools"]
    t.judge = fake_judge
    f = t.add_finding("Abu Example is a commander of the Northern Front.", "fact", 0.8,
                      "reported", evidence_ids=[kb["rel_ev"]])
    E = kb["event_ev"]
    bad = f"""# Front report

## Key judgements
- Abu Example is a commander of the Northern Front {f['marker']}.
- The Northern Front has nuclear weapons and a navy [E:{E}].
- The group operates in eleven countries across three continents today.
- A fabricated marker is cited here as well [E:987654].
"""
    res = asyncio.run(t.write_report("Front report", bad))
    assert not res["ok"]
    kinds = res["issue_counts"]
    assert kinds["uncited"] == 1 and kinds["unresolved"] == 1
    assert kinds["unsupported"] + kinds.get("partial", 0) >= 1

    good = f"""# Front report

## Key judgements
- Abu Example is a commander of the Northern Front {f['marker']}.
- The group carried out the attack in Testville [E:{E}].

## Methodology and limitations
Open sources only; one news article; collection window one day.
"""
    res2 = asyncio.run(t.write_report("Front report", good, supersedes_id=res["report_id"]))
    assert res2["ok"], res2
    app = kb["app"]
    with app.session_factory() as s:
        r = s.get(Report, res2["report_id"])
        assert r.status == "verified" and r.supersedes_id == res["report_id"]
        from osint.reports.render import render_report

        paths = render_report(s, r, Path(app.settings.data_path) / "reports")
    md_text = paths["md"].read_text(encoding="utf-8")
    assert f"[^E{E}]" in md_text and kb["art_sha"] in md_text
    assert "https://news.example/front" in md_text and "status **verified**" in md_text
    html_text = paths["html"].read_text(encoding="utf-8")
    assert "footnote" in html_text and "prefers-color-scheme" in html_text


def test_gate_fails_when_evidence_file_is_tampered(kb):
    app = kb["app"]
    path = app.raw_store.path_for(kb["art_sha"])
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    path.write_bytes(b"tampered")
    v = asyncio.run(verify_report(app.session_factory, app.raw_store, kb["inv"],
                                  f"The group carried out the attack in Testville [E:{kb['event_ev']}]."))
    assert not v.ok and v.unresolved == 1
    assert "integrity" in v.checks[0].issues[0]


def test_mcp_server_exposes_tools_by_toolset(kb):
    from osint.mcp_server.server import build_server

    full = build_server(kb["tools"], "full")
    read = build_server(kb["tools"], "read")
    full_names = {x.name for x in asyncio.run(full.list_tools())}
    read_names = {x.name for x in asyncio.run(read.list_tools())}
    assert {"add_finding", "request_collection", "write_report"} <= full_names
    assert "add_finding" not in read_names and "get_evidence" in read_names
    res = asyncio.run(read.call_tool("get_evidence", {"evidence_ids": [kb["rel_ev"]]}))
    assert "Northern Front" in res.content[0].text
    # in-process call_tool raises; over the protocol the SDK turns this into an is_error
    # result, and the message (how to fix the call) is what the model gets to see
    from mcp.server.mcpserver.exceptions import ToolError as MCPToolError

    with pytest.raises(MCPToolError, match="no claim without proof"):
        asyncio.run(full.call_tool("add_finding", {"text": "x", "kind": "fact",
                                                   "confidence": 0.5,
                                                   "epistemic_status": "observed"}))


# --------------------------------------------------------------------------- Claude bridge


def _runner(app: App):
    from osint.llm.claude_cli import ClaudeRunner

    return ClaudeRunner(app, binary=[sys.executable, str(ROOT / "tests" / "fake_claude.py")])


def test_claude_runner_flags_cache_and_api_key_stripping(kb, tmp_path, monkeypatch):
    app = kb["app"]
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(log))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-leak")
    r = _runner(app)
    res = r.run("plan_investigation", kb["inv"], "PROMPT", "SYSTEM", fingerprint="v1",
                max_requests=5, max_turns=7)
    assert not res.cached and res.data["questions"] == ["Who is behind the attacks?"]
    call = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    argv = call["argv"]
    assert call["api_key_present"] is False
    assert argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--allowedTools") + 1] == "mcp__osint__*"
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    assert "--strict-mcp-config" in argv and argv[argv.index("--max-turns") + 1] == "7"
    env = call["mcp_config"]["mcpServers"]["osint"]["env"]
    assert env["OSINT_INVESTIGATION_ID"] == str(kb["inv"]) and env["OSINT_MAX_REQUESTS"] == "5"
    assert call["prompt_head"] == "PROMPT"

    again = r.run("plan_investigation", kb["inv"], "PROMPT", "SYSTEM", fingerprint="v1")
    assert again.cached and again.job_id == res.job_id
    changed = r.run("plan_investigation", kb["inv"], "PROMPT", "SYSTEM", fingerprint="v2")
    assert not changed.cached
    with app.session_factory() as s:
        row = s.get(ClaudeJob, res.job_id)
        assert row.status == "done" and row.input_tokens == 100 and row.output_tokens == 50


@pytest.mark.parametrize("mode,exc,status", [
    ("quota", "QuotaExceeded", "quota"),
    ("error", "ClaudeJobError", "error"),
    ("garbage", "ClaudeJobError", "error"),
])
def test_claude_runner_failures_are_recorded(kb, monkeypatch, mode, exc, status):
    from osint.llm import claude_cli

    monkeypatch.setenv("FAKE_CLAUDE_MODE", mode)
    r = _runner(kb["app"])
    with pytest.raises(getattr(claude_cli, exc)):
        r.run("analyze_investigation", kb["inv"], f"P-{mode}", "S", fingerprint=mode)
    with kb["app"].session_factory() as s:
        row = s.scalar(select(ClaudeJob).where(ClaudeJob.job == "analyze_investigation")
                       .order_by(ClaudeJob.id.desc()).limit(1))
        assert row.status == status


def test_analyst_plan_job_stores_plan(kb):
    from osint.analyst.jobs import Analyst

    a = Analyst(kb["app"], runner=_runner(kb["app"]))
    out = a.plan(kb["inv"])
    with kb["app"].session_factory() as s:
        inv = s.get(Investigation, kb["inv"])
        assert inv.config["plan"]["questions"] == ["Who is behind the attacks?"]
    assert out.extra["plan"]["echo"] > 100  # the rendered prompt was sent


def test_findings_require_proof_even_via_raw_sql(kb):
    """Defense in depth: bypassing the tools still hits the DB trigger."""
    from sqlalchemy.exc import DBAPIError

    with pytest.raises(DBAPIError, match="no proof"), kb["app"].session_factory() as s, s.begin():
        s.add(Finding(investigation_id=kb["inv"], kind="fact", text="x", confidence=0.5,
                      epistemic_status="observed", created_by="sneaky"))

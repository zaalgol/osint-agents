"""GPU memory discipline: one chat model loaded at a time, and OCR batched after extraction.

Why: the 14B extraction model and the 27B vision model don't fit in 16 GB of VRAM
together; Ollama spills the overflow into system RAM, which ran the machine out of memory.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest
from pydantic import BaseModel

from osint.core.config import LocalModels, LocalRole
from osint.core.context import App
from osint.core.models import TaskSpec
from osint.llm.local import LocalLLM
from osint.orchestrator import queue
from osint.orchestrator.runner import Runner
from osint.storage.db import Investigation, Task


class Out(BaseModel):
    ok: bool


def test_only_one_chat_model_runs_at_a_time():
    active: dict[str, int] = {}
    events: list[str] = []
    overlap: list[set[str]] = []

    async def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        if req.url.path == "/api/generate" and body.get("keep_alive") == 0:
            events.append(f"unload {body['model']}")
            return httpx.Response(200, json={})
        m = body["model"]
        active[m] = active.get(m, 0) + 1
        if len([k for k, v in active.items() if v]) > 1:
            overlap.append({k for k, v in active.items() if v})
        events.append(f"start {m}")
        await asyncio.sleep(0.01)
        active[m] -= 1
        return httpx.Response(200, json={"message": {"content": '{"ok": true}'}})

    cfg = LocalModels(base_url="http://o.test/v1",
                      roles={"agent": LocalRole(model="small"), "vision": LocalRole(model="big")})
    llm = LocalLLM(cfg, slots=2, transport=httpx.MockTransport(handler))

    async def go():
        calls = [llm.chat_json("agent" if i % 3 else "vision", "s", "u", Out) for i in range(12)]
        await asyncio.gather(*calls)
        await llm.aclose()

    asyncio.run(go())
    assert not overlap, f"two models ran together: {overlap}"
    starts = [e for e in events if e.startswith("start")]
    assert len(starts) == 12
    # every switch unloads the previous model before the next one starts
    last, unloaded = None, set()
    for e in events:
        verb, model = e.split()
        if verb == "unload":
            unloaded.add(model)
        else:
            if last is not None and model != last:
                assert last in unloaded, f"switched {last} -> {model} without unloading"
            last, unloaded = model, set()
    assert llm.switches >= 1 and any(e.startswith("unload") for e in events)
    assert llm.switches <= 4                    # batched, not ping-ponging per call


@pytest.mark.integration
def test_ocr_waits_until_text_extraction_is_drained(pg_settings):
    app = App(pg_settings)
    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"gpu-{uuid.uuid4().hex[:6]}", seed={"focus": "x"},
                            status="active", config={})
        s.add(inv)
        s.flush()
        inv_id = inv.id
        for spec in [TaskSpec(investigation_id=inv_id, type="ocr", plugin="ocr",
                              params={"artifact_id": 1}, priority=120),
                     TaskSpec(investigation_id=inv_id, type="extract", plugin="extract",
                              params={"document_id": 1}, priority=80),
                     TaskSpec(investigation_id=inv_id, type="parse", plugin="parse",
                              params={"artifact_id": 2}, priority=50)]:
            queue.enqueue(s, spec)
    r = Runner(app, inv_id, services={})

    def claim():
        with app.session_factory() as s, s.begin():
            t = r._claim_llm(s, "test")
            return t.type if t else None

    def finish(kind: str):
        with app.session_factory() as s, s.begin():
            for t in s.query(Task).filter_by(investigation_id=inv_id, type=kind):
                t.status = "done"

    assert claim() == "extract"
    finish("extract")
    assert claim() is None                      # parse may still produce more text to extract
    finish("parse")
    assert claim() == "ocr"                     # text pipeline drained: OCR batch starts
    with app.session_factory() as s, s.begin():
        queue.enqueue(s, TaskSpec(investigation_id=inv_id, type="ocr", plugin="ocr",
                                  params={"artifact_id": 3}, priority=120))
        queue.enqueue(s, TaskSpec(investigation_id=inv_id, type="extract", plugin="extract",
                                  params={"document_id": 9}, priority=80))
    assert claim() == "ocr"                     # an OCR batch in progress keeps going
    finish("ocr")
    assert claim() == "extract"


def test_runner_rss_counts_only_ollama_runners():
    from types import SimpleNamespace

    from osint.orchestrator.runner import runner_rss

    def proc(name, gb):
        return SimpleNamespace(info={"name": name, "memory_info": SimpleNamespace(rss=gb * 2**30)})

    fake = SimpleNamespace(process_iter=lambda attrs: [
        proc("llama-server.exe", 5), proc("llama-server.exe", 1), proc("chrome.exe", 9),
        proc("ollama.exe", 1), SimpleNamespace(info={"name": None, "memory_info": None})])
    assert runner_rss(fake) == 6 * 2**30

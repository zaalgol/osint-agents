"""Investigation runner: drains the task queue with network and LLM worker pools.

Pipeline (each step is a durable task):
    collect (plugin) --CapturedItem--> parse --document--> extract
            \\--FollowUp--> collect (e.g. search result -> web fetch)

Network-bound work (collect/parse) runs with many workers; GPU-bound work (extract) is
capped at llm_slots. Ctrl+C releases in-flight tasks back to pending; ``osint resume``
picks them up again, with collectors restored from their checkpoints.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select

from osint.core.context import App, PluginContext
from osint.core.models import CapturedItem, DocumentView, ExtractionResult, FollowUp, TaskSpec
from osint.evidence import custody
from osint.evidence.capture import persist_item
from osint.evidence.parse import parse_artifact, should_parse
from osint.extraction.writer import ExtractionWriter
from osint.llm.local import usage_tag
from osint.orchestrator import queue
from osint.resolution.resolver import add_ref
from osint.storage.db import Artifact, Capture, Document, Investigation, ReviewItem, RunLog, Task
from osint.storage.raw_store import BlockedContent

log = logging.getLogger(__name__)

NET_TYPES = ["collect", "parse", "enrich"]
LLM_TYPES = ["extract"]
HEARTBEAT_S = 20
STALE_AFTER = timedelta(seconds=90)


@dataclass
class RunSummary:
    done: int = 0
    retried: int = 0
    failed: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    seconds: float = 0.0


def chunk_text(text: str, size: int, overlap: int, max_chunks: int) -> list[tuple[int, str]]:
    """Split at paragraph/sentence boundaries; returns (offset, chunk) pairs."""
    chunks, pos = [], 0
    while pos < len(text) and len(chunks) < max_chunks:
        end = min(len(text), pos + size)
        if end < len(text):
            window = text[pos:end]
            cut = max(window.rfind("\n\n"), window.rfind("\n"), window.rfind(". "))
            if cut > size // 2:
                end = pos + cut + 1
        chunks.append((pos, text[pos:end]))
        if end >= len(text):
            break
        pos = max(end - overlap, pos + 1)
    return chunks


def investigation_focus(inv: Investigation) -> str:
    seed = inv.seed or {}
    parts = [seed.get("focus") or inv.name]
    if seed.get("queries"):
        parts.append("Search terms: " + "; ".join(seed["queries"]))
    return " | ".join(parts)


class Runner:
    def __init__(self, app: App, investigation_id: int, services: dict[str, Any], *,
                 net_workers: int | None = None, llm_workers: int | None = None,
                 max_fetches: int | None = None,
                 on_event: Callable[[str], None] | None = None):
        self.app = app
        self.inv_id = investigation_id
        self.services = services
        s = app.settings
        self.net_workers = net_workers or min(s.concurrency.network_tasks, 8)
        self.llm_workers = llm_workers or s.concurrency.llm_slots
        self.Session = app.session_factory
        with self.Session() as sess:
            inv = sess.get(Investigation, investigation_id)
            if inv is None:
                raise ValueError(f"no investigation {investigation_id}")
            self.focus = investigation_focus(inv)
            self.max_fetches = max_fetches or int((inv.config or {}).get("max_fetches", 200))
        self.on_event = on_event or (lambda msg: log.info(msg))
        self.summary = RunSummary()
        self._stop = asyncio.Event()
        self._mem_warned = False

    @property
    def ctx(self) -> PluginContext:
        return self.app.context(self.inv_id, **self.services)

    # ------------------------------------------------------------------ main loop

    async def run(self) -> RunSummary:
        t0 = time.monotonic()
        with self.Session() as s, s.begin():
            n = queue.reclaim(s, self.inv_id, STALE_AFTER)
        if n:
            self.on_event(f"reclaimed {n} stale task(s)")
        workers = [asyncio.create_task(self._worker(NET_TYPES, f"net{i}"))
                   for i in range(self.net_workers)]
        workers += [asyncio.create_task(self._worker(LLM_TYPES, f"llm{i}"))
                    for i in range(self.llm_workers)]
        recycler = asyncio.create_task(self._recycle_llm())
        try:
            await asyncio.gather(*workers)
        finally:
            recycler.cancel()
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            self.summary.seconds = time.monotonic() - t0
        return self.summary

    def stop(self) -> None:
        self._stop.set()

    async def _wait_for_memory(self) -> None:
        """Don't start new work while the machine is short of RAM (Ollama, Chromium, Neo4j
        and Docker share 32 GB). Running tasks finish; new ones wait for memory to recover."""
        try:
            import psutil
        except ImportError:
            return
        floor = self.app.settings.concurrency.min_free_ram_gb * 1024 ** 3
        waited = 0
        while psutil.virtual_memory().available < floor and not self._stop.is_set():
            if waited == 0 and not self._mem_warned:
                self._mem_warned = True
                free = psutil.virtual_memory().available / 1024 ** 3
                self.on_event(f"[yellow]low memory[/] ({free:.1f} GB free): pausing new tasks")
            await asyncio.sleep(5)
            waited += 5
        if waited:
            self._mem_warned = False

    async def _recycle_llm(self) -> None:
        """Unload Ollama models when RAM runs low; they reload on the next request."""
        try:
            import psutil
        except ImportError:
            return
        llm = self.services.get("llm")
        if llm is None:
            return
        floor = self.app.settings.concurrency.recycle_llm_below_gb * 1024 ** 3
        last = 0.0
        while True:
            await asyncio.sleep(30)
            if psutil.virtual_memory().available < floor and time.monotonic() - last > 180:
                last = time.monotonic()
                models = await llm.unload_all()
                free = psutil.virtual_memory().available / 1024 ** 3
                self.on_event(f"[yellow]RAM low[/] ({free:.1f} GB): recycled local models "
                              f"{models} to free Ollama's memory")

    async def _worker(self, types: list[str], name: str) -> None:
        while not self._stop.is_set():
            await self._wait_for_memory()
            with self.Session() as s, s.begin():
                task = queue.claim(s, self.inv_id, types, worker=f"{queue.WORKER_ID}/{name}")
                if task is None:
                    open_work = queue.has_open_work(s, self.inv_id)
            if task is None:
                if not open_work:
                    return
                await asyncio.sleep(1.0)
                continue
            await self._execute(task)

    async def _execute(self, task: Task) -> None:
        usage_tag.set(task.id)
        hb = asyncio.create_task(self._heartbeat(task.id))
        label = f"{task.type}:{task.plugin}#{task.id}"
        try:
            handler = {"collect": self._collect, "parse": self._parse,
                       "extract": self._extract, "enrich": self._enrich}[task.type]
            result = await handler(task)
            hb.cancel()
            with self.Session() as s, s.begin():
                queue.complete(s, task.id, result, checkpoint=result.pop("_checkpoint", None))
            self.summary.done += 1
            self.summary.by_type[task.type] = self.summary.by_type.get(task.type, 0) + 1
            self.on_event(f"[green]✓[/] {label} {_fmt(result)}")
        except asyncio.CancelledError:
            hb.cancel()
            with self.Session() as s, s.begin():
                queue.release(s, task.id)
            raise
        except Exception as e:
            hb.cancel()
            log.debug("task %s failed", label, exc_info=True)
            with self.Session() as s, s.begin():
                outcome = queue.fail(s, task.id, f"{type(e).__name__}: {e}")
            if outcome == "retry":
                self.summary.retried += 1
            else:
                self.summary.failed += 1
            self.on_event(f"[red]✗[/] {label} {outcome}: {type(e).__name__}: {str(e)[:200]}")
        finally:
            hb.cancel()

    async def _heartbeat(self, task_id: int) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_S)
            with self.Session() as s, s.begin():
                queue.heartbeat(s, task_id)

    # ------------------------------------------------------------------ handlers

    async def _collect(self, task: Task) -> dict:
        from osint.core.plugins import check_collector_allowed

        check_collector_allowed(self.app.registry.get("collector", task.plugin), self.app.settings)
        collector = self.app.registry.create("collector", task.plugin)
        params = collector.parse_params(task.params)
        collector.restore(task.checkpoint or {})
        stats = {"artifacts": 0, "new": 0, "captures": 0, "followups": 0, "skipped": 0,
                 "blocked": 0, "via_vpn": 0}
        async for out in collector.collect(params, self.ctx):
            with self.Session() as s, s.begin():
                if isinstance(out, CapturedItem):
                    try:
                        art, created = persist_item(s, self.app.raw_store, out,
                                                    actor=collector.ident)
                    except BlockedContent as e:
                        # nothing was written; record only that it was refused
                        custody.append(s, "blocked", collector.ident, None,
                                       {"url": out.meta.url, "sha256": e.sha256,
                                        "blocklist": e.list_name})
                        stats["refused"] = stats.get("refused", 0) + 1
                        self.on_event(f"[red]refused blocklisted content[/] from {out.meta.url}")
                        continue
                    add_ref(s, self.inv_id, "artifact", art.id, collector.ident)
                    stats["artifacts"] += 1
                    stats["new"] += int(created)
                    stats["captures"] += len(out.extra_captures)
                    extra = out.meta.extra or {}
                    stats["via_vpn"] += int(extra.get("route") == "vpn")
                    if extra.get("blocked"):
                        stats["blocked"] += 1
                        self._report_block(s, out.meta.final_url or out.meta.url,
                                           extra["blocked"], extra.get("route_attempts"))
                    if out.parse and should_parse(out.mime, self.app.settings.media.ocr):
                        queue.enqueue(s, TaskSpec(investigation_id=self.inv_id, type="parse",
                                                  plugin="parse", params={"artifact_id": art.id},
                                                  priority=50))
                elif isinstance(out, FollowUp):
                    if out.type == "collect" and self._fetch_budget_left(s) <= 0:
                        stats["skipped"] += 1
                    else:
                        _, created = queue.enqueue(s, TaskSpec(
                            investigation_id=self.inv_id, type=out.type, plugin=out.plugin,
                            params=out.params, priority=out.priority))
                        stats["followups"] += int(created)
                queue.heartbeat(s, task.id, checkpoint=collector.checkpoint())
        stats["_checkpoint"] = collector.checkpoint()
        return stats

    async def _enrich(self, task: Task) -> dict:
        from osint.enrichment.base import entity_view, persist_enrichment

        enricher = self.app.registry.create("enricher", task.plugin)
        entity_id = int(task.params["entity_id"])
        with self.Session() as s:
            view = entity_view(s, entity_id)
        res = await enricher.enrich(view, self.ctx)
        if res.skipped:
            return {"skipped": res.skipped}
        with self.Session() as s, s.begin():
            out = persist_enrichment(s, self.app, self.inv_id, entity_id, enricher.ident,
                                     enricher.name, res)
        return {"entity": f"{view.name} ({view.type})", **out}

    def _report_block(self, s, url: str | None, reason: str, attempts) -> None:
        from urllib.parse import urlsplit

        from osint.storage.db import ReviewItem

        host = urlsplit(url or "").hostname or "?"
        exists = s.scalar(select(ReviewItem.id).where(
            ReviewItem.investigation_id == self.inv_id, ReviewItem.kind == "blocked_source",
            ReviewItem.payload["host"].as_string() == host))
        if exists is None:
            vpn = self.app.settings.network.vpn_proxy
            s.add(ReviewItem(
                investigation_id=self.inv_id, kind="blocked_source",
                reason=f"{host} blocked us ({reason})"
                       + ("" if vpn else "; no VPN fallback configured (network.vpn_proxy)"),
                payload={"host": host, "url": url, "reason": reason, "attempts": attempts},
                created_by="runner"))
        self.on_event(f"[yellow]blocked[/] {host}: {reason}")

    def _fetch_budget_left(self, s) -> int:
        used = s.scalar(select(func.count()).where(Task.investigation_id == self.inv_id,
                                                   Task.type == "collect"))
        return self.max_fetches - (used or 0)

    async def _parse(self, task: Task) -> dict:
        artifact_id = int(task.params["artifact_id"])
        with self.Session() as s:
            art = s.get(Artifact, artifact_id)
            rendered = s.scalar(select(Capture).where(Capture.artifact_id == artifact_id,
                                                      Capture.kind == "rendered_html")
                                .order_by(Capture.id.desc()).limit(1))
        store = self.app.raw_store
        data = store.read_bytes(art.sha256)
        rendered_bytes = store.read_bytes(rendered.sha256) if rendered else None
        doc = await asyncio.to_thread(
            parse_artifact, data, art.mime, art.final_url or art.url,
            (art.capture_meta or {}).get("extra", {}).get("charset"), rendered_bytes,
            self.app.settings.extraction.min_text_chars,
        )
        media_meta: dict = {}
        if doc is None and self.app.settings.media.ocr:
            doc, media_meta = await self._ocr(art, data)
        if media_meta.get("exif", {}).get("gps") or media_meta.get("exif", {}).get("Make"):
            with self.Session() as s, s.begin():
                # where/when/which camera is a lead (and can identify people): a human looks
                s.add(ReviewItem(investigation_id=self.inv_id, kind="media_metadata",
                                 reason="image carries EXIF metadata"
                                        + (" with a GPS position" if media_meta["exif"].get("gps")
                                           else ""),
                                 payload={"artifact_id": artifact_id, **media_meta},
                                 created_by="media:exif"))
        if doc is None:
            return {"document": None, "reason": "no extractable text", **media_meta}
        with self.Session() as s, s.begin():
            existing = s.scalar(select(Document).where(Document.artifact_id == artifact_id,
                                                       Document.text_sha256 == doc.text_sha256))
            if existing is None:
                existing = Document(artifact_id=artifact_id, extractor=doc.parser, text=doc.text,
                                    text_sha256=doc.text_sha256, title=doc.title, lang=doc.lang,
                                    published_at=doc.published_at, meta=doc.meta)
                s.add(existing)
                s.flush()
                custody.append(s, "parsed", doc.parser, artifact_id,
                               {"document_id": existing.id, "text_sha256": doc.text_sha256,
                                "chars": len(doc.text)})
            add_ref(s, self.inv_id, "document", existing.id, doc.parser)
            enough = len(doc.text) >= self.app.settings.extraction.min_text_chars
            if enough:
                queue.enqueue(s, TaskSpec(investigation_id=self.inv_id, type="extract",
                                          plugin="extract",
                                          params={"document_id": existing.id}, priority=80))
            return {"document": existing.id, "chars": len(doc.text), "extract": enough}

    async def _ocr(self, art: Artifact, data: bytes):
        """Images and scanned PDFs: EXIF + OCR with the vision model. (doc|None, meta)"""
        from osint.evidence.parse import PARSER_VERSION, ParsedDoc, needs_ocr
        from osint.media import image

        kind = needs_ocr(art.mime, data)
        if kind is None:
            return None, {}
        meta: dict = {}
        if kind == "image":
            meta["exif"] = await asyncio.to_thread(image.exif, data)
            png = await asyncio.to_thread(image.to_png_for_vision, data)
            pages = [png] if png else []
        else:
            pages = await asyncio.to_thread(image.pdf_pages_png, data,
                                            self.app.settings.media.max_ocr_pages)
        if not pages:
            return None, meta
        role = self.app.settings.media.ocr_role
        try:
            text, starts, lang = await image.ocr_images(self.services["llm"], role, pages)
        except Exception as e:  # noqa: BLE001 - no vision model: keep the metadata
            log.warning("OCR failed for artifact %s: %s", art.id, e)
            return None, {**meta, "ocr_error": str(e)[:300]}
        if not text:
            return None, {**meta, "ocr": "no text"}
        model = self.services["llm"].role(role).model
        doc = ParsedDoc(text=text, parser=f"ocr:{PARSER_VERSION}/{model}", lang=lang,
                        meta={"ocr": image.ocr_meta(model, len(pages)), "page_starts": starts,
                              **({"exif": meta["exif"]} if meta.get("exif") else {})})
        return doc, meta

    async def _extract(self, task: Task) -> dict:
        doc_id = int(task.params["document_id"])
        with self.Session() as s:
            doc = s.get(Document, doc_id)
            art = s.get(Artifact, doc.artifact_id)
            url = art.final_url or art.url
        cfg = self.app.settings.extraction
        chunks = chunk_text(doc.text, cfg.chunk_chars, cfg.chunk_overlap,
                            cfg.max_chunks_per_document)
        extractors = [self.app.registry.create("extractor", n) for n in cfg.extractors]
        ctx = self.ctx
        if task.params.get("role"):  # e.g. reextract with agent_heavy
            ctx.settings = ctx.settings.model_copy(deep=True)
            ctx.settings.extraction.llm_role = task.params["role"]
        results: list[tuple[int, ExtractionResult, str]] = []
        relevant_chunks = 0
        # Per-chunk checkpoint: a resumed task continues from the next chunk. Valid only for
        # the same text, extractors and model role.
        key = {"text_sha256": doc.text_sha256, "extractors": [e.ident for e in extractors],
               "role": ctx.settings.extraction.llm_role}
        cp = task.checkpoint or {}
        done: set[int] = set()
        if cp.get("key") == key:
            for r in cp.get("results", []):
                results.append((r["offset"], ExtractionResult.model_validate(r["result"]),
                                r["extractor"]))
            done = set(cp.get("done_offsets", []))
            relevant_chunks = int(cp.get("relevant_chunks", 0))
        for offset, chunk in chunks:
            if offset in done:
                continue
            view = DocumentView(id=doc.id, artifact_id=doc.artifact_id, text=chunk,
                                title=doc.title, url=url, lang=doc.lang,
                                published_at=doc.published_at,
                                investigation_focus=self.focus, chunk_offset=offset)
            chunk_relevant = True
            for ex in extractors:
                if not chunk_relevant:
                    break
                res = await ex.extract(view, ctx)
                res.extractor = ex.ident
                results.append((offset, res, ex.ident))
                if not res.relevant:
                    chunk_relevant = False  # skip the remaining extractors for this chunk
            relevant_chunks += int(chunk_relevant)
            done.add(offset)
            with self.Session() as s, s.begin():
                queue.heartbeat(s, task.id, checkpoint={
                    "key": key, "done_offsets": sorted(done), "relevant_chunks": relevant_chunks,
                    "results": [{"offset": o, "extractor": x, "result": r.model_dump(mode="json")}
                                for o, r, x in results]})

        with self.Session() as s, s.begin():
            doc = s.get(Document, doc_id)
            idents = ",".join(e.ident for e in extractors)
            writer = ExtractionWriter(s, ctx.ontology, self.inv_id, doc, actor=idents)
            for offset, res, _ in results:
                writer.write(res, chunk_start=offset)
            writer.finish(idents)
            self._drain_usage(s, task.id, idents)
        st = writer.stats.as_dict()
        st["chunks"] = len(chunks)
        st["relevant_chunks"] = relevant_chunks
        return st

    def _drain_usage(self, s, task_id: int, agent: str) -> None:
        llm = self.services.get("llm")
        if llm is None:
            return
        for u in llm.drain_usage(task_id):
            s.add(RunLog(task_id=task_id, agent=agent, model=u.model, prompt_hash=u.prompt_hash,
                         input_tokens=u.input_tokens, output_tokens=u.output_tokens,
                         duration_ms=u.duration_ms))


def _fmt(result: dict) -> str:
    keep = {k: v for k, v in result.items() if v not in (0, None, False, "") and k != "relevant"}
    return " ".join(f"{k}={v}" for k, v in keep.items())

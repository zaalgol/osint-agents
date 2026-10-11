"""Local LLM client with schema-constrained JSON output.

Backends:
  * ollama: the native /api/chat with ``format=<json schema>``, which constrains
    decoding to the schema. ``think=false`` turns off Qwen3 thinking, and num_ctx is
    set per role.
  * openai: any OpenAI-compatible server (llama.cpp, vLLM) using
    response_format=json_schema.

Every call is validated with pydantic. On invalid output, the model gets one retry with
the validation error. Calls are limited by a semaphore (llm_slots) and logged to run_log.

One chat model at a time (``exclusive``): the 14B extraction model and the 27B vision
model don't fit in 16 GB of VRAM together, and Ollama then spills the second one into
system RAM (10+ GB). A call for another model waits until the current model's calls
have finished, then the current model is unloaded before the next one loads. While a
switch is waiting, no new calls for the current model are admitted, so neither side
starves. The runner batches work per model so switches stay rare.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from osint.core.config import LocalModels, LocalRole

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)

TOO_LONG = ("Your previous answer was cut off at the output limit. Answer again, more "
            "selectively: only the most important items (at most 25 entities, 15 relations, "
            "15 events), each quote under 200 characters, and never repeat an item.")

# Set by the orchestrator per task, so usage from concurrent tasks is attributed correctly.
usage_tag: ContextVar[int | None] = ContextVar("llm_usage_tag", default=None)


class LLMError(RuntimeError):
    pass


@dataclass
class LLMUsage:
    model: str
    prompt_hash: str
    input_tokens: int | None
    output_tokens: int | None
    duration_ms: int
    tag: int | None = None


class LocalLLM:
    def __init__(self, cfg: LocalModels, slots: int = 2, timeout_s: float = 600,
                 transport: httpx.AsyncBaseTransport | None = None,
                 exclusive: bool | None = None):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(slots)
        self.exclusive = cfg.exclusive if exclusive is None else exclusive
        self._gate = asyncio.Condition()
        self.current: str | None = None       # the chat model whose calls may run now
        self._inflight = 0
        self._waiting: Counter[str] = Counter()
        self._admit = 0                       # waiters admitted with the current batch
        self.switches = 0
        self._paused = 0                      # >0 while drained() holds new calls back
        self._client = httpx.AsyncClient(timeout=timeout_s, transport=transport)
        self._think_unsupported: set[str] = set()
        self.usage_log: list[LLMUsage] = []   # drained by the orchestrator into run_log

    def role(self, name: str) -> LocalRole:
        try:
            return self.cfg.roles[name]
        except KeyError:
            raise LLMError(f"no local model role {name!r} in models.yaml") from None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def unload_all(self) -> list[str]:
        """Ask Ollama to unload every model of our roles (frees its runner's RAM; the next
        request reloads it). In-flight requests finish first."""
        if self.cfg.backend != "ollama":
            return []
        base = self.cfg.base_url.removesuffix("/v1")
        done = []
        for r in {r.model for r in self.cfg.roles.values()}:
            try:
                resp = await self._client.post(f"{base}/api/generate",
                                               json={"model": r, "keep_alive": 0})
                if resp.status_code == 200:
                    done.append(r)
            except httpx.HTTPError:
                continue
        return done

    async def drained(self, action):
        """Run `action` (sync or async) with no chat call in flight and none admitted until
        it returns: used to restart Ollama's runner process without breaking a request."""
        async with self._gate:
            self._paused += 1
            try:
                await self._gate.wait_for(lambda: self._inflight == 0)
                result = action()
                if asyncio.iscoroutine(result):
                    result = await result
                self.current = None              # the next call loads its model fresh
                return result
            finally:
                self._paused -= 1
                self._gate.notify_all()

    async def _unload(self, model: str) -> None:
        if self.cfg.backend != "ollama":
            return
        base = self.cfg.base_url.removesuffix("/v1")
        try:
            await self._client.post(f"{base}/api/generate", json={"model": model, "keep_alive": 0})
        except httpx.HTTPError:
            log.info("could not unload %s before switching models", model)

    async def _enter(self, model: str) -> None:
        async with self._gate:
            await self._gate.wait_for(lambda: not self._paused)
            if not self.exclusive:
                self._inflight += 1
                return
            self._waiting[model] += 1
            try:
                while True:
                    if self._paused:
                        await self._gate.wait()
                        continue
                    others = any(m != model for m in self._waiting)
                    if self.current is None:
                        break                          # idle: anyone may start
                    if self.current == model and (not others or self._admit > 0):
                        if others:
                            self._admit -= 1           # admitted with the batch at switch time
                        break                          # join the running batch
                    if self.current != model and self._inflight == 0:
                        break                          # batch drained: switch to us
                    await self._gate.wait()
            finally:
                self._waiting[model] -= 1
                if not self._waiting[model]:
                    del self._waiting[model]
            if self.current != model:
                if self.current is not None:
                    await self._unload(self.current)   # free VRAM/RAM before the next loads
                    self.switches += 1
                # everyone already waiting for this model comes along; later arrivals wait
                # their turn if another model is waiting, so neither side starves
                self._admit = self._waiting.get(model, 0)
                self.current = model
                self._gate.notify_all()
            self._inflight += 1

    async def _leave(self) -> None:
        async with self._gate:
            self._inflight -= 1
            self._gate.notify_all()

    def drain_usage(self, tag: int | None) -> list[LLMUsage]:
        mine = [u for u in self.usage_log if u.tag == tag]
        self.usage_log = [u for u in self.usage_log if u.tag != tag]
        return mine

    async def chat_json(self, role: str, system: str, user: str, schema: type[T],
                        images: list[bytes] | None = None) -> T:
        """Structured chat. `images` (PNG/JPEG bytes) need a vision-capable model."""
        import base64

        r = self.role(role)
        first: dict = {"role": "user", "content": user}
        if images:
            first["images"] = [base64.b64encode(b).decode("ascii") for b in images]
        messages = [{"role": "system", "content": system}, first]
        last_err: Exception | None = None
        for attempt in range(2):
            raw, truncated = await self._chat(r, messages, schema)
            if truncated:
                # hit max_output_tokens (often a repetition loop): ask again, more selectively;
                # the cut-off answer is not sent back (long and useless)
                last_err = LLMError("output exceeded max_output_tokens")
                log.info("LLM output truncated at the token cap (attempt %d)", attempt + 1)
                messages = messages[:2] + [{"role": "user", "content": TOO_LONG}]
                continue
            try:
                return schema.model_validate_json(raw)
            except ValidationError as e:
                last_err = e
                log.info("LLM output failed validation (attempt %d): %s", attempt + 1, e)
                messages += [
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": "Your JSON did not validate:\n"
                     f"{str(e)[:2000]}\nReturn corrected JSON only."},
                ]
        raise LLMError(f"invalid structured output after retry: {last_err}")

    async def embed(self, texts: list[str], role: str = "embedding") -> list[list[float]]:
        r = self.role(role)
        base = self.cfg.base_url.removesuffix("/v1")
        async with self._sem:
            resp = await self._client.post(f"{base}/api/embed",
                                           json={"model": r.model, "input": texts})
        resp.raise_for_status()
        return resp.json()["embeddings"]

    # ------------------------------------------------------------------ backends

    async def _chat(self, r: LocalRole, messages: list[dict],
                    schema: type[BaseModel]) -> tuple[str, bool]:
        prompt_hash = hashlib.sha256(
            json.dumps(messages, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        t0 = time.monotonic()
        await self._enter(r.model)            # before the semaphore: a waiter holds no slot
        try:
            async with self._sem:
                if self.cfg.backend == "ollama":
                    content, tin, tout, truncated = await self._ollama(r, messages, schema)
                else:
                    content, tin, tout, truncated = await self._openai(r, messages, schema)
        finally:
            await self._leave()
        self.usage_log.append(LLMUsage(r.model, prompt_hash, tin, tout,
                                       int((time.monotonic() - t0) * 1000), usage_tag.get()))
        return content, truncated

    async def _ollama(self, r: LocalRole, messages, schema
                      ) -> tuple[str, int | None, int | None, bool]:
        base = self.cfg.base_url.removesuffix("/v1")
        body = {
            "model": r.model,
            "messages": messages,
            "stream": False,
            "format": schema.model_json_schema(),
            "options": {k: v for k, v in
                        {"num_ctx": r.context, "temperature": r.temperature,
                         "num_predict": r.max_output_tokens}.items()
                        if v is not None},
        }
        if r.model not in self._think_unsupported:
            body["think"] = False
        if r.keep_alive is not None:
            body["keep_alive"] = r.keep_alive
        resp = await self._client.post(f"{base}/api/chat", json=body)
        if resp.status_code == 400 and "think" in resp.text.lower() and "think" in body:
            self._think_unsupported.add(r.model)  # older templates reject the flag
            body.pop("think")
            resp = await self._client.post(f"{base}/api/chat", json=body)
        if resp.status_code != 200:
            raise LLMError(f"ollama {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        return (data["message"]["content"], data.get("prompt_eval_count"),
                data.get("eval_count"), data.get("done_reason") == "length")

    async def _openai(self, r: LocalRole, messages, schema
                      ) -> tuple[str, int | None, int | None, bool]:
        def openai_message(m: dict) -> dict:
            if not m.get("images"):
                return m
            parts = [{"type": "text", "text": m["content"]}] + [
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b}"}}
                for b in m["images"]]
            return {"role": m["role"], "content": parts}

        body = {
            "model": r.model,
            "messages": [openai_message(m) for m in messages],
            "temperature": r.temperature if r.temperature is not None else 0.2,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema()},
            },
        }
        resp = await self._client.post(
            f"{self.cfg.base_url}/chat/completions", json=body,
            headers={"Authorization": f"Bearer {self.cfg.api_key}"},
        )
        if resp.status_code != 200:
            raise LLMError(f"openai-compatible {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        usage = data.get("usage") or {}
        choice = data["choices"][0]
        return (choice["message"]["content"], usage.get("prompt_tokens"),
                usage.get("completion_tokens"), choice.get("finish_reason") == "length")

"""Local LLM client with schema-constrained JSON output.

Backends:
  * ollama: the native /api/chat with ``format=<json schema>``, which constrains
    decoding to the schema. ``think=false`` turns off Qwen3 thinking, and num_ctx is
    set per role.
  * openai: any OpenAI-compatible server (llama.cpp, vLLM) using
    response_format=json_schema.

Every call is validated with pydantic. On invalid output, the model gets one retry with
the validation error. Calls are limited by a semaphore (llm_slots) and logged to run_log.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from osint.core.config import LocalModels, LocalRole

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)

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
                 transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(slots)
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

    def drain_usage(self, tag: int | None) -> list[LLMUsage]:
        mine = [u for u in self.usage_log if u.tag == tag]
        self.usage_log = [u for u in self.usage_log if u.tag != tag]
        return mine

    async def chat_json(self, role: str, system: str, user: str, schema: type[T]) -> T:
        r = self.role(role)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        last_err: Exception | None = None
        for attempt in range(2):
            raw = await self._chat(r, messages, schema)
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

    async def _chat(self, r: LocalRole, messages: list[dict], schema: type[BaseModel]) -> str:
        prompt_hash = hashlib.sha256(
            json.dumps(messages, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        t0 = time.monotonic()
        async with self._sem:
            if self.cfg.backend == "ollama":
                content, tin, tout = await self._ollama(r, messages, schema)
            else:
                content, tin, tout = await self._openai(r, messages, schema)
        self.usage_log.append(LLMUsage(r.model, prompt_hash, tin, tout,
                                       int((time.monotonic() - t0) * 1000), usage_tag.get()))
        return content

    async def _ollama(self, r: LocalRole, messages, schema) -> tuple[str, int | None, int | None]:
        base = self.cfg.base_url.removesuffix("/v1")
        body = {
            "model": r.model,
            "messages": messages,
            "stream": False,
            "format": schema.model_json_schema(),
            "options": {k: v for k, v in
                        {"num_ctx": r.context, "temperature": r.temperature}.items()
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
                data.get("eval_count"))

    async def _openai(self, r: LocalRole, messages, schema) -> tuple[str, int | None, int | None]:
        body = {
            "model": r.model,
            "messages": messages,
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
        return (data["choices"][0]["message"]["content"], usage.get("prompt_tokens"),
                usage.get("completion_tokens"))

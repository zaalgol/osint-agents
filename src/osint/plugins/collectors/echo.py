"""Reference collector: turns given text into evidence artifacts.

It's a minimal working example of the Collector contract, used by tests and as a template
for real collectors. It is also useful for manually adding material (pasted text, notes)
into an investigation with full provenance.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from pydantic import BaseModel, Field

from osint.core.context import PluginContext
from osint.core.models import CapturedItem, CaptureMeta
from osint.core.plugins import Collector


class EchoParams(BaseModel):
    items: list[str] = Field(min_length=1)
    url_prefix: str = "manual://echo/"


class EchoCollector(Collector):
    name = "echo"
    description = "Ingest provided text items as artifacts (reference implementation)."
    params_schema = EchoParams

    def __init__(self) -> None:
        self._cursor = 0

    async def collect(self, params: EchoParams, ctx: PluginContext) -> AsyncIterator[CapturedItem]:
        # The cursor advances only after the consumer comes back for the next item,
        # i.e. after it has persisted the previous one: at-least-once delivery.
        for i in range(self._cursor, len(params.items)):
            yield CapturedItem(
                data=params.items[i].encode("utf-8"),
                meta=CaptureMeta(url=f"{params.url_prefix}{i}", collector=self.ident),
                mime="text/plain",
            )
            self._cursor = i + 1

    def checkpoint(self) -> dict[str, Any]:
        return {"cursor": self._cursor}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        self._cursor = int(checkpoint.get("cursor", 0))

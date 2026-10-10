"""GLiNER zero-shot NER (multilingual): fast, high-recall entity mentions on CPU.

It finds entities only (no relations or events), and its spans come straight from the
text, so quotes always verify. Install with ``uv sync --extra ner`` and enable via
settings.extraction.extractors: [llm, gliner].
"""

from __future__ import annotations

import asyncio
from typing import ClassVar

from osint.core.context import PluginContext
from osint.core.models import DocumentView, ExtractedEntity, ExtractionResult
from osint.core.plugins import Extractor

MODEL = "urchade/gliner_multi-v2.1"
WINDOW = 1500   # chars per GLiNER pass (the model has a ~384-token limit)
SKIP_TYPES = {"url", "document", "media_file"}


class GlinerExtractor(Extractor):
    name = "gliner"
    version = "0.1.0"
    description = "GLiNER multilingual zero-shot NER (entities only, exact spans)."
    threshold: ClassVar[float] = 0.5
    _model = None
    _lock = asyncio.Lock()

    async def _load(self):
        async with GlinerExtractor._lock:
            if GlinerExtractor._model is None:
                from gliner import GLiNER

                GlinerExtractor._model = await asyncio.to_thread(GLiNER.from_pretrained, MODEL)
        return GlinerExtractor._model

    async def extract(self, document: DocumentView, ctx: PluginContext) -> ExtractionResult:
        model = await self._load()
        labels = {t.replace("_", " "): t for t in ctx.ontology.entity_types if t not in SKIP_TYPES}
        text = document.text

        def run() -> list[dict]:
            found = []
            for start in range(0, len(text), WINDOW - 200):
                window = text[start:start + WINDOW]
                found.extend(model.predict_entities(window, list(labels),
                                                    threshold=self.threshold))
            return found

        ents = await asyncio.to_thread(run)
        seen, out = set(), []
        for e in ents:
            key = (e["text"], e["label"])
            if key in seen:
                continue
            seen.add(key)
            out.append(ExtractedEntity(name=e["text"], type=labels[e["label"]], quote=e["text"]))
        return ExtractionResult(relevant=True, entities=out)

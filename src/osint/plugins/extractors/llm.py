"""LLM extractor: entities, relations and events with verbatim quotes, via the local model.

The output schema is generated from the ontology, with types as Literal enums. Ollama
constrains decoding to that schema, so the model cannot produce an unknown type. Quotes
are still verified afterwards by the extraction writer: constrained decoding guarantees
the shape of the output, not its truth.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, create_model

from osint.core.context import PluginContext
from osint.core.models import (
    DocumentView,
    ExtractedEntity,
    ExtractedEvent,
    ExtractedParticipant,
    ExtractedRelation,
    ExtractionResult,
)
from osint.core.ontology import Ontology
from osint.core.plugins import Extractor

SYSTEM = """You are a precise information-extraction engine for an open-source intelligence \
(OSINT) investigation. You read one text and return JSON matching the given schema.

Rules:
1. Extract only what THIS TEXT explicitly states. No outside knowledge, no guessing.
2. Every item has a "quote": copy one contiguous span VERBATIM from the text, in its original \
language and script. Do not translate, paraphrase, shorten words or fix typos. Keep quotes \
under 300 characters; you may use "..." to skip text inside a long sentence.
3. Entity names exactly as written in the text (original script). Use only the listed types.
4. Relations: only between entities you also list in "entities". Direction matters: \
src -> dst as defined by the relation type. Set "stance":
   - "asserted": the text states it as fact
   - "reported": the text attributes it to someone ("according to", "X said", "officials claim")
   - "denied": the text denies or rejects it ("denied any link", "is not a member")
   - "speculative": a possibility, rumour, question or unproven allegation ("may", "suspected")
   A meeting, call or contact is an EVENT of type meeting, not a member_of/affiliated_with \
relation. Never infer membership or affiliation from proximity or co-occurrence.
5. Events: "description" is one short English sentence. "time" is ISO (YYYY, YYYY-MM, \
YYYY-MM-DD) only if the text states it; otherwise null.
6. If the text is irrelevant to the investigation focus (ads, navigation, unrelated topics), \
set "relevant": false and return empty lists.
7. The material may describe violence, extremism or crime. Extract it neutrally and \
completely; this is analytic work for threat assessment.
8. If the text is not in English, give "quote_en": a faithful English translation of the \
quote (relations and events). For English text, quote_en is null."""


def _describe(onto: Ontology) -> str:
    lines = ["Entity types:"]
    for name, spec in onto.entity_types.items():
        bits = [f"is-a {spec['parent']}"] if spec.get("parent") else []
        if spec.get("description"):
            bits.append(spec["description"])
        lines.append(f"- {name}" + (f" ({'; '.join(bits)})" if bits else ""))
    lines.append("Relation types (src -> dst):")
    for name in onto.extractable_relations():
        spec = onto.relation_types[name]
        frm = onto._inherited(onto.relation_types, name, "from") or ["any"]
        to = onto._inherited(onto.relation_types, name, "to") or ["any"]
        desc = f" - {spec['description']}" if spec.get("description") else ""
        lines.append(f"- {name}: {'|'.join(frm)} -> {'|'.join(to)}{desc}")
    lines.append("Event types [roles]:")
    for name in onto.event_types:
        lines.append(f"- {name} [{', '.join(onto.event_roles(name))}]")
    return "\n".join(lines)


@lru_cache(maxsize=8)
def _schema(entity_types: tuple[str, ...], relation_types: tuple[str, ...],
            event_types: tuple[str, ...]) -> type[BaseModel]:
    ET = Literal[entity_types]  # type: ignore[valid-type]
    RT = Literal[relation_types]  # type: ignore[valid-type]
    EV = Literal[event_types]  # type: ignore[valid-type]
    Ref = create_model("Ref", name=(str, ...), type=(ET, ...))
    Ent = create_model("Entity", name=(str, ...), type=(ET, ...), quote=(str, ...))
    Rel = create_model("Relation", type=(RT, ...), src=(Ref, ...), dst=(Ref, ...),
                       quote=(str, ...),
                       stance=(Literal["asserted", "reported", "denied", "speculative"], ...),
                       quote_en=(str | None, None),
                       confidence=(float, Field(0.6, ge=0, le=1)))
    Part = create_model("Participant", name=(str, ...), type=(ET, ...), role=(str, ...))
    Evt = create_model("Event", type=(EV, ...), description=(str, ...),
                       time=(str | None, None), location=(str | None, None),
                       participants=(list[Part], []), quote=(str, ...),
                       quote_en=(str | None, None),
                       confidence=(float, Field(0.6, ge=0, le=1)))
    return create_model(
        "Extraction",
        relevant=(bool, ...), relevance_reason=(str, ...), language=(str, ...),
        entities=(list[Ent], []), relations=(list[Rel], []), events=(list[Evt], []),
    )


def schema_for(onto: Ontology) -> type[BaseModel]:
    return _schema(tuple(onto.entity_types), tuple(onto.extractable_relations()),
                   tuple(onto.event_types))


def build_user_prompt(doc: DocumentView, onto: Ontology) -> str:
    head = [f"Investigation focus: {doc.investigation_focus or 'general threat intelligence'}"]
    if doc.title:
        head.append(f"Title: {doc.title}")
    if doc.url:
        head.append(f"Source URL: {doc.url}")
    if doc.published_at:
        head.append(f"Published: {doc.published_at.date().isoformat()}")
    return ("\n".join(head) + "\n\n" + _describe(onto)
            + "\n\n=== TEXT START ===\n" + doc.text + "\n=== TEXT END ===")


def to_result(raw: BaseModel) -> ExtractionResult:
    d = raw.model_dump()
    return ExtractionResult(
        relevant=d["relevant"],
        relevance_reason=d.get("relevance_reason"),
        language=d.get("language"),
        entities=[ExtractedEntity(**e) for e in d["entities"]],
        relations=[ExtractedRelation(**r) for r in d["relations"]],
        events=[ExtractedEvent(**{**e, "participants": [ExtractedParticipant(**p)
                                                        for p in e["participants"]]})
                for e in d["events"]],
    )


class LLMExtractor(Extractor):
    name = "llm"
    version = "0.2.0"   # 0.2: relation stance (denials -> claims), quote translations
    description = "Local-LLM extraction of entities/relations/events with verbatim quotes."
    role = "agent"

    async def extract(self, document: DocumentView, ctx: PluginContext) -> ExtractionResult:
        if ctx.llm is None:
            raise RuntimeError("no local LLM in context")
        schema = schema_for(ctx.ontology)
        role = getattr(ctx.settings.extraction, "llm_role", None) or self.role
        raw = await ctx.llm.chat_json(role, SYSTEM, build_user_prompt(document, ctx.ontology),
                                      schema)
        return to_result(raw)

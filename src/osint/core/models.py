"""Domain models (pydantic). These are the typed contracts between plugins, agents,
storage and Claude's MCP tools. Persistence lives in osint.storage.db.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


class EpistemicStatus(StrEnum):
    OBSERVED = "observed"    # directly visible in evidence
    REPORTED = "reported"    # a source says so
    INFERRED = "inferred"    # derived from other facts (needs a proof tree)
    ASSESSED = "assessed"    # analytic judgement (needs a proof tree)


class SourceReliability(StrEnum):
    A = "A"  # completely reliable
    B = "B"  # usually reliable
    C = "C"  # fairly reliable
    D = "D"  # not usually reliable
    E = "E"  # unreliable
    F = "F"  # reliability cannot be judged


class InformationCredibility(StrEnum):
    CONFIRMED = "1"
    PROBABLY_TRUE = "2"
    POSSIBLY_TRUE = "3"
    DOUBTFUL = "4"
    IMPROBABLE = "5"
    CANNOT_BE_JUDGED = "6"


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    BLOCKED = "blocked"


class CaptureKind(StrEnum):
    RAW = "raw"
    WARC = "warc"
    SCREENSHOT_PNG = "screenshot_png"
    PDF_RENDER = "pdf_render"
    MEDIA_ORIGINAL = "media_original"
    ARCHIVE_ORG = "archive_org"


class TargetType(StrEnum):
    """Objects that can be cited (evidence_link.target_type) or concluded (inference)."""

    RELATION = "relation"
    EVENT = "event"
    CLAIM = "claim"
    FINDING = "finding"
    CROSS_LINK = "cross_link"


class PremiseType(StrEnum):
    EVIDENCE = "evidence"
    CLAIM = "claim"
    RELATION = "relation"
    EVENT = "event"
    FINDING = "finding"


# --------------------------------------------------------------------------- evidence


class BlobRef(BaseModel):
    """A file in the content-addressed raw store."""

    sha256: str
    sha512: str
    size: int
    path: str  # relative to data_dir


class CaptureMeta(BaseModel):
    url: str | None = None
    final_url: str | None = None
    http_status: int | None = None
    resolved_ip: str | None = None
    user_agent: str | None = None
    proxy: str | None = None
    collector: str | None = None          # plugin@version
    platform: str | None = None
    platform_id: str | None = None         # e.g. telegram channel/message id
    posted_at: datetime | None = None      # platform time, distinct from fetched_at
    extra: dict[str, Any] = Field(default_factory=dict)


class Citation(BaseModel):
    """Pointer to an exact location in preserved evidence (maps to evidence_link)."""

    artifact_id: int
    document_id: int | None = None
    quote_original: str | None = None
    quote_translated: str | None = None
    translator: str | None = None          # model@version for translated quotes
    char_start: int | None = None
    char_end: int | None = None
    media_locator: str | None = None       # "p.4", "00:03:12", "bbox:x,y,w,h"

    @model_validator(mode="after")
    def _locatable(self) -> Citation:
        if not (self.quote_original or self.media_locator):
            raise ValueError("citation needs a verbatim quote or a media locator")
        if (self.char_start is None) != (self.char_end is None):
            raise ValueError("char_start and char_end must be given together")
        if self.char_start is not None and self.char_end < self.char_start:  # type: ignore[operator]
            raise ValueError("char_end < char_start")
        return self


# --------------------------------------------------------------------------- knowledge


class Investigation(BaseModel):
    id: int | None = None
    name: str
    seed: dict[str, Any] = Field(default_factory=dict)
    playbook: str | None = None
    status: str = "active"
    parent_id: int | None = None


class EntityIn(BaseModel):
    type: str
    canonical_name: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    aliases: list[str] = Field(default_factory=list)
    confidence: float = Field(0.5, ge=0, le=1)


class RelationIn(BaseModel):
    type: str
    src_entity_id: int
    dst_entity_id: int
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(0.5, ge=0, le=1)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    citations: list[Citation] = Field(min_length=1)


class EventIn(BaseModel):
    type: str
    time: datetime | None = None
    time_precision: str | None = None      # year|month|day|hour|exact
    location_entity_id: int | None = None
    description: str
    participants: dict[str, list[int]] = Field(default_factory=dict)  # role -> entity ids
    confidence: float = Field(0.5, ge=0, le=1)
    citations: list[Citation] = Field(min_length=1)


class FindingIn(BaseModel):
    investigation_id: int
    kind: str
    text: str
    confidence: float = Field(ge=0, le=1)
    epistemic_status: EpistemicStatus
    created_by: str                        # agent name | claude:<job> | human:<name>
    citations: list[Citation] = Field(default_factory=list)
    premises: list[tuple[PremiseType, int]] = Field(default_factory=list)
    method: str | None = None              # how premises lead to the conclusion

    @model_validator(mode="after")
    def _provable(self) -> FindingIn:
        if not self.citations and not self.premises:
            raise ValueError("a finding needs citations or premises (no claim without proof)")
        if self.epistemic_status in (EpistemicStatus.INFERRED, EpistemicStatus.ASSESSED):
            if not self.premises:
                raise ValueError(f"{self.epistemic_status} findings need a proof tree (premises)")
            if not self.method:
                raise ValueError("inferred/assessed findings must state their method")
        return self


class TaskSpec(BaseModel):
    investigation_id: int
    type: str                              # collect|parse|extract|enrich|analyze|...
    plugin: str
    params: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[int] = Field(default_factory=list)
    priority: int = 100                    # lower runs first


# --------------------------------------------------------------------------- collector output


class ExtraCapture(BaseModel):
    """An additional file in a capture bundle (WARC, screenshot, PDF render, ...)."""

    kind: CaptureKind | str
    data: bytes
    mime: str | None = None


class CapturedItem(BaseModel):
    """A collector yields these: the raw content plus its proof bundle."""

    data: bytes
    meta: CaptureMeta
    mime: str | None = None
    extra_captures: list[ExtraCapture] = Field(default_factory=list)
    parse: bool = True                     # False for search-result JSON, feed XML, ...


class FollowUp(BaseModel):
    """A collector asks the orchestrator to schedule more work (e.g. fetch a found URL)."""

    type: str = "collect"
    plugin: str
    params: dict[str, Any]
    priority: int = 100


# --------------------------------------------------------------------------- extractor output
# Extractors return *claims about text*, each with a verbatim quote. The extraction
# writer (osint.extraction.writer) verifies every quote against the document, resolves
# entities and writes everything with citations. Extractors never touch the DB.


class EntityRef(BaseModel):
    name: str = Field(description="Name exactly as written in the text")
    type: str = Field(description="Entity type from the ontology")


class ExtractedEntity(EntityRef):
    quote: str = Field(description="Verbatim span from the text that mentions the entity")
    attributes: dict[str, str] = Field(default_factory=dict)


Stance = Literal["asserted", "reported", "denied", "speculative"]


class ExtractedRelation(BaseModel):
    type: str
    src: EntityRef
    dst: EntityRef
    quote: str = Field(description="Verbatim sentence from the text stating the relation")
    confidence: float = Field(0.5, ge=0, le=1)
    # asserted/reported -> relation; denied/speculative -> claim (kept out of the graph)
    stance: Stance = "asserted"
    quote_en: str | None = None             # English translation (non-English sources)


class ExtractedParticipant(EntityRef):
    role: str


class ExtractedEvent(BaseModel):
    type: str
    description: str = Field(description="One-sentence English description")
    time: str | None = Field(None, description="ISO date: YYYY, YYYY-MM, YYYY-MM-DD or full")
    location: str | None = None
    participants: list[ExtractedParticipant] = Field(default_factory=list)
    quote: str = Field(description="Verbatim sentence from the text describing the event")
    confidence: float = Field(0.5, ge=0, le=1)
    quote_en: str | None = None


class DocumentView(BaseModel):
    """What an extractor sees: the document plus the investigation's focus."""

    id: int
    artifact_id: int
    text: str
    title: str | None = None
    url: str | None = None
    lang: str | None = None
    published_at: datetime | None = None
    investigation_focus: str | None = None   # seed description / questions
    chunk_offset: int = 0                    # text is document.text[chunk_offset:...]


class ExtractionResult(BaseModel):
    relevant: bool = True
    relevance_reason: str | None = None
    language: str | None = None
    entities: list[ExtractedEntity] = Field(default_factory=list)
    relations: list[ExtractedRelation] = Field(default_factory=list)
    events: list[ExtractedEvent] = Field(default_factory=list)
    extractor: str | None = None           # plugin ident, filled by the pipeline

"""PostgreSQL schema (SQLAlchemy 2.0 ORM): the system of record.

Design rules (plan.md sections 5 and 8):
  * Entities are global; investigations reference them (investigation_ref).
  * Raw evidence (artifact, capture) is immutable. custody_log is append-only and
    hash-chained. Both are enforced by DB triggers (see the migrations).
  * Relations, events, claims, findings and cross-links can't exist without proof:
    a deferred constraint trigger requires an evidence_link or an inference for each
    one when the transaction commits.
  * Integer IDs keep citation markers short and readable: [E:1234], [F:56].
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

EMBED_DIM = 1024  # bge-m3; keep in sync with config/models.yaml roles.embedding.dimensions

TARGET_TYPES = ("relation", "event", "claim", "finding", "cross_link")
PREMISE_TYPES = ("evidence", "claim", "relation", "event", "finding")
EPISTEMIC = ("observed", "reported", "inferred", "assessed")
CAPTURE_KINDS = ("raw", "warc", "screenshot_png", "pdf_render", "rendered_html",
                 "media_original", "archive_org")


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in values)})"


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )
    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy declarative convention
        dict[str, Any]: JSONB,
        datetime: DateTime(timezone=True),
    }


def pk() -> Mapped[int]:
    return mapped_column(BigInteger, primary_key=True, autoincrement=True)


def created() -> Mapped[datetime]:
    return mapped_column(server_default=func.now())


# =========================================================================== runs


class Investigation(Base):
    __tablename__ = "investigation"
    id: Mapped[int] = pk()
    name: Mapped[str] = mapped_column(String(300), unique=True)
    seed: Mapped[dict[str, Any]] = mapped_column(default=dict)
    playbook: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), default="active")
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("investigation.id"))
    created_at: Mapped[datetime] = created()
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Task(Base):
    __tablename__ = "task"
    __table_args__ = (
        CheckConstraint(
            _in("status", ("pending", "running", "done", "failed", "blocked")), name="status"
        ),
        UniqueConstraint("investigation_id", "type", "params_hash", name="uq_task_idempotent"),
        Index("ix_task_queue", "status", "priority", "id"),
    )
    id: Mapped[int] = pk()
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigation.id"))
    type: Mapped[str] = mapped_column(String(64))
    plugin: Mapped[str] = mapped_column(String(200))
    params: Mapped[dict[str, Any]] = mapped_column(default=dict)
    params_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    depends_on: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), default=list)
    checkpoint: Mapped[dict[str, Any]] = mapped_column(default=dict)
    result: Mapped[dict[str, Any] | None] = mapped_column()
    error: Mapped[str | None] = mapped_column(Text)
    worker: Mapped[str | None] = mapped_column(String(200))
    heartbeat_at: Mapped[datetime | None] = mapped_column()
    created_at: Mapped[datetime] = created()
    started_at: Mapped[datetime | None] = mapped_column()
    finished_at: Mapped[datetime | None] = mapped_column()


class RunLog(Base):
    __tablename__ = "run_log"
    id: Mapped[int] = pk()
    task_id: Mapped[int | None] = mapped_column(ForeignKey("task.id"))
    agent: Mapped[str] = mapped_column(String(200))
    model: Mapped[str | None] = mapped_column(String(200))
    prompt_hash: Mapped[str | None] = mapped_column(String(64))
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created()


# =========================================================================== evidence


class Source(Base):
    __tablename__ = "source"
    __table_args__ = (
        CheckConstraint(_in("reliability", tuple("ABCDEF")), name="reliability"),
        UniqueConstraint("kind", "locator", name="uq_source_kind_locator"),
    )
    id: Mapped[int] = pk()
    kind: Mapped[str] = mapped_column(String(64))          # website|telegram_channel|rss|...
    locator: Mapped[str] = mapped_column(Text)             # base URL / channel id / feed URL
    platform: Mapped[str | None] = mapped_column(String(64))
    reliability: Mapped[str] = mapped_column(String(1), default="F")
    reliability_note: Mapped[str | None] = mapped_column(Text)
    policy: Mapped[dict[str, Any]] = mapped_column(default=dict)   # ToS/rate-limit/proxy policy
    first_seen: Mapped[datetime] = created()
    last_seen: Mapped[datetime | None] = mapped_column()


class Artifact(Base):
    """One captured item (page, post, file). Immutable once written."""

    __tablename__ = "artifact"
    id: Mapped[int] = pk()
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    sha512: Mapped[str] = mapped_column(String(128))
    size: Mapped[int] = mapped_column(BigInteger)
    path: Mapped[str] = mapped_column(Text)                # relative to data_dir
    source_id: Mapped[int | None] = mapped_column(ForeignKey("source.id"))
    mime: Mapped[str | None] = mapped_column(String(200))
    lang: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(Text)
    final_url: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    platform_id: Mapped[str | None] = mapped_column(String(300), index=True)
    posted_at: Mapped[datetime | None] = mapped_column()
    fetched_at_utc: Mapped[datetime] = mapped_column()
    capture_meta: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = created()

    captures: Mapped[list[Capture]] = relationship(back_populates="artifact")


class Capture(Base):
    """A file in an artifact's capture bundle (WARC, screenshot, PDF render, ...). Immutable."""

    __tablename__ = "capture"
    __table_args__ = (
        CheckConstraint(
            _in("kind", CAPTURE_KINDS),
            name="kind",
        ),
    )
    id: Mapped[int] = pk()
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifact.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str | None] = mapped_column(String(64))  # null for external archive URLs
    sha512: Mapped[str | None] = mapped_column(String(128))
    path: Mapped[str | None] = mapped_column(Text)
    external_url: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created()

    artifact: Mapped[Artifact] = relationship(back_populates="captures")


class CustodyLog(Base):
    """Append-only, hash-chained chain of custody. See osint.evidence.custody."""

    __tablename__ = "custody_log"
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("artifact.id"), index=True)
    action: Mapped[str] = mapped_column(String(64))       # captured|parsed|translated|cited|...
    actor: Mapped[str] = mapped_column(String(200))       # plugin ident | user:<name>
    at_utc: Mapped[datetime] = mapped_column()
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)


class Manifest(Base):
    """Merkle root over a batch of capture hashes; the unit that gets timestamped and signed."""

    __tablename__ = "manifest"
    id: Mapped[int] = pk()
    merkle_root: Mapped[str] = mapped_column(String(64), unique=True)
    leaf_count: Mapped[int] = mapped_column(Integer)
    first_custody_seq: Mapped[int | None] = mapped_column(BigInteger)
    last_custody_seq: Mapped[int | None] = mapped_column(BigInteger)
    path: Mapped[str] = mapped_column(Text)                # manifest JSON file in data_dir
    signature: Mapped[str | None] = mapped_column(Text)
    signer_key_id: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class TimestampProof(Base):
    __tablename__ = "timestamp_proof"
    __table_args__ = (
        CheckConstraint(_in("method", ("rfc3161", "opentimestamps")), name="method"),
    )
    id: Mapped[int] = pk()
    manifest_id: Mapped[int] = mapped_column(ForeignKey("manifest.id"), index=True)
    method: Mapped[str] = mapped_column(String(32))
    authority: Mapped[str | None] = mapped_column(String(300))
    proof_path: Mapped[str] = mapped_column(Text)
    stamped_at: Mapped[datetime | None] = mapped_column()
    verified_at: Mapped[datetime | None] = mapped_column()
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending|complete|failed


class Document(Base):
    """Text extracted from an artifact (HTML text, OCR, transcript), with an embedding."""

    __tablename__ = "document"
    id: Mapped[int] = pk()
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifact.id"), index=True)
    extractor: Mapped[str] = mapped_column(String(200))   # plugin ident that produced the text
    title: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column()
    meta: Mapped[dict[str, Any]] = mapped_column(default=dict)
    text: Mapped[str] = mapped_column(Text)
    text_sha256: Mapped[str] = mapped_column(String(64), index=True)  # offsets refer to this text
    lang: Mapped[str | None] = mapped_column(String(16))
    translated_text: Mapped[str | None] = mapped_column(Text)
    translator: Mapped[str | None] = mapped_column(String(200))
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBED_DIM))
    origin_cluster: Mapped[int | None] = mapped_column(BigInteger, index=True)  # syndication
    created_at: Mapped[datetime] = created()


# =========================================================================== knowledge


class Entity(Base):
    __tablename__ = "entity"
    __table_args__ = (Index("ix_entity_type_name", "type", "canonical_name"),)
    id: Mapped[int] = pk()
    type: Mapped[str] = mapped_column(String(64))
    canonical_name: Mapped[str] = mapped_column(Text)
    strong_key: Mapped[str | None] = mapped_column(Text)   # normalized phone/email/wallet/...
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBED_DIM))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    merged_into_id: Mapped[int | None] = mapped_column(ForeignKey("entity.id"))
    first_seen: Mapped[datetime] = created()
    last_seen: Mapped[datetime | None] = mapped_column()


Index(
    "uq_entity_strong_key", Entity.type, Entity.strong_key, unique=True,
    postgresql_where=Entity.strong_key.isnot(None) & Entity.merged_into_id.is_(None),
)


class EntityAlias(Base):
    __tablename__ = "entity_alias"
    __table_args__ = (UniqueConstraint("entity_id", "alias", "lang", name="uq_alias"),)
    id: Mapped[int] = pk()
    entity_id: Mapped[int] = mapped_column(ForeignKey("entity.id"), index=True)
    alias: Mapped[str] = mapped_column(Text, index=True)
    alias_norm: Mapped[str | None] = mapped_column(Text, index=True)  # transliterated/folded
    alias_type: Mapped[str | None] = mapped_column(String(32))        # name|handle|kunya|...
    lang: Mapped[str | None] = mapped_column(String(16))
    source_artifact_id: Mapped[int | None] = mapped_column(ForeignKey("artifact.id"))


class EntityMerge(Base):
    """Reversible merge log for entity resolution."""

    __tablename__ = "entity_merge"
    id: Mapped[int] = pk()
    winner_id: Mapped[int] = mapped_column(ForeignKey("entity.id"))
    loser_id: Mapped[int] = mapped_column(ForeignKey("entity.id"))
    method: Mapped[str] = mapped_column(String(64))
    score: Mapped[float | None] = mapped_column(Float)
    rationale: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str] = mapped_column(String(200))
    moved: Mapped[dict[str, Any]] = mapped_column(default=dict)  # rows repointed (for undo)
    reverted_at: Mapped[datetime | None] = mapped_column()
    created_at: Mapped[datetime] = created()


class Mention(Base):
    __tablename__ = "mention"
    id: Mapped[int] = pk()
    entity_id: Mapped[int] = mapped_column(ForeignKey("entity.id"), index=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("document.id"), index=True)
    char_start: Mapped[int] = mapped_column(Integer)
    char_end: Mapped[int] = mapped_column(Integer)
    surface: Mapped[str] = mapped_column(Text)
    context: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    extractor: Mapped[str] = mapped_column(String(200))


class Relation(Base):
    __tablename__ = "relation"
    id: Mapped[int] = pk()
    type: Mapped[str] = mapped_column(String(64))
    src_entity_id: Mapped[int] = mapped_column(ForeignKey("entity.id"), index=True)
    dst_entity_id: Mapped[int] = mapped_column(ForeignKey("entity.id"), index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    valid_from: Mapped[datetime | None] = mapped_column()
    valid_to: Mapped[datetime | None] = mapped_column()
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class Event(Base):
    __tablename__ = "event"
    id: Mapped[int] = pk()
    type: Mapped[str] = mapped_column(String(64), index=True)
    time: Mapped[datetime | None] = mapped_column(index=True)
    time_precision: Mapped[str | None] = mapped_column(String(16))
    location_entity_id: Mapped[int | None] = mapped_column(ForeignKey("entity.id"))
    description: Mapped[str] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBED_DIM))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    # same real-world incident reported by several sources: cluster_id = canonical event
    cluster_id: Mapped[int | None] = mapped_column(ForeignKey("event.id"), index=True)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class EventParticipant(Base):
    __tablename__ = "event_participant"
    event_id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entity.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(64), primary_key=True)


class Claim(Base):
    """'Source S says X': a reported statement, kept separate from what we believe."""

    __tablename__ = "claim"
    __table_args__ = (
        CheckConstraint(_in("stance", ("asserts", "denies", "speculates", "quotes")), name="stance"),
        CheckConstraint(_in("credibility", tuple("123456")), name="credibility"),
    )
    id: Mapped[int] = pk()
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[int] = mapped_column(BigInteger)
    predicate: Mapped[str] = mapped_column(String(200))
    object_type: Mapped[str | None] = mapped_column(String(32))
    object_id: Mapped[int | None] = mapped_column(BigInteger)
    object_literal: Mapped[str | None] = mapped_column(Text)
    stance: Mapped[str] = mapped_column(String(16), default="asserts")
    credibility: Mapped[str] = mapped_column(String(1), default="6")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class EvidenceLink(Base):
    """A citation: a target object pointing to an exact location in preserved evidence."""

    __tablename__ = "evidence_link"
    __table_args__ = (
        CheckConstraint(_in("target_type", TARGET_TYPES), name="target_type"),
        CheckConstraint(
            "quote_original IS NOT NULL OR media_locator IS NOT NULL", name="locatable"
        ),
        CheckConstraint(
            "(char_start IS NULL AND char_end IS NULL) OR "
            "(char_start IS NOT NULL AND char_end >= char_start)",
            name="offsets",
        ),
        Index("ix_evidence_target", "target_type", "target_id"),
    )
    id: Mapped[int] = pk()
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[int] = mapped_column(BigInteger)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifact.id"), index=True)
    document_id: Mapped[int | None] = mapped_column(ForeignKey("document.id"))
    quote_original: Mapped[str | None] = mapped_column(Text)
    quote_translated: Mapped[str | None] = mapped_column(Text)
    translator: Mapped[str | None] = mapped_column(String(200))
    char_start: Mapped[int | None] = mapped_column(Integer)
    char_end: Mapped[int | None] = mapped_column(Integer)
    media_locator: Mapped[str | None] = mapped_column(String(200))
    quote_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column()
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class Inference(Base):
    """Proof-tree node: a conclusion derived from premises by a stated method."""

    __tablename__ = "inference"
    __table_args__ = (
        CheckConstraint(_in("conclusion_type", TARGET_TYPES), name="conclusion_type"),
        Index("ix_inference_conclusion", "conclusion_type", "conclusion_id"),
    )
    id: Mapped[int] = pk()
    conclusion_type: Mapped[str] = mapped_column(String(32))
    conclusion_id: Mapped[int] = mapped_column(BigInteger)
    method: Mapped[str] = mapped_column(String(200))
    rationale: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()

    premises: Mapped[list[InferencePremise]] = relationship(back_populates="inference")


class InferencePremise(Base):
    __tablename__ = "inference_premise"
    __table_args__ = (CheckConstraint(_in("premise_type", PREMISE_TYPES), name="premise_type"),)
    inference_id: Mapped[int] = mapped_column(ForeignKey("inference.id"), primary_key=True)
    premise_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    premise_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)

    inference: Mapped[Inference] = relationship(back_populates="premises")


class Corroboration(Base):
    __tablename__ = "corroboration"
    claim_id: Mapped[int] = mapped_column(ForeignKey("claim.id"), primary_key=True)
    independent_source_count: Mapped[int] = mapped_column(Integer, default=0)
    origin_cluster_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), default=list)
    contradicting_claim_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), default=list)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Finding(Base):
    __tablename__ = "finding"
    __table_args__ = (CheckConstraint(_in("epistemic_status", EPISTEMIC), name="epistemic"),)
    id: Mapped[int] = pk()
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigation.id"), index=True)
    kind: Mapped[str] = mapped_column(String(64))         # fact|hypothesis|assessment|gap|...
    text: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    epistemic_status: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class InvestigationRef(Base):
    """Which global objects belong to which investigation (scope, not ownership)."""

    __tablename__ = "investigation_ref"
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigation.id"), primary_key=True)
    object_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    object_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    relevance: Mapped[float] = mapped_column(Float, default=1.0)
    added_by: Mapped[str] = mapped_column(String(200))
    added_at: Mapped[datetime] = created()


Index("ix_investigation_ref_object", InvestigationRef.object_type, InvestigationRef.object_id)


class CrossLink(Base):
    __tablename__ = "cross_link"
    __table_args__ = (
        CheckConstraint(_in("status", ("candidate", "confirmed", "rejected")), name="status"),
        CheckConstraint(_in("tier", ("hard", "soft", "analytic")), name="tier"),
        CheckConstraint("investigation_a < investigation_b", name="ordered"),
        UniqueConstraint("investigation_a", "investigation_b", "via_type", "via_id",
                         name="uq_cross_link_via"),
    )
    id: Mapped[int] = pk()
    investigation_a: Mapped[int] = mapped_column(ForeignKey("investigation.id"))
    investigation_b: Mapped[int] = mapped_column(ForeignKey("investigation.id"))
    via_type: Mapped[str] = mapped_column(String(32))
    via_id: Mapped[int] = mapped_column(BigInteger)
    tier: Mapped[str] = mapped_column(String(16))
    score: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="candidate")
    decided_by: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class Report(Base):
    __tablename__ = "report"
    __table_args__ = (
        CheckConstraint(_in("status", ("draft", "verified", "overridden", "final")), name="status"),
    )
    id: Mapped[int] = pk()
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigation.id"), index=True)
    title: Mapped[str] = mapped_column(Text)
    markdown: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    verification: Mapped[dict[str, Any] | None] = mapped_column()  # verify-report results
    supersedes_id: Mapped[int | None] = mapped_column(ForeignKey("report.id"))
    override_by: Mapped[str | None] = mapped_column(String(200))
    override_reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class ReviewItem(Base):
    """Human-review queue: unverifiable quotes, ontology violations, resolution candidates."""

    __tablename__ = "review_item"
    __table_args__ = (
        CheckConstraint(_in("status", ("open", "accepted", "rejected")), name="status"),
        Index("ix_review_open", "status", "kind"),
    )
    id: Mapped[int] = pk()
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigation.id"))
    kind: Mapped[str] = mapped_column(String(64))   # quote_not_found|ontology|resolution_candidate
    reason: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    document_id: Mapped[int | None] = mapped_column(ForeignKey("document.id"))
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = created()


class ClaudeJob(Base):
    """Ledger of headless Claude runs: usage accounting, result cache, quota tracking."""

    __tablename__ = "claude_job"
    __table_args__ = (
        CheckConstraint(_in("status", ("running", "done", "error", "quota")), name="status"),
        Index("ix_claude_job_cache", "job", "input_hash", "status"),
    )
    id: Mapped[int] = pk()
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigation.id"))
    job: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(64))
    input_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="running")
    result_text: Mapped[str | None] = mapped_column(Text)
    result_json: Mapped[dict[str, Any] | None] = mapped_column()
    session_id: Mapped[str | None] = mapped_column(String(100))
    num_turns: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    cache_read_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd_equiv: Mapped[float | None] = mapped_column(Float)  # informational on Max plans
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created()
    finished_at: Mapped[datetime | None] = mapped_column()


class SupportStats(Base):
    """Corroboration of a relation/event: how many *independent* sources back it."""

    __tablename__ = "support_stats"
    target_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    citations: Mapped[int] = mapped_column(Integer, default=0)
    documents: Mapped[int] = mapped_column(Integer, default=0)
    domains: Mapped[int] = mapped_column(Integer, default=0)
    independent_sources: Mapped[int] = mapped_column(Integer, default=0)
    origin_clusters: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), default=list)
    contradicted_by: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), default=list)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Schedule(Base):
    """Recurring refresh of an investigation (run by `osint daemon`)."""

    __tablename__ = "schedule"
    id: Mapped[int] = pk()
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigation.id"), unique=True)
    every_minutes: Mapped[int] = mapped_column(Integer)
    time_range: Mapped[str | None] = mapped_column(String(16))   # searxng time_range on refresh
    analyze: Mapped[bool] = mapped_column(Boolean, default=False)  # Claude analyze if new data
    extract_role: Mapped[str | None] = mapped_column(String(32))  # e.g. agent_heavy overnight
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column()
    next_run_at: Mapped[datetime] = mapped_column()
    last_result: Mapped[dict[str, Any] | None] = mapped_column()


class CitationRetraction(Base):
    """A citation found to be wrong (e.g. a sanctions entry for a different party).
    Citations are append-only, so the correction is a new row, never an edit."""

    __tablename__ = "citation_retraction"
    evidence_link_id: Mapped[int] = mapped_column(ForeignKey("evidence_link.id"), primary_key=True)
    reason: Mapped[str] = mapped_column(Text)
    retracted_by: Mapped[str] = mapped_column(String(200))
    retracted_at: Mapped[datetime] = created()

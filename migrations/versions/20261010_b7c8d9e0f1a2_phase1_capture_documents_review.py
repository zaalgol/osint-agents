"""phase 1: rendered_html captures, document metadata, review queue

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-10-10
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7c8d9e0f1a2"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = ("raw", "warc", "screenshot_png", "pdf_render", "media_original", "archive_org")
NEW_KINDS = ("raw", "warc", "screenshot_png", "pdf_render", "rendered_html",
             "media_original", "archive_org")


def _kinds(values: tuple[str, ...]) -> str:
    return "kind IN (" + ", ".join(repr(v) for v in values) + ")"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_capture_kind"), "capture", type_="check")
    op.create_check_constraint(op.f("ck_capture_kind"), "capture", _kinds(NEW_KINDS))

    op.add_column("document", sa.Column("title", sa.Text(), nullable=True))
    op.add_column("document", sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("document", sa.Column("meta", postgresql.JSONB(), nullable=False,
                                        server_default=sa.text("'{}'::jsonb")))
    op.create_index("ix_document_text_sha256", "document", ["text_sha256"])

    op.create_table(
        "review_item",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("investigation_id", sa.BigInteger(), nullable=True),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("document_id", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
                  nullable=False),
        sa.CheckConstraint("status IN ('open', 'accepted', 'rejected')",
                           name=op.f("ck_review_item_status")),
        sa.ForeignKeyConstraint(["document_id"], ["document.id"],
                                name=op.f("fk_review_item_document_id_document")),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigation.id"],
                                name=op.f("fk_review_item_investigation_id_investigation")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_review_item")),
    )
    op.create_index("ix_review_open", "review_item", ["status", "kind"])


def downgrade() -> None:
    op.drop_index("ix_review_open", table_name="review_item")
    op.drop_table("review_item")
    op.drop_index("ix_document_text_sha256", table_name="document")
    op.drop_column("document", "meta")
    op.drop_column("document", "published_at")
    op.drop_column("document", "title")
    op.drop_constraint(op.f("ck_capture_kind"), "capture", type_="check")
    op.create_check_constraint(op.f("ck_capture_kind"), "capture", _kinds(OLD_KINDS))

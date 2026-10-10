"""integrity triggers: immutable evidence, append-only custody, proof required

Revision ID: a1b2c3d4e5f6
Revises: 88255ded5fbc
Create Date: 2026-10-10

Enforced in the database, so no code path (plugin, agent, Claude via MCP, manual SQL)
can get around them:

  1. artifact / capture / custody_log / evidence_link / inference_premise are append-only.
     UPDATE / DELETE / TRUNCATE are refused unless the session sets
     ``SET LOCAL osint.maintenance = 'on'``. Even then, custody tampering is detectable
     by hash-chain verification.
  2. custody_log inserts must chain onto the current head (no forks or reordering).
  3. evidence_link targets and inference premises must reference existing rows.
  4. relation / event / claim / finding (and confirmed cross_link) must have an
     evidence_link or an inference by COMMIT (deferred constraint trigger).
     Inferred/assessed findings need an inference specifically.
  5. An inference must have at least one premise by COMMIT.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "88255ded5fbc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY = ("artifact", "capture", "custody_log", "evidence_link", "inference_premise")
PROOF_REQUIRED = ("relation", "event", "claim", "finding")

# polymorphic type name -> table
OBJECT_TABLES = """
    CASE $1
        WHEN 'evidence' THEN 'evidence_link'
        WHEN 'relation' THEN 'relation'
        WHEN 'event' THEN 'event'
        WHEN 'claim' THEN 'claim'
        WHEN 'finding' THEN 'finding'
        WHEN 'cross_link' THEN 'cross_link'
        ELSE NULL
    END
"""


def upgrade() -> None:
    # ------------------------------------------------------------- helpers
    op.execute(f"""
    CREATE FUNCTION osint_object_table(text) RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT {OBJECT_TABLES} $$;
    """)
    op.execute("""
    CREATE FUNCTION osint_object_exists(obj_type text, obj_id bigint) RETURNS boolean
    LANGUAGE plpgsql STABLE AS $$
    DECLARE tbl text := osint_object_table(obj_type); found boolean;
    BEGIN
        IF tbl IS NULL THEN RETURN false; END IF;
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I WHERE id = $1)', tbl)
            INTO found USING obj_id;
        RETURN found;
    END $$;
    """)
    op.execute("""
    CREATE FUNCTION osint_maintenance() RETURNS boolean
    LANGUAGE sql STABLE AS $$
        SELECT coalesce(current_setting('osint.maintenance', true), '') = 'on'
    $$;
    """)

    # ------------------------------------------------------------- 1. append-only
    op.execute("""
    CREATE FUNCTION osint_forbid_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF osint_maintenance() THEN
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END IF;
        RAISE EXCEPTION '% on % is forbidden: evidence tables are append-only', TG_OP, TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Record corrections as new rows (custody action), never edit evidence.';
    END $$;
    """)
    for t in APPEND_ONLY:
        op.execute(f"""
        CREATE TRIGGER {t}_append_only BEFORE UPDATE OR DELETE ON {t}
        FOR EACH ROW EXECUTE FUNCTION osint_forbid_mutation();
        CREATE TRIGGER {t}_no_truncate BEFORE TRUNCATE ON {t}
        FOR EACH STATEMENT EXECUTE FUNCTION osint_forbid_mutation();
        """)

    # ------------------------------------------------------------- 2. custody chain head
    op.execute("""
    CREATE FUNCTION osint_custody_chain() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE head text;
    BEGIN
        SELECT entry_hash INTO head FROM custody_log ORDER BY seq DESC LIMIT 1;
        IF NEW.prev_hash IS DISTINCT FROM coalesce(head, repeat('0', 64)) THEN
            RAISE EXCEPTION 'custody chain fork: prev_hash % does not match head %',
                NEW.prev_hash, coalesce(head, 'GENESIS')
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END $$;
    CREATE TRIGGER custody_log_chain BEFORE INSERT ON custody_log
    FOR EACH ROW EXECUTE FUNCTION osint_custody_chain();
    """)

    # ------------------------------------------------------------- 3. polymorphic FKs
    op.execute("""
    CREATE FUNCTION osint_check_evidence_target() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NOT osint_object_exists(NEW.target_type, NEW.target_id) THEN
            RAISE EXCEPTION 'evidence_link target % % does not exist', NEW.target_type, NEW.target_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;
        RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER evidence_link_target AFTER INSERT ON evidence_link
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION osint_check_evidence_target();

    CREATE FUNCTION osint_check_premise() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NOT osint_object_exists(NEW.premise_type, NEW.premise_id) THEN
            RAISE EXCEPTION 'inference premise % % does not exist', NEW.premise_type, NEW.premise_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;
        RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER inference_premise_exists AFTER INSERT ON inference_premise
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION osint_check_premise();

    CREATE FUNCTION osint_check_conclusion() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF NOT osint_object_exists(NEW.conclusion_type, NEW.conclusion_id) THEN
            RAISE EXCEPTION 'inference conclusion % % does not exist',
                NEW.conclusion_type, NEW.conclusion_id
                USING ERRCODE = 'foreign_key_violation';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM inference_premise WHERE inference_id = NEW.id) THEN
            RAISE EXCEPTION 'inference % has no premises (a proof tree needs leaves)', NEW.id
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER inference_valid AFTER INSERT ON inference
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION osint_check_conclusion();
    """)

    # ------------------------------------------------------------- 4. proof required
    op.execute("""
    CREATE FUNCTION osint_require_proof() RETURNS trigger
    LANGUAGE plpgsql AS $$
    DECLARE obj_type text := TG_ARGV[0]; has_ev boolean; has_inf boolean;
    BEGIN
        -- row deleted later in the same transaction: nothing to prove
        IF NOT osint_object_exists(obj_type, NEW.id) THEN RETURN NULL; END IF;
        has_ev := EXISTS (SELECT 1 FROM evidence_link
                          WHERE target_type = obj_type AND target_id = NEW.id);
        has_inf := EXISTS (SELECT 1 FROM inference
                           WHERE conclusion_type = obj_type AND conclusion_id = NEW.id);
        IF NOT (has_ev OR has_inf) THEN
            RAISE EXCEPTION 'no proof: % % has no evidence_link and no inference', obj_type, NEW.id
                USING ERRCODE = 'check_violation',
                      HINT = 'Insert the object and its citation(s) in the same transaction.';
        END IF;
        -- nested IF: plpgsql does not short-circuit AND, and only finding has this column
        IF obj_type = 'finding' AND NOT has_inf THEN
            IF NEW.epistemic_status IN ('inferred', 'assessed') THEN
                RAISE EXCEPTION 'finding % is %, which requires a proof tree (inference)',
                    NEW.id, NEW.epistemic_status USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        RETURN NULL;
    END $$;
    """)
    for t in PROOF_REQUIRED:
        op.execute(f"""
        CREATE CONSTRAINT TRIGGER {t}_requires_proof AFTER INSERT ON {t}
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION osint_require_proof('{t}');
        """)
    op.execute("""
    CREATE CONSTRAINT TRIGGER cross_link_requires_proof AFTER INSERT OR UPDATE OF status
    ON cross_link DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.status = 'confirmed')
    EXECUTE FUNCTION osint_require_proof('cross_link');
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS cross_link_requires_proof ON cross_link")
    for t in PROOF_REQUIRED:
        op.execute(f"DROP TRIGGER IF EXISTS {t}_requires_proof ON {t}")
    op.execute("DROP TRIGGER IF EXISTS inference_valid ON inference")
    op.execute("DROP TRIGGER IF EXISTS inference_premise_exists ON inference_premise")
    op.execute("DROP TRIGGER IF EXISTS evidence_link_target ON evidence_link")
    op.execute("DROP TRIGGER IF EXISTS custody_log_chain ON custody_log")
    for t in APPEND_ONLY:
        op.execute(f"DROP TRIGGER IF EXISTS {t}_append_only ON {t}")
        op.execute(f"DROP TRIGGER IF EXISTS {t}_no_truncate ON {t}")
    for fn in (
        "osint_require_proof()", "osint_check_conclusion()", "osint_check_premise()",
        "osint_check_evidence_target()", "osint_custody_chain()", "osint_forbid_mutation()",
        "osint_maintenance()", "osint_object_exists(text, bigint)", "osint_object_table(text)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")

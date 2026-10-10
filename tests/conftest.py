from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from osint.core.config import Settings, project_home
from osint.storage.raw_store import RawStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def raw_store(tmp_path: Path) -> RawStore:
    return RawStore(tmp_path / "data")


@pytest.fixture(scope="session")
def pg_url() -> str:
    """Create a throwaway database, migrate it to head, drop it after the session."""
    settings = Settings()
    admin_url = settings.postgres.url.rsplit("/", 1)[0] + "/postgres"
    db_name = f"osint_test_{uuid.uuid4().hex[:8]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as c:
            c.execute(text(f'CREATE DATABASE "{db_name}"'))
    except Exception as e:  # noqa: BLE001 - any connection problem means skip
        pytest.skip(f"postgres not available: {e}")

    url = settings.postgres.url.rsplit("/", 1)[0] + f"/{db_name}"
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(project_home() / "alembic.ini") if (project_home() / "alembic.ini").exists()
                 else str(ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    cfg.attributes["skip_logging"] = True
    command.upgrade(cfg, "head")
    yield url
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)'))
    admin.dispose()


@pytest.fixture
def pg_settings(pg_url: str, tmp_path: Path) -> Settings:
    """Settings pointing at the throwaway DB and a temp data dir (for App/Runner tests)."""
    base = Settings()
    pg = base.postgres.model_copy(update={"database": pg_url.rsplit("/", 1)[1]})
    return base.model_copy(update={"postgres": pg, "data_dir": tmp_path / "data"})


@pytest.fixture
def session_factory(pg_url: str):
    engine = create_engine(pg_url)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()

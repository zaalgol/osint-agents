from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from osint.core.config import Settings


def make_engine(settings: Settings) -> Engine:
    return create_engine(settings.postgres.url, pool_pre_ping=True, future=True)


def make_session_factory(settings: Settings) -> sessionmaker[Session]:
    return sessionmaker(make_engine(settings), expire_on_commit=False)

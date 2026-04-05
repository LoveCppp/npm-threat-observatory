from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
SessionLocal = sessionmaker(autoflush=False, autocommit=False, expire_on_commit=False)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(settings.database_url, future=True, pool_pre_ping=True)
        SessionLocal.configure(bind=_engine)
    return _engine

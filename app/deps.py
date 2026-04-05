from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from app.db import SessionLocal, get_engine


def get_db() -> Generator[Session, None, None]:
    get_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

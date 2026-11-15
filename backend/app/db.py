from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from .config import get_settings

_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        url = get_settings().db_url
        # Both pipelines may write at once (UI "run all"); wait for the lock instead of failing fast.
        connect_args = {"check_same_thread": False, "timeout": 60} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args)
        if url.startswith("sqlite"):

            @event.listens_for(_engine, "connect")
            def _pragmas(dbapi_conn, _record):  # pragma: no cover - driver hook
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA busy_timeout=60000")
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.close()

    return _engine


def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    SQLModel.metadata.create_all(get_engine())
    _add_missing_columns()


def _add_missing_columns() -> None:
    """create_all() never alters existing tables. Add columns introduced after a database was created
    (e.g. phish_samples.threat_score), so an existing data/ctiops.db keeps working without a wipe."""
    from sqlalchemy import inspect, text

    engine = get_engine()
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in SQLModel.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for column in table.columns:
                if column.name in have:
                    continue
                ddl_type = column.type.compile(dialect=engine.dialect)
                default = column.default.arg if column.default is not None and not callable(column.default.arg) else None
                clause = f" DEFAULT {default!r}" if isinstance(default, int | float | str) and not isinstance(default, bool) else ""
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {ddl_type}{clause}'))
                if column.index:
                    conn.execute(text(f'CREATE INDEX IF NOT EXISTS "ix_{table.name}_{column.name}" '
                                      f'ON "{table.name}" ("{column.name}")'))


def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session


@contextmanager
def session_scope() -> Iterator[Session]:
    session = Session(get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DB_DIR = Path.home() / ".websentinel"
DB_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{DB_DIR / 'websentinel.db'}")

engine = create_async_engine(DATABASE_URL, echo=False)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with engine.begin() as conn:
        await conn.run_sync(_run_migrations)


def _run_migrations(conn):
    import sqlalchemy as sa
    from sqlalchemy import inspect

    inspector = inspect(conn)
    columns = {c["name"] for c in inspector.get_columns("findings")}
    if "status" not in columns:
        conn.execute(sa.text("ALTER TABLE findings ADD COLUMN status VARCHAR(16) DEFAULT 'open'"))
        conn.execute(sa.text("ALTER TABLE findings ADD COLUMN resolved_at DATETIME"))
    scan_cols = {c["name"] for c in inspector.get_columns("scans")}
    if "remediation_plan" not in scan_cols:
        conn.execute(sa.text("ALTER TABLE scans ADD COLUMN remediation_plan JSON"))
        conn.execute(sa.text("ALTER TABLE scans ADD COLUMN finding_status_counts JSON DEFAULT '{}'"))

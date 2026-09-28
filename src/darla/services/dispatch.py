"""Commit-then-dispatch for Celery chains started from API requests."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession


async def commit_then_dispatch(db: AsyncSession, chain: Any) -> Any:
    """Commit the session, then ``apply_async`` the chain.

    ``get_db`` commits only after the request handler returns, but a worker
    can dequeue the task sooner.  It then finds no kit row, raises
    "Kit ... not found" and burns its only retry (30 s later) — observed on
    root kits in live investigations.  The session factory uses
    ``expire_on_commit=False``, so ORM objects stay usable after this.
    """
    await db.commit()
    return chain.apply_async()

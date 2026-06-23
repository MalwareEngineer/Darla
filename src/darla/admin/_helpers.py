"""Shared helpers for ``darla-admin`` subcommands.

Two responsibilities:

1. Run async service code from sync Typer commands.  Each command
   spins up a fresh event loop, opens an async session against the
   live DB, runs its work, exits.
2. Record an audit row for every invocation.  Operator actions need
   the same attribution trail as HTTP requests — different actor
   format (``cli:<principal>``) so audit consumers can tell them
   apart from token-derived actors.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

from darla.database import async_session_factory
from darla.models import AuditLog


T = TypeVar("T")


def run_async(coro: Awaitable[T]) -> T:
    """Drive an async coroutine from a sync Typer command.

    Trivial wrapper, but having one entry point lets us swap in a
    different runtime (e.g. uvloop) later without touching every
    command.  Each CLI invocation creates its own event loop and
    discards it on exit — fine because the CLI is short-lived.
    """
    return asyncio.run(coro)


def resolve_principal() -> str:
    """Best-effort identity of who is running ``darla-admin``.

    Resolution order:

    1. ``AWS_PRINCIPAL_ARN`` — explicitly set in SSM Session Manager
       wrappers (we plan to inject this in the Phase 7 Terraform).
    2. ``SSM_USER`` — what AWS SSM sets as the OS user when you
       ``aws ssm start-session``; format is ``ssm-user`` or the
       federated principal name depending on the SSM document.
    3. ``USER`` — local-dev fallback, the developer's OS account.
    4. Literal ``"unknown"`` — if everything else is missing
       (cron job, init script, whatever).

    Returns a value already prefixed with ``cli:`` so callers can
    persist it directly into ``audit_log.actor_subject``.
    """
    for env_var in ("AWS_PRINCIPAL_ARN", "SSM_USER", "USER"):
        val = os.environ.get(env_var)
        if val:
            return f"cli:{val}"
    return "cli:unknown"


async def write_cli_audit_row(
    db: AsyncSession,
    *,
    command: str,
    args: dict[str, Any] | None = None,
    status_code: int = 0,
    elapsed_ms: int = 0,
) -> None:
    """Persist an audit row for one CLI invocation.

    Uses the existing :class:`AuditLog` model — the same table that
    HTTP requests write to.  The ``method`` field is set to ``CLI``
    so audit consumers can filter operator actions from HTTP traffic
    with a single predicate.  The ``path`` field carries the
    subcommand (e.g. ``user.disable``) so a single grep finds every
    invocation of the same operation.

    ``status_code`` follows HTTP-shaped conventions for ease of
    filtering: ``0`` = success, ``1`` = expected failure (e.g. user
    not found), ``2`` = unexpected error.  ``elapsed_ms`` is wall-
    clock duration of the command — useful for spotting hung CLI
    operations in long-term audit review.
    """
    row = AuditLog(
        actor_subject=resolve_principal(),
        actor_upn=None,
        auth_mode="cli",
        method="CLI",
        path=command,
        status_code=status_code,
        response_ms=elapsed_ms,
        request_id=str(uuid.uuid4()),
        extra={"args": args} if args else None,
    )
    db.add(row)
    await db.commit()


class _AuditedCommand:
    """Context manager that times a CLI operation and writes an
    audit row on exit, regardless of success or exception.

    Usage::

        async with audited("user.disable", args={"subject": s}) as ctx:
            ... do work ...
            ctx.status = 0  # explicit success

    If the block raises, status is recorded as 2 and the exception
    re-raises — so the operator still sees the error.
    """

    def __init__(self, command: str, args: dict[str, Any] | None = None):
        self.command = command
        self.args = args
        self.status: int = 0
        self._start: float = 0.0
        self._db: AsyncSession | None = None

    async def __aenter__(self) -> "_AuditedCommand":
        self._start = time.monotonic()
        self._db = async_session_factory()
        await self._db.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, tb) -> None:
        try:
            elapsed_ms = int((time.monotonic() - self._start) * 1000)
            # ``typer.Exit`` is a controlled exit — used for expected
            # failures like "target not found" (exit 1) and bad input
            # (exit 2).  Honor whatever status the command recorded
            # before raising, instead of overwriting with the generic
            # "unexpected error" code.  Real exceptions still flag as 2.
            import typer

            if exc_type is None or (exc_type is typer.Exit):
                status = self.status
            else:
                status = 2
            if self._db is not None:
                try:
                    await write_cli_audit_row(
                        self._db,
                        command=self.command,
                        args=self.args,
                        status_code=status,
                        elapsed_ms=elapsed_ms,
                    )
                except Exception:
                    # Audit write failed — log? swallow?  The CLI's
                    # primary job is to perform the operation; an audit
                    # failure shouldn't mask the original outcome.
                    # We swallow here for the same reason the HTTP
                    # middleware does (RFC §5.2).  In a future hardening
                    # pass we could log this to stderr.
                    pass
        finally:
            if self._db is not None:
                await self._db.__aexit__(exc_type, exc_value, tb)


def audited(command: str, args: dict[str, Any] | None = None) -> _AuditedCommand:
    """Factory mirroring stdlib conventions for context managers."""
    return _AuditedCommand(command, args)

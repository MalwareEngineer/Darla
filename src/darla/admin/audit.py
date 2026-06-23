"""``darla-admin audit recent`` — query audit_log with filters.

The audit table is queryable from any SQL client (psql, DataGrip,
whatever), but ``darla-admin`` ships a convenience wrapper for two
reasons:

* The common questions ("who did what in the last 24h", "every
  access to victim X this quarter") shouldn't require remembering
  the schema.
* CLI-driven access via SSM is the same trust boundary as everything
  else in this module — anyone who can answer audit questions via
  this command can also answer them via psql.  Centralising the
  question vocabulary keeps incident-response runbooks one tool
  shorter.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from darla.admin._helpers import audited, run_async
from darla.models import AuditLog

app = typer.Typer(no_args_is_help=True, help="Query the audit log.")
console = Console()


# Accept "7d" / "24h" / "30m" / "60s" — single-letter unit suffix.
_DURATION_RE = re.compile(r"^(\d+)([smhd])$", re.IGNORECASE)
_UNIT_TO_TIMEDELTA = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def _parse_since(value: str) -> timedelta:
    """Parse ``"<int><s|m|h|d>"`` into a timedelta.  Operators want to
    type ``--since 7d`` not ``--since-hours 168``."""
    m = _DURATION_RE.match(value)
    if not m:
        raise typer.BadParameter(
            f"--since must look like '7d', '24h', '30m', or '60s' (got {value!r})"
        )
    n = int(m.group(1))
    unit = m.group(2).lower()
    return timedelta(**{_UNIT_TO_TIMEDELTA[unit]: n})


@app.command()
def recent(
    user: str | None = typer.Option(
        None,
        "--user",
        help="Filter to one actor (OIDC subject OR 'cli:<principal>' for CLI ops).",
    ),
    since: str = typer.Option(
        "24h",
        "--since",
        help="Time window suffixed by s/m/h/d (e.g. 7d, 24h).",
    ),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Filter rows whose path starts with this prefix.",
    ),
    status: int | None = typer.Option(
        None,
        "--status",
        help="Filter by HTTP status code (or CLI status: 0=ok, 1=expected fail, 2=error).",
    ),
    limit: int = typer.Option(
        100,
        "--limit",
        help="Maximum rows to return.",
        min=1,
        max=10_000,
    ),
    show_extra: bool = typer.Option(
        False,
        "--show-extra",
        help="Render the JSONB extra column (victim_ids, etc.).  Wider output.",
    ),
) -> None:
    """Most-recent audit rows matching the filters, newest first."""
    delta = _parse_since(since)
    cutoff = datetime.now(UTC) - delta
    run_async(_recent_impl(user, cutoff, path, status, limit, show_extra))


async def _recent_impl(
    user: str | None,
    cutoff: datetime,
    path_prefix: str | None,
    status: int | None,
    limit: int,
    show_extra: bool,
) -> None:
    async with audited(
        "audit.recent",
        {
            "user": user,
            "since": cutoff.isoformat(),
            "path": path_prefix,
            "status": status,
            "limit": limit,
        },
    ) as ctx:
        db = ctx._db
        assert db is not None

        q = (
            select(AuditLog)
            .where(AuditLog.timestamp >= cutoff)
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        if user is not None:
            q = q.where(AuditLog.actor_subject == user)
        if path_prefix is not None:
            # ``startswith`` translates to a ``LIKE 'prefix%'`` predicate;
            # the ``ix_audit_log_path`` btree index handles prefix
            # lookups efficiently (Postgres can use the index for
            # left-anchored LIKE patterns in C locale; for non-C locale
            # we'd add a varchar_pattern_ops opclass — not in v1).
            q = q.where(AuditLog.path.startswith(path_prefix))
        if status is not None:
            q = q.where(AuditLog.status_code == status)

        rows = list((await db.scalars(q)).all())

        table = Table(title=f"Audit log: {len(rows)} rows since {cutoff.isoformat(timespec='seconds')}")
        table.add_column("time", style="dim")
        table.add_column("actor", overflow="fold")
        table.add_column("method")
        table.add_column("path", overflow="fold")
        table.add_column("status")
        table.add_column("ms")
        if show_extra:
            table.add_column("extra", overflow="fold")
        for r in rows:
            row_values = [
                r.timestamp.isoformat(timespec="seconds") if r.timestamp else "—",
                r.actor_subject or "—",
                r.method,
                r.path,
                str(r.status_code),
                str(r.response_ms),
            ]
            if show_extra:
                # Compact JSON — wide output already, no need for indent.
                row_values.append(
                    json.dumps(r.extra, separators=(",", ":"))
                    if r.extra else "—"
                )
            table.add_row(*row_values)
        console.print(table)
        ctx.status = 0

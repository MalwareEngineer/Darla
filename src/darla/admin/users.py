"""``darla-admin user ...`` subcommands.

Five operations matching RFC §9:

* ``list``                     — paginated user listing with role/disabled filters
* ``disable <subject>``        — flip the local kill switch
* ``enable <subject>``         — clear the kill switch
* ``set-role-override <subject> <role>`` — CLI lever that wins over the
                                  IdP-derived role (covers IdP propagation lag)
* ``clear-role-override <subject>``       — restore IdP-derived role

All commands operate by ``oidc_subject``, not internal UUID — the
operator sees subjects in the audit log and HTTP error responses
and can copy/paste directly.  For Entra deployments, this is the
user's ``oid`` (which is what we configured ``PK_OIDC_SUBJECT_CLAIM``
to be).
"""

from __future__ import annotations

from datetime import UTC, datetime

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from darla.admin._helpers import audited, run_async
from darla.models import User, UserRole

app = typer.Typer(no_args_is_help=True, help="Manage Darla users.")
console = Console()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@app.command(name="list")
def list_users(
    role: str | None = typer.Option(
        None,
        "--role",
        help="Filter by IdP-derived role (viewer|analyst).",
    ),
    disabled: bool = typer.Option(
        False,
        "--disabled",
        help="Show only users with disabled_at set.",
    ),
) -> None:
    """Print users as a table.  Default: all users, all roles."""
    role_enum: UserRole | None = None
    if role is not None:
        try:
            role_enum = UserRole(role.lower())
        except ValueError as e:
            console.print(
                f"[red]invalid role {role!r} — must be 'viewer' or 'analyst'[/red]"
            )
            raise typer.Exit(2) from e
    run_async(_list_users_impl(role_enum, disabled))


async def _list_users_impl(role: UserRole | None, disabled_only: bool) -> None:
    async with audited("user.list", {"role": role.value if role else None, "disabled": disabled_only}) as ctx:
        # Reuse the audited session for the actual query — same
        # transaction, single round-trip, and the audit row commits
        # alongside the read.
        db = ctx._db
        assert db is not None  # set by __aenter__
        q = select(User).order_by(User.last_login_at.desc())
        if role is not None:
            q = q.where(User.role == role)
        if disabled_only:
            q = q.where(User.disabled_at.is_not(None))
        users = list((await db.scalars(q)).all())

        table = Table(title=f"Users ({len(users)})")
        table.add_column("subject", style="dim", overflow="fold")
        table.add_column("upn")
        table.add_column("display_name")
        table.add_column("role")
        table.add_column("override")
        table.add_column("last_login")
        table.add_column("disabled", style="red")
        for u in users:
            table.add_row(
                u.oidc_subject,
                u.upn,
                u.display_name,
                u.role.value,
                u.role_override.value if u.role_override else "—",
                u.last_login_at.isoformat(timespec="seconds") if u.last_login_at else "—",
                u.disabled_at.isoformat(timespec="seconds") if u.disabled_at else "",
            )
        console.print(table)
        ctx.status = 0


# ---------------------------------------------------------------------------
# disable / enable
# ---------------------------------------------------------------------------


@app.command()
def disable(
    subject: str = typer.Argument(..., help="OIDC subject (oid for Entra)."),
) -> None:
    """Flip the local kill switch — user is rejected on next request,
    regardless of IdP token validity.

    Use case: an analyst is being offboarded RIGHT NOW and IT hasn't
    propagated the Entra group removal yet (token refresh lag is up to
    ~1h).  This is the instant-revoke lever.

    Idempotent — disabling an already-disabled user is a no-op.
    """
    run_async(_flip_disabled_impl(subject, disable=True))


@app.command()
def enable(
    subject: str = typer.Argument(..., help="OIDC subject (oid for Entra)."),
) -> None:
    """Clear the local kill switch.  Token validity then determines
    whether the user can sign in (the IdP-side group assignment still
    applies)."""
    run_async(_flip_disabled_impl(subject, disable=False))


async def _flip_disabled_impl(subject: str, *, disable: bool) -> None:
    action = "user.disable" if disable else "user.enable"
    async with audited(action, {"subject": subject}) as ctx:
        db = ctx._db
        assert db is not None
        user = await db.scalar(select(User).where(User.oidc_subject == subject))
        if user is None:
            console.print(f"[yellow]no user with subject {subject!r}[/yellow]")
            ctx.status = 1
            raise typer.Exit(1)
        user.disabled_at = datetime.now(UTC) if disable else None
        await db.commit()
        verb = "disabled" if disable else "enabled"
        console.print(f"[green]{verb}[/green] {user.upn} ({user.oidc_subject})")
        ctx.status = 0


# ---------------------------------------------------------------------------
# set-role-override / clear-role-override
# ---------------------------------------------------------------------------


@app.command(name="set-role-override")
def set_role_override(
    subject: str = typer.Argument(..., help="OIDC subject."),
    role: str = typer.Argument(..., help="Override role: viewer or analyst."),
) -> None:
    """Force a user's role regardless of what the IdP token says.

    The override wins on every subsequent request until cleared.
    Use it when IdP propagation lag is unacceptable (incident response,
    immediate downgrade) or to test role-gated behavior without
    re-shuffling IdP groups.
    """
    try:
        role_enum = UserRole(role.lower())
    except ValueError as e:
        console.print(
            f"[red]invalid role {role!r} — must be 'viewer' or 'analyst'[/red]"
        )
        raise typer.Exit(2) from e
    run_async(_set_override_impl(subject, role_enum))


@app.command(name="clear-role-override")
def clear_role_override(
    subject: str = typer.Argument(..., help="OIDC subject."),
) -> None:
    """Remove the CLI-set override.  IdP-derived role takes over again
    on the next login."""
    run_async(_set_override_impl(subject, None))


async def _set_override_impl(subject: str, role: UserRole | None) -> None:
    action = "user.set-role-override" if role else "user.clear-role-override"
    async with audited(action, {"subject": subject, "role": role.value if role else None}) as ctx:
        db = ctx._db
        assert db is not None
        user = await db.scalar(select(User).where(User.oidc_subject == subject))
        if user is None:
            console.print(f"[yellow]no user with subject {subject!r}[/yellow]")
            ctx.status = 1
            raise typer.Exit(1)
        user.role_override = role
        await db.commit()
        if role is None:
            console.print(
                f"[green]cleared[/green] override for {user.upn} "
                f"(reverts to IdP role: {user.role.value})"
            )
        else:
            console.print(
                f"[green]override[/green] {user.upn} → {role.value} "
                f"(IdP role: {user.role.value}, override wins)"
            )
        ctx.status = 0

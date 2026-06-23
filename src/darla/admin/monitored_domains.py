"""``darla-admin monitored-domain ...`` subcommands.

Two operations:

* ``reload [--dry-run]`` — read ``monitored_domains.yaml`` from a
  configurable path, diff against the DB, apply INSERT/UPDATE/DELETE.
  This is the **only** writable path for the allowlist once Phase 6b
  removes the HTTP endpoints (per RFC §3 decision #14 — sensitive
  org-protected data lives behind the AWS-IAM boundary, not behind
  the HTTP API).
* ``list``                  — print current DB rows.  Cheap read for
  sanity-checking after a reload.

The YAML format is intentionally minimal::

    # monitored_domains.yaml
    domains:
      - domain: acme.com
        description: Primary corporate domain
      - domain: subsidiary.example
        description: Q3 2025 acquisition
      - domain: legacy.acme.com  # description optional

A reload is **diff-based**: domains present in YAML but missing from
DB → INSERT, present in DB but missing from YAML → DELETE, present in
both with a different description → UPDATE.  Existing Victim rows
under a deleted domain are NOT cascaded — see
``MonitoredDomainService.delete_domain`` for the historical-data
preservation rationale.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from darla.admin._helpers import audited, run_async
from darla.models import MonitoredDomain

app = typer.Typer(no_args_is_help=True, help="Manage the protected-domain allowlist.")
console = Console()

# Default path inside the container.  Override via $PK_MONITORED_DOMAINS_FILE
# for local dev or alternative deployments.
DEFAULT_YAML_PATH = "/etc/darla/monitored_domains.yaml"


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@app.command(name="list")
def list_domains() -> None:
    """Print the current DB rows."""
    run_async(_list_impl())


async def _list_impl() -> None:
    async with audited("monitored-domain.list") as ctx:
        db = ctx._db
        assert db is not None
        rows = list(
            (await db.scalars(
                select(MonitoredDomain).order_by(MonitoredDomain.domain)
            )).all()
        )
        table = Table(title=f"Monitored Domains ({len(rows)})")
        table.add_column("domain", style="cyan")
        table.add_column("description")
        table.add_column("created", style="dim")
        for d in rows:
            table.add_row(
                d.domain,
                d.description or "—",
                d.created_at.isoformat(timespec="seconds") if d.created_at else "",
            )
        console.print(table)
        ctx.status = 0


# ---------------------------------------------------------------------------
# reload
# ---------------------------------------------------------------------------


@app.command()
def reload(
    source: Path | None = typer.Option(
        None,
        "--source",
        help=(
            "Path to monitored_domains.yaml.  Defaults to "
            "$PK_MONITORED_DOMAINS_FILE or /etc/darla/monitored_domains.yaml."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the diff but don't apply.",
    ),
) -> None:
    """Sync the DB to the YAML file: INSERT / UPDATE / DELETE as needed.

    Idempotent — running twice in a row with no file changes is a no-op
    after the first run.  Always prints the diff before applying so
    the operator sees what they're about to do.
    """
    yaml_path = source or Path(
        os.environ.get("PK_MONITORED_DOMAINS_FILE", DEFAULT_YAML_PATH),
    )
    if not yaml_path.exists():
        console.print(f"[red]file not found:[/red] {yaml_path}")
        raise typer.Exit(2)

    desired = _parse_yaml(yaml_path)
    run_async(_reload_impl(yaml_path, desired, dry_run))


def _parse_yaml(path: Path) -> dict[str, str | None]:
    """Parse the YAML file into ``{domain: description}`` mapping.

    Returns lower-cased domain keys (match DB-side storage convention)
    so the subsequent diff is just a dict comparison.  Raises
    ``typer.Exit`` on malformed input — cleaner exit than letting a
    yaml.YAMLError ladder back up to the user as a Python traceback.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            doc: Any = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        console.print(f"[red]YAML parse error in {path}:[/red] {e}")
        raise typer.Exit(2) from e

    entries = doc.get("domains", []) if isinstance(doc, dict) else []
    if not isinstance(entries, list):
        console.print(f"[red]'domains' key in {path} must be a list[/red]")
        raise typer.Exit(2)

    result: dict[str, str | None] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or "domain" not in entry:
            console.print(f"[red]entry {i} missing 'domain' key[/red]")
            raise typer.Exit(2)
        key = str(entry["domain"]).strip().lower()
        if not key:
            console.print(f"[red]entry {i} has empty domain[/red]")
            raise typer.Exit(2)
        if key in result:
            console.print(f"[red]duplicate domain in YAML: {key!r}[/red]")
            raise typer.Exit(2)
        result[key] = entry.get("description")
    return result


async def _reload_impl(
    yaml_path: Path,
    desired: dict[str, str | None],
    dry_run: bool,
) -> None:
    async with audited(
        "monitored-domain.reload",
        {"file": str(yaml_path), "dry_run": dry_run, "desired_count": len(desired)},
    ) as ctx:
        db = ctx._db
        assert db is not None

        current_rows = list(
            (await db.scalars(select(MonitoredDomain))).all()
        )
        current = {r.domain: r for r in current_rows}

        to_insert = [d for d in desired if d not in current]
        to_delete = [d for d in current if d not in desired]
        to_update = [
            d for d in desired
            if d in current and (desired[d] or "") != (current[d].description or "")
        ]

        # Print the diff regardless of dry-run — operator always sees
        # what would happen before it does.
        _print_diff(desired, current, to_insert, to_update, to_delete)

        if dry_run:
            console.print("[yellow]--dry-run: no changes applied[/yellow]")
            ctx.status = 0
            return

        if not (to_insert or to_update or to_delete):
            console.print("[green]nothing to do — DB already matches YAML[/green]")
            ctx.status = 0
            return

        # Apply.  Each operation is a single statement; no need to
        # batch under one INSERT...VALUES because realistic counts are
        # in the tens, not thousands.
        for d in to_insert:
            db.add(MonitoredDomain(domain=d, description=desired[d]))
        for d in to_update:
            current[d].description = desired[d]
        for d in to_delete:
            await db.delete(current[d])
        await db.commit()

        console.print(
            f"[green]applied:[/green] +{len(to_insert)} added, "
            f"~{len(to_update)} updated, -{len(to_delete)} removed"
        )
        ctx.status = 0


def _print_diff(
    desired: dict[str, str | None],
    current: dict[str, MonitoredDomain],
    to_insert: list[str],
    to_update: list[str],
    to_delete: list[str],
) -> None:
    """Pretty-print the diff using rich-prefixed lines.

    Format intentionally mirrors ``git status``-style symbols so the
    output is scannable at a glance:

       + added
       ~ updated  old → new
       - removed
    """
    for d in sorted(to_insert):
        desc = desired[d] or "—"
        console.print(f"  [green]+ {d}[/green]  ({desc})")
    for d in sorted(to_update):
        old = current[d].description or "—"
        new = desired[d] or "—"
        console.print(f"  [yellow]~ {d}[/yellow]  ({old} → {new})")
    for d in sorted(to_delete):
        console.print(f"  [red]- {d}[/red]")

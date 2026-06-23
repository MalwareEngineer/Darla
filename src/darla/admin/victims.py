"""``darla-admin victim reload --source <CSV>``.

Bulk-loads / updates the Victim table from a CSV exported from the
HR side of the org.  The CSV is the source-of-truth for "who works
here"; observations from the analysis pipeline (handled separately
in ``darla.services.victim_service.observe_victim_email``) still
promote NEW victims when an attacker hits an unknown address on a
monitored domain.  This command exists for the bulk-onboarding case:
"here's everyone the org cares about, make them all Victim rows."

CSV format (header required, columns can be in any order)::

    email,display_name,type,notes
    alice@acme.com,Alice Anderson,user,
    bob@acme.com,Bob Builder,exec,VP of Engineering
    support@acme.com,Support Inbox,shared_mailbox,
    noreply@acme.com,No-Reply Mailer,service,

* ``email`` is the upsert key.  Required.
* ``display_name``, ``type``, ``notes`` are optional and only update
  the existing row if non-empty (so re-running with partial data
  doesn't blank out fields populated by other paths).
* ``type`` must be one of the :class:`VictimType` enum string values
  (``user`` / ``exec`` / ``distro`` / ``shared_mailbox`` / ``service`` /
  ``unknown``).  Defaults to ``user`` for new rows when omitted.

Important: this command does NOT validate emails against
``monitored_domains``.  Bulk imports trust the source.  If an
operator wants the validation, they can run ``monitored-domain
reload`` first and inspect mismatches via SQL.
"""

from __future__ import annotations

import csv
import uuid
from pathlib import Path

import typer
from rich.console import Console
from sqlalchemy import select

from darla.admin._helpers import audited, run_async
from darla.models import Victim
from darla.models.victim import VictimType

app = typer.Typer(no_args_is_help=True, help="Bulk-manage Victim records.")
console = Console()


@app.command()
def reload(
    source: Path = typer.Option(
        ...,
        "--source",
        help="Path to the CSV file to import.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Parse + diff but don't write to the DB.",
    ),
) -> None:
    """Idempotent upsert of Victim rows keyed on ``email``.

    Prints a count summary (new / updated / unchanged) before applying.
    Re-running on the same CSV is a no-op after the first run.
    """
    rows = _parse_csv(source)
    run_async(_reload_impl(source, rows, dry_run))


def _parse_csv(path: Path) -> list[dict[str, str]]:
    """Parse + validate the CSV.  Returns row dicts with normalized
    keys (lower-case emails, stripped strings).  Exits with a clear
    error on malformed input — the user gets a fixable message
    instead of a Python traceback.
    """
    out: list[dict[str, str]] = []
    seen_emails: set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "email" not in reader.fieldnames:
            console.print(
                "[red]CSV missing required 'email' column header[/red]"
            )
            raise typer.Exit(2)
        for i, raw in enumerate(reader, start=2):  # start=2 so error reports match line numbers (after header)
            email = (raw.get("email") or "").strip().lower()
            if not email or "@" not in email:
                console.print(f"[red]row {i}: invalid email {email!r}[/red]")
                raise typer.Exit(2)
            if email in seen_emails:
                console.print(f"[red]row {i}: duplicate email {email!r}[/red]")
                raise typer.Exit(2)
            type_str = (raw.get("type") or "").strip().lower()
            if type_str and type_str not in {v.value for v in VictimType}:
                allowed = ", ".join(v.value for v in VictimType)
                console.print(
                    f"[red]row {i}: invalid type {type_str!r} "
                    f"(must be one of: {allowed})[/red]"
                )
                raise typer.Exit(2)
            seen_emails.add(email)
            out.append({
                "email": email,
                "display_name": (raw.get("display_name") or "").strip(),
                "type": type_str,
                "notes": (raw.get("notes") or "").strip(),
            })
    return out


async def _reload_impl(
    source: Path,
    rows: list[dict[str, str]],
    dry_run: bool,
) -> None:
    async with audited(
        "victim.reload",
        {"file": str(source), "dry_run": dry_run, "row_count": len(rows)},
    ) as ctx:
        db = ctx._db
        assert db is not None

        emails = [r["email"] for r in rows]
        # Fetch existing rows in one query.  ``in_`` over a list of N
        # emails is fine for any reasonable CSV size — Postgres handles
        # 10k-element IN lists without breaking a sweat.
        existing = {}
        if emails:
            result = await db.scalars(
                select(Victim).where(Victim.email.in_(emails))
            )
            existing = {v.email: v for v in result.all()}

        added = updated = unchanged = 0
        for r in rows:
            email = r["email"]
            victim = existing.get(email)
            if victim is None:
                added += 1
                if not dry_run:
                    new = Victim(
                        id=uuid.uuid4(),
                        email=email,
                        domain=email.split("@", 1)[1],
                        display_name=r["display_name"] or None,
                        # Default to USER if not specified — matches
                        # the schema's server_default.
                        type=VictimType(r["type"]) if r["type"] else VictimType.USER,
                        notes=r["notes"] or None,
                    )
                    db.add(new)
            else:
                # Update only NON-EMPTY fields.  Re-running with a
                # partial CSV must not clobber fields populated by
                # other paths (analyst edits in the UI, observation-
                # time auto-classification, etc.).
                changed = False
                if r["display_name"] and r["display_name"] != victim.display_name:
                    victim.display_name = r["display_name"]
                    changed = True
                if r["type"] and VictimType(r["type"]) != victim.type:
                    victim.type = VictimType(r["type"])
                    changed = True
                if r["notes"] and r["notes"] != victim.notes:
                    victim.notes = r["notes"]
                    changed = True
                if changed:
                    updated += 1
                else:
                    unchanged += 1

        if not dry_run:
            await db.commit()

        prefix = "[yellow]would:[/yellow]" if dry_run else "[green]applied:[/green]"
        console.print(
            f"{prefix} +{added} added, ~{updated} updated, ={unchanged} unchanged"
        )
        ctx.status = 0

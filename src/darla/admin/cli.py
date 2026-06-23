"""``darla-admin`` — Typer app composition + entry point.

Each subcommand group is a self-contained Typer app under
:mod:`darla.admin`; this module just stitches them into a single
command tree::

    darla-admin user list
    darla-admin user disable <subject>
    darla-admin monitored-domain reload
    darla-admin monitored-domain list
    darla-admin victim reload --source <csv>
    darla-admin audit recent --since 7d --user cli:ops

Registered as a console script in ``pyproject.toml`` so it's on the
container's PATH after ``pip install``.
"""

from __future__ import annotations

import typer

from darla.admin import audit, monitored_domains, users, victims

app = typer.Typer(
    name="darla-admin",
    help=(
        "Administrative CLI for the Darla deployment.  Talks directly "
        "to the database; safe to run when the API is wedged or auth "
        "is misconfigured.  Access is controlled by AWS IAM (who can "
        "SSM into the container)."
    ),
    no_args_is_help=True,
)

app.add_typer(users.app, name="user")
app.add_typer(monitored_domains.app, name="monitored-domain")
app.add_typer(victims.app, name="victim")
app.add_typer(audit.app, name="audit")


if __name__ == "__main__":
    app()

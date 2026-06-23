"""``darla-admin`` — administrative CLI run inside the API container.

Why a separate CLI from the existing ``darla`` CLI:

* ``darla`` is the analyst-facing tool — talks to the API over HTTP.
  In an auth-enabled deployment it requires a token (currently
  unimplemented; see RFC §15 / the project_auth_plan memory).
* ``darla-admin`` is for operators — talks to the database directly,
  so it works even when the API is wedged, an IdP outage prevents
  authentication, or the CLI is being run from inside the container
  via ``aws ssm start-session``.

Access control comes from AWS IAM (who can SSM into the container).
There is no in-app role check on ``darla-admin`` — by the time you're
typing a command, you've already proven you can shell into prod.
Every invocation writes one row to ``audit_log`` with
``actor_subject='cli:<principal>'`` so the action is attributable.

See ``RFC 0001 §9`` in the deployment repo for the spec.
"""

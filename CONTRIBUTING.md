# Contributing to Darla

Thanks for helping. Darla is an anti-phishing research platform, so the
repository follows one rule above the others:

> **Code is public. Data and infrastructure are private.**

## What belongs in this repository

- Application code (`src/darla/`), the frontend, and Alembic migrations
- Generic / community YARA rules (`rules/*.yar`)
- Tests — with **fake** data only (`example.com`, `acme.test`, `a@x.com`)
- Default configuration (`.env.example`) with placeholder values
- Docs and install instructions

## What never belongs here

Anything specific to an organization running Darla stays in that
organization's own private deployment repository or secrets manager:

| Keep out of this repo | Why |
|---|---|
| `monitored_domains.yaml`, victim / HR CSV exports | Reveal who a deployment protects |
| Real victim email addresses — even base64-encoded inside a lure URL used as a test fixture | Personal data; also reveals the deployment's organization |
| Custom YARA rules with proprietary IOCs, `rules/user/` playground rules | May embed kit URLs or victim patterns |
| Tenant IDs, client IDs, object IDs, UPNs from a real IdP | Identity metadata |
| `.env` files, credentials, API keys, certificates | Secrets — use a secrets manager |
| Terraform / IaC, account IDs, hostnames, VPC layout | Infrastructure |

`.gitignore` covers the common file names, and CI runs
[gitleaks](https://github.com/gitleaks/gitleaks) on every push and pull
request — but neither catches personal data pasted into code, fixtures, or
commit messages. When you reproduce a real-world lure in a test, replace
the victim identity and the organization's domain with placeholders
**before** the first commit: once pushed to a public repository, it lives
in history.

## Development

See [README.md](README.md#development) for local setup. Before opening a
pull request:

```bash
ruff check .
pytest
cd frontend && npx eslint . && npm run build
```

CI runs the same checks. New API routes must declare an auth dependency —
`tests/test_auth/test_route_coverage.py` fails on any ungated route. Auth
and identity design lives in [docs/auth/](docs/auth/README.md).

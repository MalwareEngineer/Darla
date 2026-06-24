# Authentication

Darla supports OIDC authentication via any compliant identity provider. The
auth machinery is identical across providers — only configuration differs.

Three setup paths exist; pick the one that fits where you're running Darla.

## Which path do I follow?

| Use case | Doc | Time |
|---|---|---|
| Trying Darla locally, single user, evaluating the platform | [no-auth.md](no-auth.md) | 2 min |
| Deploying behind Microsoft Entra (Azure AD) | [entra.md](entra.md) | 15 min |
| Deploying behind Okta, Auth0, Keycloak, Authelia, Pocket-ID, or another OIDC provider | [oidc-generic.md](oidc-generic.md) | 15 min |

## How it works in one paragraph

When auth is enabled, every API request must carry a valid OIDC bearer token in
the `Authorization` header. The FastAPI middleware validates the token's
signature against the provider's JWKS, checks the issuer and audience, extracts
the user's stable subject identifier, and looks for a role claim mapping to
either `Darla.Viewer` (read-only) or `Darla.Analyst` (full access). A user
appearing for the first time is JIT-provisioned into the local `users` table;
subsequent logins refresh the user's display fields and IdP-derived role. A
local kill switch column (`disabled_at`) gives operators an instant revoke
lever via the `darla-admin` CLI.

When auth is **disabled**, six hardstop guardrails prevent the deployment
from being reachable anywhere that resembles production — see
[no-auth.md](no-auth.md) for the full list.

## Architecture quick reference

```
Browser → OIDC provider (sign-in) → Darla SPA (token in sessionStorage)
                                       │
                                       │ Authorization: Bearer <jwt>
                                       ▼
                              Darla API (FastAPI)
                                       │
                              ┌────────┴────────┐
                              │  JWKS validation │  ← provider's public keys
                              │  iss / aud check │
                              │  role claim     │  ← maps to Viewer/Analyst
                              │  JIT user upsert │
                              │  disabled_at?    │
                              └────────┬────────┘
                                       ▼
                              route handler runs
                                       │
                                       ▼
                              audit_log row written
                              X-Request-ID returned
```

## Common environment variables

These are universal across IdPs. The setup docs above describe how to fill them
in for each provider.

| Variable | Purpose |
|---|---|
| `PK_AUTH_ENABLED` | `true` to enforce auth, `false` for the no-auth / local-eval mode |
| `PK_OIDC_ISSUER` | Provider's issuer URL (e.g. `https://login.microsoftonline.com/<tenant>/v2.0`) |
| `PK_OIDC_AUDIENCE` | Expected `aud` claim — usually the API's client/application ID |
| `PK_OIDC_SUBJECT_CLAIM` | JSON path to the user's stable subject. Default `sub`. Entra deployments override to `oid`. |
| `PK_OIDC_ROLE_CLAIM` | JSON path to the role(s). Default `roles`. Supports dotted paths (e.g. `realm_access.roles` for Keycloak). |
| `PK_OIDC_VIEWER_ROLE_VALUE` | String the role claim must contain to grant viewer access. Default `Darla.Viewer`. |
| `PK_OIDC_ANALYST_ROLE_VALUE` | String the role claim must contain to grant analyst access. Default `Darla.Analyst`. |

Frontend has matching `VITE_AUTH_ENABLED`, `VITE_OIDC_AUTHORITY`,
`VITE_OIDC_CLIENT_ID`, `VITE_OIDC_API_SCOPE`.

## Verifying your setup

Once configured, sign in via the SPA at `http://localhost:5173`. The browser
flow should redirect to your IdP, sign in, and land back on the Darla
dashboard. The header will show your display name and role badge.

Pop open DevTools → Network → click any page in the SPA. The `/api/v1/*`
requests should carry `Authorization: Bearer eyJ...`. If they don't, the token
isn't being attached — check `VITE_AUTH_ENABLED=true` and rebuild.

Decode any access token at [jwt.io](https://jwt.io/) to verify the claims your
IdP is emitting. The `roles` claim is what the backend reads; if it's missing
or differently-named, adjust `PK_OIDC_ROLE_CLAIM`.

## Admin tooling

Once auth is on, sensitive administrative operations move to the operator
CLI accessed via `docker compose exec api darla-admin ...` (locally) or
`aws ssm start-session ...` (production). The CLI talks directly to the
database — it works even if the API is wedged or the IdP has an outage.

See the [main README](../../README.md#cli) and `darla-admin --help` for the
full command surface. Examples:

```bash
# List all users
docker compose exec api darla-admin user list

# Emergency-revoke a user's access (faster than waiting for IdP propagation)
docker compose exec api darla-admin user disable <oidc-subject>

# Sync the monitored-domain allowlist from a YAML file
docker compose exec api darla-admin monitored-domain reload --source /etc/darla/domains.yaml --dry-run

# Inspect recent audit-log activity
docker compose exec api darla-admin audit recent --since 7d --user <oidc-subject>
```

# Running Darla behind Microsoft Entra

Step-by-step Entra (Azure AD) setup with the gotchas called out. Estimated
time: 15 minutes, plus however long your IT team takes to provision the
production app registrations.

## What you'll create

Two app registrations in your Entra tenant:

| Registration | Type | Purpose |
|---|---|---|
| `Darla API` | Resource server | Defines the OIDC scope (`access_as_user`) and the two app roles (`Darla.Viewer`, `Darla.Analyst`) that grant access |
| `Darla SPA` | Single-page application | The React frontend. Public client (no secret). Has API permission to call `Darla API` |

Plus user-to-role assignment in the Enterprise Applications view.

## Choose your tenant

- **Production:** your organization's corporate Entra tenant. IT/Identity owns
  it; you submit a ticket asking them to provision the two app registrations
  using the spec below.
- **Local development:** any Entra tenant you have admin rights in. Options:
  - Your personal Microsoft account's "Default Directory" (free; sign in at
    [portal.azure.com](https://portal.azure.com) with an `@outlook.com` /
    `@hotmail.com` account)
  - A Microsoft 365 Developer Program sandbox tenant (subscription required as
    of recent changes)
  - A separate "Darla Dev" registration in the corporate tenant (requires IT
    to add a localhost redirect URI)

The instructions below work in any of them.

## Step 1 — Create the `Darla API` app registration

[portal.azure.com](https://portal.azure.com) → Microsoft Entra ID → App registrations → **New registration**.

| Field | Value |
|---|---|
| Name | `Darla API` |
| Supported account types | **Accounts in this organizational directory only (single tenant)** |
| Redirect URI | Leave blank — this is the resource server, not a client |

Click **Register**. On the overview page, copy and save:

- **Application (client) ID** — becomes `PK_OIDC_AUDIENCE`
- **Directory (tenant) ID** — becomes part of `PK_OIDC_ISSUER`

### Expose the API scope

Left sidebar → **Expose an API**:

1. **Application ID URI** → click **Add** → accept default `api://<client-id>` → Save
2. **Add a scope**:
   - Scope name: `access_as_user`
   - Who can consent: **Admins and users**
   - Admin consent display name: `Access Darla as the user`
   - Admin consent description: `Allows Darla to act on behalf of the signed-in user.`
   - State: **Enabled**
   - Click **Add scope**

### Define the app roles

Left sidebar → **App roles** → **Create app role**.

Create two roles. The `Value` field is what appears in the JWT's `roles`
claim — match these exactly.

**Role 1 — Viewer:**
- Display name: `Darla Viewer`
- Allowed member types: **Users/Groups**
- Value: `Darla.Viewer`
- Description: `Read-only access to Darla`
- Enabled: yes

**Role 2 — Analyst:**
- Display name: `Darla Analyst`
- Allowed member types: **Users/Groups**
- Value: `Darla.Analyst`
- Description: `Full analyst access — submit, reanalyze, annotate`
- Enabled: yes

### Critical — bump the manifest to v2 tokens

This is the one that catches people. Without this, your tokens come from the
legacy `sts.windows.net/<tenant>/` issuer instead of the modern
`login.microsoftonline.com/<tenant>/v2.0` issuer, and the backend's `iss`
validation will reject every request.

Left sidebar → **Manifest** → find `"accessTokenAcceptedVersion": null` (or
`1`) → change to `"accessTokenAcceptedVersion": 2` → **Save**.

To verify after sign-in, decode an access token at [jwt.io](https://jwt.io/)
and confirm:
- `"iss": "https://login.microsoftonline.com/<tenant-id>/v2.0"`
- `"ver": "2.0"`

If `iss` still starts with `sts.windows.net/`, the manifest change didn't
save — re-check the value.

## Step 2 — Create the `Darla SPA` app registration

Back to **App registrations** → **New registration**:

| Field | Value |
|---|---|
| Name | `Darla SPA` |
| Supported account types | **Accounts in this organizational directory only (single tenant)** |
| Redirect URI | Platform: **Single-page application (SPA)** — value: `http://localhost:5173/auth/callback` (for production, use your real hostname's `/auth/callback`) |

Click **Register**. Copy the **Application (client) ID** — becomes
`PK_OIDC_SPA_CLIENT_ID` and `VITE_OIDC_CLIENT_ID`.

### Grant the SPA permission to call the API

Still on the SPA registration:

1. Left sidebar → **API permissions** → **Add a permission**
2. Tab: **My APIs** → click **Darla API**
3. **Delegated permissions** → check `access_as_user` → **Add permissions**
4. Back on the permissions list, click **Grant admin consent for &lt;directory name&gt;** (button at the top)
5. Wait for the green checkmark next to `access_as_user`

## Step 3 — Assign yourself a role

App roles are *defined* on the app registration and *assigned* on the
enterprise application. This is a common confusion point — your role
definitions can exist without any users actually having the role.

Top search bar → **Enterprise applications** → click **Darla API** → left
sidebar → **Users and groups** → **Add user/group**:

- **Users:** select yourself (or whoever should have access)
- **Role:** pick `Darla Analyst` (or `Darla Viewer`)
- Click **Assign**

For production, IT typically prefers group-based assignment: assign a security
group (e.g. `sg-darla-analysts`) to the role instead of individual users, then
manage membership via your existing user lifecycle process.

## Step 4 — Wire it into Darla

In your project root `.env` (gitignored, do not commit):

```bash
PK_AUTH_ENABLED=true

# Issuer URL — note the /v2.0 suffix is mandatory
PK_OIDC_ISSUER=https://login.microsoftonline.com/<your-tenant-id>/v2.0

# The Darla API registration's client ID
PK_OIDC_AUDIENCE=<darla-api-client-id>

# Entra's stable subject is `oid`, not the default `sub` (which is pairwise)
PK_OIDC_SUBJECT_CLAIM=oid

# Defaults are correct for Entra app-role assignments
PK_OIDC_ROLE_CLAIM=roles
PK_OIDC_VIEWER_ROLE_VALUE=Darla.Viewer
PK_OIDC_ANALYST_ROLE_VALUE=Darla.Analyst

# Auth-enabled deployments bind to all interfaces
PK_BIND_ADDRESS=0.0.0.0
```

In `frontend/.env.local` (also gitignored):

```bash
VITE_AUTH_ENABLED=true
VITE_OIDC_AUTHORITY=https://login.microsoftonline.com/<your-tenant-id>/v2.0
VITE_OIDC_CLIENT_ID=<darla-spa-client-id>
VITE_OIDC_API_SCOPE=api://<darla-api-client-id>/access_as_user
```

Restart the stack:

```bash
docker compose up -d
cd frontend && npm run dev   # restart, not just hot-reload — Vite env vars only re-read on cold start
```

## Step 5 — Verify

1. Open `http://localhost:5173` in an incognito window
2. Browser redirects to `login.microsoftonline.com`
3. Sign in as the user you assigned to `Darla.Analyst`
4. Browser redirects back to `localhost:5173/auth/callback?code=...`
5. Briefly see "Completing sign-in…"
6. Land on the Darla dashboard
7. Header shows your display name + an `analyst` badge + Sign out button

Open DevTools → Network → click any page. The `/api/v1/*` requests should
carry an `Authorization: Bearer eyJ...` header.

### Sanity checks

**Sign in as a user with no role assignment** → expect to land on
`/unauthorized` with actionable copy. Sign out, assign yourself a role,
sign back in.

**Hit F5 on any page while signed in** → should NOT bounce through Entra
again. Session persistence works.

**Hit the API directly with no token:**
```bash
curl http://localhost:8000/api/v1/kits
# Expect: {"detail":"Missing Bearer token"} with HTTP 401
```

## Production migration

When ready to onboard real corp users:

1. **Corporate IT** creates two app registrations in the corp Entra tenant
   following the spec above (redirect URI = your production hostname's
   `/auth/callback`)
2. **Corporate IT** assigns security groups to the app roles (e.g.
   `sg-darla-analysts` → `Darla.Analyst`)
3. **Security team** applies a Conditional Access policy targeting the
   `Darla API` enterprise app — see the [Conditional Access ask](#conditional-access-policy-template) below
4. **Update your production environment** in your deployment repo's Terraform
   / Secrets Manager:
   - `PK_OIDC_ISSUER` → corp tenant issuer URL
   - `PK_OIDC_AUDIENCE` → corp `Darla API` client ID
   - Frontend env vars likewise at build time
   - `PK_AUTH_ENABLED=true` should be **hardcoded as a literal in the ECS task
     definition**, not pulled from Secrets Manager. This is a deliberate
     guardrail — see RFC §16.
5. **Deploy** — no application code changes between dev and prod
6. **First prod login** by a corp user creates their `User` row via JIT. Dev
   test users stay in your dev tenant; they don't migrate.

The dev tenant keeps existing for local development and CI testing forever.
It never connects to prod.

## Conditional Access policy template

Hand this to your security team when production goes live:

> Please apply a Conditional Access policy targeting the **Darla API**
> enterprise application:
>
> - **Users:** members of `sg-darla-analysts` and `sg-darla-viewers`
> - **Cloud apps:** `Darla API`
> - **Grant:** require **phishing-resistant MFA** (FIDO2 / Windows Hello for
>   Business / Entra Certificate-Based Authentication)
> - **Optional:** also require compliant device (Intune-managed)
>
> No Darla code change is needed — the policy is enforced by Entra at sign-in.

This is intentionally not blocking the implementation work; it gates the
production cutover.

## Troubleshooting

### "Invalid token: Invalid issuer"

The token's `iss` claim doesn't match `PK_OIDC_ISSUER`. Two common causes:

1. You set `accessTokenAcceptedVersion: 2` in the manifest but the user hasn't
   signed in since the change. Tokens are cached client-side; sign out and
   back in.
2. You forgot to change the manifest at all. Decode the token at jwt.io; if
   `"iss"` starts with `sts.windows.net/`, the manifest is still on v1.

### "No app role assigned in OIDC token"

The user signed in successfully but the token has no `roles` claim. Two
common causes:

1. You defined the app roles on the `Darla API` *registration* but never
   *assigned* the user to a role on the **Enterprise applications** view.
   Go to Enterprise applications → Darla API → Users and groups → Add the
   user with a role.
2. The user has a role assigned but it's case-mismatched — e.g. assignment
   value `darla.analyst` but `PK_OIDC_ANALYST_ROLE_VALUE=Darla.Analyst`.
   Comparison is case-sensitive. Pick one casing and use it consistently in
   both places.

### "Missing Bearer token"

The frontend isn't sending the Authorization header. Common causes:

1. `VITE_AUTH_ENABLED` is `false` (or unset) — the SPA never asks for a
   token. Set it to `true` and **restart** `npm run dev` (env vars only
   re-read on cold start).
2. The user signed in successfully but the OIDC subject claim was missing,
   so the middleware rejected before the SPA could store the token.

### "Redirect URI mismatch"

Entra received a sign-in attempt with a redirect URI that's not registered
on the SPA app registration. The URI must match exactly — same protocol,
hostname, port, and path. Common mistakes:

- Hitting `127.0.0.1:5173` instead of `localhost:5173` (different hostname)
- Hitting `localhost:3000` because you ran `npm run dev` with a non-default
  port
- Production hostname not added yet — IT only registered the dev URI

### Roles claim is in the access token but not the ID token

Both should have it for Entra by default after `accessTokenAcceptedVersion: 2`,
but if you see this in DevTools, the frontend code reads roles from the
access token directly (not the ID token) to stay aligned with what the
backend validates. This is the expected design; no fix needed.

### Browser keeps redirecting to Entra in a loop

Usually means the `/auth/callback` page failed to exchange the code for a
token. Open DevTools → Console; look for an error. Common causes:

- Browser blocked third-party cookies for `login.microsoftonline.com`
- The single-page-app platform wasn't selected in the SPA registration
  (defaulted to "Web" which expects a client secret)
- The authorization code was consumed twice (React 18 strict mode double-
  effect — this is guarded against in code, but if you've patched the
  callback, the latch may be broken)

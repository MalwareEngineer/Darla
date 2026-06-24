# Running Darla behind a generic OIDC provider

Darla's backend is IdP-agnostic — any OIDC-compliant provider works. This
guide covers the providers most commonly asked about, with per-provider gotchas
called out.

If you're using Microsoft Entra, follow [entra.md](entra.md) instead — it has
Entra-specific manifest and claim-shape detail this guide doesn't repeat.

## How OIDC integrates with Darla

Darla validates incoming JWTs against the provider's JWKS. Five things must
line up:

| What Darla checks | Where it's configured | Provider-side requirement |
|---|---|---|
| Issuer | `PK_OIDC_ISSUER` | Provider's `iss` claim must match exactly |
| Audience | `PK_OIDC_AUDIENCE` | Token's `aud` claim must contain this value (typically the API's client/application ID) |
| Subject | `PK_OIDC_SUBJECT_CLAIM` (default `sub`) | Provider must emit a stable per-user identifier in this claim |
| Role | `PK_OIDC_ROLE_CLAIM` (default `roles`) | Provider must emit a string or array containing the role values below |
| Role values | `PK_OIDC_VIEWER_ROLE_VALUE` / `PK_OIDC_ANALYST_ROLE_VALUE` | Provider must populate the role claim with these exact strings |

The role claim path is a dotted lookup with one fallback: top-level keys are
checked first as literal strings (so URL-namespaced custom claims work for
Auth0), then the path is split on `.` and walked through nested objects (so
`realm_access.roles` works for Keycloak).

## Choose a provider

| Provider | Hosted | Free tier | Best fit |
|---|---|---|---|
| [Okta](#okta) | ✓ | 1,000 MAU | Enterprise SSO, already-Okta orgs |
| [Auth0](#auth0) | ✓ | 25,000 MAU | Quick eval, B2C apps |
| [Keycloak](#keycloak) | self-hosted | n/a | Full control, no per-user costs |
| [Authelia](#authelia) | self-hosted | n/a | Minimal footprint, homelab/SMB |
| [Pocket-ID](#pocket-id) | self-hosted | n/a | Passkey-only, very simple |
| [Google Cloud Identity](#google-cloud-identity) | ✓ | 50 users free | Google-first orgs |

This guide walks through each in order. Skip to the one you're using.

---

## Okta

### Setup

1. Okta admin console → **Applications** → **Create App Integration**
2. Sign-in method: **OIDC - OpenID Connect** → Application type: **Single-Page Application**
3. **Sign-in redirect URIs:** `http://localhost:5173/auth/callback` (and your prod hostname later)
4. **Sign-out redirect URIs:** `http://localhost:5173`
5. **Controlled access:** pick how users get assigned (everyone, specific groups)
6. **Save**

Note the **Client ID** from the application's General tab.

### Groups → roles

Okta typically emits group membership as the `groups` claim. To map your
existing groups to Darla roles:

1. Create two Okta groups: `darla-viewers` and `darla-analysts`
2. Assign users to the appropriate group
3. In the SPA application → **Sign On** tab → **OpenID Connect ID Token** →
   **Groups claim filter** → set to `groups` matches regex `.*`
4. Verify by decoding a token at jwt.io — should see `"groups": ["darla-analysts", ...]`

### Wire it in

```bash
PK_AUTH_ENABLED=true
PK_OIDC_ISSUER=https://<your-org>.okta.com/oauth2/default
PK_OIDC_AUDIENCE=<spa-client-id>
PK_OIDC_SUBJECT_CLAIM=sub
PK_OIDC_ROLE_CLAIM=groups
PK_OIDC_VIEWER_ROLE_VALUE=darla-viewers
PK_OIDC_ANALYST_ROLE_VALUE=darla-analysts
PK_BIND_ADDRESS=0.0.0.0
```

```bash
# frontend/.env.local
VITE_AUTH_ENABLED=true
VITE_OIDC_AUTHORITY=https://<your-org>.okta.com/oauth2/default
VITE_OIDC_CLIENT_ID=<spa-client-id>
VITE_OIDC_API_SCOPE=openid profile email
```

### Gotchas

- **Different authorization servers.** Okta lets you have multiple. The
  `/oauth2/default` path is the "Default" server. If you use a custom one,
  swap that segment.
- **MFA enforcement.** Configure in Okta's **Security → Authenticators**
  policy targeting the Darla app, not in Darla.

---

## Auth0

### Setup

1. Auth0 dashboard → **Applications** → **Create Application**
2. **Single Page Web Application** → Create
3. **Settings** tab:
   - **Allowed Callback URLs:** `http://localhost:5173/auth/callback`
   - **Allowed Logout URLs:** `http://localhost:5173`
   - **Allowed Web Origins:** `http://localhost:5173`
4. Save

Note the **Client ID** and **Domain** from the Settings tab.

### Custom claim for roles

Auth0 doesn't emit a `roles` claim by default. You add it via a Post-Login
Action:

1. **Actions** → **Library** → **Build Custom**
2. Name: `Add Darla roles`
3. Trigger: **Login / Post Login**
4. Code:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const namespace = "https://darla.example/roles";
  // event.user.roles requires Auth0 RBAC enabled on the API
  // Or use event.user.app_metadata.roles for app-managed roles
  const roles = (event.user.app_metadata && event.user.app_metadata.roles) || [];
  api.idToken.setCustomClaim(namespace, roles);
  api.accessToken.setCustomClaim(namespace, roles);
};
```

5. **Deploy** → drag the action into the Login flow

Set each user's `app_metadata.roles` to `["Darla.Analyst"]` or
`["Darla.Viewer"]` via the user management UI or Management API.

### Wire it in

```bash
PK_AUTH_ENABLED=true
PK_OIDC_ISSUER=https://<your-tenant>.auth0.com/
PK_OIDC_AUDIENCE=<spa-client-id>
PK_OIDC_SUBJECT_CLAIM=sub

# The exact string from the namespace above — Darla's resolver matches it
# as a literal top-level key despite the slashes/dots in the URL.
PK_OIDC_ROLE_CLAIM=https://darla.example/roles

PK_OIDC_VIEWER_ROLE_VALUE=Darla.Viewer
PK_OIDC_ANALYST_ROLE_VALUE=Darla.Analyst
PK_BIND_ADDRESS=0.0.0.0
```

```bash
# frontend/.env.local
VITE_AUTH_ENABLED=true
VITE_OIDC_AUTHORITY=https://<your-tenant>.auth0.com/
VITE_OIDC_CLIENT_ID=<spa-client-id>
VITE_OIDC_API_SCOPE=openid profile email
```

### Gotchas

- **The trailing slash on the issuer matters.** Auth0 uses
  `https://<tenant>.auth0.com/` (with trailing `/`). Match it exactly.
- **Custom claim URL is a literal key**, not a path. Darla's claim resolver
  handles this — it tries top-level literal-key match before dotted-path
  walking.
- **API audience vs SPA client ID.** Auth0 also supports a separate "API"
  registration with its own audience. If you go that route, set
  `PK_OIDC_AUDIENCE` to the API's `Identifier` field, not the SPA's
  client ID, and request that audience in the SPA's scope.

---

## Keycloak

### Setup

In your Keycloak admin console, pick a realm (create one if needed):

1. **Clients** → **Create client**
   - Client type: **OpenID Connect**
   - Client ID: `darla`
   - Name: `Darla`
   - Next
2. **Capability config:**
   - Client authentication: **Off** (this is a public SPA client)
   - Standard flow: **On**
   - Next
3. **Login settings:**
   - Valid redirect URIs: `http://localhost:5173/*`
   - Web origins: `http://localhost:5173`
   - Save

### Realm roles

1. **Realm roles** → **Create role** → `Darla.Viewer` → Save
2. Repeat for `Darla.Analyst`

### Assign roles to users

1. **Users** → pick a user → **Role mapping** tab → **Assign role**
2. Filter: **Realm roles** → check `Darla.Analyst` or `Darla.Viewer` → Assign

### Wire it in

```bash
PK_AUTH_ENABLED=true
PK_OIDC_ISSUER=https://<keycloak-host>/realms/<realm-name>
PK_OIDC_AUDIENCE=darla
PK_OIDC_SUBJECT_CLAIM=sub

# Keycloak nests realm roles under realm_access.roles
PK_OIDC_ROLE_CLAIM=realm_access.roles

PK_OIDC_VIEWER_ROLE_VALUE=Darla.Viewer
PK_OIDC_ANALYST_ROLE_VALUE=Darla.Analyst
PK_BIND_ADDRESS=0.0.0.0
```

```bash
# frontend/.env.local
VITE_AUTH_ENABLED=true
VITE_OIDC_AUTHORITY=https://<keycloak-host>/realms/<realm-name>
VITE_OIDC_CLIENT_ID=darla
VITE_OIDC_API_SCOPE=openid profile
```

### Gotchas

- **Audience claim.** Keycloak doesn't put the client ID in `aud` by default
  — it puts it in `azp`. You may need to add an audience mapper:
  **Clients → darla → Client scopes → darla-dedicated → Add mapper →
  By configuration → Audience** → set "Included Client Audience" to `darla`.
- **Client scopes.** Keycloak ships a `roles` client scope by default that
  adds `realm_access.roles` to tokens. If you've customized scopes, verify
  it's still attached to the `darla` client.
- **HTTPS required for production.** Keycloak refuses cookies over plain HTTP
  for non-localhost origins. Use HTTPS or set `KC_HOSTNAME_STRICT_HTTPS=false`
  if you really need HTTP.

---

## Authelia

Authelia is a self-hosted authentication portal with OIDC support. Popular
for homelabs and SMB deployments.

### Setup

In your `authelia/configuration.yml`:

```yaml
identity_providers:
  oidc:
    hmac_secret: <random-64-char-string>
    issuer_certificate_chain: |
      -----BEGIN CERTIFICATE-----
      ...
    issuer_private_key: |
      -----BEGIN PRIVATE KEY-----
      ...
    clients:
      - client_id: darla
        client_name: Darla
        public: true
        authorization_policy: two_factor
        consent_mode: implicit
        redirect_uris:
          - http://localhost:5173/auth/callback
        scopes:
          - openid
          - profile
          - email
          - groups
        response_types:
          - code
        grant_types:
          - authorization_code
        userinfo_signed_response_alg: none
```

### Groups → roles

Authelia emits group membership as the `groups` claim when the `groups` scope
is requested. Define groups in your `users_database.yml`:

```yaml
users:
  alice:
    displayname: Alice
    password: <hashed>
    email: alice@example.com
    groups:
      - darla-analysts
  bob:
    displayname: Bob
    password: <hashed>
    email: bob@example.com
    groups:
      - darla-viewers
```

### Wire it in

```bash
PK_AUTH_ENABLED=true
PK_OIDC_ISSUER=https://<authelia-host>
PK_OIDC_AUDIENCE=darla
PK_OIDC_SUBJECT_CLAIM=sub
PK_OIDC_ROLE_CLAIM=groups
PK_OIDC_VIEWER_ROLE_VALUE=darla-viewers
PK_OIDC_ANALYST_ROLE_VALUE=darla-analysts
PK_BIND_ADDRESS=0.0.0.0
```

```bash
# frontend/.env.local
VITE_AUTH_ENABLED=true
VITE_OIDC_AUTHORITY=https://<authelia-host>
VITE_OIDC_CLIENT_ID=darla
VITE_OIDC_API_SCOPE=openid profile groups
```

### Gotchas

- **Scope request matters.** Authelia only emits `groups` if the `groups`
  scope is requested. Make sure it's in `VITE_OIDC_API_SCOPE` and in the
  client's scopes list.
- **First setup is verbose.** Authelia needs an issuer key and HMAC secret
  upfront. Generate with `openssl rand -hex 32` and `openssl genpkey
  -algorithm RSA -out issuer.key`.

---

## Pocket-ID

Pocket-ID is a passkey-only OIDC provider. Single binary, minimal config.
Strong fit if you're a small team and want phishing-resistant auth out of
the box.

### Setup

After installing Pocket-ID and signing in as admin:

1. **Applications** → **Add application**
   - Name: `Darla`
   - Callback URLs: `http://localhost:5173/auth/callback`
   - Logout URL: `http://localhost:5173`
2. Copy the **Client ID** and the **OIDC Discovery URL** shown after creation
3. **User Groups** → **Create group** → `darla-analysts`, `darla-viewers`
4. **Users** → assign each user to a group
5. Back on the application: **Allowed User Groups** → assign your two groups

### Wire it in

```bash
PK_AUTH_ENABLED=true
PK_OIDC_ISSUER=https://<pocket-id-host>
PK_OIDC_AUDIENCE=<client-id-from-pocket-id>
PK_OIDC_SUBJECT_CLAIM=sub
PK_OIDC_ROLE_CLAIM=groups
PK_OIDC_VIEWER_ROLE_VALUE=darla-viewers
PK_OIDC_ANALYST_ROLE_VALUE=darla-analysts
PK_BIND_ADDRESS=0.0.0.0
```

```bash
# frontend/.env.local
VITE_AUTH_ENABLED=true
VITE_OIDC_AUTHORITY=https://<pocket-id-host>
VITE_OIDC_CLIENT_ID=<client-id-from-pocket-id>
VITE_OIDC_API_SCOPE=openid profile email groups
```

### Why this is a great match for Darla

Darla hunts phishing kits — running it behind a passkey-only IdP eats your
own dog food. Pocket-ID users can't be phished because there's nothing to
phish. The platform's threat model and the operator's auth method line up.

---

## Google Cloud Identity

For Google Workspace-first orgs. Google Workspace Premium includes
Cloud Identity; standalone Cloud Identity Free covers up to 50 users.

### Setup

1. Google Cloud Console → **APIs & Services** → **Credentials** → **Create
   credentials** → **OAuth client ID**
2. Application type: **Web application**
3. Authorized redirect URIs: `http://localhost:5173/auth/callback`
4. Save

Copy the **Client ID** shown.

### Groups → roles

Google emits OAuth tokens, but the OIDC role/group claims require extra
work. Two approaches:

1. **Cloud Identity groups via Directory API.** Requires a service account
   with Directory API access and a custom claim mapping in your IAP / IAM
   config. Complex.
2. **App-side mapping.** Hardcode a mapping from `email` claim to role in
   your Darla deployment — simpler but doesn't scale.

For most Google Workspace deployments, the path of least resistance is to use
IAP (Identity-Aware Proxy) in front of Darla rather than configuring direct
OIDC. IAP handles group → role mapping at the proxy layer and forwards a
signed JWT to Darla.

This guide stops here because IAP integration is its own pattern. If you go
this route, point `PK_OIDC_ISSUER` at the IAP issuer URL and `PK_OIDC_AUDIENCE`
at the audience IAP signs with.

---

## General troubleshooting

The Darla-side troubleshooting from [entra.md's bottom section](entra.md#troubleshooting)
applies to any provider — the error messages reference the same env variables
regardless of which IdP emitted the token. Verify each step:

1. **Token signature.** `kid` in the JWT header must match a key in the
   provider's JWKS. If JWKS lookup fails: check `PK_OIDC_ISSUER` resolves to
   the OIDC discovery doc at `<issuer>/.well-known/openid-configuration`.
2. **Issuer match.** Decode at jwt.io. The `iss` claim must equal
   `PK_OIDC_ISSUER` byte-for-byte (mind trailing slashes).
3. **Audience match.** The `aud` claim must contain `PK_OIDC_AUDIENCE`.
4. **Subject present.** A non-empty value at the configured
   `PK_OIDC_SUBJECT_CLAIM` path.
5. **Role present.** A value at the configured `PK_OIDC_ROLE_CLAIM` path that
   matches one of `PK_OIDC_VIEWER_ROLE_VALUE` or `PK_OIDC_ANALYST_ROLE_VALUE`
   (case-sensitive).

If any of these fail, the backend rejects the request with 401 or 403 — the
detail message will name the specific check that failed.

## Contributing a new provider guide

If you've gotten Darla working behind an OIDC provider not listed here,
please open a PR adding a section to this doc. The format above
(setup → roles → wire-it-in → gotchas) is what reviewers will expect.

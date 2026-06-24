# Running Darla without authentication

For local evaluation, single-user development, or community quickstart use.

> **This mode is not safe for any deployment reachable from a network.** Six
> hardstop guardrails actively prevent it from starting in production-shaped
> environments, but the responsibility for not exposing it is yours. If you
> have more than one user, deploy behind an IdP — see
> [entra.md](entra.md) or [oidc-generic.md](oidc-generic.md).

## When to use this mode

- You want to try Darla locally without setting up an identity provider
- You're a single security researcher analyzing kits on your laptop
- You're contributing to Darla and need the platform running for development
- You're running a one-off analysis pipeline on a build server with no inbound
  traffic

## When NOT to use this mode

- More than one human will use the platform
- The platform will be reachable from a network beyond `127.0.0.1`
- You need an audit trail attributable to specific operators (the audit log
  still records every request, but `actor_subject` is NULL — you can see *what*
  happened, not *who* did it)
- You care about who saw which victim PII

## Quick start

In your project root `.env`:

```bash
PK_AUTH_ENABLED=false
PK_I_UNDERSTAND_AUTH_IS_OFF=yes-only-for-local-eval
PK_BIND_ADDRESS=127.0.0.1
PK_DEBUG=true
```

In `frontend/.env.local`:

```bash
VITE_AUTH_ENABLED=false
```

Then:

```bash
docker compose up -d
cd frontend && npm run dev
```

Open `http://localhost:5173`. The frontend renders directly with no login
flow; the API accepts requests with no `Authorization` header.

## The six guardrails

Auth-disabled mode is gated by six runtime controls. Five enforce at startup;
one logs per-request. They exist because "I'll just leave auth off for now" is
how production data ends up exposed.

### 1. Required acknowledgement token

`PK_I_UNDERSTAND_AUTH_IS_OFF` must equal the literal string
`yes-only-for-local-eval`. Any other value (including empty) refuses startup
with:

```
[guardrail] PK_AUTH_ENABLED=false requires PK_I_UNDERSTAND_AUTH_IS_OFF='yes-only-for-local-eval'.
```

The verbosity is intentional. Nobody types that string by accident.

### 2. Localhost-only bind

`PK_BIND_ADDRESS` must be `127.0.0.1`, `localhost`, or `::1`. Any other value
(notably `0.0.0.0`, the prod default) refuses startup. This prevents the
"I'll just turn auth off for a quick test" trap where the container ends up
listening on a routable interface.

### 3. Debug mode required

`PK_DEBUG=true`. Setting `PK_DEBUG=false` while auth is disabled refuses
startup — the combination of "no auth" plus "not debug" is exactly the shape
of an accidental production deployment.

### 4. AWS metadata service is unreachable

On startup, the process probes `http://169.254.169.254/latest/meta-data/` (the
AWS instance-metadata endpoint) with a 200ms timeout. If the endpoint
responds, the process refuses to start. Any response from that address means
the host is on AWS, and a no-auth deployment on AWS is unambiguously a
mistake.

### 5. `/health` endpoint reports unhealthy

`GET /api/v1/health` returns HTTP 503 with an empty body in disabled mode.
AWS ALB and ECS health checks treat a 503 as "do not route traffic to this
target." Overriding the healthcheck to accept 503 requires a deliberate
infrastructure change — guardrail #4 already refused to start anyway, so this
is belt-and-braces.

### 6. CRITICAL log per request

Every request in disabled mode emits a CRITICAL log line containing the
literal string `"AUTH DISABLED"` plus the client IP and path. A CloudWatch
metric filter or any log aggregator can alert on the literal string. Even if
the previous five guardrails were all defeated, the operator gets paged
within minutes of the first request.

The combination is intentionally over-determined. Running disabled-mode in
production requires deliberate sabotage — copying-pasting a stale dev `.env`
without reading what's in it won't do it.

## What works in no-auth mode

All read endpoints, all write endpoints, the YARA playground, the analysis
pipeline, file uploads. The platform behaves exactly like it did before auth
was added, with one nuance: every request still writes a row to `audit_log`,
but `actor_subject` is `NULL` and `auth_mode` is `disabled`. The audit log is
still useful for "what happened on this kit" investigations even without
attribution.

The frontend hides auth-specific UI affordances (no user badge in the header,
no sign-out button). The `/auth/callback` and `/unauthorized` routes still
exist but are dead — the callback bounces home, the unauthorized page is
unreachable.

## What's harder in no-auth mode

- **Operator attribution.** `audit_log.actor_subject` is `NULL` for every
  request. You can see "someone submitted kit X at time Y" but not which
  operator. If you need attribution for compliance or incident review, switch
  to authenticated mode.
- **PII access tracking.** Reads of `/victims/*` still write the returned IDs
  into `audit_log.extra.victim_ids`, but with NULL actor it's only useful as
  bulk-volume data ("kits viewed this hour"), not for "who saw this victim."
- **`darla-admin` audit attribution.** The CLI's `cli:<principal>` resolution
  falls back to `cli:unknown` when neither `AWS_PRINCIPAL_ARN` nor `SSM_USER`
  nor `USER` are set in the environment. For a single-developer local
  workflow, setting `USER` in your shell is enough; for shared local
  deployments, prefer authenticated mode.

## Upgrading to authenticated mode

You can swap an existing no-auth deployment to authenticated mode in place:

1. Set up your IdP per [entra.md](entra.md) or [oidc-generic.md](oidc-generic.md)
2. In your `.env`, change `PK_AUTH_ENABLED` to `true` and remove the
   `PK_I_UNDERSTAND_AUTH_IS_OFF` line (or leave it; it's ignored when auth is
   on). Add the four `PK_OIDC_*` variables.
3. Change `PK_BIND_ADDRESS=0.0.0.0` so the container is reachable beyond
   localhost.
4. Change `frontend/.env.local`'s `VITE_AUTH_ENABLED` to `true` and add the
   three `VITE_OIDC_*` variables.
5. Restart the stack.

Existing data (kits, indicators, audit rows) is preserved. Pre-auth audit
rows keep their `NULL` actor; post-auth rows get the OIDC subject.

## Common pitfalls

**"My container isn't starting and I see a guardrail error."**
Read the guardrail message — it names the specific environment variable that's
wrong. The messages are designed to be self-correcting.

**"I want to expose this to my team without setting up an IdP."**
Don't. The localhost-bind guardrail will refuse, and even if you patched
around it, you'd have no audit attribution. Set up Authelia or Pocket-ID —
both are self-hosted, free, and take less than an hour. See
[oidc-generic.md](oidc-generic.md).

**"I'm running this in a VM and the metadata-service check fails."**
The VM's metadata endpoint (Azure, GCP, or Hyper-V) probably matches the AWS
IMDS pattern. The guardrail's intent is correct — you should not run no-auth
mode on a cloud VM. If you really need to, the workaround is firewalling
`169.254.169.254` outbound, but you should reconsider whether auth-disabled is
the right mode.

**"I see `CRITICAL AUTH DISABLED` lines flooding my logs."**
That's the guardrail working. Either set up authentication, or pipe the logs
to a sink with a higher severity threshold for local-dev work.

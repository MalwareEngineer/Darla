/**
 * OIDC client configuration — read from Vite env vars at build time.
 *
 * Default mode is **auth disabled** (community / local-evaluation),
 * matching the backend's `PK_AUTH_ENABLED=false` default.  Production
 * builds set `VITE_AUTH_ENABLED=true` plus the four OIDC values via
 * the deployment-repo Terraform.
 *
 * IdP examples (see RFC 0001 §8.2):
 *
 *   Entra:    VITE_OIDC_AUTHORITY=https://login.microsoftonline.com/<tenant>/v2.0
 *             VITE_OIDC_API_SCOPE=api://<api-client-id>/access_as_user
 *
 *   Okta:     VITE_OIDC_AUTHORITY=https://<your-org>.okta.com/oauth2/default
 *             VITE_OIDC_API_SCOPE=darla.access
 *
 *   Keycloak: VITE_OIDC_AUTHORITY=https://<host>/realms/<realm>
 *             VITE_OIDC_API_SCOPE=darla
 */
import type { UserManagerSettings } from "oidc-client-ts";

export interface OidcEnv {
  enabled: boolean;
  authority: string;
  clientId: string;
  apiScope: string;
}

/**
 * Reads the four `VITE_*` auth vars at build time.  Returns an
 * `enabled: false` shape when `VITE_AUTH_ENABLED` isn't truthy or
 * any required value is missing — the AuthProvider then short-circuits
 * to disabled mode rather than crashing on a half-configured build.
 */
export function readOidcEnv(): OidcEnv {
  const enabled = String(import.meta.env.VITE_AUTH_ENABLED ?? "").toLowerCase() === "true";
  const authority = String(import.meta.env.VITE_OIDC_AUTHORITY ?? "");
  const clientId = String(import.meta.env.VITE_OIDC_CLIENT_ID ?? "");
  const apiScope = String(import.meta.env.VITE_OIDC_API_SCOPE ?? "");

  // Half-configured builds (`VITE_AUTH_ENABLED=true` but missing IDs)
  // are treated as disabled — better to render an unauthenticated UI
  // and let the backend reject than to render a broken login redirect.
  if (enabled && (!authority || !clientId || !apiScope)) {
    // Visible-on-purpose console warning so the developer notices.
    console.warn(
      "[auth] VITE_AUTH_ENABLED=true but one or more of " +
        "VITE_OIDC_AUTHORITY / VITE_OIDC_CLIENT_ID / VITE_OIDC_API_SCOPE " +
        "is missing — falling back to disabled mode.",
    );
    return { enabled: false, authority: "", clientId: "", apiScope: "" };
  }

  return { enabled, authority, clientId, apiScope };
}

/**
 * Build the `oidc-client-ts` UserManager settings from the env.
 *
 * Notes on the choices:
 *
 * - `response_type: "code"` + automatic PKCE (the default in
 *   oidc-client-ts v3) — the only safe public-client flow per
 *   OAuth 2.1.
 * - `scope: "openid profile email <api-scope>"` — `openid` is required;
 *   `profile`+`email` get us name/upn for display; the API scope is
 *   what makes the access token usable against the Darla API.
 * - `redirect_uri` derived from `window.location.origin` so the same
 *   build serves any hostname (localhost dev, prod hostname).
 *   The IdP's app registration must list every origin × `/auth/callback`
 *   pair — see RFC §10.3 / §11.
 * - `loadUserInfo: false` — Entra's `roles` claim is in the access
 *   token, not the userinfo endpoint, and userinfo is per-app-pairwise
 *   on Entra anyway.  Skipping the extra round-trip avoids confusion.
 * - WebStorage default (`sessionStorage`) — fine for an internal tool
 *   per RFC §3 decision #15; httpOnly-cookie BFF is over-engineered
 *   for the current scale.
 */
export function buildUserManagerSettings(env: OidcEnv): UserManagerSettings {
  if (!env.enabled) {
    throw new Error("buildUserManagerSettings called in disabled mode");
  }
  const origin = window.location.origin;
  return {
    authority: env.authority,
    client_id: env.clientId,
    redirect_uri: `${origin}/auth/callback`,
    post_logout_redirect_uri: origin,
    response_type: "code",
    scope: `openid profile email ${env.apiScope}`,
    loadUserInfo: false,
    automaticSilentRenew: true,
    // Renew 60s before expiry — leaves headroom for clock skew + the
    // ~1s round-trip without ever serving a request with a token
    // that's about to expire.
    accessTokenExpiringNotificationTimeInSeconds: 60,
  };
}

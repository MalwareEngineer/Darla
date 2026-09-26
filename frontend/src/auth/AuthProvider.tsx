/**
 * Auth context provider — single source of truth for the UI's auth state.
 *
 * Two distinct modes selected at provider mount based on `readOidcEnv()`:
 *
 * 1. **Disabled** (`VITE_AUTH_ENABLED!=="true"`) — the provider is a
 *    pass-through.  `user` is `null`, all guards no-op, `getAccessToken`
 *    returns `null`, the API client sends no Authorization header.
 *    The backend's disabled-mode (RFC §16) accepts the request.  No
 *    OIDC code path runs.
 *
 * 2. **Enabled** — wraps an `oidc-client-ts` `UserManager`.  On mount,
 *    tries `getUser()` → if a stored session exists we're logged in;
 *    otherwise the consumer (typically `AuthGate`) calls `signIn()` to
 *    redirect to the IdP.  Listens for `userLoaded` / `userUnloaded` /
 *    `silentRenewError` events and re-renders.  Registers an access-
 *    token getter with `lib/auth-token.ts` so the API client picks up
 *    fresh tokens after silent refresh.
 *
 * Roles come from the configured role claim on the access token.  The
 * frontend doesn't enforce role gates server-side — the backend does
 * the authoritative check in `darla.auth.middleware.require_role`.
 * Frontend role-gating only hides UI affordances the user can't use,
 * which is a UX nicety, not a security boundary.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { User, UserManager } from "oidc-client-ts";
import { buildUserManagerSettings, readOidcEnv } from "./oidcConfig";
import { setAccessTokenGetter } from "@/lib/auth-token";
import { AuthContext, type AuthContextValue, type AuthUser, type Role } from "./authContext";


/** Wire the OIDC role claim into our two-tier role enum. */
function pickRole(roles: string[] | undefined): Role | null {
  if (!roles || roles.length === 0) return null;
  // Mirror the backend's higher-tier-wins semantics
  // (darla.auth.middleware._map_role).  Frontend role-gating must
  // match what the backend will allow, otherwise we'd hide buttons
  // the user could actually use.
  if (roles.includes("Darla.Analyst")) return "analyst";
  if (roles.includes("Darla.Viewer")) return "viewer";
  return null;
}

/**
 * Decode a JWT's payload segment.  No signature verification — the
 * backend is the authoritative validator (see darla.auth.middleware).
 * We just need to inspect claims for UI display.
 *
 * Returns `{}` on any error rather than throwing — a malformed token
 * is treated as "no claims", which collapses to a 403-equivalent UI
 * state and forces a fresh sign-in.
 */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return {};
    // JWT uses base64url (URL-safe variant) — convert to standard
    // base64 for atob, padding with '=' as needed.
    let payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (payload.length % 4) payload += "=";
    return JSON.parse(atob(payload)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** Convert an `oidc-client-ts` `User` into our flatter shape.
 *
 * Identity fields (subject, name, upn) come from the ID token via
 * `user.profile` — that's its semantic purpose.  But **roles come
 * from the access token**, because that's what the backend's
 * `darla.auth.middleware` will validate against.
 *
 * Why this matters: Entra (and some other IdPs) emit app-role
 * assignments only in the access token by default — the ID token's
 * `roles` claim, when present at all, may carry different content
 * (directory roles like "Global Admin", not app-role assignments).
 * Reading roles from `user.profile` made the UI think a freshly-
 * assigned analyst had no role, and gated them onto /unauthorized
 * while the backend would have happily accepted them.  Decode the
 * access token instead so the UI and the API always agree.
 */
function toAuthUser(user: User): AuthUser {
  const idClaims = user.profile as Record<string, unknown>;
  const accessClaims = decodeJwtPayload(user.access_token);

  // Identity — ID token is the right source.  Fall back to access
  // token's `oid`/`sub` if a custom subject claim configured
  // upstream isn't in the ID token.
  const subject = String(
    idClaims.sub ?? idClaims.oid ?? accessClaims.oid ?? accessClaims.sub ?? "",
  );
  const displayName = String(
    idClaims.name ?? accessClaims.name ?? idClaims.preferred_username ?? subject,
  );
  const upn = String(
    idClaims.preferred_username ??
      idClaims.email ??
      accessClaims.preferred_username ??
      accessClaims.email ??
      "",
  );

  // Authorization — access token is the right source (must match
  // what the backend sees).  ID token roles is a last-resort fallback
  // for IdPs that put roles only in the ID token.
  const rawRoles = accessClaims.roles ?? idClaims.roles;
  const roles = Array.isArray(rawRoles) ? rawRoles.map(String) : [];

  return { subject, displayName, upn, role: pickRole(roles) };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const env = useMemo(() => readOidcEnv(), []);
  const userManagerRef = useRef<UserManager | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState<boolean>(env.enabled);
  const [error, setError] = useState<Error | null>(null);
  // Hold the live oidc-client User so getAccessToken can read fresh
  // tokens after silent renew.  Refs (not state) because we don't
  // want React re-renders on every silent-refresh tick.
  const oidcUserRef = useRef<User | null>(null);

  // ── Disabled-mode short circuit ──────────────────────────────────
  // No effects, no UserManager construction, nothing.
  // Memoised value below renders an inert provider.

  // ── Enabled-mode setup ───────────────────────────────────────────
  useEffect(() => {
    if (!env.enabled) return;

    const um = new UserManager(buildUserManagerSettings(env));
    userManagerRef.current = um;

    // Register the token getter with the API client BEFORE doing
    // anything async — first-render API calls (e.g. health) need to
    // see the registered getter even if it returns null briefly.
    setAccessTokenGetter(() => oidcUserRef.current?.access_token ?? null);

    // Subscribe to the events oidc-client emits across the session
    // lifecycle.  Storage events fire when a SECOND tab signs in/out
    // — we react so multi-tab UX is consistent.
    const onLoaded = (loaded: User) => {
      oidcUserRef.current = loaded;
      setUser(toAuthUser(loaded));
      setError(null);
    };
    const onUnloaded = () => {
      oidcUserRef.current = null;
      setUser(null);
    };
    const onSilentError = (e: Error) => {
      // Silent refresh failed — token will eventually expire and
      // requests will start 401-ing.  Surface it to AuthGate which
      // triggers a fresh sign-in redirect.
      console.warn("[auth] silent renew failed:", e);
      setError(e);
    };

    um.events.addUserLoaded(onLoaded);
    um.events.addUserUnloaded(onUnloaded);
    um.events.addSilentRenewError(onSilentError);

    // On mount: do we already have a stored session?  This handles
    // the page-reload case — no need to redirect through the IdP
    // again if we have a still-valid refresh token.
    void um
      .getUser()
      .then((stored) => {
        if (stored && !stored.expired) {
          oidcUserRef.current = stored;
          setUser(toAuthUser(stored));
        }
      })
      .catch((e) => {
        console.warn("[auth] getUser() failed:", e);
        setError(e instanceof Error ? e : new Error(String(e)));
      })
      .finally(() => setLoading(false));

    return () => {
      um.events.removeUserLoaded(onLoaded);
      um.events.removeUserUnloaded(onUnloaded);
      um.events.removeSilentRenewError(onSilentError);
    };
  }, [env]);

  const signIn = useCallback(async () => {
    if (!env.enabled || !userManagerRef.current) return;
    // Stash the path the user was trying to reach so the post-signin
    // redirect drops them where they expected to be.  Excluded paths:
    // /auth/callback (would loop) and /unauthorized (no role assigned —
    // signing in again won't help).
    const here = window.location.pathname + window.location.search;
    const safe =
      here.startsWith("/auth/") || here.startsWith("/unauthorized") ? "/" : here;
    await userManagerRef.current.signinRedirect({ state: { return_to: safe } });
  }, [env.enabled]);

  const signOut = useCallback(async () => {
    if (!env.enabled || !userManagerRef.current) return;
    try {
      // signoutRedirect hits the IdP's end_session endpoint; if the
      // IdP doesn't support it (older Entra deployments), oidc-client
      // throws — fall back to local-only removal.
      await userManagerRef.current.signoutRedirect();
    } catch (e) {
      console.warn("[auth] IdP signout failed, removing local session:", e);
      await userManagerRef.current.removeUser();
      setUser(null);
      window.location.href = "/";
    }
  }, [env.enabled]);

  const getAccessToken = useCallback(
    (): string | null => oidcUserRef.current?.access_token ?? null,
    [],
  );

  const value: AuthContextValue = useMemo(
    () => ({
      authEnabled: env.enabled,
      loading,
      user,
      signIn,
      signOut,
      getAccessToken,
      error,
    }),
    [env.enabled, loading, user, signIn, signOut, getAccessToken, error],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

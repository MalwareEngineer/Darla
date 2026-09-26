/**
 * /auth/callback — OIDC redirect-back handler.
 *
 * The IdP redirects the browser here after the user signs in.  The
 * URL carries `?code=...&state=...`; we hand it to oidc-client-ts'
 * `signinRedirectCallback`, which exchanges the code for tokens and
 * stores the User in the configured WebStorage.
 *
 * We construct a fresh UserManager here rather than using the one
 * from `AuthProvider` because:
 *
 * 1. AuthProvider's UserManager is created in a `useEffect` — by the
 *    time this component renders, AuthProvider's effect may not have
 *    run yet.  Constructing one here avoids the race.
 * 2. The Callback page renders OUTSIDE the normal Shell so we don't
 *    pull in the rest of the app while we're just handling the
 *    code exchange.
 *
 * The two UserManager instances share the same WebStorage backing
 * store (defaulting to sessionStorage), so once `signinRedirectCallback`
 * persists the User, AuthProvider's `getUser()` finds it on next mount.
 */

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { UserManager } from "oidc-client-ts";
import { buildUserManagerSettings, readOidcEnv } from "./oidcConfig";

interface CallbackState {
  return_to?: string;
}

export function AuthCallback() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  // Strict-mode guards: React 18+ runs effects twice in dev, which
  // would call signinRedirectCallback twice and consume the
  // authorization code twice (the second call always fails — codes
  // are single-use).  A ref-tracked latch prevents that.
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;

    const env = readOidcEnv();
    if (!env.enabled) {
      // Someone hit /auth/callback in disabled mode — nothing to do,
      // bounce them home.
      navigate("/", { replace: true });
      return;
    }

    const um = new UserManager(buildUserManagerSettings(env));
    um.signinRedirectCallback()
      .then((user) => {
        const state = (user.state as CallbackState | undefined) ?? {};
        const target = state.return_to ?? "/";
        // Replace so the browser back button doesn't return to
        // /auth/callback (which would just bounce again).
        navigate(target, { replace: true });
      })
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : String(e);
        console.error("[auth/callback] sign-in failed:", e);
        setError(msg);
      });
  }, [navigate]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6">
        <div className="max-w-md rounded-lg border border-destructive/40 bg-destructive/5 p-6 text-sm">
          <h1 className="text-lg font-semibold text-destructive">Sign-in failed</h1>
          <p className="mt-2 text-foreground">
            The identity provider returned an error during sign-in. This usually
            means the redirect URI isn't registered, the authorization code
            already expired, or the IdP rejected the request.
          </p>
          <pre className="mt-3 overflow-auto rounded bg-muted p-2 text-xs text-muted-foreground">
            {error}
          </pre>
          <button
            type="button"
            onClick={() => navigate("/", { replace: true })}
            className="mt-4 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Return to home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <p className="text-sm text-muted-foreground">Completing sign-in…</p>
    </div>
  );
}

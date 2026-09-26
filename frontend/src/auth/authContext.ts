/**
 * Auth context object + its types, split out of AuthProvider.tsx so that
 * file exports only a component (React Fast Refresh requirement).
 */

import { createContext } from "react";

export type Role = "viewer" | "analyst";

export interface AuthUser {
  /** Stable subject identifier from the configured subject claim. */
  subject: string;
  /** Display name (token's `name` claim, falls back to UPN/subject). */
  displayName: string;
  /** UPN / preferred_username — typically email-shaped. */
  upn: string;
  /** Effective role derived from the token's role claim. */
  role: Role | null;
}

export interface AuthContextValue {
  /** Build-time mode flag.  Stable for the life of the app. */
  authEnabled: boolean;

  /** True while the provider is determining initial state. */
  loading: boolean;

  /** Authenticated user, or `null` when not signed in / disabled mode. */
  user: AuthUser | null;

  /** Trigger a redirect-to-IdP sign-in.  No-op in disabled mode. */
  signIn: () => Promise<void>;

  /** Sign out locally and (when supported) at the IdP. */
  signOut: () => Promise<void>;

  /** Returns the current access token, or null. */
  getAccessToken: () => string | null;

  /** Last sign-in / silent-renew error, if any.  Used by AuthGate. */
  error: Error | null;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

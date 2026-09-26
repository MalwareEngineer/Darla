/**
 * `useAuth` — read the current auth state from anywhere in the tree.
 *
 * Usage:
 *
 *   const { user, signOut, authEnabled } = useAuth();
 *   if (user?.role === "analyst") return <ReanalyzeButton />;
 *
 * Throws if the consuming component isn't wrapped in `AuthProvider` —
 * a rendering bug, not a runtime configuration choice, so we want a
 * loud failure rather than a silent null.
 */
import { useContext } from "react";
import { AuthContext, type AuthContextValue } from "./authContext";

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error(
      "useAuth() called outside <AuthProvider>.  Wrap the component " +
        "tree with <AuthProvider> in main.tsx.",
    );
  }
  return ctx;
}

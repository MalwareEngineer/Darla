/**
 * Component-level role gate.  Wraps children that should only render
 * for a specific minimum role.
 *
 * Usage:
 *
 *   <RequireRole role="analyst">
 *     <ReanalyzeButton />
 *   </RequireRole>
 *
 *   <RequireRole role="analyst" fallback={<p>Read-only mode.</p>}>
 *     <KitSubmitForm />
 *   </RequireRole>
 *
 * Important: this is a UX nicety, not a security boundary.  The
 * authoritative check happens server-side in
 * `darla.auth.middleware.require_role`.  A user who bypasses this
 * guard (e.g. by editing the bundled JS) still gets 403 from the API.
 *
 * In disabled mode, all gates pass — there's no role concept and
 * the localhost-only bind keeps the surface trivially safe.
 */

import type { ReactNode } from "react";
import type { Role } from "./authContext";
import { useAuth } from "./useAuth";

// Re-export so callers can `import { Role } from "@/auth/RequireRole"`
// without importing from AuthProvider directly.
export type { Role };

export interface RequireRoleProps {
  role: Role;
  children: ReactNode;
  /** Rendered when the user lacks `role`.  Default: nothing. */
  fallback?: ReactNode;
}

export function RequireRole({ role, children, fallback = null }: RequireRoleProps) {
  const { authEnabled, user } = useAuth();

  // Disabled mode — gates are no-ops.
  if (!authEnabled) return <>{children}</>;

  // Auth on but no user yet (loading window) — treat as "not allowed
  // yet".  AuthGate will have triggered the sign-in redirect; this
  // gate just hides the button until the user actually appears.
  if (!user || user.role === null) return <>{fallback}</>;

  // Two-tier lattice mirroring the backend: analyst ⊃ viewer.
  const allowed = role === "viewer" ? true : user.role === "analyst";
  return <>{allowed ? children : fallback}</>;
}

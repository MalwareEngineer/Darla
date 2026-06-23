"""Route-coverage lint — RFC 0001 Phase 4 default-deny enforcement.

Every route mounted under ``/api/v1/`` must either authenticate the
caller (via ``Depends(current_user)`` somewhere in its dependency
tree) or be explicitly listed in :data:`ANONYMOUS_ALLOWLIST` below.

This is the load-bearing test that catches the common foot-gun:
"new endpoint added, dev forgot the auth dependency, ships to prod
serving sensitive data anonymously."  Adding a route without a gate
breaks CI, not production.

How it works:

1. Import the FastAPI app to enumerate routes.
2. For each ``APIRoute`` under ``/api/v1/``, walk its
   ``dependant`` tree (the router-level deps + per-route deps +
   transitive deps each of those bring in).
3. Pass if ``current_user`` appears anywhere in that tree.
4. Pass if the route's path is in the explicit anonymous allowlist
   (just ``/api/v1/health``, the load-balancer probe).
5. Fail otherwise, naming the route so the failure tells you exactly
   what to fix.

To add a new genuinely-anonymous route, you must edit both the
allowlist AND justify the addition in the PR description.  The
deliberate friction is the point.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from darla.auth.middleware import current_user
from darla.main import app

# Routes that are intentionally anonymous.  Every entry should have a
# matching reason — RFC reference or specific design constraint.
ANONYMOUS_ALLOWLIST: set[tuple[str, str]] = {
    # GET /api/v1/health — Liveness probe for ALBs / ECS.  Returns
    # 200/503 with empty body; non-disclosing to anonymous callers
    # per RFC §17.4.  Disabled-mode returns 503 (RFC §16 guardrail #5)
    # so load balancers refuse traffic.
    ("GET", "/api/v1/health"),
}


def _dependency_uses_current_user(dep) -> bool:
    """Recursively check if a Dependant references ``current_user``.

    ``require_role(...)`` constructs an inner async function that
    declares ``Depends(current_user)`` — so any route gated by
    ``require_role`` automatically satisfies this check via the
    transitive dependency chain.
    """
    if dep.call is current_user:
        return True
    return any(_dependency_uses_current_user(sub) for sub in dep.dependencies)


def _api_routes() -> list[APIRoute]:
    return [
        r for r in app.routes
        if isinstance(r, APIRoute) and r.path.startswith("/api/v1/")
    ]


def test_route_coverage_baseline_exists():
    """Sanity: the app actually has routes.  Without this guard, a
    completely empty router list would trivially pass the per-route
    test below."""
    routes = _api_routes()
    assert len(routes) > 20, (
        f"Suspiciously few /api/v1 routes registered: {len(routes)}.  "
        "Check that all sub-routers are wired into darla.api.router."
    )


@pytest.mark.parametrize(
    "route",
    _api_routes(),
    ids=lambda r: f"{sorted(r.methods)[0]} {r.path}",
)
def test_route_is_gated_or_explicitly_anonymous(route: APIRoute):
    """Every API route must require ``current_user`` (directly or via
    ``require_role``) unless explicitly listed in
    :data:`ANONYMOUS_ALLOWLIST`.

    To fix a failure: add ``Depends(current_user)`` (typically at the
    router level in ``darla.api.router``) or, if the route genuinely
    must be anonymous, add it to the allowlist above with a comment
    explaining why.
    """
    methods = sorted(route.methods or {"GET"})
    primary_method = methods[0]  # Routes usually have one method; pick first

    # Explicit anonymous allowlist short-circuits the check.
    allowlist_key = (primary_method, route.path)
    if allowlist_key in ANONYMOUS_ALLOWLIST:
        return

    # Otherwise the dependency tree must include current_user.
    gated = _dependency_uses_current_user(route.dependant)
    assert gated, (
        f"{primary_method} {route.path} is not gated by current_user "
        f"and is not in ANONYMOUS_ALLOWLIST.  Either add "
        f"`Depends(current_user)` (or `Depends(require_role(...))`) "
        f"to the route, or add the route to the allowlist with a "
        f"justification."
    )


def test_writes_require_analyst_role():
    """Write endpoints (POST/PUT/DELETE that mutate state) must carry
    ``require_role(UserRole.ANALYST)`` somewhere in their dep tree.

    This is a softer check than the gate test — we can't perfectly
    detect "mutation" from route metadata, so this whitelist of
    KNOWN write endpoints documents the intent.  If a write route
    is added without the analyst gate, this test fails by absence
    in the whitelist.  (False negatives are possible if a new write
    sneaks in without being listed; the gate test above still
    catches anonymous access.  This test catches "viewer can write".)
    """
    from darla.auth.middleware import require_role

    # Expected ANALYST-gated routes — keep alphabetised within each
    # method for ease of review.
    EXPECTED_ANALYST_WRITES: set[tuple[str, str]] = {
        ("DELETE", "/api/v1/actors/{actor_id}"),
        ("DELETE", "/api/v1/campaigns/{campaign_id}"),
        ("DELETE", "/api/v1/families/{family_id}"),
        ("DELETE", "/api/v1/investigations/{investigation_id}"),
        ("DELETE", "/api/v1/kits/{kit_id}"),
        ("DELETE", "/api/v1/phishmatch/kit/{kit_id}/attribute"),
        ("DELETE", "/api/v1/yara/rules/user/{name}"),
        # Not a write but reveals deployment shape — analyst-gated per
        # RFC §17.4 non-disclosure rule.  Anonymous /health is the
        # liveness probe; /health/detail is the triage endpoint.
        ("GET", "/api/v1/health/detail"),
        ("POST", "/api/v1/actors"),
        ("POST", "/api/v1/actors/{actor_id}/link"),
        ("POST", "/api/v1/campaigns"),
        ("POST", "/api/v1/campaigns/{campaign_id}/kits"),
        ("POST", "/api/v1/families"),
        ("POST", "/api/v1/families/{family_id}/actors"),
        ("POST", "/api/v1/families/{family_id}/kits"),
        ("POST", "/api/v1/investigations"),
        ("POST", "/api/v1/investigations/bulk-delete"),
        ("POST", "/api/v1/investigations/upload"),
        ("POST", "/api/v1/kits"),
        ("POST", "/api/v1/kits/bulk"),
        ("POST", "/api/v1/kits/bulk-delete"),
        ("POST", "/api/v1/kits/upload"),
        ("POST", "/api/v1/kits/upload/bulk"),
        ("POST", "/api/v1/kits/{kit_id}/add-to-actor"),
        ("POST", "/api/v1/kits/{kit_id}/add-to-campaign"),
        ("POST", "/api/v1/kits/{kit_id}/add-to-family"),
        ("POST", "/api/v1/kits/{kit_id}/reanalyze"),
        ("POST", "/api/v1/phishmatch/kit/{kit_id}/attribute"),
        ("POST", "/api/v1/yara/compile"),
        ("POST", "/api/v1/yara/playground"),
        ("PUT", "/api/v1/actors/{actor_id}"),
        ("PUT", "/api/v1/campaigns/{campaign_id}"),
        ("PUT", "/api/v1/families/{family_id}"),
        ("PUT", "/api/v1/investigations/{investigation_id}"),
        ("PUT", "/api/v1/yara/rules/user/{name}"),
    }

    actual_analyst_gated: set[tuple[str, str]] = set()

    def _dep_uses_require_role(dep) -> bool:
        # ``require_role(...)`` returns a closure named ``_dep`` whose
        # ``__qualname__`` includes the literal ``"require_role"``.
        # That's how we detect it through the dep tree without
        # reaching into FastAPI internals.
        call = dep.call
        if callable(call) and "require_role" in getattr(call, "__qualname__", ""):
            return True
        return any(_dep_uses_require_role(sub) for sub in dep.dependencies)

    for route in _api_routes():
        if _dep_uses_require_role(route.dependant):
            for m in route.methods or {"GET"}:
                actual_analyst_gated.add((m, route.path))

    missing = EXPECTED_ANALYST_WRITES - actual_analyst_gated
    unexpected = actual_analyst_gated - EXPECTED_ANALYST_WRITES

    # Reference require_role to keep the import live for static-analysis
    # tools that flag "imported but unused"; the actual detection works
    # via qualname string match.
    _ = require_role

    assert not missing, (
        f"These routes are expected to require ANALYST but don't:\n"
        + "\n".join(f"  {m} {p}" for m, p in sorted(missing))
    )
    assert not unexpected, (
        f"These routes are ANALYST-gated but not in the EXPECTED list "
        f"— add them to the test if intentional:\n"
        + "\n".join(f"  {m} {p}" for m, p in sorted(unexpected))
    )

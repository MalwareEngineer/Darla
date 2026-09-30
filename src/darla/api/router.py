"""Root API router aggregating all sub-routers.

**Auth enforcement (RFC 0001 Phase 4):** Every sub-router below — except
``health`` — is mounted with a router-level ``Depends(current_user)``.
This is the default-deny gate: any new endpoint added to any of these
routers automatically inherits the requirement to authenticate.  Write
endpoints additionally carry per-route ``Depends(require_role(ANALYST))``
in their own signatures.

The lint test in ``tests/test_auth/test_route_coverage.py`` enforces
this invariant — adding a route under ``/api/v1/`` that bypasses
``current_user`` will fail CI.

In auth-disabled mode (community / local-eval), ``current_user``
returns ``None`` instead of raising, so the same code path serves
anonymous traffic when the operator opts in via ``PK_AUTH_ENABLED=false``
plus the §16 guardrails.
"""

from fastapi import APIRouter, Depends

from darla.api import (
    actors,
    analysis,
    campaigns,
    diff,
    families,
    health,
    indicators,
    investigations,
    kits,
    monitored_domains,
    phishmatch,
    stages,
    victims,
    yara,
)
from darla.auth import current_user

api_router = APIRouter()

# Auth dep applied at the router level — every route inside the
# sub-router inherits it.  We keep it as a single list so adding a
# future router that should also require auth is a single-line change.
_AUTH = [Depends(current_user)]

# ``health`` is the ONE explicit anonymous mount.  It must remain
# anonymous so load balancers can probe it without a token, and the
# disabled-mode 503 (RFC §16 guardrail #5) is observable to ECS/ALB.
api_router.include_router(health.router, prefix="/health", tags=["health"])

# Everything else requires authentication.
api_router.include_router(kits.router, prefix="/kits", tags=["kits"], dependencies=_AUTH)
api_router.include_router(
    investigations.router, prefix="/investigations", tags=["investigations"],
    dependencies=_AUTH,
)
api_router.include_router(
    indicators.router, prefix="/indicators", tags=["indicators"],
    dependencies=_AUTH,
)
api_router.include_router(actors.router, prefix="/actors", tags=["actors"], dependencies=_AUTH)
api_router.include_router(
    campaigns.router, prefix="/campaigns", tags=["campaigns"],
    dependencies=_AUTH,
)
api_router.include_router(
    families.router, prefix="/families", tags=["families"],
    dependencies=_AUTH,
)
api_router.include_router(
    analysis.router, prefix="/analysis", tags=["analysis"],
    dependencies=_AUTH,
)
api_router.include_router(diff.router, prefix="/diff", tags=["diff"], dependencies=_AUTH)
api_router.include_router(
    stages.router, prefix="/stages", tags=["stages"], dependencies=_AUTH,
)
api_router.include_router(yara.router, prefix="/yara", tags=["yara"], dependencies=_AUTH)
api_router.include_router(
    phishmatch.router, prefix="/phishmatch", tags=["phishmatch"],
    dependencies=_AUTH,
)
api_router.include_router(
    victims.router, prefix="/victims", tags=["phishprint"],
    dependencies=_AUTH,
)
api_router.include_router(
    monitored_domains.router,
    prefix="/monitored-domains", tags=["phishprint"], dependencies=_AUTH,
)

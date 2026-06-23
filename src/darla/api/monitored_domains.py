"""MonitoredDomain read-only endpoints.

Writes for this table moved out of the HTTP API in Phase 6b (RFC §9
decision #14: sensitive org-protected configuration lives behind the
AWS-IAM boundary, not behind the HTTP API).  The authoritative path
is now ``darla-admin monitored-domain reload <yaml-file>`` — see
:mod:`darla.admin.monitored_domains`.

Reads stay over HTTP because the PhishPrint UI needs them for the
dashboard, and "show me the current allowlist" is not a sensitive
action — the operator either knows the org's protected domains
already, or they're authorised to see them as part of analyst access.
"""

import uuid

from fastapi import APIRouter, HTTPException

from darla.api.deps import DbSession, Pagination
from darla.schemas.victim import (
    MonitoredDomainListResponse,
    MonitoredDomainOut,
)
from darla.services.monitored_domain_service import MonitoredDomainService

router = APIRouter()


@router.get("", response_model=MonitoredDomainListResponse)
async def list_monitored_domains(db: DbSession, pagination: Pagination):
    service = MonitoredDomainService(db)
    items, total = await service.list_domains(
        offset=pagination.offset, limit=pagination.limit,
    )
    return MonitoredDomainListResponse(items=items, total=total)


@router.get("/{domain_id}", response_model=MonitoredDomainOut)
async def get_monitored_domain(domain_id: uuid.UUID, db: DbSession):
    service = MonitoredDomainService(db)
    domain = await service.get_domain(domain_id)
    if domain is None:
        raise HTTPException(status_code=404, detail="Monitored domain not found")
    return domain

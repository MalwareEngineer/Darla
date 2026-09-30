"""All models imported here for Alembic autogeneration to detect them."""

from darla.models.actor import Actor
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.associations import (
    campaign_actors,
    campaign_kits,
    family_actors,
    family_kits,
    kit_actors,
)
from darla.models.audit_log import (
    AUTH_MODE_DISABLED,
    AUTH_MODE_OIDC,
    AuditLog,
)
from darla.models.base import Base
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.indicator import Indicator, IndicatorType
from darla.models.investigation import Investigation, InvestigationStatus
from darla.models.kit import Kit, KitStatus
from darla.models.monitored_domain import MonitoredDomain
from darla.models.resource import Resource, StageResource
from darla.models.stage import Stage, StageRole
from darla.models.user import User, UserRole
from darla.models.victim import (
    KitVictim,
    Victim,
    VictimObservationSource,
    VictimType,
)

__all__ = [
    "AUTH_MODE_DISABLED",
    "AUTH_MODE_OIDC",
    "AnalysisResult",
    "AnalysisType",
    "Actor",
    "AuditLog",
    "Base",
    "Campaign",
    "Family",
    "Indicator",
    "IndicatorType",
    "Investigation",
    "InvestigationStatus",
    "Kit",
    "KitStatus",
    "KitVictim",
    "MonitoredDomain",
    "Resource",
    "Stage",
    "StageResource",
    "StageRole",
    "User",
    "UserRole",
    "Victim",
    "VictimObservationSource",
    "VictimType",
    "campaign_actors",
    "campaign_kits",
    "family_actors",
    "family_kits",
    "kit_actors",
]

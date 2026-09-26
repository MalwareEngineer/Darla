"""Structural guards on ``CampaignService.get_stats`` and the six
drill-down methods backing the rebuilt campaign-detail page.

Same source-inspection rationale as the actor / family stats tests:
the aggregation SQL uses Postgres-only features that don't translate
cleanly to a hermetic SQLite test, and the codebase has no existing
async-test harness to bolt onto.

Each test pins a specific failure mode that would silently regress
the page if the refactor missed it.
"""

from __future__ import annotations

import inspect

from darla.schemas.campaign import CampaignStats
from darla.services import campaign_service

# ---------------------------------------------------------------------------
# get_stats — the Overview-tab payload
# ---------------------------------------------------------------------------

def test_get_stats_uses_campaign_kits_junction() -> None:
    """Kit count + first/last seen must filter through
    ``campaign_kits``."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "campaign_kits" in src
    assert "campaign_kits.c.campaign_id == campaign_id" in src


def test_get_stats_uses_campaign_actors_junction_for_actor_count() -> None:
    """Curated actor count must filter through ``campaign_actors`` —
    distinct from the kit-level ``kit_actors`` reach used for the
    'top deploying actors' panel."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "campaign_actors" in src


def test_get_stats_top_actors_uses_kit_actors_junction() -> None:
    """Top deploying actors = actors attributed to kits in this
    campaign (kit-level kit_actors), NOT the curated campaign_actors
    link."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "kit_actors" in src


def test_get_stats_family_count_via_shared_kits() -> None:
    """Families reach campaigns through shared kits.  Distinct
    aggregate over ``family_kits`` joined to ``campaign_kits``."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "family_kits" in src
    assert "func.distinct(family_kits.c.family_id)" in src


def test_get_stats_victim_count_via_kit_victims_junction() -> None:
    """Victim count is the PhishPrint integration headline.  Reach:
    ``kit_victims → campaign_kits`` with DISTINCT victim_id so a
    victim observed across multiple kits counts once."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "KitVictim" in src
    assert "func.distinct(KitVictim.victim_id)" in src


def test_get_stats_top_victims_includes_display_metadata() -> None:
    """Top-victims rows must include ``display_name`` and ``type`` so
    the panel can render the operator-set label and tag without a
    follow-up fetch."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "Victim.display_name" in src
    assert "Victim.type" in src


def test_get_stats_victim_source_breakdown_groups_by_source() -> None:
    """Source-channel breakdown must group by ``KitVictim.source`` so
    the operator can see "this campaign is purely AITM via
    login_hint" or similar patterns."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "KitVictim.source" in src
    assert ".group_by(KitVictim.source)" in src


def test_get_stats_distributions_are_top_n_only() -> None:
    """Top-actors, top-families, top-victims capped at 10; top-indicators
    + top-YARA at 20.  Removing the limit would let a long-tail
    campaign blow up the response size."""
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    # Three .limit(10) — top actors, top families, top victims.
    assert src.count(".limit(10)") >= 3
    assert ".limit(20)" in src
    assert "[:20]" in src  # YARA top-N applied in Python after agg


def test_get_stats_timeline_uses_postgres_date_trunc_month() -> None:
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert 'date_trunc("month"' in src
    assert "%Y-%m" in src


def test_get_stats_returns_none_for_unknown_campaign() -> None:
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    assert "if campaign is None:" in src
    assert "return None" in src


# ---------------------------------------------------------------------------
# Schema shape — every field promised in CampaignStats must be populated
# ---------------------------------------------------------------------------

def test_get_stats_returns_all_campaignstats_fields() -> None:
    src = inspect.getsource(campaign_service.CampaignService.get_stats)
    expected_keys = set(CampaignStats.model_fields.keys())
    for key in expected_keys:
        assert f'"{key}"' in src, (
            f"CampaignService.get_stats does not populate {key} in its "
            f"return dict — CampaignStats response will fail validation"
        )


# ---------------------------------------------------------------------------
# YARA aggregation helper
# ---------------------------------------------------------------------------

def test_yara_rule_counts_filters_to_yara_scan_rows() -> None:
    src = inspect.getsource(
        campaign_service.CampaignService._yara_rule_counts
    )
    assert "AnalysisType.YARA_SCAN" in src
    assert "campaign_kits.c.campaign_id == campaign_id" in src


# ---------------------------------------------------------------------------
# Drill-down methods — same scope-guard contract
# ---------------------------------------------------------------------------

def test_list_kits_filters_by_campaign_kits() -> None:
    src = inspect.getsource(campaign_service.CampaignService.list_kits)
    assert "campaign_kits.c.campaign_id == campaign_id" in src
    assert "Kit.created_at.desc()" in src


def test_list_kits_supports_status_filter() -> None:
    src = inspect.getsource(campaign_service.CampaignService.list_kits)
    assert "if status:" in src
    assert "Kit.status == status" in src


def test_list_indicators_reaches_through_campaign_kits() -> None:
    src = inspect.getsource(
        campaign_service.CampaignService.list_indicators
    )
    assert "campaign_kits.c.kit_id == Indicator.kit_id" in src
    assert "campaign_kits.c.campaign_id == campaign_id" in src


def test_list_victims_deduplicates_per_victim() -> None:
    """Victims tab must show one row per victim (not one row per
    kit-victim observation).  Implementation uses a subquery that
    groups by victim_id."""
    src = inspect.getsource(campaign_service.CampaignService.list_victims)
    assert "group_by(KitVictim.victim_id)" in src
    assert "max(KitVictim.observed_at)" in src.replace("func.", "")


def test_list_victims_orders_by_latest_observation() -> None:
    """Fresh-hits-at-the-top is the operator-friendly ordering."""
    src = inspect.getsource(campaign_service.CampaignService.list_victims)
    assert ".latest.desc()" in src


def test_list_actors_uses_campaign_actors_junction() -> None:
    src = inspect.getsource(campaign_service.CampaignService.list_actors)
    assert "campaign_actors.c.campaign_id == campaign_id" in src


def test_list_families_reaches_through_shared_kits() -> None:
    src = inspect.getsource(campaign_service.CampaignService.list_families)
    assert "family_kits" in src
    assert "campaign_kits" in src
    assert "distinct" in src.lower()


def test_list_yara_rules_uses_helper() -> None:
    src = inspect.getsource(
        campaign_service.CampaignService.list_yara_rules
    )
    assert "_yara_rule_counts" in src


# ---------------------------------------------------------------------------
# update_campaign refresh — MissingGreenlet trap (PR #75 / #76 / #77)
# ---------------------------------------------------------------------------

def test_update_campaign_refreshes_after_flush() -> None:
    src = inspect.getsource(
        campaign_service.CampaignService.update_campaign
    )
    assert "await self.db.refresh(campaign)" in src

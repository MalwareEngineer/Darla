"""Structural guards on ``FamilyService.get_stats`` and the five
drill-down methods backing the rebuilt family-detail page.

Same source-inspection rationale as
``test_actor_service_stats``: the aggregation SQL uses Postgres
features (``date_trunc``, ARRAY, JSONB) that don't translate cleanly
to a hermetic SQLite test, and the codebase has no existing
async-test harness.  Each test pins a specific failure mode that
would silently regress the page if the refactor missed it.
"""

from __future__ import annotations

import inspect

from darla.schemas.family import FamilyStats
from darla.services import family_service

# ---------------------------------------------------------------------------
# get_stats — the Overview-tab payload
# ---------------------------------------------------------------------------

def test_get_stats_uses_family_kits_junction() -> None:
    """Kit count + first/last seen must filter through
    ``family_kits``, not return all kits."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "family_kits" in src
    assert "family_kits.c.family_id == family_id" in src


def test_get_stats_uses_family_actors_junction() -> None:
    """Curated actor count must filter through ``family_actors`` —
    distinct from the kit-level ``kit_actors`` reach used for the
    'top deploying actors' panel."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "family_actors" in src


def test_get_stats_top_actors_uses_kit_actors_junction() -> None:
    """Top deploying actors = actors attributed to kits in this
    family (kit-level kit_actors), NOT the curated family_actors
    link.  This is the analyst's 'who's slinging this kit' view."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "kit_actors" in src


def test_get_stats_campaign_count_via_shared_kits() -> None:
    """Campaigns reach families through shared kits (no direct
    family↔campaign junction).  The count must distinct-aggregate
    over campaign_kits joined to family_kits."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "campaign_kits" in src
    assert "func.distinct(campaign_kits.c.campaign_id)" in src


def test_get_stats_target_brand_distribution_filters_null_brands() -> None:
    """Many campaigns don't have a target_brand set; including NULLs
    in the bar chart would surface a blank bar."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "Campaign.target_brand.is_not(None)" in src


def test_get_stats_distributions_are_top_n_only() -> None:
    """Brand mix and top-actors are limited to top 10; top-indicators
    + top-YARA capped at 20.  Removing the limit would let a
    long-tail family blow up the response size."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    # Two .limit(10) calls — brand + top actors.  Two .limit(20) — top
    # indicators in SQL + top YARA via Python slice (counted below).
    assert src.count(".limit(10)") >= 2
    assert ".limit(20)" in src
    assert "[:20]" in src  # YARA top-N applied in Python after agg


def test_get_stats_polymorphism_counts_distinct_hashes() -> None:
    """Polymorphism panel needs both distinct SHA256 and distinct
    TLSH counts — drops between kit_count and these reveal
    repackaging vs recompile patterns."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "distinct_sha256_count" in src
    assert "distinct_tlsh_count" in src
    assert "Kit.sha256.is_not(None)" in src
    assert "Kit.tlsh.is_not(None)" in src


def test_get_stats_timeline_uses_postgres_date_trunc_month() -> None:
    """Monthly bucketing relies on Postgres's ``date_trunc``."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert 'date_trunc("month"' in src
    assert "%Y-%m" in src


def test_get_stats_returns_none_for_unknown_family() -> None:
    """Unknown family must return None so the API layer can translate
    to 404 cleanly."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    assert "if family is None:" in src
    assert "return None" in src


# ---------------------------------------------------------------------------
# Schema shape — every field promised in FamilyStats must be populated
# ---------------------------------------------------------------------------

def test_get_stats_returns_all_familystats_fields() -> None:
    """Source must populate every field declared on the
    :class:`FamilyStats` schema."""
    src = inspect.getsource(family_service.FamilyService.get_stats)
    expected_keys = set(FamilyStats.model_fields.keys())
    for key in expected_keys:
        assert f'"{key}"' in src, (
            f"FamilyService.get_stats does not populate {key} in its "
            f"return dict — FamilyStats response will fail validation"
        )


# ---------------------------------------------------------------------------
# YARA aggregation helper — Python-side rule rollup
# ---------------------------------------------------------------------------

def test_yara_rule_counts_filters_to_yara_scan_rows() -> None:
    """Helper must filter ``AnalysisResult`` rows by
    ``analysis_type=YARA_SCAN`` — pulling all analysis rows would
    inflate counts with non-YARA payloads that lack the matches
    array shape."""
    src = inspect.getsource(family_service.FamilyService._yara_rule_counts)
    assert "AnalysisType.YARA_SCAN" in src
    assert "family_kits.c.family_id == family_id" in src


def test_yara_rule_counts_distinct_kit_per_rule() -> None:
    """A single kit hitting the same rule across multiple files
    must count as 1 — aggregate uses a set of kit_ids per rule."""
    src = inspect.getsource(family_service.FamilyService._yara_rule_counts)
    assert "set" in src  # set[uuid.UUID] storage per rule
    assert "len(kits)" in src


# ---------------------------------------------------------------------------
# Drill-down methods — same scope-guard contract
# ---------------------------------------------------------------------------

def test_list_kits_filters_by_family_kits() -> None:
    src = inspect.getsource(family_service.FamilyService.list_kits)
    assert "family_kits" in src
    assert "family_kits.c.family_id == family_id" in src
    assert "Kit.created_at.desc()" in src


def test_list_kits_supports_status_filter() -> None:
    """Operator can narrow the Kits tab by status."""
    src = inspect.getsource(family_service.FamilyService.list_kits)
    assert "if status:" in src
    assert "Kit.status == status" in src


def test_list_indicators_reaches_through_family_kits() -> None:
    """Indicators have no direct family_id FK; must reach through
    ``family_kits``."""
    src = inspect.getsource(family_service.FamilyService.list_indicators)
    assert "family_kits.c.kit_id == Indicator.kit_id" in src
    assert "family_kits.c.family_id == family_id" in src


def test_list_yara_rules_uses_helper() -> None:
    """Public list_yara_rules must reuse the shared aggregation
    helper to keep get_stats and the YARA tab consistent."""
    src = inspect.getsource(family_service.FamilyService.list_yara_rules)
    assert "_yara_rule_counts" in src


def test_list_actors_uses_family_actors_junction() -> None:
    """Actors tab shows the analyst-curated family_actors junction
    (NOT kit_actors-derived 'top deploying actors')."""
    src = inspect.getsource(family_service.FamilyService.list_actors)
    assert "family_actors" in src
    assert "family_actors.c.family_id == family_id" in src


def test_list_campaigns_reaches_through_shared_kits() -> None:
    """Campaign list reaches via campaign_kits ∩ family_kits — no
    direct family↔campaign junction exists.  Must be DISTINCT to
    avoid duplicate rows when a campaign shares multiple kits with
    the family."""
    src = inspect.getsource(family_service.FamilyService.list_campaigns)
    assert "campaign_kits" in src
    assert "family_kits" in src
    assert "distinct" in src.lower()


# ---------------------------------------------------------------------------
# update_family refresh — same MissingGreenlet trap as ActorService
# ---------------------------------------------------------------------------

def test_update_family_refreshes_after_flush() -> None:
    """``Family.updated_at`` has the same server-side ``onupdate=now()``
    that triggers MissingGreenlet on async lazy-load — must refresh
    explicitly, mirroring the PR #75 / #76 fix."""
    src = inspect.getsource(family_service.FamilyService.update_family)
    assert "await self.db.refresh(family)" in src

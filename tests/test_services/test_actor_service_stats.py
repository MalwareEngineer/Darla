"""Structural guards on ``ActorService.get_stats`` and the four
drill-down methods backing the rebuilt actor-detail page.

The actual aggregation SQL runs against Postgres-specific functions
(``date_trunc``, ``ARRAY``, JSONB) that don't translate cleanly to a
hermetic SQLite test, and the codebase has no existing async-test
harness to bolt onto.  Instead we lock down the structure via
source inspection: every method must reach the right junction
table, apply the right filter, and shape the response with the
fields the schema promises.  The full SQL behaviour is validated by
the live API smoke test in the PR description.

Each test pins a specific failure mode that would silently regress
the page if the refactor missed it.
"""

from __future__ import annotations

import inspect

from darla.schemas.actor import ActorStats
from darla.services import actor_service

# ---------------------------------------------------------------------------
# get_stats — the Overview-tab payload
# ---------------------------------------------------------------------------

def test_get_stats_uses_kit_actors_junction() -> None:
    """The kit count + first/last seen must filter through
    ``kit_actors``, not return all kits.  Anchoring on the junction
    name ensures a refactor can't accidentally widen the scope."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    assert "kit_actors" in src
    assert "kit_actors.c.actor_id == actor_id" in src


def test_get_stats_uses_campaign_and_family_actor_junctions() -> None:
    """Counts for campaigns + families must filter through their
    respective actor-junction tables."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    assert "campaign_actors" in src
    assert "family_actors" in src


def test_get_stats_target_brand_distribution_filters_null_brands() -> None:
    """Many campaigns don't have a target_brand set; including NULLs
    in the bar chart would surface a blank bar that confuses the
    operator.  Source-level guard that the WHERE clause excludes
    NULL brands."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    assert "Campaign.target_brand.is_not(None)" in src


def test_get_stats_distributions_are_top_n_only() -> None:
    """Brand mix and family distribution are limited to the top 10
    so the chart stays readable.  Removing the limit would let a
    long-tail actor blow up the response size."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    # Two ``.limit(10)`` calls — one for brand, one for family.
    assert src.count(".limit(10)") >= 2


def test_get_stats_top_indicators_limited_to_20() -> None:
    """Top-indicators panel is capped at 20 — same readability/size
    contract as the distributions but a deeper cap because the
    top-indicators table is denser per row than a bar chart."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    assert ".limit(20)" in src


def test_get_stats_timeline_uses_postgres_date_trunc_month() -> None:
    """Monthly bucketing relies on Postgres's ``date_trunc``.  The
    string-formatted ``YYYY-MM`` output is what the frontend chart
    expects on its x-axis."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    assert 'date_trunc("month"' in src
    assert "%Y-%m" in src


def test_get_stats_returns_none_for_unknown_actor() -> None:
    """Unknown actor must return None so the API layer can translate
    to 404 cleanly.  Source-level guard on the early-out branch."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    assert "if actor is None:" in src
    assert "return None" in src


# ---------------------------------------------------------------------------
# Schema shape — every field promised in ActorStats must be populated
# ---------------------------------------------------------------------------

def test_get_stats_returns_all_actorstats_fields() -> None:
    """Source must populate every field declared on the
    :class:`ActorStats` schema — pydantic would error at response
    time if a field is missing, but the test catches the drift at
    edit time."""
    src = inspect.getsource(actor_service.ActorService.get_stats)
    expected_keys = set(ActorStats.model_fields.keys())
    for key in expected_keys:
        assert f'"{key}"' in src, (
            f"ActorService.get_stats does not populate {key} in its "
            f"return dict — ActorStats response will fail validation"
        )


# ---------------------------------------------------------------------------
# Drill-down methods — same scope-guard contract
# ---------------------------------------------------------------------------

def test_list_kits_filters_by_kit_actors() -> None:
    src = inspect.getsource(actor_service.ActorService.list_kits)
    assert "kit_actors" in src
    assert "kit_actors.c.actor_id == actor_id" in src
    # Kit ordering should be most-recent-first; the rebuilt page's
    # Kits tab assumes this.
    assert "Kit.created_at.desc()" in src


def test_list_kits_supports_status_filter() -> None:
    """Operator can narrow the Kits tab by status — the predicate
    must be wired conditionally."""
    src = inspect.getsource(actor_service.ActorService.list_kits)
    assert "if status:" in src
    assert "Kit.status == status" in src


def test_list_indicators_uses_actor_id_fk() -> None:
    """Indicators tab is the 'this actor owns this IOC' view —
    filters on ``Indicator.actor_id``, not via kit junction.
    Indicators that are kit-attached but not actor-attached belong
    on the kit detail page, not here."""
    src = inspect.getsource(actor_service.ActorService.list_indicators)
    assert "Indicator.actor_id == actor_id" in src


def test_list_campaigns_filters_through_junction() -> None:
    src = inspect.getsource(actor_service.ActorService.list_campaigns)
    assert "campaign_actors" in src
    assert "campaign_actors.c.actor_id == actor_id" in src


def test_list_families_filters_through_junction() -> None:
    src = inspect.getsource(actor_service.ActorService.list_families)
    assert "family_actors" in src
    assert "family_actors.c.actor_id == actor_id" in src


# ---------------------------------------------------------------------------
# update_actor refresh — fix from PR #75 must not regress
# ---------------------------------------------------------------------------

def test_update_actor_refreshes_after_flush() -> None:
    """``Actor.updated_at`` has a server-side ``onupdate=now()`` that
    pydantic would lazy-load post-flush, hitting the
    MissingGreenlet trap from PR #75.  Update path must refresh
    explicitly so the response carries the new timestamp."""
    src = inspect.getsource(actor_service.ActorService.update_actor)
    assert "await self.db.refresh(actor)" in src

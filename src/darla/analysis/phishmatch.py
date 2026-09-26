"""PhishMatch — similarity-based attribution decision support.

Given an unattributed kit, rank candidate entities (Actors, Families,
Campaigns) by how well they *would* fit as the kit's attribution, based on
a weighted composite of multiple signals:

- **TLSH distance**       → structural closeness to already-attributed kits.
- **IOC overlap**         → shared indicators weighted by type specificity
                            (a Telegram bot token is far more diagnostic
                            than a shared ``example.com`` domain).
- **YARA rule overlap**   → shared family/technique rule hits.
- **Source-URL overlap**  → same or structurally similar landing URLs.
- **Redirect-chain host** → shared intermediate/relay hosts.

The scorer does *not* mutate attribution — it produces a ranked list of
candidates with per-signal breakdowns.  Analysts consume this via the
PhishMatch UI and decide whether to link the kit (writing the signal
snapshot into the junction's ``evidence_snapshot`` column).

Design principles:

1.  **Null-transparent**: zero matches returns an empty list, not random
    low-confidence noise.  The UI tells the analyst "no close matches"
    rather than surfacing 1% suggestions.
2.  **Explainable**: every score includes the *why* — which specific
    indicators / rules / TLSH neighbours drove it.
3.  **Bounded**: we only examine kits already attributed to a candidate
    entity and the kit's own neighbourhood (TLSH-close peers), not every
    kit in the DB.  This keeps scoring O(attributed_kits) per entity
    rather than O(N²).
4.  **Weight-tunable**: see ``DEFAULT_WEIGHTS`` — knobs live here so we
    can iterate on the signal without touching callers.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from darla.analysis.hasher import compute_tlsh_distance
from darla.models.actor import Actor
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.campaign import Campaign
from darla.models.family import Family
from darla.models.indicator import Indicator, IndicatorType
from darla.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunable weights
# ---------------------------------------------------------------------------

# Per-IOC-type weight.  High-specificity types (telegram bot tokens, chat
# IDs, crypto wallets) anchor attribution almost by themselves; generic
# ones (domains, IPs) are suggestive but weak on their own.  Values are
# point contributions per matching indicator, capped in ``IOC_SIGNAL_CAP``.
IOC_TYPE_WEIGHTS: dict[IndicatorType, float] = {
    IndicatorType.TELEGRAM_BOT_TOKEN: 30.0,
    IndicatorType.TELEGRAM_CHAT_ID: 25.0,
    IndicatorType.TELEGRAM_HANDLE: 20.0,
    IndicatorType.SMTP_CREDENTIAL: 25.0,
    IndicatorType.CRYPTOCURRENCY_WALLET: 20.0,
    IndicatorType.C2_URL: 15.0,
    IndicatorType.EMAIL: 10.0,
    IndicatorType.PHONE_NUMBER: 8.0,
    IndicatorType.IP_ADDRESS: 6.0,
    IndicatorType.DOMAIN: 5.0,
    IndicatorType.SOURCE_URL: 8.0,
    IndicatorType.BASE64_BLOCK: 2.0,
}

DEFAULT_WEIGHTS: dict[str, float] = {
    # Signal caps — how much a single signal can contribute to the composite.
    "tlsh": 40.0,          # TLSH distance drops from 40 at dist=0 to 0 at dist=>=100.
    "ioc": 40.0,           # Cap on summed IOC contributions.
    "yara": 15.0,          # Cap on YARA rule overlap signal.
    "source_url": 10.0,    # Registered-domain match.
    "redirect_chain": 10.0,  # Shared redirect hostnames.
}

# TLSH distance beyond which two kits are considered unrelated for
# PhishMatch purposes.  Below TLSH_NEAR_THRESHOLD the kits are effectively
# near-duplicates.  Between them the score decays linearly.
TLSH_NEAR_THRESHOLD = 30
TLSH_MAX_DISTANCE = 150

# Minimum composite score for a candidate to surface in results.
# Below this the UI shows "no close matches" rather than noise.
MIN_SURFACE_SCORE = 5.0

# Top-N limit to prevent unbounded result growth per entity type.
RESULT_LIMIT_PER_TYPE = 10


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


EntityType = Literal["actor", "family", "campaign"]


@dataclass
class SignalBreakdown:
    """Per-signal contribution to a candidate's composite score."""

    tlsh: float = 0.0
    ioc: float = 0.0
    yara: float = 0.0
    source_url: float = 0.0
    redirect_chain: float = 0.0

    # Evidence — shown verbatim to the analyst so they can audit *why*.
    tlsh_matches: list[dict[str, Any]] = field(default_factory=list)
    ioc_matches: list[dict[str, Any]] = field(default_factory=list)
    yara_matches: list[str] = field(default_factory=list)
    source_url_matches: list[str] = field(default_factory=list)
    redirect_matches: list[str] = field(default_factory=list)

    def total(self) -> float:
        return self.tlsh + self.ioc + self.yara + self.source_url + self.redirect_chain

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": round(self.total(), 2),
            "tlsh": round(self.tlsh, 2),
            "ioc": round(self.ioc, 2),
            "yara": round(self.yara, 2),
            "source_url": round(self.source_url, 2),
            "redirect_chain": round(self.redirect_chain, 2),
            "evidence": {
                "tlsh": self.tlsh_matches,
                "ioc": self.ioc_matches,
                "yara": self.yara_matches,
                "source_url": self.source_url_matches,
                "redirect": self.redirect_matches,
            },
        }


@dataclass
class Candidate:
    entity_type: EntityType
    entity_id: uuid.UUID
    entity_name: str
    auto_generated: bool
    score: float
    signals: SignalBreakdown
    supporting_kit_ids: list[uuid.UUID] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_id": str(self.entity_id),
            "entity_name": self.entity_name,
            "auto_generated": self.auto_generated,
            "score": round(self.score, 2),
            "signals": self.signals.as_dict(),
            "supporting_kit_ids": [str(kid) for kid in self.supporting_kit_ids],
        }


@dataclass
class PhishMatchResult:
    kit_id: uuid.UUID
    actors: list[Candidate] = field(default_factory=list)
    families: list[Candidate] = field(default_factory=list)
    campaigns: list[Candidate] = field(default_factory=list)
    # Null-result transparency.
    no_matches_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kit_id": str(self.kit_id),
            "actors": [c.as_dict() for c in self.actors],
            "families": [c.as_dict() for c in self.families],
            "campaigns": [c.as_dict() for c in self.campaigns],
            "no_matches_reason": self.no_matches_reason,
        }


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------


class PhishMatchScorer:
    """Composite-scoring engine.  One instance per scoring run."""

    def __init__(self, db: Session):
        self.db = db

    # -- public ----------------------------------------------------------

    def score_kit(self, kit_id: uuid.UUID) -> PhishMatchResult:
        """Score candidate entities for ``kit_id``."""
        kit = self.db.query(Kit).filter(Kit.id == kit_id).first()
        if not kit:
            return PhishMatchResult(
                kit_id=kit_id, no_matches_reason="kit_not_found"
            )

        # Pre-compute the subject kit's signal material ONCE — it's the
        # common factor in every candidate comparison.
        subject = self._load_kit_signals(kit)

        # For each candidate kit (any analyzed kit not == subject), compute
        # a per-kit score.  Then group by the entities attached to that
        # kit.  This lets us report the specific supporting kits per
        # entity candidate.
        per_kit_scores: dict[uuid.UUID, tuple[float, SignalBreakdown]] = {}

        candidate_kits = (
            self.db.query(Kit)
            .filter(
                Kit.id != kit.id,
                Kit.status == KitStatus.ANALYZED,
            )
            .all()
        )

        for other in candidate_kits:
            breakdown = self._score_pair(subject, other)
            if breakdown.total() <= 0:
                continue
            per_kit_scores[other.id] = (breakdown.total(), breakdown)

        if not per_kit_scores:
            return PhishMatchResult(
                kit_id=kit_id,
                no_matches_reason="no_signal_overlap_with_any_analyzed_kit",
            )

        # Aggregate per-kit scores into per-entity candidates.  An entity's
        # composite score is the *max* of its member kits' scores (rather
        # than sum, to avoid inflating large-family candidates).  We
        # retain the top supporting kit IDs and merge their evidence.
        result = PhishMatchResult(kit_id=kit_id)

        result.actors = self._aggregate_candidates(
            entity_type="actor",
            entity_model=Actor,
            per_kit_scores=per_kit_scores,
        )
        result.families = self._aggregate_candidates(
            entity_type="family",
            entity_model=Family,
            per_kit_scores=per_kit_scores,
        )
        result.campaigns = self._aggregate_candidates(
            entity_type="campaign",
            entity_model=Campaign,
            per_kit_scores=per_kit_scores,
        )

        if not (result.actors or result.families or result.campaigns):
            result.no_matches_reason = (
                "signal_overlap_found_but_no_attributed_entities"
            )

        return result

    def suggest_kits_for_entity(
        self,
        entity_type: EntityType,
        entity_id: uuid.UUID,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Reverse lookup: unattributed kits that score high against this entity.

        Returns kits that:
        1.  Have at least one "attributable" status (ANALYZED).
        2.  Are NOT already linked to ``entity_id``.
        3.  Have a composite score > MIN_SURFACE_SCORE against any member
            kit of the entity.
        """
        entity_kits = self._entity_member_kits(entity_type, entity_id)
        if not entity_kits:
            return []

        attributed_kit_ids = {k.id for k in entity_kits}
        subject_pool = (
            self.db.query(Kit)
            .filter(
                Kit.status == KitStatus.ANALYZED,
                ~Kit.id.in_(attributed_kit_ids),
            )
            .all()
        )

        suggestions: list[dict[str, Any]] = []
        for subject_kit in subject_pool:
            subject = self._load_kit_signals(subject_kit)
            best_score = 0.0
            best_breakdown: SignalBreakdown | None = None
            best_via_kit: uuid.UUID | None = None
            for member_kit in entity_kits:
                breakdown = self._score_pair(subject, member_kit)
                if breakdown.total() > best_score:
                    best_score = breakdown.total()
                    best_breakdown = breakdown
                    best_via_kit = member_kit.id
            if best_score >= MIN_SURFACE_SCORE and best_breakdown:
                suggestions.append({
                    "kit_id": str(subject_kit.id),
                    "source_url": subject_kit.source_url,
                    "sha256": subject_kit.sha256,
                    "score": round(best_score, 2),
                    "via_kit_id": str(best_via_kit) if best_via_kit else None,
                    "signals": best_breakdown.as_dict(),
                })

        suggestions.sort(key=lambda s: s["score"], reverse=True)
        return suggestions[:limit]

    # -- internals -------------------------------------------------------

    @dataclass
    class _KitSignals:
        """Cached signal material for a single kit (subject or candidate)."""

        kit: Kit
        tlsh: str | None
        indicators: list[Indicator]
        yara_rules: set[str]
        source_root: str | None
        redirect_hosts: set[str]

    def _load_kit_signals(self, kit: Kit) -> _KitSignals:
        indicators = (
            self.db.query(Indicator)
            .filter(Indicator.kit_id == kit.id)
            .all()
        )

        yara_rules = self._load_yara_rules(kit.id)
        redirect_hosts = self._load_redirect_hosts(kit.id)
        source_root = _registered_domain(kit.source_url)

        return PhishMatchScorer._KitSignals(
            kit=kit,
            tlsh=kit.tlsh,
            indicators=indicators,
            yara_rules=yara_rules,
            source_root=source_root,
            redirect_hosts=redirect_hosts,
        )

    def _load_yara_rules(self, kit_id: uuid.UUID) -> set[str]:
        row = (
            self.db.query(AnalysisResult)
            .filter(
                AnalysisResult.kit_id == kit_id,
                AnalysisResult.analysis_type == AnalysisType.YARA_SCAN,
            )
            .first()
        )
        if not row or not isinstance(row.result_data, dict):
            return set()
        matches = row.result_data.get("matches") or []
        return {
            m.get("rule")
            for m in matches
            if isinstance(m, dict) and m.get("rule")
        }

    def _load_redirect_hosts(self, kit_id: uuid.UUID) -> set[str]:
        row = (
            self.db.query(AnalysisResult)
            .filter(
                AnalysisResult.kit_id == kit_id,
                AnalysisResult.analysis_type == AnalysisType.REDIRECT_CHAIN,
            )
            .first()
        )
        if not row or not isinstance(row.result_data, dict):
            return set()
        hosts: set[str] = set()
        for hop in row.result_data.get("hops") or []:
            if not isinstance(hop, dict):
                continue
            for key in ("url", "location"):
                url = hop.get(key)
                if url:
                    host = _url_host(url)
                    if host:
                        hosts.add(host)
        final = row.result_data.get("final_url")
        if final:
            host = _url_host(final)
            if host:
                hosts.add(host)
        return hosts

    def _score_pair(
        self, subject: _KitSignals, other: Kit
    ) -> SignalBreakdown:
        """Score the subject kit against a single candidate kit."""
        other_signals = self._load_kit_signals(other)
        breakdown = SignalBreakdown()

        # --- TLSH -------------------------------------------------------
        if subject.tlsh and other_signals.tlsh:
            distance = compute_tlsh_distance(subject.tlsh, other_signals.tlsh)
            if distance is not None and distance <= TLSH_MAX_DISTANCE:
                # Piecewise-linear decay.
                if distance <= TLSH_NEAR_THRESHOLD:
                    tlsh_score = DEFAULT_WEIGHTS["tlsh"]
                else:
                    span = TLSH_MAX_DISTANCE - TLSH_NEAR_THRESHOLD
                    fraction = 1.0 - (
                        (distance - TLSH_NEAR_THRESHOLD) / span
                    )
                    tlsh_score = DEFAULT_WEIGHTS["tlsh"] * max(0.0, fraction)
                if tlsh_score > 0:
                    breakdown.tlsh = tlsh_score
                    breakdown.tlsh_matches.append({
                        "kit_id": str(other.id),
                        "distance": distance,
                        "tlsh": other_signals.tlsh,
                    })

        # --- IOC overlap ------------------------------------------------
        subject_index = _index_indicators(subject.indicators)
        other_index = _index_indicators(other_signals.indicators)
        ioc_total = 0.0
        for key, sub_indicators in subject_index.items():
            if key not in other_index:
                continue
            ind_type, value = key
            weight = IOC_TYPE_WEIGHTS.get(ind_type, 3.0)
            ioc_total += weight
            breakdown.ioc_matches.append({
                "type": ind_type.value,
                "value": value,
                "weight": weight,
                "subject_indicator_id": str(sub_indicators[0].id),
                "peer_indicator_id": str(other_index[key][0].id),
                "peer_kit_id": str(other.id),
            })
        breakdown.ioc = min(ioc_total, DEFAULT_WEIGHTS["ioc"])

        # --- YARA rule overlap -----------------------------------------
        shared_rules = subject.yara_rules & other_signals.yara_rules
        if shared_rules:
            # Diminishing returns: first rule is 60% of cap, every additional
            # rule adds (remaining/2).  Even a single shared rule is a
            # strong signal.
            cap = DEFAULT_WEIGHTS["yara"]
            yara_score = cap * 0.6
            remaining = cap - yara_score
            for _ in range(len(shared_rules) - 1):
                yara_score += remaining / 2
                remaining /= 2
            breakdown.yara = min(yara_score, cap)
            breakdown.yara_matches = sorted(shared_rules)

        # --- source URL registered-domain match -------------------------
        if (
            subject.source_root
            and other_signals.source_root
            and subject.source_root == other_signals.source_root
        ):
            breakdown.source_url = DEFAULT_WEIGHTS["source_url"]
            breakdown.source_url_matches.append(subject.source_root)

        # --- redirect-chain host overlap --------------------------------
        shared_hosts = subject.redirect_hosts & other_signals.redirect_hosts
        if shared_hosts:
            # Scale linearly up to the cap with 2+ shared hosts saturating.
            ratio = min(1.0, len(shared_hosts) / 2.0)
            breakdown.redirect_chain = DEFAULT_WEIGHTS["redirect_chain"] * ratio
            breakdown.redirect_matches = sorted(shared_hosts)

        return breakdown

    def _aggregate_candidates(
        self,
        entity_type: EntityType,
        entity_model: type[Actor] | type[Family] | type[Campaign],
        per_kit_scores: dict[uuid.UUID, tuple[float, SignalBreakdown]],
    ) -> list[Candidate]:
        """Walk each attributed entity and aggregate its member kits' scores."""
        entities = self.db.query(entity_model).all()
        candidates: list[Candidate] = []

        for entity in entities:
            member_kits = [k for k in entity.kits if k.id in per_kit_scores]
            if not member_kits:
                continue

            # Take the MAX score across members, then merge evidence.
            best_score = 0.0
            merged = SignalBreakdown()
            for member_kit in member_kits:
                score, bd = per_kit_scores[member_kit.id]
                if score > best_score:
                    best_score = score
                # Merge evidence — take max per signal so the UI shows
                # the strongest supporting kit per channel.
                merged.tlsh = max(merged.tlsh, bd.tlsh)
                merged.ioc = max(merged.ioc, bd.ioc)
                merged.yara = max(merged.yara, bd.yara)
                merged.source_url = max(merged.source_url, bd.source_url)
                merged.redirect_chain = max(
                    merged.redirect_chain, bd.redirect_chain
                )
                merged.tlsh_matches.extend(bd.tlsh_matches)
                merged.ioc_matches.extend(bd.ioc_matches)
                merged.yara_matches.extend(bd.yara_matches)
                merged.source_url_matches.extend(bd.source_url_matches)
                merged.redirect_matches.extend(bd.redirect_matches)

            # Deduplicate merged evidence — multiple member kits may share
            # the same rule/domain.
            merged.yara_matches = sorted(set(merged.yara_matches))
            merged.source_url_matches = sorted(set(merged.source_url_matches))
            merged.redirect_matches = sorted(set(merged.redirect_matches))

            if best_score < MIN_SURFACE_SCORE:
                continue

            candidates.append(Candidate(
                entity_type=entity_type,
                entity_id=entity.id,
                entity_name=entity.name,
                auto_generated=bool(getattr(entity, "auto_generated", False)),
                score=best_score,
                signals=merged,
                supporting_kit_ids=[k.id for k in member_kits][:10],
            ))

        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates[:RESULT_LIMIT_PER_TYPE]

    def _entity_member_kits(
        self, entity_type: EntityType, entity_id: uuid.UUID
    ) -> list[Kit]:
        model_map: dict[str, type] = {
            "actor": Actor, "family": Family, "campaign": Campaign,
        }
        model = model_map.get(entity_type)
        if not model:
            return []
        entity = self.db.query(model).filter(model.id == entity_id).first()
        if not entity:
            return []
        return [k for k in entity.kits if k.status == KitStatus.ANALYZED]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _url_host(url: str) -> str | None:
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:
        return None


def _registered_domain(url: str | None) -> str | None:
    """Naive registered-domain extractor — the right-most two labels.

    We deliberately don't pull in tldextract here; for scoring purposes
    ``foo.bar.attacker.tld`` vs ``baz.attacker.tld`` both normalize to
    ``attacker.tld`` which is what matters.  Public-suffix edge cases
    (``co.uk``) will collide on ``co.uk`` — acceptable noise.
    """
    host = _url_host(url) if url else None
    if not host:
        return None
    parts = host.split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _index_indicators(
    indicators: Iterable[Indicator],
) -> dict[tuple[IndicatorType, str], list[Indicator]]:
    """Group indicators by (type, normalized_value) for O(1) overlap lookup."""
    out: dict[tuple[IndicatorType, str], list[Indicator]] = defaultdict(list)
    for ind in indicators:
        key = (ind.type, (ind.value or "").lower())
        out[key].append(ind)
    return out

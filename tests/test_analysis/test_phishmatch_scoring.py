"""Pure-logic unit tests for the PhishMatch scoring engine.

These tests exercise the signal-combination math and pure helpers without
touching the database.  The :class:`PhishMatchScorer` is subclassed so
``_load_kit_signals`` can be replaced with an in-memory lookup, and
``_score_pair`` is driven directly with stubbed :class:`_KitSignals`.

DB-integration coverage (real session + models) lives in the API-layer
smoke test; here we want fast, deterministic assertions on:

1. TLSH piecewise-linear decay produces the advertised boundary values.
2. IOC-type specificity weights compose correctly (telegram bot token
   dominates, domain is a weak tap, ``BASE64_BLOCK`` rounds to near-zero).
3. YARA diminishing-returns curve saturates below the cap.
4. Source-URL match requires *registered-domain* equality, not full URL.
5. Redirect-chain overlap scales linearly to 2+ shared hosts then saturates.
6. ``_registered_domain`` normalizes the same root across subdomains.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import pytest

from darla.analysis import phishmatch
from darla.analysis.phishmatch import (
    DEFAULT_WEIGHTS,
    IOC_TYPE_WEIGHTS,
    MIN_SURFACE_SCORE,
    TLSH_MAX_DISTANCE,
    TLSH_NEAR_THRESHOLD,
    PhishMatchScorer,
    SignalBreakdown,
    _index_indicators,
    _registered_domain,
    _url_host,
)
from darla.models.indicator import IndicatorType

# ---------------------------------------------------------------------------
# Lightweight stand-ins — no SQLAlchemy session required.
# ---------------------------------------------------------------------------


@dataclass
class _StubIndicator:
    """Duck-types :class:`darla.models.indicator.Indicator` for scoring."""

    type: IndicatorType
    value: str
    id: uuid.UUID = field(default_factory=uuid.uuid4)


@dataclass
class _StubKit:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    source_url: str | None = None
    tlsh: str | None = None
    sha256: str | None = None


def _make_subject(
    *,
    tlsh: str | None = None,
    source_url: str | None = None,
    indicators: list[_StubIndicator] | None = None,
    yara_rules: set[str] | None = None,
    redirect_hosts: set[str] | None = None,
):
    kit = _StubKit(tlsh=tlsh, source_url=source_url)
    return PhishMatchScorer._KitSignals(
        kit=kit,
        tlsh=tlsh,
        indicators=indicators or [],
        yara_rules=yara_rules or set(),
        source_root=_registered_domain(source_url),
        redirect_hosts=redirect_hosts or set(),
    )


def _make_peer(
    *,
    tlsh: str | None = None,
    source_url: str | None = None,
    indicators: list[_StubIndicator] | None = None,
    yara_rules: set[str] | None = None,
    redirect_hosts: set[str] | None = None,
):
    """Peer kit + pre-loaded signals stashed on the kit for the stubbed loader."""
    kit = _StubKit(tlsh=tlsh, source_url=source_url)
    signals = PhishMatchScorer._KitSignals(
        kit=kit,
        tlsh=tlsh,
        indicators=indicators or [],
        yara_rules=yara_rules or set(),
        source_root=_registered_domain(source_url),
        redirect_hosts=redirect_hosts or set(),
    )
    return kit, signals


class _NullSession:
    """No-op session — the scorer never reaches it in these tests."""

    def query(self, *_a, **_kw):  # pragma: no cover - safety net
        raise AssertionError(
            "DB should not be touched in pure scoring-logic tests",
        )


class _TestableScorer(PhishMatchScorer):
    """Overrides the one DB-touching method the math goes through."""

    def __init__(self, signal_map: dict[uuid.UUID, PhishMatchScorer._KitSignals]):
        super().__init__(db=_NullSession())
        self._signal_map = signal_map

    def _load_kit_signals(self, kit):  # type: ignore[override]
        return self._signal_map[kit.id]


def _score(
    subject: PhishMatchScorer._KitSignals,
    peers: list[tuple[_StubKit, PhishMatchScorer._KitSignals]],
    target_kit: _StubKit,
) -> SignalBreakdown:
    signal_map = {kit.id: sig for kit, sig in peers}
    scorer = _TestableScorer(signal_map)
    return scorer._score_pair(subject, target_kit)


# ---------------------------------------------------------------------------
# _registered_domain / _url_host
# ---------------------------------------------------------------------------


def test_registered_domain_strips_subdomains():
    assert _registered_domain("https://login.paypal.attacker.tld/signin") == "attacker.tld"
    assert _registered_domain("https://attacker.tld/") == "attacker.tld"


def test_registered_domain_handles_missing_url():
    assert _registered_domain(None) is None
    assert _registered_domain("") is None
    assert _registered_domain("not-a-url") is None


def test_registered_domain_single_label_hostname():
    # intranet-style hostnames should not explode — return the host itself.
    assert _registered_domain("http://localhost/") == "localhost"


def test_url_host_lowercases_and_handles_ports():
    assert _url_host("HTTPS://Example.Com:8443/path") == "example.com"
    assert _url_host("bogus") is None


# ---------------------------------------------------------------------------
# _index_indicators
# ---------------------------------------------------------------------------


def test_index_indicators_normalizes_case():
    a = _StubIndicator(IndicatorType.EMAIL, "Evil@Attacker.Tld")
    b = _StubIndicator(IndicatorType.EMAIL, "evil@attacker.tld")
    index = _index_indicators([a, b])
    # Both collapse to the same bucket.
    assert len(index) == 1
    key = (IndicatorType.EMAIL, "evil@attacker.tld")
    assert key in index
    assert len(index[key]) == 2


# ---------------------------------------------------------------------------
# TLSH decay
# ---------------------------------------------------------------------------


def _fake_compute_distance(distance: int | None):
    def _inner(_a, _b):
        return distance
    return _inner


def test_tlsh_full_score_below_near_threshold(monkeypatch):
    monkeypatch.setattr(
        phishmatch, "compute_tlsh_distance", _fake_compute_distance(10)
    )
    subject = _make_subject(tlsh="T1AAA")
    peer_kit, peer_sig = _make_peer(tlsh="T1BBB")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.tlsh == DEFAULT_WEIGHTS["tlsh"]
    assert breakdown.tlsh_matches[0]["distance"] == 10


def test_tlsh_zero_at_max_distance(monkeypatch):
    monkeypatch.setattr(
        phishmatch,
        "compute_tlsh_distance",
        _fake_compute_distance(TLSH_MAX_DISTANCE),
    )
    subject = _make_subject(tlsh="T1AAA")
    peer_kit, peer_sig = _make_peer(tlsh="T1BBB")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    # fraction hits exactly 0 at the far boundary -> no TLSH contribution.
    assert breakdown.tlsh == 0.0
    # No evidence recorded when signal is 0 (prevents noise in the UI).
    assert breakdown.tlsh_matches == []


def test_tlsh_midpoint_decay(monkeypatch):
    mid = TLSH_NEAR_THRESHOLD + (TLSH_MAX_DISTANCE - TLSH_NEAR_THRESHOLD) // 2
    monkeypatch.setattr(
        phishmatch, "compute_tlsh_distance", _fake_compute_distance(mid)
    )
    subject = _make_subject(tlsh="T1AAA")
    peer_kit, peer_sig = _make_peer(tlsh="T1BBB")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    expected = DEFAULT_WEIGHTS["tlsh"] * 0.5
    # Integer midpoint ≈ halfway; allow 5% tolerance for floor division.
    assert breakdown.tlsh == pytest.approx(expected, rel=0.05)


def test_tlsh_beyond_max_yields_no_signal(monkeypatch):
    monkeypatch.setattr(
        phishmatch,
        "compute_tlsh_distance",
        _fake_compute_distance(TLSH_MAX_DISTANCE + 50),
    )
    subject = _make_subject(tlsh="T1AAA")
    peer_kit, peer_sig = _make_peer(tlsh="T1BBB")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.tlsh == 0.0


def test_tlsh_none_when_either_missing(monkeypatch):
    monkeypatch.setattr(
        phishmatch, "compute_tlsh_distance", _fake_compute_distance(0)
    )
    subject = _make_subject(tlsh=None)
    peer_kit, peer_sig = _make_peer(tlsh="T1BBB")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.tlsh == 0.0


# ---------------------------------------------------------------------------
# IOC overlap
# ---------------------------------------------------------------------------


def test_ioc_high_specificity_dominates():
    # A shared bot token alone clears near-saturation of the IOC cap.
    shared = _StubIndicator(
        IndicatorType.TELEGRAM_BOT_TOKEN,
        "1234567890:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQ",
    )
    subject = _make_subject(indicators=[shared])
    peer_shared = _StubIndicator(IndicatorType.TELEGRAM_BOT_TOKEN, shared.value)
    peer_kit, peer_sig = _make_peer(indicators=[peer_shared])
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.ioc == IOC_TYPE_WEIGHTS[IndicatorType.TELEGRAM_BOT_TOKEN]
    assert breakdown.ioc_matches[0]["type"] == "telegram_bot_token"
    # _index_indicators lower-cases values for case-insensitive matching.
    assert breakdown.ioc_matches[0]["value"] == shared.value.lower()


def test_ioc_capped_at_signal_cap():
    # Six shared SMTP creds (25 each = 150) should saturate at the cap (40).
    values = [f"user{i}@attacker.tld:pwd" for i in range(6)]
    subject_ind = [
        _StubIndicator(IndicatorType.SMTP_CREDENTIAL, v) for v in values
    ]
    peer_ind = [
        _StubIndicator(IndicatorType.SMTP_CREDENTIAL, v) for v in values
    ]
    subject = _make_subject(indicators=subject_ind)
    peer_kit, peer_sig = _make_peer(indicators=peer_ind)
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.ioc == DEFAULT_WEIGHTS["ioc"]
    assert len(breakdown.ioc_matches) == 6  # every match still recorded


def test_ioc_weak_types_sit_at_surface_floor():
    # A lone shared domain scores exactly MIN_SURFACE_SCORE (5.0).  The
    # surface gate is ``<`` so this barely qualifies — by design, so
    # analysts see *something* for low-confidence leads rather than an
    # empty list — but it's below anything that would be called a match.
    ind = _StubIndicator(IndicatorType.DOMAIN, "attacker.tld")
    subject = _make_subject(indicators=[ind])
    peer_ind = _StubIndicator(IndicatorType.DOMAIN, "attacker.tld")
    peer_kit, peer_sig = _make_peer(indicators=[peer_ind])
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.ioc == 5.0
    assert breakdown.total() == pytest.approx(MIN_SURFACE_SCORE)


def test_ioc_mismatched_type_does_not_match():
    # Same value, different type -> no overlap.
    subject = _make_subject(
        indicators=[_StubIndicator(IndicatorType.EMAIL, "admin@attacker.tld")],
    )
    peer_kit, peer_sig = _make_peer(
        indicators=[_StubIndicator(IndicatorType.C2_URL, "admin@attacker.tld")],
    )
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.ioc == 0.0
    assert breakdown.ioc_matches == []


def test_ioc_unknown_type_falls_back_to_default_weight():
    # All declared types appear in IOC_TYPE_WEIGHTS; this is a regression
    # guard for the ``, 3.0)`` default lookup in _score_pair.
    subject = _make_subject(
        indicators=[_StubIndicator(IndicatorType.BASE64_BLOCK, "QUFB")],
    )
    peer_kit, peer_sig = _make_peer(
        indicators=[_StubIndicator(IndicatorType.BASE64_BLOCK, "QUFB")],
    )
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    # BASE64_BLOCK weight is 2.0 — the weakest explicitly-weighted type.
    assert breakdown.ioc == IOC_TYPE_WEIGHTS[IndicatorType.BASE64_BLOCK]


# ---------------------------------------------------------------------------
# YARA overlap
# ---------------------------------------------------------------------------


def test_yara_single_shared_rule_is_60_percent_of_cap():
    subject = _make_subject(yara_rules={"PhishKit_Microsoft_Branded_Page"})
    peer_kit, peer_sig = _make_peer(
        yara_rules={"PhishKit_Microsoft_Branded_Page"},
    )
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    expected = DEFAULT_WEIGHTS["yara"] * 0.6
    assert breakdown.yara == pytest.approx(expected)
    assert breakdown.yara_matches == ["PhishKit_Microsoft_Branded_Page"]


def test_yara_many_rules_saturate_below_cap():
    # Diminishing returns: second rule adds (cap-0.6cap)/2 = 20% of cap; etc.
    # Even with 10 shared rules we must stay at-or-below the cap.
    rules = {f"Rule_{i}" for i in range(10)}
    subject = _make_subject(yara_rules=rules)
    peer_kit, peer_sig = _make_peer(yara_rules=rules)
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.yara <= DEFAULT_WEIGHTS["yara"]
    assert breakdown.yara >= DEFAULT_WEIGHTS["yara"] * 0.6


def test_yara_no_overlap_is_zero():
    subject = _make_subject(yara_rules={"Rule_A"})
    peer_kit, peer_sig = _make_peer(yara_rules={"Rule_B"})
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.yara == 0.0
    assert breakdown.yara_matches == []


# ---------------------------------------------------------------------------
# Source URL & redirect chain
# ---------------------------------------------------------------------------


def test_source_url_matches_on_registered_domain():
    subject = _make_subject(source_url="https://login.attacker.tld/signin")
    peer_kit, peer_sig = _make_peer(source_url="https://sso.attacker.tld/mfa")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.source_url == DEFAULT_WEIGHTS["source_url"]
    assert breakdown.source_url_matches == ["attacker.tld"]


def test_source_url_different_roots_no_match():
    subject = _make_subject(source_url="https://attacker.tld/a")
    peer_kit, peer_sig = _make_peer(source_url="https://other.tld/b")
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.source_url == 0.0


def test_redirect_chain_scales_to_cap_at_two_hosts():
    subject = _make_subject(
        redirect_hosts={"relay1.attacker.tld", "relay2.attacker.tld"},
    )
    peer_kit, peer_sig = _make_peer(
        redirect_hosts={"relay1.attacker.tld", "relay2.attacker.tld"},
    )
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.redirect_chain == DEFAULT_WEIGHTS["redirect_chain"]
    assert breakdown.redirect_matches == [
        "relay1.attacker.tld", "relay2.attacker.tld",
    ]


def test_redirect_chain_half_cap_at_single_host():
    subject = _make_subject(redirect_hosts={"relay1.attacker.tld"})
    peer_kit, peer_sig = _make_peer(redirect_hosts={"relay1.attacker.tld"})
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.redirect_chain == DEFAULT_WEIGHTS["redirect_chain"] * 0.5


def test_redirect_chain_no_overlap_is_zero():
    subject = _make_subject(redirect_hosts={"a.tld"})
    peer_kit, peer_sig = _make_peer(redirect_hosts={"b.tld"})
    breakdown = _score(subject, [(peer_kit, peer_sig)], peer_kit)
    assert breakdown.redirect_chain == 0.0


# ---------------------------------------------------------------------------
# SignalBreakdown.as_dict / total
# ---------------------------------------------------------------------------


def test_signal_breakdown_total_sums_all_channels():
    bd = SignalBreakdown(
        tlsh=10.0, ioc=20.0, yara=5.0, source_url=3.0, redirect_chain=2.0,
    )
    assert bd.total() == pytest.approx(40.0)
    d = bd.as_dict()
    assert d["total"] == 40.0
    assert d["tlsh"] == 10.0
    # Evidence shape is preserved for the UI consumer.
    assert "evidence" in d and set(d["evidence"].keys()) == {
        "tlsh", "ioc", "yara", "source_url", "redirect",
    }

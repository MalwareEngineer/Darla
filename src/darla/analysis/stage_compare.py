"""Stage comparison, flow alignment, and clustering.

Built on the primitives in :mod:`darla.analysis.stage_fingerprint`.  Three
things live here:

* :func:`compare_stages` — a role-aware verdict between two stage
  fingerprints, with a per-signal breakdown so the UI can say *why* two
  bot checks are "the same" (identical script set, TLSH 14) or two AiTM
  pages "different" (other WebSocket endpoint).
* :func:`align_flows` — sequence-aligns two attack flows by role so an
  investigation-vs-investigation diff lines matching stages up and shows
  where one has a stage the other lacks.
* :func:`cluster_stages` — groups same-role stages into families so the
  UI can build the "which bot check pairs with which AiTM backend"
  co-occurrence matrix.

Fingerprint dicts are the plain JSON stored on ``Stage.fingerprint``
merged with the indexed columns; see :func:`stage_to_fingerprint` in
:mod:`darla.services.stage_service` for the shape.  Keeping this module
pure (dicts in, dicts out) makes the whole comparison layer unit-testable
without a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from darla.analysis.stage_fingerprint import (
    jaccard,
    phash_distance,
    tlsh_distance,
)

# TLSH distance at/under which two blobs are considered "the same"
# template.  ~30 matches the browser-dedup threshold used elsewhere.
SAME_TLSH = 30
# ...and the ceiling past which they're unrelated.
FAR_TLSH = 120
# Screenshot dhash Hamming distance under which two shots look identical.
SAME_PHASH = 6


@dataclass
class SignalResult:
    name: str
    verdict: str          # "same" | "similar" | "different" | "unknown"
    detail: str
    score: float          # 0..1 similarity (1 = identical), -1 = unknown


@dataclass
class StageComparison:
    verdict: str                       # "same" | "similar" | "different"
    score: float                       # 0..1 blended similarity
    signals: list[SignalResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "signals": [
                {
                    "name": s.name,
                    "verdict": s.verdict,
                    "detail": s.detail,
                    "score": round(s.score, 3) if s.score >= 0 else None,
                }
                for s in self.signals
            ],
        }


# Per-role signal weights.  A bot check is best identified by its script
# set + layout; an AiTM cred page by its injected scripts/endpoints (the
# proxied IdP HTML dominates raw TLSH, so weight that down and the
# request shape up).  Weights need not sum to 1 — they're renormalised
# over whichever signals are actually present.
_ROLE_WEIGHTS: dict[str, dict[str, float]] = {
    "bot_check": {
        "script_set": 0.35, "skeleton": 0.2, "tlsh_rendered": 0.2,
        "request_shape": 0.15, "screenshot": 0.1,
    },
    "cred_capture": {
        "injected": 0.4, "request_shape": 0.25, "script_set": 0.2,
        "skeleton": 0.1, "screenshot": 0.05,
    },
    "interstitial": {
        "skeleton": 0.3, "tlsh_rendered": 0.3, "script_set": 0.2,
        "screenshot": 0.2,
    },
    "email_gate": {
        "skeleton": 0.3, "tlsh_rendered": 0.25, "script_set": 0.25,
        "screenshot": 0.2,
    },
}
_DEFAULT_WEIGHTS = {
    "tlsh_rendered": 0.3, "skeleton": 0.25, "script_set": 0.25,
    "request_shape": 0.1, "screenshot": 0.1,
}


def _tlsh_signal(name: str, a: str | None, b: str | None) -> SignalResult:
    dist = tlsh_distance(a, b)
    if dist is None:
        return SignalResult(name, "unknown", "no TLSH on one side", -1.0)
    if dist <= SAME_TLSH:
        return SignalResult(name, "same", f"TLSH {dist}", 1.0)
    if dist >= FAR_TLSH:
        return SignalResult(name, "different", f"TLSH {dist}", 0.0)
    # Linear ramp between same and far.
    score = 1.0 - (dist - SAME_TLSH) / (FAR_TLSH - SAME_TLSH)
    return SignalResult(name, "similar", f"TLSH {dist}", round(score, 3))


def _set_signal(name: str, a: set[str], b: set[str], label: str) -> SignalResult:
    if not a and not b:
        return SignalResult(name, "unknown", f"no {label}", -1.0)
    j = jaccard(a, b)
    shared = len(a & b)
    verdict = "same" if j >= 0.9 else "similar" if j >= 0.3 else "different"
    return SignalResult(
        name, verdict,
        f"{shared} shared / {len(a | b)} total {label} (Jaccard {j:.2f})",
        round(j, 3),
    )


def compare_stages(a: dict, b: dict, role: str | None = None) -> StageComparison:
    """Compare two stage fingerprints, weighted by ``role``.

    ``role`` defaults to ``a['role']``.  Only signals present on both
    sides contribute; the blended score renormalises over them.
    """
    role = role or a.get("role") or "unknown"
    weights = _ROLE_WEIGHTS.get(role, _DEFAULT_WEIGHTS)
    signals: list[SignalResult] = []

    signals.append(_tlsh_signal(
        "tlsh_rendered", a.get("tlsh_rendered"), b.get("tlsh_rendered"),
    ))
    signals.append(_set_signal(
        "script_set",
        set(a.get("script_shas") or []), set(b.get("script_shas") or []),
        "scripts",
    ))

    # Skeleton: exact hash match is "same"; otherwise unknown (we don't
    # store the full skeleton, only its hash, so no partial score).
    sa, sb = a.get("skeleton_hash"), b.get("skeleton_hash")
    if sa and sb:
        signals.append(SignalResult(
            "skeleton", "same" if sa == sb else "different",
            "identical layout" if sa == sb else "different layout",
            1.0 if sa == sb else 0.0,
        ))
    else:
        signals.append(SignalResult("skeleton", "unknown", "no skeleton", -1.0))

    ra, rb = a.get("request_shape_hash"), b.get("request_shape_hash")
    if ra and rb:
        signals.append(SignalResult(
            "request_shape", "same" if ra == rb else "different",
            "identical request sequence" if ra == rb
            else "different request sequence",
            1.0 if ra == rb else 0.0,
        ))
    else:
        signals.append(SignalResult(
            "request_shape", "unknown", "no request shape", -1.0,
        ))

    pd = phash_distance(a.get("screenshot_phash"), b.get("screenshot_phash"))
    if pd is None:
        signals.append(SignalResult("screenshot", "unknown", "no screenshot", -1.0))
    else:
        verdict = "same" if pd <= SAME_PHASH else "similar" if pd <= 16 else "different"
        signals.append(SignalResult(
            "screenshot", verdict, f"dhash distance {pd}",
            round(max(0.0, 1.0 - pd / 32), 3),
        ))

    # Injected fingerprint (cred_capture, baseline-subtracted).
    if "injected_scripts" in a or "injected_scripts" in b:
        signals.append(_set_signal(
            "injected",
            set(a.get("injected_scripts") or []) | set(a.get("injected_endpoints") or []),
            set(b.get("injected_scripts") or []) | set(b.get("injected_endpoints") or []),
            "injected artifacts",
        ))

    # Blend present signals by role weight.
    num = 0.0
    den = 0.0
    for s in signals:
        if s.score < 0:
            continue
        w = weights.get(s.name, 0.05)
        num += w * s.score
        den += w
    score = num / den if den else 0.0
    verdict = "same" if score >= 0.85 else "similar" if score >= 0.45 else "different"
    # Present, ordered most-informative first.
    signals.sort(key=lambda s: (s.score < 0, -weights.get(s.name, 0.0)))
    return StageComparison(verdict=verdict, score=score, signals=signals)


# ---------------------------------------------------------------------------
# Flow alignment (investigation A vs investigation B)
# ---------------------------------------------------------------------------

# Roles that carry comparison weight when aligning two flows.  A pure
# redirector or an unknown stage still appears in the flow but shouldn't
# drive the alignment score.
_ALIGNABLE = {
    "bot_check", "interstitial", "email_gate", "cred_capture", "decoy",
}


@dataclass
class FlowPair:
    kind: str                    # "match" | "only_a" | "only_b"
    role: str | None
    a_index: int | None
    b_index: int | None
    comparison: dict | None      # StageComparison.to_dict() when kind=="match"


def align_flows(
    flow_a: list[dict], flow_b: list[dict],
) -> list[FlowPair]:
    """Needleman-Wunsch alignment of two ordered stage-fingerprint lists.

    Match reward = same role (and a similarity bonus); gaps allow a flow
    to skip a stage the other has (e.g. only A had an interstitial).
    Returns the alignment as an ordered list of :class:`FlowPair`.
    """
    n, m = len(flow_a), len(flow_b)
    gap = -1.0

    def match_score(i: int, j: int) -> float:
        sa = flow_a[i]
        sb = flow_b[j]
        if sa.get("role") != sb.get("role"):
            return -1.0
        base = 1.0
        cmp = compare_stages(sa, sb, sa.get("role"))
        return base + cmp.score  # 1..2 for same-role, better if similar

    # DP table.
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        dp[i][0] = dp[i - 1][0] + gap
    for j in range(1, m + 1):
        dp[0][j] = dp[0][j - 1] + gap
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            dp[i][j] = max(
                dp[i - 1][j - 1] + match_score(i - 1, j - 1),
                dp[i - 1][j] + gap,
                dp[i][j - 1] + gap,
            )

    # Traceback.
    pairs: list[FlowPair] = []
    i, j = n, m
    while i > 0 and j > 0:
        diag = dp[i - 1][j - 1] + match_score(i - 1, j - 1)
        if dp[i][j] == diag and flow_a[i - 1].get("role") == flow_b[j - 1].get("role"):
            cmp = compare_stages(
                flow_a[i - 1], flow_b[j - 1], flow_a[i - 1].get("role"),
            )
            pairs.append(FlowPair(
                "match", flow_a[i - 1].get("role"), i - 1, j - 1, cmp.to_dict(),
            ))
            i, j = i - 1, j - 1
        elif dp[i][j] == dp[i - 1][j] + gap:
            pairs.append(FlowPair("only_a", flow_a[i - 1].get("role"), i - 1, None, None))
            i -= 1
        else:
            pairs.append(FlowPair("only_b", flow_b[j - 1].get("role"), None, j - 1, None))
            j -= 1
    while i > 0:
        pairs.append(FlowPair("only_a", flow_a[i - 1].get("role"), i - 1, None, None))
        i -= 1
    while j > 0:
        pairs.append(FlowPair("only_b", flow_b[j - 1].get("role"), None, j - 1, None))
        j -= 1
    pairs.reverse()
    return pairs


# ---------------------------------------------------------------------------
# Clustering (union-find over same-role stages)
# ---------------------------------------------------------------------------


def cluster_stages(
    stages: list[dict], role: str, same_threshold: float = 0.85,
) -> list[list[str]]:
    """Group same-role stages into families by pairwise similarity.

    ``stages`` items must carry an ``id`` plus the fingerprint fields.
    Two stages join the same cluster when :func:`compare_stages` scores
    them at/above ``same_threshold``.  Returns a list of clusters, each a
    list of stage ids, largest first.  O(n²) in the candidate set — the
    caller is expected to pre-filter by ``role`` (and optionally
    ``tlsh_bucket``) so n stays small.
    """
    items = [s for s in stages if s.get("role") == role]
    parent: dict[str, str] = {s["id"]: s["id"] for s in items}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        parent[find(x)] = find(y)

    for idx, sa in enumerate(items):
        for sb in items[idx + 1:]:
            if find(sa["id"]) == find(sb["id"]):
                continue
            if compare_stages(sa, sb, role).score >= same_threshold:
                union(sa["id"], sb["id"])

    groups: dict[str, list[str]] = {}
    for s in items:
        groups.setdefault(find(s["id"]), []).append(s["id"])
    return sorted(groups.values(), key=len, reverse=True)

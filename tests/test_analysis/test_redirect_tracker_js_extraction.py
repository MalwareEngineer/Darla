"""JS-redirect extraction tests for RedirectTracker.

The pre-existing ``_extract_js_redirect`` returned the *first* target
it found in body order — which silently broke the Microsoft OAuth AITM
trace on investigations ``bc4cd2d6``, ``b5a4f794``, ``66fbd412``,
``435ffd3f``, ``8f578dd8``.  Microsoft's 200 HTML body ships BOTH:

  * a real cross-host MSA handoff URL (``https://login.live.com/
    oauth20_authorize.srf?...``) — where a real browser actually goes
  * a same-host ``location.replace("/error.aspx?err=504")`` **fallback**
    that only executes if the JS handoff fails

The old logic picked the same-host ``/error.aspx`` target, followed it
to an empty HTTP 404, and misclassified the investigation as dead when
the attacker's app + AITM proxy were actually live.

The new extractor:

  1. collects ALL JS-redirect candidates,
  2. drops same-host dead-end fallback handlers (``/error.aspx`` on
     ``login.microsoftonline.com``, ``/err.srf`` on ``login.live.com``),
  3. prefers a cross-host candidate over any surviving same-host one,
  4. falls back to first-seen order as the final tiebreaker.

These tests lock that behavior in so a future refactor can't silently
regress to the old "first match wins" path.
"""

from __future__ import annotations

from darla.analysis.redirect_tracker import _extract_js_redirect

# ---------------------------------------------------------------------------
# The Azure OAuth AITM case — the specific regression that drove this work.
# ---------------------------------------------------------------------------

# Minimized shape of what Microsoft's authorize endpoint returned for
# the 5 captured lures.  The real body is ~25KB of bootstrap JS that
# builds the MSA handoff URL dynamically; the synthetic body below
# preserves the two redirect *shapes* our extractor has to choose
# between — a cross-host MSA handoff as a literal string, and the
# same-host ``/error.aspx`` fallback that fires if the JS handoff fails.
_MS_OAUTH_RESPONSE_BODY = r"""
<html><body><script>
  // Real handoff target — the URL the MSA auth JS navigates to on
  // success.  In production this is built by concatenation; we use a
  // literal here so the regex can see it the same way it would see a
  // fully-resolved location.replace in attacker-crafted pages.
  location.replace("https://login.live.com/oauth20_authorize.srf?client_id=78ce50cb-54eb-42b2-9e79-9c71b0309da7&scope=openid+profile+email&response_type=code");
  // Fallback that fires if the JS above hasn't already replaced location:
  location.replace("/error.aspx?err=504");
</script></body></html>
"""


def test_ms_oauth_body_prefers_live_com_handoff_over_error_fallback() -> None:
    """The exact bug: same-host ``/error.aspx?err=504`` MUST NOT win
    when a cross-host ``login.live.com`` handoff exists in the same body.
    """
    result = _extract_js_redirect(
        _MS_OAUTH_RESPONSE_BODY,
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    )
    # The real target is the cross-host MSA handoff.  The error.aspx
    # fallback must have been filtered out.
    assert result is not None
    assert "login.live.com/oauth20_authorize.srf" in result
    assert "error.aspx" not in result


def test_error_aspx_only_body_returns_none_not_dead_end() -> None:
    """If the ONLY JS target is a known same-host dead-end fallback,
    return None — let the current page be treated as final rather than
    marching into a guaranteed 404."""
    body = """
    <html><body><script>
      location.replace("/error.aspx?err=504");
    </script></body></html>
    """
    result = _extract_js_redirect(
        body, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    )
    assert result is None


def test_live_com_err_srf_also_filtered() -> None:
    """Same rule as ``/error.aspx`` on microsoftonline.com, but for the
    MSA equivalent (``/err.srf`` on ``login.live.com``)."""
    body = """<script>location.replace("/err.srf?code=504");</script>"""
    result = _extract_js_redirect(
        body, "https://login.live.com/oauth20_authorize.srf",
    )
    assert result is None


# ---------------------------------------------------------------------------
# Cross-host preference — general hygiene, not Microsoft-specific.
# ---------------------------------------------------------------------------

def test_cross_host_wins_over_same_host_even_when_same_host_appears_first() -> None:
    """Generic rule: a cross-host candidate beats a same-host one
    regardless of body order.  Protects us from attackers ordering
    candidates to trick first-match extractors."""
    body = """
    <script>
      location.href = "/same-host-path";
      location.replace("https://cross.example.com/target");
    </script>
    """
    result = _extract_js_redirect(body, "https://original.example.com/")
    assert result == "https://cross.example.com/target"


def test_same_host_returned_when_no_cross_host_exists() -> None:
    """If every candidate is same-host AND none is a known dead-end,
    take the first same-host target — don't bail out needlessly."""
    body = """<script>location.href = "/next-page";</script>"""
    result = _extract_js_redirect(body, "https://example.com/start")
    assert result == "https://example.com/next-page"


def test_meta_refresh_respected() -> None:
    body = """
    <meta http-equiv="refresh" content="0; url=https://target.example.com/x">
    """
    result = _extract_js_redirect(body, "https://source.example.com/")
    assert result == "https://target.example.com/x"


def test_meta_refresh_cross_host_wins_over_samehost_js() -> None:
    """Meta-refresh to a cross-host target beats a same-host
    ``location.href`` even when the JS assignment appears earlier
    in the document."""
    body = """
    <script>location.href = "/same";</script>
    <meta http-equiv="refresh" content="0; url=https://target.example.com/x">
    """
    result = _extract_js_redirect(body, "https://source.example.com/")
    assert result == "https://target.example.com/x"


# ---------------------------------------------------------------------------
# Pre-existing guardrails preserved.
# ---------------------------------------------------------------------------

def test_self_referencing_location_ignored() -> None:
    """``location.href = location.href`` is a no-op obfuscation.  Don't
    follow it as a redirect."""
    body = """<script>location.href = location.href;</script>"""
    assert _extract_js_redirect(body, "https://example.com/") is None


def test_javascript_and_anchor_targets_ignored() -> None:
    body = """
    <script>location.href = "javascript:void(0)";</script>
    <script>location.replace("#anchor");</script>
    """
    assert _extract_js_redirect(body, "https://example.com/") is None


def test_empty_body_returns_none() -> None:
    assert _extract_js_redirect("", "https://example.com/") is None


def test_duplicate_candidates_deduplicated() -> None:
    """A body that mentions the same target twice (e.g. both a meta
    refresh AND a JS location.replace) must still return a single
    target — the first one."""
    body = """
    <meta http-equiv="refresh" content="0; url=https://next.example.com/x">
    <script>location.replace("https://next.example.com/x");</script>
    """
    result = _extract_js_redirect(body, "https://start.example.com/")
    assert result == "https://next.example.com/x"

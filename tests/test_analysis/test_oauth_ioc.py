"""OAuth authorize URL IOC extractor tests.

Covers the Azure-OAuth consent-phishing / AITM pattern observed on
investigations ``bc4cd2d6``, ``b5a4f794``, ``66fbd412``, ``435ffd3f``,
``8f578dd8`` — all five landing pages are ``login.microsoftonline.com/
common/oauth2/v2.0/authorize`` URLs with attacker-registered
``client_id``s, each encoding the victim's email into ``state`` as
base64 so the downstream AITM proxy can pre-populate a fake M365
sign-in form.

The IOC extractor is deliberately pure and side-effect-free so it runs
at the TOP of ``download_kit`` — the URL itself is the durable artifact
even when Microsoft later disables the malicious app or when the
attacker's redirect_uri host goes down.  Guard tests in this file make
sure that contract holds.
"""

from __future__ import annotations

from darla.analysis.oauth_ioc import (
    extract_oauth_iocs,
    is_oauth_authorize_url,
)

# ---------------------------------------------------------------------------
# is_oauth_authorize_url — host/path gating
# ---------------------------------------------------------------------------

def test_recognizes_microsoft_v2_authorize() -> None:
    assert is_oauth_authorize_url(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X"
    )


def test_recognizes_microsoft_v1_authorize() -> None:
    assert is_oauth_authorize_url(
        "https://login.microsoftonline.com/common/oauth2/authorize?client_id=X"
    )


def test_recognizes_tenant_guid_v2_authorize() -> None:
    assert is_oauth_authorize_url(
        "https://login.microsoftonline.com/"
        "72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/authorize?x=1"
    )


def test_recognizes_live_com_msa_handoff() -> None:
    # Consumer MSA handoff endpoint — what ``login.microsoftonline.com``
    # hands off to for MSA-registered apps.  Also a valid standalone
    # lure target.
    assert is_oauth_authorize_url(
        "https://login.live.com/oauth20_authorize.srf?client_id=X"
    )


def test_rejects_token_endpoint() -> None:
    # ``/oauth2/v2.0/token`` is the back-channel code exchange, NOT a
    # user-facing lure.  Must not be treated as an authorize URL.
    assert not is_oauth_authorize_url(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    )


def test_rejects_adminconsent() -> None:
    # Admin-consent has a different lure pattern and different IOC shape;
    # we may handle it later, but it must not collide with this extractor.
    assert not is_oauth_authorize_url(
        "https://login.microsoftonline.com/common/adminconsent?client_id=X"
    )


def test_rejects_unrelated_microsoft_urls() -> None:
    assert not is_oauth_authorize_url("https://www.microsoft.com/")
    assert not is_oauth_authorize_url(
        "https://login.microsoftonline.com/error.aspx?err=504"
    )


def test_rejects_non_microsoft_idp() -> None:
    # Google's OAuth looks similar; we only emit IOCs for providers we
    # understand to avoid schema-fragmented data.
    assert not is_oauth_authorize_url(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=X"
    )


def test_rejects_empty_and_bad_input() -> None:
    assert not is_oauth_authorize_url(None)
    assert not is_oauth_authorize_url("")
    assert not is_oauth_authorize_url("not a url")
    assert not is_oauth_authorize_url(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# extract_oauth_iocs — the real-world AITM lure shape
# ---------------------------------------------------------------------------

# Synthetic test lure modelled on a captured campaign URL shape.
# The state param decodes to a synthetic placeholder email
# (``YWxpY2VAYWNtZS5jb20=`` → ``alice@acme.com``) so this fixture is
# safe to ship in the public repo without leaking real victim PII.
_REAL_LURE = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    "?client_id=78ce50cb-54eb-42b2-9e79-9c71b0309da7"
    "&response_type=code"
    "&response_mode=query"
    "&scope=openid+profile+email+https://graph.microsoft.com/User.Read"
    "&prompt=none"
    "&state=YWxpY2VAYWNtZS5jb20="
)


def test_real_lure_extracts_full_campaign_fingerprint() -> None:
    iocs = extract_oauth_iocs(_REAL_LURE)
    assert iocs is not None
    assert iocs["provider"] == "microsoft"
    assert iocs["host"] == "login.microsoftonline.com"
    assert iocs["tenant"] == "common"
    assert iocs["client_id"] == "78ce50cb-54eb-42b2-9e79-9c71b0309da7"
    assert iocs["response_type"] == "code"
    assert iocs["response_mode"] == "query"
    assert iocs["prompt"] == "none"
    # Prompt=none is the smoking gun — attackers use it so logged-out
    # victims still bounce to the redirect_uri (AITM proxy) with an
    # OAuth error instead of seeing a real consent screen.
    assert iocs["silent_auth_abuse"] is True
    # State base64-decodes to the victim's email; both raw and decoded
    # must be preserved so operators can correlate.
    assert iocs["state_raw"] == "YWxpY2VAYWNtZS5jb20="
    assert iocs["state_decoded"] == "alice@acme.com"
    assert iocs["victim_email"] == "alice@acme.com"


def test_scope_is_split_on_plus_and_space() -> None:
    iocs = extract_oauth_iocs(_REAL_LURE)
    assert iocs is not None
    # Microsoft accepts both ``+`` and space as scope separators.  The
    # split view makes it obvious at a glance which permissions the
    # attacker was asking for.
    assert "openid" in iocs["scopes"]
    assert "profile" in iocs["scopes"]
    assert "email" in iocs["scopes"]
    assert "https://graph.microsoft.com/User.Read" in iocs["scopes"]
    # Raw form preserved verbatim for operators who need to replay.
    assert "User.Read" in iocs["scope_raw"]


def test_redirect_uri_surfaced_when_present() -> None:
    # When the attacker sets the redirect_uri in the URL (instead of
    # relying on app-registration default), that host is an immediate
    # campaign IOC — it's the AITM proxy.
    url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X"
        "&response_type=code"
        "&redirect_uri=https%3A%2F%2Fsolarworldbotswana.co.bw%2F.media%2F"
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["redirect_uri"] == "https://solarworldbotswana.co.bw/.media/"


def test_login_hint_is_surfaced() -> None:
    # ``login_hint`` is a direct PII leak — the attacker put the victim
    # email into the URL itself.  Surface it.
    url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X&login_hint=ceo%40target.example.com"
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["login_hint"] == "ceo@target.example.com"


def test_urlsafe_base64_state_decoded() -> None:
    # Some attacker kits use urlsafe-b64 (``-`` / ``_``) — our decoder
    # must handle both forms.  Encodes ``alice+tag@co.example``.
    url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X&state=YWxpY2UrdGFnQGNvLmV4YW1wbGU="
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["state_decoded"] == "alice+tag@co.example"
    assert iocs["victim_email"] == "alice+tag@co.example"


def test_non_base64_state_not_decoded() -> None:
    # Legitimate OAuth clients put CSRF tokens in state (not base64).
    # We must NOT surface a fake ``state_decoded`` for those.
    url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X&state=csrf-xyz-8742-not-b64!"
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["state_raw"] == "csrf-xyz-8742-not-b64!"
    assert "state_decoded" not in iocs
    assert "victim_email" not in iocs


def test_base64_state_decoding_to_garbage_not_surfaced() -> None:
    # A string that happens to pass the base64 regex but decodes to
    # non-printable bytes must not be presented as decoded PII.
    url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X&state=QUJDREVGR0g="  # "ABCDEFGH" — printable, OK
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["state_decoded"] == "ABCDEFGH"
    # No email present so no victim_email field.
    assert "victim_email" not in iocs


def test_live_com_handoff_extracts_client_id() -> None:
    # The MSA handoff URL (the one Microsoft's JS redirects victim to
    # after the authorize call) carries the same client_id — we want
    # IOCs out of it too.
    url = (
        "https://login.live.com/oauth20_authorize.srf"
        "?client_id=78ce50cb-54eb-42b2-9e79-9c71b0309da7"
        "&scope=openid+profile"
        "&response_type=code"
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["host"] == "login.live.com"
    # login.live.com has no tenant segment.
    assert "tenant" not in iocs
    assert iocs["client_id"] == "78ce50cb-54eb-42b2-9e79-9c71b0309da7"


# ---------------------------------------------------------------------------
# Non-OAuth input → None (don't emit empty IOC blocks)
# ---------------------------------------------------------------------------

def test_non_oauth_url_returns_none() -> None:
    assert extract_oauth_iocs("https://example.com/") is None
    assert extract_oauth_iocs(None) is None


def test_token_endpoint_returns_none() -> None:
    # Back-channel endpoint — never a lure, must not emit IOC.
    assert extract_oauth_iocs(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    ) is None


# ---------------------------------------------------------------------------
# Robustness — we must not crash on weird but real-world inputs
# ---------------------------------------------------------------------------

def test_empty_query_string_still_recognized() -> None:
    # A bare authorize URL with no params is still OAuth-shaped; we
    # emit the provider+host+tenant fields and nothing else.
    iocs = extract_oauth_iocs(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    assert iocs is not None
    assert iocs["provider"] == "microsoft"
    assert iocs["tenant"] == "common"
    assert "client_id" not in iocs


def test_trailing_slash_on_authorize_still_matched() -> None:
    assert is_oauth_authorize_url(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize/"
        "?client_id=X"
    )


def test_unpadded_b64_state_still_decoded() -> None:
    # Attacker kits occasionally strip trailing ``=`` padding.  Our
    # decoder pads before attempting.
    url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=X&state=YWxpY2VAYWNtZS5jb20"  # no ``=``
    )
    iocs = extract_oauth_iocs(url)
    assert iocs is not None
    assert iocs["state_decoded"] == "alice@acme.com"

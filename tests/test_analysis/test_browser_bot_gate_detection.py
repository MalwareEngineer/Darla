"""Structural regression guards for browser_downloader bot-gate detection.

The full ``_detect_bot_gate`` logic runs as JS inside a live Playwright
page — covered by integration detonation, not by unit tests.  This file
guards the specific selectors and strategies that address gaps seen in
real kits, so a refactor can't silently drop them:

  * **Fake click-captcha gate** (kit ``eae2ac74-be7a-4db1-90cf-db9df0be5056``)
    — ``#captcha-box``/``.captcha-wrapper`` wrapping an AITM cred harvester
    with ``wss://user.cheacker.store/*`` exfil.  The previous detection
    missed it because body innerText had no gate vocabulary and there was
    no form.  Strategy 0 now scans for ``captcha``/``human-check``/
    ``human-verif`` class/id tokens as a high-confidence structural hint.
"""

from __future__ import annotations

import inspect

from darla.analysis import browser_downloader


def _source_of(obj) -> str:
    return inspect.getsource(obj)


# ---------------------------------------------------------------------------
# Strategy 0 — captcha class/id detection
# ---------------------------------------------------------------------------

def test_detect_bot_gate_scans_captcha_class_tokens() -> None:
    """Legitimate login pages don't use ``captcha`` in element class names;
    fake click-captcha templates almost always do.  The querySelector
    must cover class AND id substrings for both ``captcha`` and the
    ``human-*`` variants seen in the wild."""
    src = _source_of(browser_downloader._detect_bot_gate)
    # Substring selectors — keep these exact so attacker-template
    # variations ("captcha-wrapper", "clickcaptcha", "human-check-v2")
    # all match.
    required_selectors = [
        '[class*="captcha"]',
        '[id*="captcha"]',
        '[class*="human-check"]',
        '[class*="human-verif"]',
    ]
    for sel in required_selectors:
        assert sel in src, f"detect_bot_gate lost selector: {sel!r}"


def test_detect_bot_gate_emits_fake_captcha_gate_type() -> None:
    """Strategy 0 must surface a dedicated ``fake_captcha_gate`` type —
    the bypass flow treats it like an auto-submit-form gate (waits for
    navigation after click) rather than a simple button."""
    src = _source_of(browser_downloader._detect_bot_gate)
    assert "'fake_captcha_gate'" in src or '"fake_captcha_gate"' in src


def test_bypass_waits_for_navigation_on_fake_captcha_gate() -> None:
    """After clicking a fake_captcha_gate, the bypass must call the
    form-submit wait (polls for URL change / networkidle) rather than
    the simple gate-resolution wait — these gates typically navigate
    or swap the DOM into a cred harvester."""
    assert "fake_captcha_gate" in browser_downloader._FORM_SUBMIT_GATE_TYPES, (
        "bypass flow must route fake_captcha_gate through "
        "_wait_for_form_submit"
    )
    src = _source_of(browser_downloader._attempt_bot_gate_bypass)
    assert "_FORM_SUBMIT_GATE_TYPES" in src
    assert "_wait_for_form_submit" in src


# ---------------------------------------------------------------------------
# WebSocket capture wiring — regression guard on the handler registration.
# ---------------------------------------------------------------------------

def test_websocket_handler_registered_on_page() -> None:
    """``page.on('websocket', _on_websocket)`` MUST be registered in
    both navigation contexts (initial goto + turnstile-retry fresh
    page), or AITM cred-relay frames are silently dropped."""
    src = _source_of(browser_downloader._async_browser_download)
    # Both registrations — the fresh-context retry re-creates the page
    # and must re-attach handlers.
    assert src.count('page.on("websocket"') >= 2, (
        "page.on('websocket', ...) must be attached on BOTH the initial "
        "page and the turnstile-retry fresh page"
    )


def test_websocket_frames_persisted_when_captured() -> None:
    """Captured frames must be persisted to ``websocket_frames.jsonl``
    — this is how the AITM wss:// protocol ends up reviewable after
    the kit finishes."""
    src = _source_of(browser_downloader._async_browser_download)
    assert "websocket_frames.jsonl" in src


# ---------------------------------------------------------------------------
# Layer ordering — cheap CSS/attribute matches must precede the sweeps
# ---------------------------------------------------------------------------

_LAYER_MARKERS = [
    "L1: class/id token signal for fake captcha gates",
    "L2: slide-to-unlock / press-and-hold widget tokens",
    "L3: one innerText read + gate vocabulary",
    "L4: text/ARIA scan over button-ish candidates",
    "L5: CSS-affordance scan next to gate text",
    "L6: div/span checkbox sweep",
    "L7: hidden challenge fields with a button",
    "L8: POST form + hidden input + full pointer sweep",
    "L9: honey-email entry gate",
]


def test_detect_bot_gate_layers_run_cheapest_first() -> None:
    """The layers are ordered by cost so the common case (no gate) pays
    only for a few attribute selectors.  A refactor that reorders them
    turns every clean page into a full-DOM ``getComputedStyle`` sweep,
    and — worse — lets a text layer classify a slider as a click."""
    src = _source_of(browser_downloader._detect_bot_gate)
    positions = []
    for marker in _LAYER_MARKERS:
        idx = src.find(marker)
        assert idx != -1, f"detect_bot_gate lost layer marker: {marker!r}"
        positions.append(idx)
    assert positions == sorted(positions), (
        "detect_bot_gate layers are out of cost order"
    )


def test_innertext_read_once_after_the_free_layers() -> None:
    """``body.innerText`` forces layout.  It must be read exactly once,
    and only after the attribute-selector layers have had their chance
    to short-circuit."""
    src = _source_of(browser_downloader._detect_bot_gate)
    # The read itself, not the docstring's mention of it.
    assert src.count("document.body ? document.body.innerText") == 1
    assert src.index("document.body ? document.body.innerText") > src.index(
        "L2: slide-to-unlock / press-and-hold widget tokens"
    )


# ---------------------------------------------------------------------------
# Slide-to-unlock / press-and-hold gates
# ---------------------------------------------------------------------------

def test_detector_classifies_slide_and_hold_gates_before_text_layers() -> None:
    """Slide/hold widgets must be typed from their class/ARIA tokens in
    L2.  If a text layer reaches them first they come back as
    ``verify_button``, the bypass clicks the handle, and the gate never
    resolves — a click emits no mousemove run and no sustained press."""
    src = _source_of(browser_downloader._detect_bot_gate)
    for token in [
        '[class*="slide-to"]',
        '[class*="slidetounlock"]',
        '[class*="swipe-to"]',
        '[class*="slider-captcha"]',
        '[role="slider"]',
        'input[type="range"]',
        '[class*="press-and-hold"]',
        '[class*="hold-to"]',
        '[class*="long-press"]',
        "[data-hold-duration]",
    ]:
        assert token in src, f"detect_bot_gate lost slide/hold token: {token!r}"
    assert "'slider_gate'" in src
    assert "'hold_gate'" in src


def test_slide_and_hold_vocabulary_covers_unlock_open_access() -> None:
    """"Slide to unlock/open/access" and "hold to unlock/open/access"
    are the phrasings these kits actually ship; both pattern lists have
    to carry all three verbs."""
    src = _source_of(browser_downloader._detect_bot_gate)
    slide_block = src.split("const slidePats = [")[1].split("];")[0]
    hold_block = src.split("const holdPats = [")[1].split("];")[0]
    for verb in ["unlock", "open", "access"]:
        assert verb in slide_block, f"slide patterns miss {verb!r}"
        assert verb in hold_block, f"hold patterns miss {verb!r}"
    # The three ways a kit spells the gesture itself.
    for gesture in ["slide", "swipe", "drag"]:
        assert gesture in slide_block, f"slide patterns miss {gesture!r}"
    for gesture in ["press", "hold", "long"]:
        assert gesture in hold_block, f"hold patterns miss {gesture!r}"


def test_bypass_drags_sliders_and_holds_hold_gates() -> None:
    """The bypass must dispatch on gate type before the generic click —
    a slider needs mousedown + a run of mousemove + mouseup, a hold
    needs a sustained press."""
    src = _source_of(browser_downloader._attempt_bot_gate_bypass)
    assert "_drag_slider_gate" in src
    assert "_press_and_hold_gate" in src
    # Dispatch must happen before the query_selector/click path.
    assert src.index("_drag_slider_gate") < src.index("page.mouse.click")
    assert src.index("_press_and_hold_gate") < src.index("page.mouse.click")


def test_slider_drag_emits_intermediate_moves() -> None:
    """A slider gate rejects a teleporting pointer.  The drag must press,
    emit many intermediate moves, then release."""
    src = _source_of(browser_downloader._drag_slider_gate)
    assert "page.mouse.down()" in src
    assert "page.mouse.up()" in src
    assert src.index("page.mouse.down()") < src.index("page.mouse.up()")
    assert "for i in range(1, steps + 1)" in src


def test_hold_gate_press_is_time_bounded() -> None:
    """A hold that never resolves must not eat the page budget, and the
    button must always be released even when the press raises."""
    src = _source_of(browser_downloader._press_and_hold_gate)
    assert "_MAX_HOLD_SECONDS" in src
    assert src.count("page.mouse.up()") >= 2, (
        "hold gate must release the button on the error path too"
    )
    assert browser_downloader._MAX_HOLD_SECONDS <= 10.0


# ---------------------------------------------------------------------------
# CSS-affordance layer (L5)
# ---------------------------------------------------------------------------

def test_affordance_layer_uses_css_clickability_signals() -> None:
    """Some kits' gate element carries no text at all — an icon, a bare
    styled div.  L5 finds it by the attributes that make something look
    clickable instead."""
    src = _source_of(browser_downloader._detect_bot_gate)
    for sel in [
        '[tabindex]:not([tabindex="-1"])',
        '[class*="btn"]',
        '[role="button"]',
        "[aria-pressed]",
        "[data-action]",
        '[draggable="true"]',
        'input[type="checkbox"]',
    ]:
        assert sel in src, f"affordance layer lost selector: {sel!r}"


def test_affordance_layer_requires_gate_text_and_a_reason_to_click() -> None:
    """Unscored affordances are page furniture.  L5 must be gated on
    confirmed gate text AND only accept a labelled / containerised
    candidate, or a lone affordance — otherwise it clicks site nav."""
    src = _source_of(browser_downloader._detect_bot_gate)
    layer = src.split("L5: CSS-affordance scan")[1].split("L6:")[0]
    assert "if (hasGateText && !skipVerifyButtonStrategy)" in layer
    assert "affordances.length === 1" in layer, (
        "L5 must not click an arbitrary affordance when several exist"
    )


# ---------------------------------------------------------------------------
# Honey-email entry gate (L9)
# ---------------------------------------------------------------------------

def test_email_gate_layer_is_last_and_skips_credential_forms() -> None:
    """An email field is cheap to find but must lose to every real bot
    gate.  It must also be skipped when a password input shares its
    form: that page IS the harvester, and submitting it navigates away
    before we capture it."""
    src = _source_of(browser_downloader._detect_bot_gate)
    assert src.index("L9: honey-email entry gate") > src.index("L8: POST form")
    probe = src.split("function findEmailGateField(")[1].split("\n                }")[0]
    assert 'input[type="password"]' in probe, (
        "email probe must skip a field sharing a form with a password input"
    )


def test_email_gate_probe_runs_before_generic_next_continue_buttons() -> None:
    """A lure's email gate ships with a bare "Next"/"Continue" button.
    If L4 matches that button first we click it on an empty field and
    the kit answers "please enter the correct email" — the credential
    page is never reached.  The probe therefore runs ahead of L4 on
    pages carrying no bot-gate vocabulary."""
    src = _source_of(browser_downloader._detect_bot_gate)
    early = src.index("const earlyEmail = findEmailGateField(pageText)")
    assert early < src.index("L4: text/ARIA scan over button-ish candidates")
    assert early > src.index("const hasGateText"), (
        "the probe needs hasGateText — a real bot gate still outranks it"
    )
    # Guarded on the page having no gate text, so bot gates win.
    assert "if (!hasGateText) {" in src


def test_email_probe_requires_lure_copy_or_a_bare_lander() -> None:
    """A burned token lands us on a real decoy site.  Typing the honey
    address into some unrelated newsletter box leaks the credential to
    an uninvolved third party, so an email field alone is not enough."""
    src = _source_of(browser_downloader._detect_bot_gate)
    probe = src.split("function findEmailGateField(")[1].split("\n                }")[0]
    assert "emailLurePats" in probe
    # Structural fallback: the page's only input, next to no navigation.
    assert "inputs.length === 1" in probe
    assert "links.length <= 2" in probe


def test_fill_email_gate_skips_fields_beside_a_password_input() -> None:
    """Same guard on the Python side — ``_click_lure_cta`` presses Enter
    after filling, which would submit a half-filled credential form."""
    src = _source_of(browser_downloader._fill_email_gate)
    assert "_shares_form_with_password" in src
    guard = _source_of(browser_downloader._shares_form_with_password)
    assert 'input[type="password"]' in guard


def test_email_gate_selector_covers_unlabelled_fields() -> None:
    """Kits label the honey-email field visually only.  The selector
    must reach aria-label and ``you@company.com`` placeholders."""
    sel = browser_downloader._EMAIL_GATE_SELECTOR
    for frag in [
        'input[type="email"]',
        'input[name*="mail" i]',
        'input[aria-label*="mail" i]',
        'input[placeholder*="@"]',
    ]:
        assert frag in sel, f"email gate selector lost: {frag!r}"


def test_bypass_reports_email_gate_as_interaction() -> None:
    """The bypass returns the gate type so the caller can mark the final
    domain interaction-driven rather than relay rotation."""
    src = _source_of(browser_downloader._attempt_bot_gate_bypass)
    assert "-> str | None" in src
    assert '"email_gate"' in src
    caller = _source_of(browser_downloader._async_browser_download)
    assert 'gate_found == "email_gate"' in caller
    assert "cta_clicked = True" in caller

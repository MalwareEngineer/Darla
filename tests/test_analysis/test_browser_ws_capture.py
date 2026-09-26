"""WebSocket frame serialization tests for browser_downloader.

The live Playwright path (``page.on('websocket', ...)``) is covered by
integration detonation; here we exercise the pure Python helper that
builds each JSONL record.  AITM cred-harvester kits stream credentials
over ``wss://`` — getting this serialization wrong (or missing the
capture entirely, which was the prior bug) means we never see the
protocol used to exfil creds.

Guards to keep this test useful:
  * Binary payloads stay ASCII-safe (base64) so the JSONL file is
    readable without special tooling.
  * Text payloads preserve UTF-8 content up to the preview cap.
  * Oversized payloads are truncated *and* flagged — the reader must
    be able to tell a preview from a complete frame.
  * The ``.payload`` unwrap tolerates both modern Playwright (raw
    str/bytes) and older wrapping styles.
"""

from __future__ import annotations

import base64
import json

from darla.analysis.browser_downloader import (
    _WS_FRAME_PREVIEW_BYTES,
    _serialize_ws_frame,
)

# ---------------------------------------------------------------------------
# Text frames
# ---------------------------------------------------------------------------

def test_text_frame_roundtrips_through_jsonl() -> None:
    payload = '{"action":"login","user":"victim@example.com","pass":"hunter2"}'
    frame = _serialize_ws_frame(
        index=1,
        direction="sent",
        ws_url="wss://user.cheacker.store/wsTsk",
        payload=payload,
        timestamp=1.234,
    )
    assert frame["opcode"] == "text"
    assert frame["direction"] == "sent"
    assert frame["length"] == len(payload)
    assert frame["preview"] == payload
    assert frame["truncated"] is False
    assert frame["ws_url"].startswith("wss://")

    # Must serialize as one-line JSON (JSONL contract).
    line = json.dumps(frame)
    assert "\n" not in line
    decoded = json.loads(line)
    assert decoded["preview"] == payload


def test_text_frame_truncated_at_preview_cap() -> None:
    big = "A" * (_WS_FRAME_PREVIEW_BYTES + 500)
    frame = _serialize_ws_frame(
        index=2, direction="received", ws_url="wss://x/", payload=big,
        timestamp=0.0,
    )
    assert frame["length"] == len(big)
    assert len(frame["preview"]) == _WS_FRAME_PREVIEW_BYTES
    assert frame["truncated"] is True


def test_text_frame_at_exact_cap_is_not_flagged_truncated() -> None:
    # Payload exactly at the cap fits without loss — don't mislabel it.
    exact = "B" * _WS_FRAME_PREVIEW_BYTES
    frame = _serialize_ws_frame(
        index=3, direction="sent", ws_url="wss://x/", payload=exact,
        timestamp=0.0,
    )
    assert frame["length"] == _WS_FRAME_PREVIEW_BYTES
    assert len(frame["preview"]) == _WS_FRAME_PREVIEW_BYTES
    assert frame["truncated"] is False


def test_text_frame_preserves_utf8_multibyte() -> None:
    # AITM relays sometimes send JSON containing non-ASCII field values.
    # The preview must keep them intact — we're not doing any decoding
    # dance that would mangle them.
    payload = '{"msg":"café — привет — 🔑"}'
    frame = _serialize_ws_frame(
        index=4, direction="received", ws_url="wss://x/", payload=payload,
        timestamp=0.0,
    )
    assert frame["preview"] == payload


# ---------------------------------------------------------------------------
# Binary frames — base64 to keep JSONL ASCII-safe.
# ---------------------------------------------------------------------------

def test_binary_frame_is_base64_encoded() -> None:
    raw = b"\x00\x01\x02\xff\xfe\xfd"
    frame = _serialize_ws_frame(
        index=1, direction="sent", ws_url="wss://x/", payload=raw,
        timestamp=0.0,
    )
    assert frame["opcode"] == "binary"
    assert frame["length"] == len(raw)
    assert "preview_b64" in frame
    assert "preview" not in frame
    assert base64.b64decode(frame["preview_b64"]) == raw
    assert frame["truncated"] is False


def test_binary_frame_truncated_at_preview_cap() -> None:
    raw = b"Z" * (_WS_FRAME_PREVIEW_BYTES + 10)
    frame = _serialize_ws_frame(
        index=1, direction="sent", ws_url="wss://x/", payload=raw,
        timestamp=0.0,
    )
    assert frame["length"] == len(raw)
    # Preview is exactly the cap bytes, base64 of that.
    decoded = base64.b64decode(frame["preview_b64"])
    assert len(decoded) == _WS_FRAME_PREVIEW_BYTES
    assert frame["truncated"] is True


def test_bytearray_payload_handled_same_as_bytes() -> None:
    raw = bytearray(b"\x10\x20\x30")
    frame = _serialize_ws_frame(
        index=1, direction="received", ws_url="wss://x/", payload=raw,
        timestamp=0.0,
    )
    assert frame["opcode"] == "binary"
    assert base64.b64decode(frame["preview_b64"]) == bytes(raw)


# ---------------------------------------------------------------------------
# Playwright wrapper unwrapping — older versions wrap payload in an object.
# ---------------------------------------------------------------------------

class _PayloadWrapper:
    """Mimics older Playwright FrameData-style wrapping."""

    def __init__(self, payload):
        self.payload = payload


def test_unwraps_playwright_payload_wrapper_text() -> None:
    inner = '{"ping":1}'
    frame = _serialize_ws_frame(
        index=1, direction="sent", ws_url="wss://x/",
        payload=_PayloadWrapper(inner), timestamp=0.0,
    )
    assert frame["opcode"] == "text"
    assert frame["preview"] == inner


def test_unwraps_playwright_payload_wrapper_binary() -> None:
    inner = b"\x90\x91\x92"
    frame = _serialize_ws_frame(
        index=1, direction="received", ws_url="wss://x/",
        payload=_PayloadWrapper(inner), timestamp=0.0,
    )
    assert frame["opcode"] == "binary"
    assert base64.b64decode(frame["preview_b64"]) == inner


# ---------------------------------------------------------------------------
# Metadata fields
# ---------------------------------------------------------------------------

def test_timestamp_is_rounded_to_millis() -> None:
    frame = _serialize_ws_frame(
        index=1, direction="sent", ws_url="wss://x/", payload="",
        timestamp=1.23456789,
    )
    # 3-decimal rounding — JSONL stays tidy and millis are enough
    # resolution for AITM-relay frame-by-frame timing analysis.
    assert frame["timestamp"] == 1.235


def test_index_and_direction_passed_through() -> None:
    frame = _serialize_ws_frame(
        index=42, direction="received", ws_url="wss://relay.example.com/x",
        payload="pong", timestamp=0.0,
    )
    assert frame["index"] == 42
    assert frame["direction"] == "received"
    assert frame["ws_url"] == "wss://relay.example.com/x"


def test_none_payload_serializes_as_empty_text() -> None:
    # Playwright occasionally fires framesent with no payload on control
    # frames (ping/pong).  Don't crash.
    frame = _serialize_ws_frame(
        index=1, direction="sent", ws_url="wss://x/", payload=None,
        timestamp=0.0,
    )
    assert frame["opcode"] == "text"
    assert frame["length"] == 0
    assert frame["preview"] == ""
    assert frame["truncated"] is False

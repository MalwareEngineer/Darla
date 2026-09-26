"""Tests for JSDeobfuscator._try_layered_decode_chain.

All fixtures are synthetic: we run benign plaintext (e.g. a fake loader URL)
through the inverse of each pipeline and assert the decoder recovers it.
No real malware samples appear in this file.
"""
from __future__ import annotations

import base64
import codecs
import json

import pytest

from darla.analysis.deobfuscator import JSDeobfuscator

# ---------------------------------------------------------------------------
# Encoders — the inverse of each decoder primitive. We compose them to
# forge synthetic "encoded seeds" matching real-world loader pipelines.
# ---------------------------------------------------------------------------

def _inv_b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _inv_hex_xor(s: str, key: int) -> str:
    # decoder: b64_decode → ascii hex-pairs → int(pair,16)^key → chr → join
    # inverse: for each char in s, hex(ord(c) ^ key) → concat → b64_encode
    hex_str = "".join(f"{ord(c) ^ key:02x}" for c in s)
    return base64.b64encode(hex_str.encode("ascii")).decode()


def _inv_reverse(s: str) -> str:
    return s[::-1]


def _inv_rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")  # self-inverse


def _inv_json_parse_join(s: str, sep: str = "") -> str:
    # decoder: JSON.parse(x).join(sep) → joined string
    # inverse with sep="": split into single chars, dump as JSON array.
    if sep == "":
        return json.dumps(list(s))
    # For non-empty separator we'd need to know the piece boundaries; not
    # used in real samples, so keep it simple.
    raise NotImplementedError("only empty separator supported in tests")


# ---------------------------------------------------------------------------
# Source snippets — decoder functions that the pipeline walker must parse.
# ---------------------------------------------------------------------------

def _decoder_source_full(seed_b64: str, k1: int, k2: int) -> str:
    """Mirror the real-world 8-step chain:
    b64 → hex_xor(k1) → b64 → reverse → rot13 → json_parse_join → b64 → hex_xor(k2)
    """
    return f"""
    var D=function(e){{
        var d=e;d=atob(d);
        var h=d.match(/.{{2}}/g)||[];d='';
        for(var i=0;i<h.length;i++)d+=String.fromCharCode(parseInt(h[i],16)^{k1});
        var t=atob(d);
        d=t.split('').reverse().join('')
             .replace(/[a-zA-Z]/g,function(c){{var b=c<='Z'?65:97;
               return String.fromCharCode(((c.charCodeAt(0)-b+13)%26)+b);}});
        d=JSON.parse(d).join('');
        d=atob(d);
        var h=d.match(/.{{2}}/g)||[];d='';
        for(var i=0;i<h.length;i++)d+=String.fromCharCode(parseInt(h[i],16)^{k2});
        return d;
    }};
    var _e="{seed_b64}";
    (0,eval)(D(_e));
    """


def _decoder_source_short(seed_b64: str, k: int) -> str:
    """Simpler 2-step loader: b64 → hex_xor(k). Sanity check that the
    pipeline walker doesn't demand every primitive to be present.
    """
    return f"""
    (function(){{
        var d=atob("{seed_b64}");
        var h=d.match(/.{{2}}/g)||[];var o='';
        for(var i=0;i<h.length;i++)o+=String.fromCharCode(parseInt(h[i],16)^{k});
        eval(o);
    }})();
    """


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def deob() -> JSDeobfuscator:
    return JSDeobfuscator()


def test_full_chain_recovers_plaintext_url(deob: JSDeobfuscator) -> None:
    plaintext = "var u='https://example.com/loader.js';eval(u);"
    k1, k2 = 236, 64

    # Walker collapses each "atob → parseInt^KEY" pair into one hex_xor
    # step, so the decoder's semantic pipeline is 6 steps:
    #   hex_xor(k1) → b64 → reverse → rot13 → json_parse → hex_xor(k2)
    # Invert each in reverse order to forge a seed the decoder will chew.
    s = _inv_hex_xor(plaintext, k2)        # inverse of hex_xor(k2)
    s = _inv_json_parse_join(s)            # inverse of json_parse
    s = _inv_rot13(s)                      # inverse of rot13
    s = _inv_reverse(s)                    # inverse of reverse
    s = _inv_b64(s)                        # inverse of b64
    seed = _inv_hex_xor(s, k1)             # inverse of hex_xor(k1)

    source = _decoder_source_full(seed, k1, k2)
    result = deob.deobfuscate(source)

    assert result.layers_unwrapped > 0
    assert "js_layered_chain" in result.techniques_found
    assert plaintext in result.deobfuscated_content


def test_short_chain_hex_xor_only(deob: JSDeobfuscator) -> None:
    plaintext = "window.location='https://phish.example/step2';"
    key = 0xAD

    # plaintext → hex_xor(key) → b64 seed
    seed = _inv_hex_xor(plaintext, key)
    source = _decoder_source_short(seed, key)

    result = deob.deobfuscate(source)
    assert result.layers_unwrapped > 0
    assert plaintext in result.deobfuscated_content


def test_pipeline_walker_orders_steps_correctly(deob: JSDeobfuscator) -> None:
    source = _decoder_source_full("AAAA", 236, 64)
    pipeline = deob._build_transform_pipeline(source)
    names = [n for n, _ in pipeline]
    # Each atob that directly feeds a parseInt^KEY loop is folded into a
    # single hex_xor step; atobs that stand alone emit a b64 step. The
    # decoder's semantic pipeline is therefore 6 steps, not 8.
    assert names == [
        "hex_xor", "b64", "reverse", "rot13", "json_parse", "hex_xor",
    ]
    hex_xor_keys = [p["key"] for n, p in pipeline if n == "hex_xor"]
    assert hex_xor_keys == [236, 64]


def test_no_chain_returns_none(deob: JSDeobfuscator) -> None:
    source = """
    // Ordinary JS with an atob but no hex-XOR chain.
    var cfg = JSON.parse('{"a":1}');
    console.log(atob('aGVsbG8='));
    """
    # Pipeline walker may emit b64 + json_parse but without hex_xor or
    # reverse the layered decoder returns None. The caller still has plain
    # ATOB_PATTERN fallback for the "aGVsbG8=" literal.
    assert deob._try_layered_decode_chain(source) is None


def test_resolver_decodes_hex_escaped_url(deob: JSDeobfuscator) -> None:
    # URL hidden in "\xNN"-escaped string literal. Tail resolver should
    # surface it so URL_PATTERN matches.
    url = "https://example.com/step3.js"
    escaped = "".join(f"\\x{ord(c):02x}" for c in url)
    fake_inner_js = f'var u="{escaped}";fetch(u);'
    resolved = deob._resolve_js_string_literals(fake_inner_js)
    assert url in resolved
    assert deob.URL_PATTERN.search(resolved) is not None


def test_resolver_decodes_hex_literal(deob: JSDeobfuscator) -> None:
    # URL stored as plain hex in a quoted literal, unpacked at runtime via
    # String.fromCharCode(parseInt(h[i],16)) style loops. No XOR.
    url = "https://example.com/step5.js"
    hex_blob = url.encode("utf-8").hex()
    fake_js = (
        f'var h="{hex_blob}";'
        "for(var i=0;i<h.length;i+=2){o+=String.fromCharCode(parseInt(h.substr(i,2),16));}"
    )
    resolved = deob._resolve_js_string_literals(fake_js)
    assert url in resolved
    assert deob.URL_PATTERN.search(resolved) is not None


def test_resolver_decodes_base64_literal(deob: JSDeobfuscator) -> None:
    import base64 as _b64
    url = "https://example.com/step6.js"
    seed = _b64.b64encode(url.encode()).decode()
    fake_js = f'var b="{seed}";eval(atob(b));'
    resolved = deob._resolve_js_string_literals(fake_js)
    assert url in resolved


def test_resolver_decodes_from_char_code(deob: JSDeobfuscator) -> None:
    url = "https://example.com/step4.js"
    nums = ",".join(str(ord(c)) for c in url)
    fake_inner_js = f"location.href = String.fromCharCode({nums});"
    resolved = deob._resolve_js_string_literals(fake_inner_js)
    assert url in resolved


def test_resolver_is_noop_on_plain_content(deob: JSDeobfuscator) -> None:
    plain = "var x = 1; console.log('hello');"
    resolved = deob._resolve_js_string_literals(plain)
    # Original is always included — at worst we get back the same string.
    assert plain in resolved


def test_long_payload_does_not_oom(deob: JSDeobfuscator) -> None:
    # Seed that looks long but decodes to garbage — decoder should abort
    # gracefully, not crash or hang.
    import string
    garbage = "".join(
        [string.ascii_letters] * 200,
    )[:4000]  # ~4KB of non-base64 junk wrapped in quotes
    source = (
        f'var d=atob("{garbage}");'
        "var h=d.match(/.{2}/g);for(var i=0;i<h.length;i++)x+=parseInt(h[i],16)^5;"
    )
    # Should not raise.
    result = deob._try_layered_decode_chain(source)
    assert result is None or isinstance(result, tuple)

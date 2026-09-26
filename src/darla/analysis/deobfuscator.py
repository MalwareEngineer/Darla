"""Deobfuscation engine — PHP eval-chain unwrapping, HTML empty-tag stripping,
and JS XOR+base64+eval decoding.

PHP handles:
  1. eval(base64_decode("..."))
  2. eval(gzinflate(base64_decode("...")))
  3. eval(gzinflate(str_rot13(base64_decode("..."))))
  4. eval(str_rot13("..."))
  5. Nested combinations up to MAX_RECURSION_DEPTH layers
  6. chr() concatenation patterns

JS handles:
  7. atob() → charCodeAt()^KEY → eval() chains
  8. base64 string → byte-level XOR → eval()

Does NOT execute PHP or JS. Only applies known inverse functions in Python.
"""

import base64
import codecs
import contextlib
import json
import re
import zlib
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes

MAX_RECURSION_DEPTH = 100
MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10 MB


@dataclass
class DeobfuscationResult:
    original_content: str
    deobfuscated_content: str
    layers_unwrapped: int
    techniques_found: list[str] = field(default_factory=list)
    success: bool = True
    error: str | None = None


def _url_decode(data: bytes | str) -> bytes:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="ignore")
    return unquote_to_bytes(data)


class PHPDeobfuscator:
    """Recursive PHP deobfuscator using pattern matching and inverse functions."""

    # Match eval() calls containing known decode functions
    EVAL_PATTERN = re.compile(
        r"eval\s*\(\s*"
        r"((?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13"
        r"|rawurldecode|urldecode|convert_uudecode|hex2bin|strrev)"
        r"\s*\(.*?\))"
        r"\s*\)\s*;",
        re.DOTALL | re.IGNORECASE,
    )

    # Match function names in nested chains
    NESTED_FUNC_PATTERN = re.compile(
        r"(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13"
        r"|rawurldecode|urldecode|convert_uudecode|hex2bin|strrev)\s*\(",
        re.IGNORECASE,
    )

    # Match chr() concatenation: chr(72).chr(101).chr(108)...
    CHR_CONCAT_PATTERN = re.compile(
        r"(?:chr\s*\(\s*(\d+)\s*\)\s*\.?\s*){3,}",
        re.IGNORECASE,
    )
    CHR_SINGLE_PATTERN = re.compile(r"chr\s*\(\s*(\d+)\s*\)", re.IGNORECASE)

    # Map PHP function names to Python equivalents
    DECODERS: dict[str, callable] = {
        "base64_decode": lambda data: base64.b64decode(data),
        "gzinflate": lambda data: zlib.decompress(data, -zlib.MAX_WBITS),
        "gzuncompress": lambda data: zlib.decompress(data),
        "gzdecode": lambda data: zlib.decompress(data, zlib.MAX_WBITS | 16),
        "str_rot13": lambda data: codecs.encode(
            data if isinstance(data, str) else data.decode("utf-8", errors="ignore"),
            "rot_13",
        ).encode("utf-8"),
        "rawurldecode": lambda data: _url_decode(data),
        "urldecode": lambda data: _url_decode(data),
        "hex2bin": lambda data: bytes.fromhex(
            data if isinstance(data, str) else data.decode("ascii")
        ),
        "strrev": lambda data: (
            data[::-1] if isinstance(data, (str, bytes)) else data
        ),
    }

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Recursively deobfuscate PHP content."""
        techniques_found: list[str] = []
        current = content
        layers = 0

        for _ in range(MAX_RECURSION_DEPTH):
            previous = current

            # Try eval() unwrapping
            current, found = self._unwrap_eval_layer(current)
            techniques_found.extend(found)

            # Try chr() concatenation resolution
            current, chr_found = self._resolve_chr_concat(current)
            if chr_found:
                techniques_found.append("chr_concat")

            if current == previous:
                break
            layers += 1

            if len(current) > MAX_OUTPUT_SIZE:
                return DeobfuscationResult(
                    original_content=content[:1000],
                    deobfuscated_content=current[:MAX_OUTPUT_SIZE],
                    layers_unwrapped=layers,
                    techniques_found=list(set(techniques_found)),
                    success=False,
                    error="Output size exceeded limit",
                )

        return DeobfuscationResult(
            original_content=content[:1000],
            deobfuscated_content=current,
            layers_unwrapped=layers,
            techniques_found=list(set(techniques_found)),
            success=True,
        )

    def deobfuscate_file(self, filepath: str) -> DeobfuscationResult:
        """Deobfuscate a file by path."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.deobfuscate(content)

    def _unwrap_eval_layer(self, content: str) -> tuple[str, list[str]]:
        techniques: list[str] = []
        result = content

        for match in self.EVAL_PATTERN.finditer(content):
            inner_expr = match.group(1)
            try:
                decoded, funcs_used = self._decode_expression(inner_expr)
                if decoded and decoded != inner_expr:
                    decoded_str = (
                        decoded.decode("utf-8", errors="ignore")
                        if isinstance(decoded, bytes)
                        else decoded
                    )
                    result = result.replace(match.group(0), decoded_str)
                    techniques.extend(funcs_used)
            except Exception:
                continue

        return result, techniques

    def _decode_expression(
        self, expression: str
    ) -> tuple[bytes | str | None, list[str]]:
        """Decode a nested function expression from inside out."""
        funcs_used: list[str] = []

        # Extract chain of function names (outermost first)
        func_chain: list[str] = []
        for m in self.NESTED_FUNC_PATTERN.finditer(expression):
            func_chain.append(m.group(1).lower())

        # Find the innermost string argument
        string_match = re.search(r'["\']([^"\']*)["\']', expression)
        if not string_match:
            return None, []

        data: bytes | str = string_match.group(1)

        # Apply functions from innermost to outermost (reverse order)
        for func_name in reversed(func_chain):
            decoder = self.DECODERS.get(func_name)
            if not decoder:
                continue
            try:
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="ignore")
                data = decoder(data)
                funcs_used.append(func_name)
            except Exception:
                break

        return data, funcs_used

    def _resolve_chr_concat(self, content: str) -> tuple[str, bool]:
        """Replace chr(N).chr(N)... patterns with the decoded string."""
        changed = False

        def replace_chr_chain(match: re.Match) -> str:
            nonlocal changed
            chars = self.CHR_SINGLE_PATTERN.findall(match.group(0))
            try:
                result = "".join(chr(int(c)) for c in chars)
                changed = True
                return f'"{result}"'
            except (ValueError, OverflowError):
                return match.group(0)

        result = self.CHR_CONCAT_PATTERN.sub(replace_chr_chain, content)
        return result, changed


class HTMLDeobfuscator:
    """Strip empty inline HTML tags used for string-splitting obfuscation.

    AiTM PhaaS kits insert empty tags between characters to defeat
    text-based IOC extraction and YARA rules::

        P<b></b>a<b></b>ss<b></b>wo<b></b>rd  →  Password

    Only activates when 10+ empty tags are found (legitimate HTML rarely
    has that many).
    """

    # Match empty inline tags — allows optional attributes and whitespace.
    EMPTY_INLINE_TAG = re.compile(
        r"<(b|i|em|strong|span|u|s|small|mark|abbr|cite|code|sub|sup)"
        r"(?:\s+[^>]*)?\s*>\s*</\1\s*>",
        re.IGNORECASE,
    )

    MIN_OCCURRENCES = 10

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Strip empty inline tags if the file looks obfuscated."""
        matches = self.EMPTY_INLINE_TAG.findall(content)
        if len(matches) < self.MIN_OCCURRENCES:
            return DeobfuscationResult(
                original_content=content[:1000],
                deobfuscated_content=content,
                layers_unwrapped=0,
                techniques_found=[],
                success=True,
            )

        cleaned = self.EMPTY_INLINE_TAG.sub("", content)
        return DeobfuscationResult(
            original_content=content[:1000],
            deobfuscated_content=cleaned,
            layers_unwrapped=1,
            techniques_found=["empty_tag_splitting"],
            success=True,
        )

    def deobfuscate_file(self, filepath: str) -> DeobfuscationResult:
        """Deobfuscate a file by path."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.deobfuscate(content)


class JSDeobfuscator:
    """Deobfuscate JavaScript XOR+base64+eval chains.

    Covers common phishing-kit obfuscation patterns:
      - atob(encoded) → split('') → map(c => c.charCodeAt(0) ^ KEY) → eval
      - Base64 string embedded in array rotation (parseInt loader)
      - document.write / eval of XOR-decoded payload

    Returns the decoded plaintext (often JS that contains URLs to external
    phishing infrastructure).
    """

    # Match atob('...') calls with long base64 payloads
    ATOB_PATTERN = re.compile(
        r"""atob\s*\(\s*['"]([A-Za-z0-9+/=]{20,})['"]""",
        re.IGNORECASE,
    )

    # Match XOR key in charCodeAt(0) ^ KEY patterns
    # Handles both direct call and bracket notation:
    #   c.charCodeAt(0) ^ 0xAD
    #   c["charCodeAt"](0) ^ 0xAD
    XOR_CHARCODE_PATTERN = re.compile(
        r"""charCodeAt['"]\s*\]\s*\(\s*0?\s*\)\s*\^\s*(0x[0-9a-fA-F]+|\d+)"""
        r"""|charCodeAt\s*\(\s*0?\s*\)\s*\^\s*(0x[0-9a-fA-F]+|\d+)""",
    )

    # Match large base64 strings in JS string arrays / variables
    JS_BASE64_STRING = re.compile(
        r"""['"]([A-Za-z0-9+/=]{40,})['"]""",
    )

    # --- Layered decoder primitives ----------------------------------------
    # Together these let us reconstruct loader functions that chain several
    # transforms (atob, hex-pair XOR, reverse, ROT13, JSON.parse+join) in an
    # arbitrary order. We match each primitive's occurrence in source and
    # replay them in textual order against candidate base64 seeds.

    # hex-pair XOR: parseInt(pair, 16) ^ KEY  (captures KEY).
    # The first argument can be a bare identifier (``h``), an indexed lookup
    # (``h[i]``), or a longer expression — allow anything up to the comma.
    _PARSEINT_HEX_XOR_RE = re.compile(
        r"""parseInt\s*\(\s*[^,)]+?\s*,\s*16\s*\)\s*\^\s*(0x[0-9a-fA-F]+|\d+)""",
    )
    # reverse: x.split('').reverse().join('')
    _SPLIT_REVERSE_JOIN_RE = re.compile(
        r"""\.\s*split\s*\(\s*['"]\s*['"]\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join""",
    )
    # ROT13 math: (c.charCodeAt(0) - b + 13) % 26  (the "+13 … %26" is the
    # tell; the surrounding branching for upper/lower case varies).
    _ROT13_MATH_RE = re.compile(
        r"""charCodeAt\s*\(\s*0?\s*\)\s*-\s*\w+\s*\+\s*13\s*\)\s*%\s*26""",
    )
    # JSON.parse(x).join('sep')  — captures the join separator (usually '').
    _JSON_PARSE_JOIN_RE = re.compile(
        r"""JSON\s*\.\s*parse\s*\([^)]*\)\s*\.\s*join\s*\(\s*['"]([^'"]*)['"]\s*\)""",
    )
    # atob( — one b64_decode step per occurrence.
    _ATOB_CALL_RE = re.compile(r"""\batob\s*\(""")

    # Looser seed pattern for layered chains. Real phishing seeds are often
    # >1000 chars; the 20 floor just rules out incidental junk. We iterate
    # seeds longest-first so the biggest payload wins when multiple match.
    _SEED_BASE64_RE = re.compile(r"""['"]([A-Za-z0-9+/=]{20,})['"]""")

    # Cycled byte-array XOR loop signature.  Distinctive because the
    # ``% length`` modulo only makes sense when one operand is a byte
    # array used as a cyclic key, not a single integer key.  Catches
    # the gate-2 captcha-premium / token-burning kit family:
    #
    #   qz2[qo0] = yb4[qo0] ^ qo5[qo0 % qo5.length];
    #
    # Variable names are randomized; the structural shape is what
    # we lock onto.
    _BYTE_XOR_CYCLE_RE = re.compile(
        r"""\[\s*\w+\s*\]\s*\^\s*\w+\s*\[\s*\w+\s*%\s*\w+\s*\.\s*length\s*\]""",
    )

    # URL pattern for extracted decoded content
    URL_PATTERN = re.compile(
        r"""https?://[^\s"'<>\]\)\\]+""",
        re.IGNORECASE,
    )

    def deobfuscate(self, content: str) -> DeobfuscationResult:
        """Attempt JS deobfuscation of content."""
        techniques: list[str] = []
        decoded_parts: list[str] = []

        # Try XOR+base64 pattern (the most common in AiTM kits)
        decoded = self._try_xor_base64(content)
        if decoded:
            techniques.append("js_xor_base64")
            decoded_parts.append(decoded)
            # Recursively try to decode the output (may be another layer)
            inner = self._try_xor_base64(decoded)
            if inner:
                techniques.append("js_xor_base64_nested")
                decoded_parts.append(inner)

        # Try base64 ciphertext XOR'd against base64 key, byte-cycled.
        # This is the captcha-premium / burned-token gate pattern where
        # the loader has two long base64 strings and a ``[i] ^ [i %
        # key.length]`` loop, then ``new Function(decoded)()`` executes
        # the result.  The decoded blob almost always contains the real
        # C2 / next-stage URL plus the cloak ruleset — surfacing it
        # gives IOC extraction something to anchor on instead of the
        # decoy retail-site DOM the gate redirects us to.
        b64_xor = self._try_b64_xor_b64(content)
        if b64_xor and b64_xor not in decoded_parts:
            techniques.append("js_b64_xor_b64")
            decoded_parts.append(b64_xor)

        # Try multi-stage loader chains: parse the decoder's source for a
        # sequence of known primitives (atob / hex-XOR / reverse / ROT13 /
        # JSON.parse-join) in the order they appear, then replay that
        # sequence against each long base64 seed literal.
        layered = self._try_layered_decode_chain(content)
        if layered:
            plaintext, used_steps = layered
            techniques.append("js_layered_chain")
            for step in used_steps:
                techniques.append(f"js_chain:{step}")
            if plaintext not in decoded_parts:
                decoded_parts.append(plaintext)

            # Nested-loader tail. The unwrapped plaintext is often *another*
            # mini loader that hides the terminal URL behind String.fromCharCode
            # or \xNN hex-escaped string literals. Run a cheap resolver pass
            # so URL_PATTERN can find the URL on the output.
            resolved = self._resolve_js_string_literals(plaintext)
            if resolved and resolved != plaintext and resolved not in decoded_parts:
                decoded_parts.append(resolved)
                techniques.append("js_literals_resolved")

        # Try plain atob('...') without XOR (simpler obfuscation)
        for m in self.ATOB_PATTERN.finditer(content):
            try:
                raw = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                if len(raw) > 10 and raw.isprintable() and raw not in decoded_parts:
                    decoded_parts.append(raw)
                    techniques.append("js_atob")
            except Exception:
                continue

        # Try base64 strings found in decoded layers (handles atob(variable)
        # where the variable holds a base64 string assigned elsewhere)
        for part in list(decoded_parts):
            for m in self.JS_BASE64_STRING.finditer(part):
                try:
                    raw = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                    # Use replace to strip whitespace before printable check
                    stripped = raw.replace("\n", "").replace("\r", "").replace("\t", "")
                    if len(raw) > 10 and stripped.isprintable() and raw not in decoded_parts:
                        decoded_parts.append(raw)
                        techniques.append("js_base64_var")
                except Exception:
                    continue

        if not decoded_parts:
            return DeobfuscationResult(
                original_content=content[:1000],
                deobfuscated_content=content,
                layers_unwrapped=0,
                techniques_found=[],
                success=True,
            )

        # Build the deobfuscated output: decoded layers concatenated
        deob_content = "\n\n".join(decoded_parts)
        return DeobfuscationResult(
            original_content=content[:1000],
            deobfuscated_content=deob_content,
            layers_unwrapped=len(decoded_parts),
            techniques_found=list(set(techniques)),
            success=True,
        )

    def deobfuscate_file(self, filepath: str) -> DeobfuscationResult:
        """Deobfuscate a file by path."""
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.deobfuscate(content)

    def extract_urls(self, content: str) -> list[str]:
        """Extract URLs from decoded JS content."""
        result = self.deobfuscate(content)
        return self.URL_PATTERN.findall(result.deobfuscated_content)

    def _try_xor_base64(self, content: str) -> str | None:
        """Try to decode atob(payload) → charCodeAt ^ KEY pattern.

        Pattern:
          atob('base64string').split('').map(c => c.charCodeAt(0) ^ 0xAD)
          → new TextDecoder().decode(new Uint8Array(bytes))
          → eval(decoded)
        """
        # Find XOR key (may be in group 1 or group 2 depending on alternation)
        xor_match = self.XOR_CHARCODE_PATTERN.search(content)
        if not xor_match:
            return None

        key_str = xor_match.group(1) or xor_match.group(2)
        if not key_str:
            return None
        xor_key = int(key_str, 16) if key_str.startswith("0x") else int(key_str)
        if xor_key < 1 or xor_key > 255:
            return None

        # Find base64 payloads and try each with the XOR key
        for b64_match in self.JS_BASE64_STRING.finditer(content):
            b64_str = b64_match.group(1)
            try:
                raw_bytes = base64.b64decode(b64_str)
                decoded_bytes = bytes(b ^ xor_key for b in raw_bytes)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                # Validate: should contain printable text, URLs, or JS keywords
                if len(decoded_str) > 20 and (
                    self.URL_PATTERN.search(decoded_str)
                    or "function" in decoded_str.lower()
                    or "document" in decoded_str.lower()
                    or "var " in decoded_str
                    or "const " in decoded_str
                    or "let " in decoded_str
                    or "window." in decoded_str
                ):
                    return decoded_str
            except Exception:
                continue

        return None

    # ------------------------------------------------------------------
    # Byte-cycled XOR with a base64 key (gate-2 captcha-premium pattern)
    # ------------------------------------------------------------------

    # Validation tokens — decoded blob should look like real JS or
    # contain a URL.  Loose set, avoids false positives on random
    # binary that happens to UTF-8 decode.
    _DECODED_JS_MARKERS = (
        "function", "var ", "const ", "let ",
        "window.", "document.", "location",
        "fetch(", "eval(", "=>", "navigator.",
        "addEventListener", "submit", "XMLHttpRequest",
    )

    @staticmethod
    def _xor_cycled(cipher: bytes, key: bytes) -> bytes:
        """XOR ``cipher`` against ``key``, cycling the key byte-wise.

        Pure helper; no I/O.  Returns the bytes — caller decodes /
        validates as UTF-8.
        """
        if not key:
            return cipher
        klen = len(key)
        return bytes(c ^ key[i % klen] for i, c in enumerate(cipher))

    def _try_b64_xor_b64(self, content: str) -> str | None:
        """Decode the gate-2 / captcha-premium pattern.

        Pattern:
          let cipher_b64 = "<long_base64>";
          let key_b64    = "<short_base64>";
          let cb = Uint8Array.from(atob(cipher_b64), c => c.charCodeAt(0));
          let kb = Uint8Array.from(atob(key_b64),    c => c.charCodeAt(0));
          let pt = new Uint8Array(cb.length);
          for (let i = 0; i < cb.length; i++) pt[i] = cb[i] ^ kb[i % kb.length];
          (new Function(new TextDecoder().decode(pt)))();

        We don't pattern-match the variable names (they're randomized).
        We pin on the structural ``[i] ^ [j % k.length]`` loop signature
        plus at least two base64 string literals in the same source.

        Strategy:
          1. Reject early unless the cycled-XOR loop is present.
          2. Collect all base64 literals (length >= 16; the key blob
             can be short, so we lower the floor here vs the existing
             ``_SEED_BASE64_RE``).
          3. Try every unordered pair as (cipher, key).  Cipher is
             usually the longer of the two; key is usually 16-64 bytes
             after b64-decode.
          4. Return the first decoded result that decodes as UTF-8 and
             contains JS markers (function / var / const / window. /
             location / fetch / etc.) or a plain URL.

        Returns the decoded JS string, or None if nothing fits.
        """
        if not self._BYTE_XOR_CYCLE_RE.search(content):
            return None

        # Collect candidate base64 literals.  Use a lower floor than the
        # main seed pattern because the *key* can be short (~24 chars
        # base64-encoded for a 16-byte key) — the existing 40-char
        # threshold on ``JS_BASE64_STRING`` would skip the key.
        b64_re = re.compile(r"""['"]([A-Za-z0-9+/=]{16,})['"]""")
        seeds: list[str] = []
        seen: set[str] = set()
        for m in b64_re.finditer(content):
            s = m.group(1)
            if s not in seen:
                seen.add(s)
                seeds.append(s)
        if len(seeds) < 2:
            return None

        # Sort longest-first so the biggest candidates anchor as
        # cipher first — but we still try every ordering since the
        # key is sometimes nearly as long as the cipher (small
        # payloads).  Cap pair count to keep this O(n²) loop
        # bounded on pages with lots of incidental base64 strings.
        seeds.sort(key=len, reverse=True)
        seeds = seeds[:8]

        best: str | None = None
        for i in range(len(seeds)):
            for j in range(len(seeds)):
                if i == j:
                    continue
                try:
                    cipher = base64.b64decode(seeds[i], validate=False)
                    key = base64.b64decode(seeds[j], validate=False)
                except Exception:
                    continue
                if not cipher or not key:
                    continue
                # Cap output size to match the rest of this module.
                if len(cipher) > MAX_OUTPUT_SIZE:
                    continue
                try:
                    pt = self._xor_cycled(cipher, key)
                    decoded = pt.decode("utf-8", errors="strict")
                except (UnicodeDecodeError, Exception):
                    continue
                if len(decoded) < 20:
                    continue
                # Validate: the decoded blob must look like JS / contain
                # a URL.  Strict UTF-8 above already filtered most random
                # XOR pairings; this catches the rest.
                lower = decoded.lower()
                has_marker = any(
                    m in lower for m in self._DECODED_JS_MARKERS
                )
                has_url = bool(self.URL_PATTERN.search(decoded))
                if not has_marker and not has_url:
                    continue
                # Prefer longer plausible decodes (more likely the real
                # payload vs a coincidental pairing).
                if best is None or len(decoded) > len(best):
                    best = decoded
        return best

    # ------------------------------------------------------------------
    # Multi-stage layered chain decoder
    # ------------------------------------------------------------------

    def _build_transform_pipeline(
        self, content: str,
    ) -> list[tuple[str, dict]]:
        """Walk the source for known primitives in textual order and
        return a list of (name, params) steps describing the decode
        pipeline the decoder function applies.

        Recognised primitives:
          - b64        : base64 decode
          - hex_xor    : atob → split hex pairs → parseInt(pair,16) ^ KEY
                         → fromCharCode (params: {"key": int})
          - reverse    : .split('').reverse().join('')
          - rot13      : ROT13 over a-zA-Z
          - json_parse : JSON.parse(x).join(sep)  (params: {"sep": str})
        """
        # Pair hex_xor with the b64_decode that feeds it (the atob call
        # immediately preceding the parseInt), so we don't double-count the
        # split/XOR atob as a standalone b64 step.
        hex_xor_positions: dict[int, int] = {}
        atobs = [m.start() for m in self._ATOB_CALL_RE.finditer(content)]
        for m in self._PARSEINT_HEX_XOR_RE.finditer(content):
            pos = m.start()
            # Find nearest atob at a smaller offset — that's the one whose
            # output is being split into hex pairs.
            preceding = [a for a in atobs if a < pos]
            if preceding:
                hex_xor_positions[preceding[-1]] = int(
                    m.group(1), 16 if m.group(1).startswith("0x") else 10,
                )

        events: list[tuple[int, str, dict]] = []
        for atob_pos in atobs:
            if atob_pos in hex_xor_positions:
                events.append(
                    (atob_pos, "hex_xor", {"key": hex_xor_positions[atob_pos]}),
                )
            else:
                events.append((atob_pos, "b64", {}))

        for m in self._SPLIT_REVERSE_JOIN_RE.finditer(content):
            events.append((m.start(), "reverse", {}))
        for m in self._ROT13_MATH_RE.finditer(content):
            events.append((m.start(), "rot13", {}))
        for m in self._JSON_PARSE_JOIN_RE.finditer(content):
            events.append((m.start(), "json_parse", {"sep": m.group(1)}))

        events.sort(key=lambda t: t[0])
        return [(name, params) for _, name, params in events]

    @staticmethod
    def _apply_step(step: tuple[str, dict], data: str) -> str | None:
        """Apply one pipeline step. Returns None on failure."""
        name, params = step
        try:
            if name == "b64":
                return base64.b64decode(data, validate=False).decode(
                    "utf-8", errors="replace",
                )
            if name == "hex_xor":
                # data is "atob result" — base64-decode first, then split
                # into hex pairs, parseInt(pair,16) ^ key → chr → join.
                raw = base64.b64decode(data, validate=False).decode(
                    "ascii", errors="ignore",
                )
                key = params["key"]
                if key < 0 or key > 255:
                    return None
                out_chars: list[str] = []
                # Take pairs of ASCII hex digits.
                i = 0
                while i + 1 < len(raw):
                    pair = raw[i:i + 2]
                    if (
                        pair[0] in "0123456789abcdefABCDEF"
                        and pair[1] in "0123456789abcdefABCDEF"
                    ):
                        out_chars.append(chr(int(pair, 16) ^ key))
                    i += 2
                return "".join(out_chars)
            if name == "reverse":
                return data[::-1]
            if name == "rot13":
                return codecs.encode(data, "rot_13")
            if name == "json_parse":
                parsed = json.loads(data)
                if not isinstance(parsed, list):
                    return None
                return params.get("sep", "").join(str(x) for x in parsed)
        except Exception:
            return None
        return None

    def _try_layered_decode_chain(
        self, content: str,
    ) -> tuple[str, list[str]] | None:
        """If the source describes a multi-stage decoder, replay it against
        each long base64 seed literal. Return the first plaintext that looks
        like JS/URL output, along with the list of step names used.
        """
        pipeline = self._build_transform_pipeline(content)
        if not pipeline:
            return None
        # A realistic loader has at least one hex_xor or json_parse step;
        # otherwise the plain ATOB_PATTERN branch already handles it and we
        # avoid double-reporting trivial matches.
        names = [n for n, _ in pipeline]
        if (
            names.count("hex_xor") == 0
            and "json_parse" not in names
            and "reverse" not in names
        ):
            return None

        # Candidate seeds — the base64 literal the decoder is fed. Sort
        # longest-first since the real payload dwarfs incidentals.
        seeds = sorted(
            {m.group(1) for m in self._SEED_BASE64_RE.finditer(content)},
            key=len, reverse=True,
        )

        for seed in seeds:
            data: str | None = seed
            for step in pipeline:
                if data is None:
                    break
                data = self._apply_step(step, data)
                # Cap runaway growth.
                if data is not None and len(data) > MAX_OUTPUT_SIZE:
                    data = None
                    break
            if not data or len(data) < 20:
                continue
            if (
                self.URL_PATTERN.search(data)
                or any(
                    marker in data
                    for marker in (
                        "function", "var ", "const ", "let ",
                        "window.", "document.", "eval(", "=>",
                    )
                )
            ):
                return data, names

        return None

    # ------------------------------------------------------------------
    # Follow-on resolver for in-literal escape schemes
    # ------------------------------------------------------------------

    # Match String.fromCharCode(n, n, ...) with decimal or 0xNN arguments.
    _FROM_CHAR_CODE_RE = re.compile(
        r"""String\s*\.\s*fromCharCode\s*\(\s*([0-9xXa-fA-F,\s]+)\)""",
    )

    @staticmethod
    def _resolve_js_string_literals(content: str) -> str:
        """Produce a flattened view of ``content`` in which ``\\xNN`` / ``\\uNNNN``
        escapes and ``String.fromCharCode(...)`` calls have been decoded.

        The return value is the original content followed by the resolved
        fragments, joined on newlines. That keeps the caller able to pattern-
        match (e.g. :attr:`URL_PATTERN`) against either form — useful when a
        loader stores a URL as ``"\\x68\\x74\\x74\\x70..."`` or builds it from
        a ``fromCharCode`` call just before ``fetch``ing it.

        Safe on arbitrary content: the worst case (no escapes, no
        ``fromCharCode``) just returns the input unchanged.
        """
        fragments: list[str] = [content]

        # (a) Blanket unicode_escape over the whole document. Unaffected
        # substrings pass through untouched; ``\xNN`` / ``\uNNNN`` become
        # real characters.
        try:
            encoded = content.encode("latin-1", errors="replace")
            unescaped = codecs.decode(encoded, "unicode_escape")
            if unescaped != content:
                fragments.append(unescaped)
        except Exception:
            pass

        # (b) Per-string-literal decoders. Quoted strings that *look* like
        # pure hex (``"68747470..."``) or long base64 are decoded in case
        # the terminal URL is hiding as one of those. The alt-decoded form
        # is appended as a separate fragment so URL_PATTERN can pick it up
        # without us having to prove which literal is the URL.
        for m in re.finditer(
            r"""(['"])((?:\\.|(?!\1).)*?)\1""", content, flags=re.DOTALL,
        ):
            lit = m.group(2)
            if not lit or len(lit) < 8:
                continue
            # Hex-only, even length → bytes.fromhex().
            if len(lit) % 2 == 0 and all(
                c in "0123456789abcdefABCDEF" for c in lit
            ):
                with contextlib.suppress(Exception):
                    fragments.append(
                        bytes.fromhex(lit).decode("utf-8", errors="replace"),
                    )
                continue
            # Long base64 → try decoding; accept only if printable-ish.
            if (
                len(lit) >= 20
                and all(c in (
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789+/="
                ) for c in lit)
            ):
                try:
                    dec = base64.b64decode(lit, validate=False)
                    as_str = dec.decode("utf-8", errors="replace")
                    if sum(c.isprintable() for c in as_str) >= 0.8 * len(as_str):
                        fragments.append(as_str)
                except Exception:
                    pass

        # (c) String.fromCharCode(n1, n2, ...) — parse the argument list and
        # emit the decoded character sequence.
        for m in JSDeobfuscator._FROM_CHAR_CODE_RE.finditer(content):
            chars: list[str] = []
            for tok in m.group(1).split(","):
                tok = tok.strip()
                if not tok:
                    continue
                try:
                    n = (
                        int(tok, 16)
                        if tok.lower().startswith("0x")
                        else int(tok)
                    )
                except ValueError:
                    chars = []
                    break
                if 0 < n < 0x110000:
                    chars.append(chr(n))
                else:
                    chars = []
                    break
            if chars:
                fragments.append("".join(chars))

        return "\n".join(fragments)

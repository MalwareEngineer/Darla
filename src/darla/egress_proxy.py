"""SOCKS5 egress proxy for the browser worker (SSRF layer 2).

The httpx fetchers are guarded in-process (``darla.utils.egress``), but
Camoufox opens its own sockets while running attacker JavaScript.  With
``PK_BROWSER_EGRESS_PROXY`` set, Firefox sends every connection through
this proxy, which applies the same ``vet_host`` policy: resolve once, keep
only public addresses, connect to the vetted IP.

SOCKS5 rather than an HTTP proxy on purpose: it only relays bytes.  HTTP
headers are never touched and TLS stays end to end from Firefox, so what
a phishing site sees is unchanged apart from the proxy being on the path
(same host, same public IP).

CONNECT only, no authentication — it listens on the compose network and is
not published to the host.  Run with ``python -m darla.egress_proxy``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import socket
import struct
import time

import httpcore

from darla.utils.egress import egress_block_reason, vet_host

logger = logging.getLogger("darla.egress_proxy")

# RFC 1928 reply codes
REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_HOST_UNREACHABLE = 0x04
REP_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_UNSUPPORTED = 0x07
REP_ATYP_UNSUPPORTED = 0x08

_CMD_CONNECT = 0x01
_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6 = 0x01, 0x03, 0x04
_NO_AUTH, _NO_ACCEPTABLE = 0x00, 0xFF

_CHUNK = 64 * 1024


class VetCache:
    """Short-lived cache of ``vet_host`` outcomes.

    With remote DNS, Firefox no longer caches lookups itself, so without
    this every connection of a page would re-resolve.  Caching the *vetted
    address list* keeps rebinding impossible: we still connect only to an
    address that passed the check.  TTL matches Firefox's default DNS
    cache (``network.dnsCacheExpiration`` = 60 s).
    """

    def __init__(self, ttl: float = 60.0, max_entries: int = 4096) -> None:
        self._ttl = ttl
        self._max = max_entries
        self._entries: dict[tuple[str, int], tuple[float, list[str] | str]] = {}

    async def vet(self, host: str, port: int) -> list[str]:
        key = (host.lower(), port)
        now = time.monotonic()
        hit = self._entries.get(key)
        if hit and hit[0] > now:
            outcome = hit[1]
        else:
            try:
                outcome = await asyncio.to_thread(vet_host, host, port)
            except httpcore.ConnectError as e:
                outcome = str(e)
            if len(self._entries) >= self._max:
                self._entries.clear()
            self._entries[key] = (now + self._ttl, outcome)
        if isinstance(outcome, str):
            raise httpcore.ConnectError(outcome)
        return outcome


def _reply(code: int) -> bytes:
    # BND.ADDR / BND.PORT are unused by CONNECT clients; 0.0.0.0:0 is fine.
    return bytes([0x05, code, 0x00, _ATYP_IPV4]) + b"\x00" * 6


async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, idle: float) -> None:
    while True:
        async with asyncio.timeout(idle):
            data = await src.read(_CHUNK)
        if not data:
            break
        dst.write(data)
        await dst.drain()
    # Propagate half-close so request/response framing still works.
    with contextlib.suppress(OSError, RuntimeError):
        if dst.can_write_eof():
            dst.write_eof()


async def _read_target(reader: asyncio.StreamReader) -> tuple[int, int, str | None, int]:
    """Parse the request.  Returns ``(cmd, atyp, host, port)``; host is
    ``None`` for an unsupported address type."""
    _ver, cmd, _rsv, atyp = await reader.readexactly(4)
    if atyp == _ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    elif atyp == _ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    elif atyp == _ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        raw = await reader.readexactly(length)
        try:
            host = raw.decode("ascii")
        except UnicodeDecodeError:
            host = None
    else:
        host = None
    (port,) = struct.unpack("!H", await reader.readexactly(2))
    return cmd, atyp, host, port


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    cache: VetCache,
    connect_timeout: float = 15.0,
    idle_timeout: float = 300.0,
) -> None:
    upstream: asyncio.StreamWriter | None = None
    try:
        ver, nmethods = await reader.readexactly(2)
        methods = await reader.readexactly(nmethods)
        if ver != 0x05:
            return
        if _NO_AUTH not in methods:
            writer.write(bytes([0x05, _NO_ACCEPTABLE]))
            await writer.drain()
            return
        writer.write(bytes([0x05, _NO_AUTH]))
        await writer.drain()

        cmd, _atyp, host, port = await _read_target(reader)
        if cmd != _CMD_CONNECT:
            writer.write(_reply(REP_CMD_UNSUPPORTED))
            return
        if host is None:
            writer.write(_reply(REP_ATYP_UNSUPPORTED))
            return

        try:
            allowed = await cache.vet(host, port)
        except httpcore.ConnectError as e:
            if blocked := egress_block_reason(e):
                logger.info("Blocked browser connection to %s:%d — %s", host, port, blocked)
                writer.write(_reply(REP_NOT_ALLOWED))
            else:
                writer.write(_reply(REP_HOST_UNREACHABLE))
            return

        up_reader = None
        failure = REP_REFUSED
        for address in allowed:
            try:
                async with asyncio.timeout(connect_timeout):
                    up_reader, upstream = await asyncio.open_connection(address, port)
                break
            except TimeoutError:
                failure = REP_TTL_EXPIRED
            except OSError:
                failure = REP_REFUSED
        if upstream is None or up_reader is None:
            writer.write(_reply(failure))
            return

        writer.write(_reply(REP_SUCCEEDED))
        await writer.drain()

        pumps = [
            asyncio.create_task(_pump(reader, upstream, idle_timeout)),
            asyncio.create_task(_pump(up_reader, writer, idle_timeout)),
        ]
        done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_EXCEPTION)
        if any(t.exception() for t in done):
            for task in pending:
                task.cancel()
        await asyncio.gather(*pumps, return_exceptions=True)
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
        pass
    except Exception:
        logger.exception("egress proxy connection failed")
    finally:
        for w in (upstream, writer):
            if w is not None:
                with contextlib.suppress(Exception):
                    w.close()


async def serve(host: str, port: int) -> None:
    cache = VetCache()
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, cache=cache), host, port,
    )
    logger.info("Egress proxy listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(serve(args.host, args.port))


if __name__ == "__main__":
    main()

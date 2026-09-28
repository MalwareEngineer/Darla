"""Connect-time egress guard for outbound fetches of attacker-controlled URLs.

Darla fetches URLs that attackers choose — not just the submitted one, but
every redirect hop, email link, QR destination and external-JS reference
the chain crawler follows.  Without a guard, a lure can point those fetches
at the compose network (``api``, ``rabbitmq``), the host's LAN, or a cloud
metadata service (``169.254.169.254``), and Darla stores the response as a
kit.

The check lives in the *network backend*, below httpx: every new TCP
connection resolves the host once, drops non-public addresses, and connects
to a vetted IP literal.  That placement means

* every redirect hop is covered (each new origin opens a new connection),
  including hops httpx follows itself and hops RedirectTracker follows by
  hand;
* DNS rebinding can't slip between check and connect — there is exactly
  one resolution and the socket goes to the address that was checked;
* nothing observable changes for allowed destinations: httpcore takes the
  TLS SNI / certificate hostname from the request origin, not the connect
  address, and headers are untouched.  It is the same single DNS lookup
  httpcore's default backend performs.

``PK_EGRESS_ALLOW_CIDRS`` is an explicit escape hatch for lab setups that
host test kits on a private network.  Empty by default.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from functools import lru_cache

import httpcore
import httpx

from darla.config import get_settings

# Prefix of every block message.  httpx maps httpcore.ConnectError to
# httpx.ConnectError keeping only the message, so callers recognize a
# block by this prefix (see ``egress_block_reason``).
BLOCK_PREFIX = "egress blocked"

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 address carried inside an IPv6 one (mapped, 6to4, NAT64)."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in ipaddress.IPv6Network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_address(ip: _IPAddress) -> bool:
    """True only for globally routable unicast addresses.

    ``is_global`` already excludes RFC 1918, loopback, link-local (which
    includes the 169.254.169.254 metadata address), CGNAT 100.64/10,
    unspecified and reserved ranges.  Multicast is excluded explicitly, and
    IPv6 forms that embed an IPv4 address are judged by the embedded one —
    Python 3.12 doesn't do that for ``::ffff:127.0.0.1``.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            return is_public_address(embedded)
    return ip.is_global and not ip.is_multicast


@lru_cache(maxsize=1)
def _allowed_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(
        ipaddress.ip_network(cidr, strict=False)
        for cidr in get_settings().egress_allow_cidrs
    )


def is_allowed_address(ip: _IPAddress) -> bool:
    return is_public_address(ip) or any(ip in net for net in _allowed_networks())


def _resolve(host: str, port: int) -> list[str]:
    """All addresses for *host*, in resolver order, de-duplicated."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: dict[str, None] = {}
    for _family, _type, _proto, _canon, sockaddr in infos:
        seen.setdefault(sockaddr[0].split("%", 1)[0], None)
    return list(seen)


def vet_host(host: str, port: int) -> list[str]:
    """Resolve *host* once and return only the addresses we may connect to.

    Raises ``httpcore.ConnectError`` (surfaced by httpx as
    ``httpx.ConnectError``) when nothing is allowed.  A host that resolves to
    a mix of public and non-public addresses keeps only the public ones, so
    a poisoned record can't steer the connection inward.
    """
    try:
        addresses = _resolve(host, port)
    except socket.gaierror as e:
        raise httpcore.ConnectError(str(e)) from e
    allowed = [a for a in addresses if is_allowed_address(ipaddress.ip_address(a))]
    if not allowed:
        raise httpcore.ConnectError(
            f"{BLOCK_PREFIX}: {host} resolves only to non-public addresses "
            f"({', '.join(addresses)})",
        )
    return allowed


def _connect_first(connect, allowed: Iterable[str]):
    last_exc: Exception | None = None
    for address in allowed:
        try:
            return connect(address)
        except httpcore.ConnectError as e:
            last_exc = e
    assert last_exc is not None
    raise last_exc


class GuardedSyncBackend(httpcore.SyncBackend):
    """``httpcore.SyncBackend`` that only connects to vetted addresses."""

    def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None,
    ):
        return _connect_first(
            lambda address: super(GuardedSyncBackend, self).connect_tcp(
                address, port, timeout=timeout,
                local_address=local_address, socket_options=socket_options,
            ),
            vet_host(host, port),
        )


class GuardedAsyncBackend(httpcore.AnyIOBackend):
    """Async twin of :class:`GuardedSyncBackend` (asyncio via anyio)."""

    async def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None,
    ):
        import anyio

        allowed = await anyio.to_thread.run_sync(vet_host, host, port)
        last_exc: Exception | None = None
        for address in allowed:
            try:
                return await super().connect_tcp(
                    address, port, timeout=timeout,
                    local_address=local_address, socket_options=socket_options,
                )
            except httpcore.ConnectError as e:
                last_exc = e
        assert last_exc is not None
        raise last_exc


def guarded_transport(**kwargs) -> httpx.HTTPTransport:
    """``httpx.HTTPTransport`` whose connections go through the guard.

    httpx doesn't expose httpcore's ``network_backend``; the pool attribute
    is pinned by ``tests/test_utils/test_egress.py`` so an httpx upgrade
    that moves it fails loudly instead of silently unguarding fetches.
    """
    transport = httpx.HTTPTransport(**kwargs)
    transport._pool._network_backend = GuardedSyncBackend()
    return transport


def guarded_async_transport(**kwargs) -> httpx.AsyncHTTPTransport:
    transport = httpx.AsyncHTTPTransport(**kwargs)
    transport._pool._network_backend = GuardedAsyncBackend()
    return transport


def egress_block_reason(exc: BaseException) -> str | None:
    """The block message if *exc* is an egress block, else ``None``."""
    message = str(exc)
    return message if message.startswith(BLOCK_PREFIX) else None

"""SOCKS5 egress proxy for the browser worker (darla.egress_proxy).

Driven over real sockets with a hand-rolled SOCKS5 client, against a local
echo server.  The loopback echo server is only reachable through the
``allow_loopback`` allowlist, which is how "blocked" and "allowed" paths
are both exercised offline.
"""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest
import yaml

from darla import egress_proxy
from darla.config import get_settings
from darla.egress_proxy import (
    REP_ATYP_UNSUPPORTED,
    REP_CMD_UNSUPPORTED,
    REP_NOT_ALLOWED,
    REP_SUCCEEDED,
    VetCache,
    handle_client,
)
from darla.utils import egress
from darla.utils.egress import camoufox_egress_kwargs


@pytest.fixture(autouse=True)
def _fresh_allowlist_cache():
    egress._allowed_networks.cache_clear()
    yield
    egress._allowed_networks.cache_clear()


@pytest.fixture
def allow_loopback(monkeypatch):
    monkeypatch.setattr(get_settings(), "egress_allow_cidrs", ["127.0.0.1/32"])
    egress._allowed_networks.cache_clear()


@pytest.fixture
async def echo_server():
    received: list[bytes] = []

    async def echo(reader, writer):
        while data := await reader.read(4096):
            received.append(data)
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1], received
    server.close()
    await server.wait_closed()


@pytest.fixture
async def proxy():
    cache = VetCache()
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, cache=cache, connect_timeout=2, idle_timeout=5),
        "127.0.0.1", 0,
    )
    yield server.sockets[0].getsockname()[1], cache
    server.close()
    await server.wait_closed()


async def _socks_connect(proxy_port: int, atyp: int, addr: bytes, port: int, cmd: int = 1):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    writer.write(bytes([0x05, cmd, 0x00, atyp]) + addr + struct.pack("!H", port))
    await writer.drain()
    reply = await reader.readexactly(10)
    return reply[1], reader, writer


def _domain(name: str) -> bytes:
    raw = name.encode()
    return bytes([len(raw)]) + raw


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

async def test_loopback_blocked_and_never_contacted(proxy, echo_server) -> None:
    (pport, _), (eport, received) = proxy, echo_server
    code, _, writer = await _socks_connect(pport, 0x01, socket.inet_aton("127.0.0.1"), eport)
    writer.close()
    assert code == REP_NOT_ALLOWED
    assert received == []


async def test_metadata_by_ip_blocked(proxy) -> None:
    code, _, writer = await _socks_connect(
        proxy[0], 0x01, socket.inet_aton("169.254.169.254"), 80,
    )
    writer.close()
    assert code == REP_NOT_ALLOWED


async def test_ipv6_loopback_blocked(proxy) -> None:
    code, _, writer = await _socks_connect(
        proxy[0], 0x04, socket.inet_pton(socket.AF_INET6, "::1"), 80,
    )
    writer.close()
    assert code == REP_NOT_ALLOWED


async def test_domain_resolving_inward_blocked(proxy, monkeypatch) -> None:
    """Remote DNS: the proxy resolves the name and judges the result."""
    monkeypatch.setattr(
        egress.socket, "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                      ("10.0.0.9", port))],
    )
    code, _, writer = await _socks_connect(proxy[0], 0x03, _domain("lure.test"), 443)
    writer.close()
    assert code == REP_NOT_ALLOWED


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------

async def test_allowed_connection_relays_bytes_both_ways(
    proxy, echo_server, allow_loopback,
) -> None:
    (pport, _), (eport, received) = proxy, echo_server
    code, reader, writer = await _socks_connect(
        pport, 0x01, socket.inet_aton("127.0.0.1"), eport,
    )
    assert code == REP_SUCCEEDED
    payload = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    writer.write(payload)
    await writer.drain()
    assert await reader.readexactly(len(payload)) == payload
    writer.close()
    # Bytes reach the target unmodified — no header rewriting.
    assert b"".join(received) == payload


async def test_domain_request_uses_single_cached_resolution(
    proxy, echo_server, allow_loopback, monkeypatch,
) -> None:
    (pport, _), (eport, _) = proxy, echo_server
    calls: list[str] = []
    real = egress.socket.getaddrinfo

    def counting(host, port, *a, **k):
        calls.append(host)
        return real("127.0.0.1", port, *a, **k)

    monkeypatch.setattr(egress.socket, "getaddrinfo", counting)
    for _ in range(3):
        code, _, writer = await _socks_connect(pport, 0x03, _domain("kit.test"), eport)
        writer.close()
        assert code == REP_SUCCEEDED
    assert calls == ["kit.test"]


# ---------------------------------------------------------------------------
# Protocol edges
# ---------------------------------------------------------------------------

async def test_bind_command_rejected(proxy) -> None:
    code, _, writer = await _socks_connect(
        proxy[0], 0x01, socket.inet_aton("93.184.216.34"), 80, cmd=0x02,
    )
    writer.close()
    assert code == REP_CMD_UNSUPPORTED


async def test_unknown_address_type_rejected(proxy) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy[0])
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    await reader.readexactly(2)
    writer.write(b"\x05\x01\x00\x09" + b"\x00\x50")
    await writer.drain()
    reply = await reader.readexactly(10)
    writer.close()
    assert reply[1] == REP_ATYP_UNSUPPORTED


async def test_auth_only_clients_refused(proxy) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy[0])
    writer.write(b"\x05\x01\x02")  # offers username/password only
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\xff"
    writer.close()


# ---------------------------------------------------------------------------
# Browser wiring + deployment shape
# ---------------------------------------------------------------------------

def test_camoufox_kwargs_empty_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "browser_egress_proxy", "")
    assert camoufox_egress_kwargs() == {}


def test_camoufox_kwargs_close_firefox_proxy_bypasses(monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "browser_egress_proxy", "socks5://egress-proxy:1080")
    kwargs = camoufox_egress_kwargs()
    assert kwargs["proxy"] == {"server": "socks5://egress-proxy:1080"}
    prefs = kwargs["firefox_user_prefs"]
    # Without these, requests to localhost skip the proxy entirely.
    assert prefs["network.proxy.allow_hijacking_localhost"] is True
    assert prefs["network.proxy.no_proxies_on"] == ""
    assert prefs["network.proxy.socks_remote_dns"] is True


def test_compose_proxy_holds_no_secrets_and_is_not_published() -> None:
    from pathlib import Path

    compose = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    svc = yaml.safe_load(compose.read_text())["services"]["egress-proxy"]
    assert "ports" not in svc
    assert "env_file" not in svc
    assert set(svc["environment"]) == {"PK_EGRESS_ALLOW_CIDRS"}
    assert egress_proxy.__name__ in svc["command"]

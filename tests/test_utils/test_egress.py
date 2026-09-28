"""Connect-time egress guard (darla.utils.egress).

Attacker-controlled URLs — including every redirect hop — must never make
Darla connect to loopback, private, link-local (cloud metadata) or other
non-public addresses.  Classification is tested directly; the wiring is
tested end to end against a real local HTTP server, which doubles as proof
that a blocked request never opens a socket to its target.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpcore
import httpx
import pytest
from pydantic import ValidationError

from darla.analysis.redirect_tracker import RedirectTracker
from darla.config import Settings, get_settings
from darla.utils import egress
from darla.utils.egress import (
    BLOCK_PREFIX,
    GuardedAsyncBackend,
    GuardedSyncBackend,
    is_public_address,
    vet_host,
)
from darla.utils.http_client import download_file, get_async_client, get_sync_client

METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34",
    "2606:4700:4700::1111",
    "::ffff:8.8.8.8",             # IPv4-mapped public stays public
])
def test_public_addresses_allowed(address) -> None:
    assert is_public_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.8.9.10", "0.0.0.0",
    "10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.1",
    "169.254.169.254",            # AWS / Azure / GCP metadata
    "169.254.170.2",              # ECS task metadata
    "100.64.0.1",                 # CGNAT
    "198.18.0.1",                 # benchmarking
    "224.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1",
    "::ffff:127.0.0.1",           # IPv4-mapped loopback
    "::ffff:169.254.169.254",     # IPv4-mapped metadata
    "2002:7f00:1::1",             # 6to4 wrapping 127.0.0.1
    "64:ff9b::a9fe:a9fe",         # NAT64 wrapping 169.254.169.254
])
def test_non_public_addresses_blocked(address) -> None:
    assert not is_public_address(ipaddress.ip_address(address))


# ---------------------------------------------------------------------------
# Resolution: once, and only vetted addresses survive
# ---------------------------------------------------------------------------

def _fake_resolver(monkeypatch, mapping: dict[str, list[str]]) -> list[str]:
    calls: list[str] = []

    def fake(host, port, *args, **kwargs):
        calls.append(host)
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET,
             socket.SOCK_STREAM, 6, "", (a, port))
            for a in mapping[host]
        ]

    monkeypatch.setattr(egress.socket, "getaddrinfo", fake)
    return calls


def test_hostname_resolving_to_metadata_is_blocked(monkeypatch) -> None:
    _fake_resolver(monkeypatch, {"lure.test": ["169.254.169.254"]})
    with pytest.raises(httpcore.ConnectError, match=BLOCK_PREFIX):
        vet_host("lure.test", 80)


def test_mixed_records_keep_only_public(monkeypatch) -> None:
    """A poisoned record set can't steer the connection inward."""
    _fake_resolver(monkeypatch, {"mixed.test": ["10.0.0.7", "93.184.216.34", "::1"]})
    assert vet_host("mixed.test", 443) == ["93.184.216.34"]


def test_single_resolution_per_connection(monkeypatch) -> None:
    """DNS rebinding needs a second lookup between check and connect —
    the backend resolves once and connects to the vetted literal."""
    calls = _fake_resolver(monkeypatch, {"rebind.test": ["93.184.216.34"]})
    connected: list[str] = []
    monkeypatch.setattr(
        httpcore.SyncBackend, "connect_tcp",
        lambda self, host, port, **kw: connected.append(host) or object(),
    )
    GuardedSyncBackend().connect_tcp("rebind.test", 443)
    assert calls == ["rebind.test"]
    assert connected == ["93.184.216.34"]


def test_falls_through_to_next_allowed_address(monkeypatch) -> None:
    _fake_resolver(monkeypatch, {"two.test": ["93.184.216.34", "93.184.216.35"]})
    attempts: list[str] = []

    def connect(self, host, port, **kw):
        attempts.append(host)
        if host == "93.184.216.34":
            raise httpcore.ConnectError("refused")
        return object()

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    GuardedSyncBackend().connect_tcp("two.test", 443)
    assert attempts == ["93.184.216.34", "93.184.216.35"]


@pytest.mark.parametrize("literal", ["127.0.0.1", "::1"])
def test_ip_literals_are_blocked(literal) -> None:
    with pytest.raises(httpcore.ConnectError, match=BLOCK_PREFIX):
        vet_host(literal, 80)


@pytest.mark.parametrize("encoded", ["2130706433", "0x7f000001", "0177.0.0.1", "127.1"])
def test_numeric_host_encodings_are_judged_after_resolution(monkeypatch, encoded) -> None:
    """glibc's resolver turns these into 127.0.0.1 (Windows sends them to
    DNS instead).  The guard checks the *resolved* address, so the
    encoding can't matter — simulated here to keep the test off the network."""
    _fake_resolver(monkeypatch, {encoded: ["127.0.0.1"]})
    with pytest.raises(httpcore.ConnectError, match=BLOCK_PREFIX):
        vet_host(encoded, 80)


# ---------------------------------------------------------------------------
# End to end against a local server
# ---------------------------------------------------------------------------

class _Recorder(BaseHTTPRequestHandler):
    hosts: list[str] = []

    def do_GET(self):  # noqa: N802 — http.server API
        type(self).hosts.append(self.headers.get("Host", ""))
        if self.path == "/to-metadata":
            self.send_response(302)
            self.send_header("Location", METADATA_URL)
            self.end_headers()
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    _Recorder.hosts = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True,
    )
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def allow_loopback(monkeypatch):
    """Lab-style allowlist so the local server is reachable."""
    monkeypatch.setattr(get_settings(), "egress_allow_cidrs", ["127.0.0.1/32"])
    egress._allowed_networks.cache_clear()
    yield
    egress._allowed_networks.cache_clear()


@pytest.fixture(autouse=True)
def _fresh_allowlist_cache():
    egress._allowed_networks.cache_clear()
    yield
    egress._allowed_networks.cache_clear()


def test_blocked_request_never_reaches_the_server(local_server) -> None:
    with get_sync_client() as client, pytest.raises(httpx.ConnectError, match=BLOCK_PREFIX):
        client.get(f"http://127.0.0.1:{local_server}/")
    assert _Recorder.hosts == []


def test_allowlisted_request_keeps_hostname_in_host_header(
    local_server, allow_loopback,
) -> None:
    """Connecting to the vetted IP literal must not leak into the request:
    Host (and, for HTTPS, SNI) still carry the URL's hostname."""
    with get_sync_client() as client:
        response = client.get(f"http://localhost:{local_server}/")
    assert response.status_code == 200
    assert _Recorder.hosts == [f"localhost:{local_server}"]


def test_redirect_hop_to_metadata_is_blocked(local_server, allow_loopback) -> None:
    with get_sync_client() as client, pytest.raises(httpx.ConnectError, match=BLOCK_PREFIX):
        client.get(f"http://127.0.0.1:{local_server}/to-metadata")
    assert len(_Recorder.hosts) == 1  # first hop served, second never connected


def test_download_file_reports_block_reason(local_server, tmp_path) -> None:
    path, reason = download_file(f"http://127.0.0.1:{local_server}/", str(tmp_path))
    assert path is None
    assert reason.startswith(BLOCK_PREFIX)


def test_redirect_tracker_records_blocked_hop(local_server, allow_loopback, tmp_path) -> None:
    path, reason, chain = RedirectTracker().download_with_redirects(
        f"http://127.0.0.1:{local_server}/to-metadata", str(tmp_path),
    )
    assert path is None
    assert reason.startswith(BLOCK_PREFIX)
    # The internal target the lure aimed at is kept as evidence.
    assert chain.final_url == METADATA_URL
    assert chain.hops[0].location == METADATA_URL


async def test_async_client_is_guarded(local_server) -> None:
    client = await get_async_client()
    async with client:
        with pytest.raises(httpx.ConnectError, match=BLOCK_PREFIX):
            await client.get(f"http://127.0.0.1:{local_server}/")
    assert _Recorder.hosts == []


# ---------------------------------------------------------------------------
# Wiring pins — fail loudly if an httpx upgrade moves the hook
# ---------------------------------------------------------------------------

def test_sync_client_uses_guarded_backend() -> None:
    with get_sync_client() as client:
        assert isinstance(client._transport._pool._network_backend, GuardedSyncBackend)


async def test_async_client_uses_guarded_backend() -> None:
    client = await get_async_client()
    async with client:
        assert isinstance(client._transport._pool._network_backend, GuardedAsyncBackend)


def test_invalid_allow_cidr_fails_at_startup() -> None:
    with pytest.raises(ValidationError):
        Settings(egress_allow_cidrs=["not-a-network"])

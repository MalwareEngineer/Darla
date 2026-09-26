"""docker-compose.yml network exposure (RFC §16 guardrail #2).

The localhost-bind guardrail validates ``PK_BIND_ADDRESS``, but inside
the container uvicorn has to listen on ``0.0.0.0`` for port publishing
to work — so the guardrail only protects anything if compose publishes
the API on that same address.  Before this wiring, the guardrail logged
"localhost bind" while compose published ``8000:8000`` on every host
interface, exposing an unauthenticated API to the LAN in no-auth mode.

These tests pin the wiring so a future compose edit can't silently
re-open it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
_BIND_VAR = "${PK_BIND_ADDRESS:-127.0.0.1}"


@pytest.fixture(scope="module")
def services() -> dict:
    return yaml.safe_load(_COMPOSE.read_text())["services"]


def test_api_published_on_bind_address(services) -> None:
    assert services["api"]["ports"] == [f"{_BIND_VAR}:8000:8000"]


def test_guardrail_sees_the_published_address(services) -> None:
    """The container's PK_BIND_ADDRESS must be the same interpolation as
    the port mapping — env_file alone would diverge from a shell export,
    which compose prefers when interpolating."""
    assert services["api"]["environment"]["PK_BIND_ADDRESS"] == _BIND_VAR


def test_every_other_published_port_is_loopback(services) -> None:
    for name, svc in services.items():
        if name == "api":
            continue
        for mapping in svc.get("ports", []):
            assert str(mapping).startswith("127.0.0.1:"), (
                f"{name} publishes {mapping!r} beyond loopback"
            )

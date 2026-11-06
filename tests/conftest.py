"""Test setup that applies to every test.

- No network: any real connection outside this machine fails the test.
- No real tokens: GitHub token variables are cleared and `gh` is never asked.
- HTTP comes from recordings in tests/fixtures/http (see scripts/record_fixtures.py).
- Host canary: the whole run fails if ~/LOOKFIRST_HOST_CANARY ever exists,
  which would mean something from a target ran on this machine.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from lookfirst.core import http as lf_http

FIXTURES = Path(__file__).parent / "fixtures"
HTTP_FIXTURES = FIXTURES / "http"
HOST_CANARY = Path.home() / "LOOKFIRST_HOST_CANARY"
_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


# --- host canary -----------------------------------------------------------


def pytest_sessionstart(session: pytest.Session) -> None:
    if HOST_CANARY.exists():
        raise pytest.UsageError(
            f"{HOST_CANARY} already exists. Something may have run a target on this machine. "
            "Find out what before deleting it."
        )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if HOST_CANARY.exists():
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(
                f"HOST CANARY FOUND: {HOST_CANARY} exists, so something ran on this machine.",
                red=True,
                bold=True,
            )


# --- no network, no real tokens --------------------------------------------


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: object) -> None:
        host = address[0] if isinstance(address, tuple) else None
        if host is None or host in _LOCAL_HOSTS:  # unix sockets and loopback are fine
            return real_connect(self, address)  # type: ignore[arg-type]
        raise RuntimeError(f"Tests must not use the network (tried to connect to {address!r}).")

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
        if host not in _LOCAL_HOSTS and host is not None:
            raise RuntimeError(f"Tests must not use the network (tried to look up {host!r}).")
        return real_getaddrinfo(host, *args, **kwargs)  # type: ignore[arg-type]

    real_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


@pytest.fixture(autouse=True)
def _no_real_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOOKFIRST_NO_GH_TOKEN", "1")
    monkeypatch.setenv("LOOKFIRST_DEBUG", "1")  # show real errors instead of "this is a bug"


# --- recorded HTTP -----------------------------------------------------------


class Recorded:
    """Serves recorded responses. Anything that wasn't recorded fails the test loudly."""

    def __init__(self, *cases: str) -> None:
        self.responses: dict[tuple[str, str], tuple[int, dict[str, str], bytes]] = {}
        self.overrides: dict[tuple[str, str], Callable[[httpx.Request], httpx.Response]] = {}
        self.requests: list[httpx.Request] = []
        for case in cases:
            case_dir = HTTP_FIXTURES / case
            for entry in json.loads((case_dir / "index.json").read_text()):
                body = (case_dir / entry["body"]).read_bytes() if entry["body"] else b""
                key = (entry["method"], entry["url"])
                self.responses[key] = (entry["status"], entry["headers"], body)

    def override(self, url: str, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.overrides[("GET", url)] = handler

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = (request.method, str(request.url))
        if key in self.overrides:
            return self.overrides[key](request)
        if key not in self.responses:
            raise AssertionError(
                f"No recorded response for {key[0]} {key[1]}. "
                "Add it to scripts/record_fixtures.py and run it."
            )
        status, headers, body = self.responses[key]
        return httpx.Response(status, headers=headers, content=body)


@pytest.fixture
def recorded_http(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Recorded]:
    """Call with fixture case names; every HTTP request is then served from them."""

    def use(*cases: str) -> Recorded:
        recorded = Recorded(*cases)
        monkeypatch.setattr(lf_http, "_TRANSPORT", httpx.MockTransport(recorded.handler))
        return recorded

    return use


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[httpx.Request]]:
    """Serve every request from a handler function; returns the list of requests sent."""

    def use(handler: Callable[[httpx.Request], httpx.Response]) -> list[httpx.Request]:
        sent: list[httpx.Request] = []

        def record(request: httpx.Request) -> httpx.Response:
            sent.append(request)
            return handler(request)

        monkeypatch.setattr(lf_http, "_TRANSPORT", httpx.MockTransport(record))
        return sent

    return use

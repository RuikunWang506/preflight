"""Test setup that applies to every test.

- No network: any real connection outside this machine fails the test.
- No real tokens: GitHub token variables are cleared and `gh` is never asked.
- HTTP comes from recordings in tests/fixtures/http (see scripts/record_fixtures.py).
- No real scanners: osv-scanner and GuardDog count as not installed. Tests that need them
  use fake_tools, which serves recorded output from tests/fixtures/scanners.
- Host canary: the whole run fails if ~/LOOKFIRST_HOST_CANARY ever exists,
  which would mean something from a target ran on this machine.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
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
def _no_real_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    """osv-scanner and GuardDog count as not installed, so no test runs the real ones
    (osv-scanner would reach osv.dev). Tests that need them use fake_tools."""
    monkeypatch.setattr("lookfirst.scanners.base.locate", lambda name: None)


@pytest.fixture(autouse=True)
def _no_real_tokens(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(
        "LOOKFIRST_CACHE_DIR", str(tmp_path / "lookfirst-cache")
    )  # never the real cache
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

    def override(
        self, url: str, handler: Callable[[httpx.Request], httpx.Response], method: str = "GET"
    ) -> None:
        self.overrides[(method, url)] = handler

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


# --- fake scanners -------------------------------------------------------------

SCANNERS = FIXTURES / "scanners"
_VERSIONS = {
    "osv-scanner": "osv-scanner version: 2.7.0\nosv-scalibr version: 0.5.3",
    "guarddog": "3.2.0",
}


@dataclass
class FakeTools:
    """Handlers by tool name ("osv-scanner", "guarddog"), and every call made."""

    handlers: dict[str, Callable[[list[str]], object]] = field(default_factory=dict)
    calls: list[tuple[str, list[str]]] = field(default_factory=list)


def osv_output(name: str, root: Path, *, code: int = 1, found: int = 3) -> object:
    """A recorded osv-scanner run, as if it had scanned root."""
    from lookfirst.scanners.base import ToolOutput

    text = (SCANNERS / name).read_text().replace("{ROOT}", str(root))
    return ToolOutput(code, text, f"Scanned {root} file and found {found} packages\n")


def guarddog_output(name: str) -> object:
    from lookfirst.scanners.base import ToolOutput

    return ToolOutput(0, (SCANNERS / name).read_text(), "")


@pytest.fixture
def fake_tools(monkeypatch: pytest.MonkeyPatch):
    """Pretend the scanners in fake.handlers are installed, and answer from the handlers."""
    from lookfirst.scanners import base

    fake = FakeTools()

    def locate(name: str) -> Path | None:
        return Path("/fake/bin") / name if name in fake.handlers else None

    def run_tool(executable: Path, args: list[str], **_: object) -> object:
        fake.calls.append((executable.name, list(args)))
        if args == ["--version"]:
            return base.ToolOutput(0, _VERSIONS[executable.name], "")
        return fake.handlers[executable.name](list(args))

    monkeypatch.setattr(base, "locate", locate)
    for module in (
        "lookfirst.scanners.base",
        "lookfirst.scanners.osv",
        "lookfirst.scanners.guarddog",
    ):
        monkeypatch.setattr(f"{module}.run_tool", run_tool)
    base.tool_version.cache_clear()
    yield fake
    base.tool_version.cache_clear()

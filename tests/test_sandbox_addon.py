"""The recording proxy's addon (lookfirst/sandbox/mitm_addon.py). It runs inside mitmproxy,
so these tests load it with a small stand-in for mitmproxy's interface."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from lookfirst.sandbox.analyze import allowed
from lookfirst.sandbox.honeytokens import search_terms
from lookfirst.sandbox.proxy import addon_source

SECRET = "LookfirstTestSecret0123456789abcdef"
ALLOW = [{"host": "registry.npmjs.org", "path": ""}, {"host": "github.com", "path": "/o/tool"}]


class Headers:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        return list(self._items)


class Request:
    def __init__(self, host: str, path: str = "/", body: bytes = b"", headers=(), method="GET"):
        self.method, self.scheme, self.pretty_host, self.port, self.path = (
            method,
            "https",
            host,
            443,
            path,
        )
        self.pretty_url = f"https://{host}{path}"
        self.headers = Headers(list(headers))
        self._body = body

    def get_content(self, strict: bool = False) -> bytes:
        return self._body


class HTTPFlow:
    def __init__(self, request: Request) -> None:
        self.request, self.response = request, None


@pytest.fixture
def load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def loader(mode: str = "sinkhole") -> dict:
        config = {"mode": mode, "allow": ALLOW, "terms": search_terms([SECRET])}
        (tmp_path / "config.json").write_text(json.dumps(config))
        mitmproxy = types.ModuleType("mitmproxy")
        http = types.ModuleType("mitmproxy.http")
        http.Response = types.SimpleNamespace(make=lambda status, body, headers: ("stub", status))
        http.HTTPFlow = HTTPFlow
        tcp = types.ModuleType("mitmproxy.tcp")
        tcp.TCPFlow = object
        tls = types.ModuleType("mitmproxy.tls")
        tls.TlsData = object
        mitmproxy.http, mitmproxy.tcp, mitmproxy.tls = http, tcp, tls
        for name, module in {
            "mitmproxy": mitmproxy,
            "mitmproxy.http": http,
            "mitmproxy.tcp": tcp,
            "mitmproxy.tls": tls,
        }.items():
            monkeypatch.setitem(sys.modules, name, module)
        source = addon_source().decode()
        assert 'HERE = "/home/mitmproxy/lookfirst"' in source
        source = source.replace('HERE = "/home/mitmproxy/lookfirst"', f'HERE = "{tmp_path}"')
        namespace: dict = {"__name__": "lookfirst_addon_under_test"}
        exec(compile(source, "mitm_addon.py", "exec"), namespace)  # noqa: S102 - our own addon
        return namespace

    return loader


def records(tmp_path: Path) -> list[dict]:
    return [json.loads(line) for line in (tmp_path / "flows.jsonl").read_text().splitlines()]


def send(addon: dict, request: Request) -> HTTPFlow:
    flow = HTTPFlow(request)
    addon["request"](flow)
    return flow


def test_it_says_when_it_has_loaded(load, tmp_path: Path) -> None:
    load()
    assert (tmp_path / "ready").read_text() == "ready\n"


def test_sinkhole_answers_other_sites_and_forwards_allowed_ones(load, tmp_path: Path) -> None:
    addon = load()
    assert send(addon, Request("collect.example.net", "/u")).response == ("stub", 200)
    assert send(addon, Request("registry.npmjs.org", "/is-number")).response is None
    assert send(addon, Request("github.com", "/o/tool/archive/main.zip")).response is None
    assert send(addon, Request("github.com", "/someone/else")).response == ("stub", 200)
    assert [r["action"] for r in records(tmp_path)] == [
        "answered",
        "forwarded",
        "forwarded",
        "answered",
    ]


@pytest.mark.parametrize("mode", ["sinkhole", "passthrough"])
@pytest.mark.parametrize(
    "request_",
    [
        Request("registry.npmjs.org", "/x", body=SECRET.encode(), method="PUT"),
        Request("registry.npmjs.org", f"/x?t={SECRET}"),
        Request("registry.npmjs.org", "/x", headers=[("authorization", f"Bearer {SECRET}")]),
    ],
)
def test_a_decoy_is_never_forwarded_even_to_an_allowed_site(
    load, tmp_path: Path, mode: str, request_: Request
) -> None:
    addon = load(mode)
    assert send(addon, request_).response == ("stub", 200)
    assert records(tmp_path)[-1]["action"] == "held"


def test_passthrough_forwards_other_sites(load, tmp_path: Path) -> None:
    addon = load("passthrough")
    assert send(addon, Request("collect.example.net")).response is None
    assert records(tmp_path)[-1]["action"] == "forwarded"


def test_plain_tcp_to_other_sites_is_closed(load, tmp_path: Path) -> None:
    addon = load()
    killed = []
    conn = types.SimpleNamespace(address=("irc.example.net", 6667))
    flow = types.SimpleNamespace(server_conn=conn, kill=lambda: killed.append(True))
    addon["tcp_start"](flow)
    assert killed == [True] and records(tmp_path)[-1]["action"] == "closed"


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("registry.npmjs.org", "/a"),
        ("sub.registry.npmjs.org", "/"),
        ("github.com", "/o/tool"),
        ("github.com", "/O/Tool.git/info/refs"),
        ("github.com", "/o/toolbox"),
        ("example.net", "/"),
    ],
)
def test_the_addon_and_lookfirst_agree_on_allowed_sites(load, host: str, path: str) -> None:
    assert load()["_allowed"](host, path) == allowed(host, path, ALLOW)

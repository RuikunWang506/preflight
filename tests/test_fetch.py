"""The remote-script reader: public addresses only, size and count caps, never runs anything."""

from __future__ import annotations

import socket

import httpcore
import httpx
import pytest

from lookfirst.static import fetch
from lookfirst.static.fetch import (
    FetchLimits,
    PublicOnlyBackend,
    RemoteReader,
    make_public_transport,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",  # noqa: S104 - an address to refuse, not a bind
    ],
)
def test_private_and_local_addresses_are_refused_before_connecting(
    address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(
        fetch.socket,
        "getaddrinfo",
        lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (address, 443))],
    )
    with pytest.raises(httpcore.ConnectError, match="private address"):
        PublicOnlyBackend().connect_tcp("innocent-looking.example", 443)


def test_a_name_with_any_private_address_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ]
    monkeypatch.setattr(fetch.socket, "getaddrinfo", lambda *a, **k: infos)
    with pytest.raises(httpcore.ConnectError):
        PublicOnlyBackend().connect_tcp("rebinding.example", 443)


def test_the_public_transport_uses_the_guarded_backend() -> None:
    transport = make_public_transport()
    assert isinstance(transport._pool._network_backend, PublicOnlyBackend)


def test_a_refused_address_becomes_a_plain_reason(mock_http) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "refused: x points at a private address (10.0.0.1)", request=request
        )

    mock_http(handler)
    result = RemoteReader().get("https://x.example/i.sh")
    assert result.status == "refused"
    assert "private or local address" in (result.reason or "")


def test_scripts_are_read_with_curls_user_agent(mock_http) -> None:
    sent = mock_http(lambda r: httpx.Response(200, text="echo hi"))
    reader = RemoteReader()
    assert reader.get("https://x.example/a.sh", tool="curl").text == "echo hi"
    reader.get("https://x.example/b.sh", tool="wget")
    assert sent[0].headers["user-agent"].startswith("curl/")
    assert sent[1].headers["user-agent"].startswith("Wget/")
    assert "authorization" not in sent[0].headers and "cookie" not in sent[0].headers


def test_redirects_are_followed_and_non_http_schemes_refused(mock_http) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "https://y.example/b"})
        if request.url.path == "/b":
            return httpx.Response(200, text="echo b")
        return httpx.Response(302, headers={"location": "file:///etc/passwd"})

    mock_http(handler)
    reader = RemoteReader()
    ok = reader.get("https://x.example/a")
    assert (ok.status, ok.final_url, ok.text) == ("ok", "https://y.example/b", "echo b")
    assert reader.get("https://x.example/c").status == "refused"


def test_programs_are_recognized_not_read(mock_http) -> None:
    mock_http(lambda r: httpx.Response(200, content=b"\x7fELF" + b"\x00" * 60))
    result = RemoteReader().get("https://x.example/tool")
    assert result.status == "binary" and result.text is None and result.sha256


def test_large_scripts_are_cut_off(mock_http) -> None:
    mock_http(lambda r: httpx.Response(200, content=b"#" * 3000))
    result = RemoteReader(limits=FetchLimits(max_bytes=1000)).get("https://x.example/big.sh")
    assert result.status == "too_large"


def test_failures_are_explained(mock_http) -> None:
    mock_http(lambda r: httpx.Response(404))
    assert (
        RemoteReader().get("https://x.example/gone.sh").reason
        == "the server answered with HTTP 404"
    )


def test_at_most_n_scripts_and_each_url_once(mock_http) -> None:
    sent = mock_http(lambda r: httpx.Response(200, text="echo"))
    reader = RemoteReader(limits=FetchLimits(max_scripts=2))
    for _ in range(3):
        reader.get("https://x.example/same.sh")
    assert len(sent) == 1
    reader.get("https://x.example/2.sh")
    assert reader.get("https://x.example/3.sh").status == "limit"


def test_time_budget(mock_http, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_http(lambda r: httpx.Response(200, text="echo"))
    clock = iter([0.0, 0.0, 100.0, 100.0, 100.0])
    monkeypatch.setattr(fetch.time, "monotonic", lambda: next(clock))
    reader = RemoteReader(limits=FetchLimits(total_seconds=15))
    assert reader.get("https://x.example/1.sh").status == "ok"
    assert reader.get("https://x.example/2.sh").status == "limit"

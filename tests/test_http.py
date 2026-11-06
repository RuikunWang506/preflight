import re
import subprocess
from pathlib import Path

import httpx
import pytest

from lookfirst.core import http as lf_http
from lookfirst.core.config import Limits
from lookfirst.core.errors import FetchError
from lookfirst.core.http import download, get_json, github_token, make_client

API = frozenset({"api.github.com"})
API_AND_CODELOAD = frozenset({"api.github.com", "codeload.github.com"})
TOKEN = "test-token-0123456789"  # not a real token


def test_the_token_goes_only_to_api_github_com_even_after_a_redirect(
    mock_http, tmp_path: Path
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(
                302, headers={"location": "https://codeload.github.com/o/r/tar.gz/abc"}
            )
        return httpx.Response(200, content=b"tarball")

    sent = mock_http(handler)
    with make_client(token=TOKEN) as client:
        download(
            client,
            "https://api.github.com/repos/o/r/tarball/abc",
            tmp_path / "t",
            allowed_hosts=API_AND_CODELOAD,
            what="x",
        )
    assert [r.url.host for r in sent] == ["api.github.com", "codeload.github.com"]
    assert sent[0].headers["authorization"] == f"Bearer {TOKEN}"
    assert "authorization" not in sent[1].headers


def test_no_token_means_no_authorization_header(mock_http) -> None:
    sent = mock_http(lambda r: httpx.Response(200, json={}))
    with make_client(token=None) as client:
        get_json(client, "https://api.github.com/repos/o/r", allowed_hosts=API, what="x")
    assert "authorization" not in sent[0].headers


def test_a_redirect_to_another_host_is_refused_before_it_is_followed(mock_http) -> None:
    sent = mock_http(
        lambda r: httpx.Response(302, headers={"location": "https://evil.example/steal"})
    )
    with (
        make_client(token=TOKEN) as client,
        pytest.raises(FetchError, match=re.escape("Refused to download from evil.example")),
    ):
        get_json(client, "https://api.github.com/repos/o/r", allowed_hosts=API, what="x")
    assert [r.url.host for r in sent] == ["api.github.com"]


def test_a_redirect_to_plain_http_is_refused(mock_http) -> None:
    mock_http(lambda r: httpx.Response(302, headers={"location": "http://api.github.com/x"}))
    with make_client() as client, pytest.raises(FetchError, match="plain http"):
        get_json(client, "https://api.github.com/repos/o/r", allowed_hosts=API, what="x")


def test_redirect_loops_stop(mock_http) -> None:
    mock_http(lambda r: httpx.Response(302, headers={"location": "https://api.github.com/loop"}))
    with make_client() as client, pytest.raises(FetchError, match="Too many redirects"):
        get_json(client, "https://api.github.com/loop", allowed_hosts=API, what="x")


def test_a_too_large_declared_size_is_not_downloaded(mock_http, tmp_path: Path) -> None:
    mock_http(
        lambda r: httpx.Response(
            200, headers={"content-length": str(10 * 1024 * 1024)}, content=b"x"
        )
    )
    limits = Limits(max_download_bytes=1024 * 1024)
    with make_client() as client, pytest.raises(FetchError, match="larger than 1 MB"):
        download(
            client,
            "https://api.github.com/x",
            tmp_path / "t",
            allowed_hosts=API,
            what="The file",
            limits=limits,
        )


def test_a_too_large_body_stops_downloading(mock_http, tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=iter([b"x" * 600_000, b"x" * 600_000])
        )  # no content-length

    mock_http(handler)
    limits = Limits(max_download_bytes=1024 * 1024)
    with make_client() as client, pytest.raises(FetchError, match="stopped"):
        download(
            client,
            "https://api.github.com/x",
            tmp_path / "t",
            allowed_hosts=API,
            what="The file",
            limits=limits,
        )


def test_too_large_json_is_refused(mock_http) -> None:
    mock_http(lambda r: httpx.Response(200, content=b"[" + b"1," * 600_000 + b"1]"))
    with make_client() as client, pytest.raises(FetchError, match="larger than 1 MB"):
        get_json(
            client,
            "https://api.github.com/x",
            allowed_hosts=API,
            what="x",
            limits=Limits(max_json_bytes=1024 * 1024),
        )


def test_not_found_has_a_plain_message_and_hint(mock_http) -> None:
    mock_http(lambda r: httpx.Response(404))
    with make_client() as client, pytest.raises(FetchError) as err:
        get_json(
            client,
            "https://api.github.com/repos/o/r",
            allowed_hosts=API,
            what="The GitHub repo o/r",
            not_found_hint="Check the spelling.",
        )
    assert err.value.message == "The GitHub repo o/r wasn't found."
    assert err.value.hint == "Check the spelling."


def test_rate_limit_suggests_a_token(mock_http) -> None:
    mock_http(lambda r: httpx.Response(403, headers={"x-ratelimit-remaining": "0"}))
    with make_client() as client, pytest.raises(FetchError, match="limit") as err:
        get_json(client, "https://api.github.com/repos/o/r", allowed_hosts=API, what="x")
    assert "GITHUB_TOKEN" in (err.value.hint or "")


def test_connection_failures_are_explained(mock_http) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    mock_http(handler)
    with (
        make_client() as client,
        pytest.raises(FetchError, match=re.escape("Couldn't connect to api.github.com")),
    ):
        get_json(client, "https://api.github.com/x", allowed_hosts=API, what="x")


def test_invalid_json_is_explained(mock_http) -> None:
    mock_http(lambda r: httpx.Response(200, content=b"<html>"))
    with make_client() as client, pytest.raises(FetchError, match="wasn't valid JSON"):
        get_json(client, "https://api.github.com/x", allowed_hosts=API, what="x")


def test_download_reports_size_and_hashes(mock_http, tmp_path: Path) -> None:
    mock_http(lambda r: httpx.Response(200, content=b"abc"))
    with make_client() as client:
        got = download(
            client, "https://api.github.com/x", tmp_path / "t", allowed_hosts=API, what="x"
        )
    assert got.size == 3
    assert got.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert (tmp_path / "t").read_bytes() == b"abc"


# --- where the token comes from ----------------------------------------------


def test_github_token_prefers_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "  from-env  ")
    assert github_token() == "from-env"


def test_github_token_asks_gh_only_when_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="from-gh\n", stderr="")

    monkeypatch.setattr(lf_http.shutil, "which", lambda name: "/opt/homebrew/bin/gh")
    monkeypatch.setattr(lf_http.subprocess, "run", fake_run)
    assert github_token() is None  # LOOKFIRST_NO_GH_TOKEN is set for every test
    assert calls == []

    monkeypatch.delenv("LOOKFIRST_NO_GH_TOKEN")
    assert github_token() == "from-gh"
    assert calls == [["/opt/homebrew/bin/gh", "auth", "token", "--hostname", "github.com"]]


def test_github_token_is_none_when_gh_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOOKFIRST_NO_GH_TOKEN")
    monkeypatch.setattr(lf_http.shutil, "which", lambda name: "/opt/homebrew/bin/gh")
    monkeypatch.setattr(
        lf_http.subprocess,
        "run",
        lambda args, **kw: subprocess.CompletedProcess(args, 1, stdout="", stderr="not logged in"),
    )
    assert github_token() is None

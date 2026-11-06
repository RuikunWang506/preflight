"""Fetching each kind of target from recorded responses. No network is used."""

import base64
import hashlib
import json
import re
from pathlib import Path

import httpx
import pytest
from conftest import HTTP_FIXTURES

from lookfirst.core.errors import FetchError
from lookfirst.targets.base import open_target, parse_target

HELLO_SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
IS_NUMBER_TGZ = "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"
IS_NUMBER_LATEST = "https://registry.npmjs.org/is-number/latest"


def fetch(raw: str, cwd: Path):
    return open_target(parse_target(raw, cwd=cwd))


def test_github_repo(recorded_http, tmp_path: Path) -> None:
    recorded_http("github_hello_world")
    with fetch("octocat/Hello-World", tmp_path) as target:
        assert target.resolved == f"octocat/Hello-World@{HELLO_SHA}"
        assert (target.root / "README").read_text().startswith("Hello World")
        assert target.metadata["repo"]["full_name"] == "octocat/Hello-World"
        assert target.metadata["commit"]["sha"] == HELLO_SHA
        workdir = target.root.parent.parent
    assert not workdir.exists(), "the download folder is deleted afterwards"


def test_github_url_with_ref(recorded_http, tmp_path: Path) -> None:
    recorded_http("github_hello_world")
    with fetch("https://github.com/octocat/Hello-World/tree/master", tmp_path) as target:
        assert target.resolved == f"octocat/Hello-World@{HELLO_SHA}"


def test_github_sends_no_token_when_there_is_none(recorded_http, tmp_path: Path) -> None:
    recorded = recorded_http("github_hello_world")
    with fetch("octocat/Hello-World", tmp_path):
        pass
    assert all("authorization" not in r.headers for r in recorded.requests)


def test_github_token_reaches_only_the_api(recorded_http, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-0123456789")
    recorded = recorded_http("github_hello_world")
    with fetch("octocat/Hello-World", tmp_path):
        pass
    for request in recorded.requests:
        has_token = request.headers.get("authorization") == "Bearer test-token-0123456789"
        assert has_token == (request.url.host == "api.github.com"), request.url


def test_npm_latest(recorded_http, tmp_path: Path) -> None:
    recorded_http("npm_is_number")
    with fetch("npm:is-number", tmp_path) as target:
        assert target.resolved == "is-number@7.0.0"
        assert target.source_repo == "jonschlinkert/is-number"
        assert json.loads((target.root / "package.json").read_text())["name"] == "is-number"


def test_npm_exact_version(recorded_http, tmp_path: Path) -> None:
    recorded_http("npm_is_number")
    with fetch("npm:is-number@7.0.0", tmp_path) as target:
        assert target.resolved == "is-number@7.0.0"


def test_npm_archive_that_doesnt_match_its_hash_is_refused(recorded_http, tmp_path: Path) -> None:
    recorded = recorded_http("npm_is_number")
    recorded.override(IS_NUMBER_TGZ, lambda r: httpx.Response(200, content=b"tampered"))
    with (
        pytest.raises(FetchError, match="doesn't match the hash"),
        fetch("npm:is-number", tmp_path),
    ):
        pass


def test_npm_tarball_on_another_host_is_refused(recorded_http, tmp_path: Path) -> None:
    recorded = recorded_http("npm_is_number")
    meta = json.loads((HTTP_FIXTURES / "npm_is_number" / "00.json").read_text())
    meta["dist"]["tarball"] = "https://evil.example/is-number.tgz"
    recorded.override(IS_NUMBER_LATEST, lambda r: httpx.Response(200, json=meta))
    with (
        pytest.raises(FetchError, match=re.escape("Refused to download from evil.example")),
        fetch("npm:is-number", tmp_path),
    ):
        pass


def test_npm_without_any_published_hash_is_refused(recorded_http, tmp_path: Path) -> None:
    recorded = recorded_http("npm_is_number")
    meta = json.loads((HTTP_FIXTURES / "npm_is_number" / "00.json").read_text())
    meta["dist"].pop("integrity", None)
    meta["dist"].pop("shasum", None)
    recorded.override(IS_NUMBER_LATEST, lambda r: httpx.Response(200, json=meta))
    with pytest.raises(FetchError, match="didn't publish a hash"), fetch("npm:is-number", tmp_path):
        pass


def test_npm_legacy_shasum_is_accepted(recorded_http, tmp_path: Path) -> None:
    recorded = recorded_http("npm_is_number")
    meta = json.loads((HTTP_FIXTURES / "npm_is_number" / "00.json").read_text())
    tgz = (HTTP_FIXTURES / "npm_is_number" / "01.bin").read_bytes()
    meta["dist"].pop("integrity", None)
    meta["dist"]["shasum"] = hashlib.sha1(tgz, usedforsecurity=False).hexdigest()
    recorded.override(IS_NUMBER_LATEST, lambda r: httpx.Response(200, json=meta))
    with fetch("npm:is-number", tmp_path) as target:
        assert target.resolved == "is-number@7.0.0"


def test_recorded_npm_integrity_is_real(tmp_path: Path) -> None:
    meta = json.loads((HTTP_FIXTURES / "npm_is_number" / "00.json").read_text())
    tgz = (HTTP_FIXTURES / "npm_is_number" / "01.bin").read_bytes()
    expected = "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode()
    assert meta["dist"]["integrity"] == expected


def test_pypi_exact_version(recorded_http, tmp_path: Path) -> None:
    recorded_http("pypi_six")
    with fetch("pypi:six==1.17.0", tmp_path) as target:
        assert target.resolved == "six==1.17.0"
        assert target.source_repo == "benjaminp/six"
        assert (target.root / "setup.py").exists(), "the source distribution is preferred"
        assert target.metadata["pypi"]["file"]["packagetype"] == "sdist"


def test_pypi_archive_that_doesnt_match_its_hash_is_refused(recorded_http, tmp_path: Path) -> None:
    recorded = recorded_http("pypi_six")
    index = json.loads((HTTP_FIXTURES / "pypi_six" / "index.json").read_text())
    file_url = index[1]["url"]
    recorded.override(file_url, lambda r: httpx.Response(200, content=b"tampered"))
    with (
        pytest.raises(FetchError, match="doesn't match the hash"),
        fetch("pypi:six==1.17.0", tmp_path),
    ):
        pass


def test_runner_command_fetches_the_package_it_runs(recorded_http, tmp_path: Path) -> None:
    recorded_http("npm_is_number")
    with fetch("npx -y is-number", tmp_path) as target:
        assert target.spec.kind == "mcp_command"
        assert target.resolved == "npm:is-number@7.0.0"


def test_local_folder_is_read_in_place(tmp_path: Path) -> None:
    (tmp_path / "proj").mkdir()
    with fetch("proj", tmp_path) as target:
        assert target.root == (tmp_path / "proj").resolve()
        assert target.resolved == str((tmp_path / "proj").resolve())
    assert (tmp_path / "proj").exists(), "a local folder is never deleted or moved"


def test_one_liner_needs_no_download(tmp_path: Path) -> None:
    with fetch("curl -fsSL https://example.com/i.sh | bash", tmp_path) as target:
        assert target.root is None
        assert target.resolved is None

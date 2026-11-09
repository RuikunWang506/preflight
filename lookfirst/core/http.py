"""One HTTP client for everything lookfirst downloads.

- Every response has a timeout and a size cap.
- Redirects are followed by hand, so every hop's host is checked against
  the hosts this kind of download is allowed to use, and only https is used.
- A GitHub token, if there is one, is sent only to https://api.github.com.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from lookfirst import __version__
from lookfirst.core.config import DEFAULT_LIMITS, MB, Limits
from lookfirst.core.errors import FetchError

GITHUB_API_HOST = "api.github.com"
USER_AGENT = f"lookfirst/{__version__}"

# Tests replace this with an httpx.MockTransport so they never use the network.
_TRANSPORT: httpx.BaseTransport | None = None


def github_token() -> str | None:
    """Find an optional GitHub token: $GITHUB_TOKEN, $GH_TOKEN, then `gh auth token`.

    lookfirst only sends GET requests to api.github.com with it, to get a
    higher rate limit. Set LOOKFIRST_NO_GH_TOKEN=1 to skip asking `gh`.
    """
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(var, "").strip()
        if value:
            return value
    if os.environ.get("LOOKFIRST_NO_GH_TOKEN"):
        return None
    gh = shutil.which("gh")
    if gh is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed arguments, no shell
            [gh, "auth", "token", "--hostname", "github.com"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    token = proc.stdout.strip()
    return token if proc.returncode == 0 and token else None


class _GitHubTokenAuth(httpx.Auth):
    """Adds the token to requests for https://api.github.com and nothing else."""

    def __init__(self, token: str) -> None:
        self._token = token

    def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
        if request.url.scheme == "https" and request.url.host == GITHUB_API_HOST:
            request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


def make_client(*, token: str | None = None, limits: Limits = DEFAULT_LIMITS) -> httpx.Client:
    """Create the client. Redirects are off here and handled in _open()."""
    return httpx.Client(
        auth=_GitHubTokenAuth(token) if token else None,
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(limits.http_timeout_s),
        follow_redirects=False,
        transport=_TRANSPORT,
    )


@dataclass(frozen=True)
class Downloaded:
    path: Path
    size: int
    sha1: str
    sha256: str
    sha512: str
    final_url: str


def _check_url(url: httpx.URL, allowed_hosts: frozenset[str]) -> None:
    if url.scheme != "https":
        raise FetchError(
            f"Refused to download over plain http from {url.host or 'an unknown host'}."
        )
    if url.host not in allowed_hosts:
        allowed = ", ".join(sorted(allowed_hosts))
        raise FetchError(
            f"Refused to download from {url.host}: for this kind of target, "
            f"lookfirst only downloads from {allowed}."
        )


def _open(
    client: httpx.Client,
    url: str,
    *,
    allowed_hosts: frozenset[str],
    headers: Mapping[str, str] | None,
    limits: Limits,
    method: str = "GET",
    json_body: Any = None,
) -> httpx.Response:
    """Send a request and follow redirects by hand. The caller must close the response."""
    current = httpx.URL(url)
    for _ in range(limits.max_redirects + 1):
        _check_url(current, allowed_hosts)
        request = client.build_request(method, current, headers=headers, json=json_body)
        try:
            response = client.send(request, stream=True)
        except httpx.TimeoutException as exc:
            raise FetchError(f"{current.host} took too long to answer.") from exc
        except httpx.TransportError as exc:
            raise FetchError(
                f"Couldn't connect to {current.host}.", hint="Check your internet connection."
            ) from exc
        if not response.has_redirect_location:  # httpx calls every 3xx, even 304, a redirect
            return response
        location = response.headers.get("location", "")
        response.close()
        if not location:
            raise FetchError(f"{current.host} sent a redirect without saying where to.")
        current = current.join(location)
    raise FetchError(f"Too many redirects while downloading from {httpx.URL(url).host}.")


def _raise_for_status(response: httpx.Response, what: str, not_found_hint: str | None) -> None:
    status = response.status_code
    if 200 <= status < 300:
        return
    if status == 404:
        raise FetchError(f"{what} wasn't found.", hint=not_found_hint)
    if status in (403, 429) and response.headers.get("x-ratelimit-remaining") == "0":
        raise FetchError(
            "GitHub's limit on requests from this connection is used up for now.",
            hint="Set GITHUB_TOKEN, or sign in with `gh auth login`, then try again.",
        )
    if status in (401, 403):
        raise FetchError(
            f"{what}: access was refused (HTTP {status}).",
            hint="If it's private, set GITHUB_TOKEN to a token that can read it.",
        )
    raise FetchError(f"{what}: the server answered with HTTP {status}.")


def _check_declared_size(response: httpx.Response, cap: int, what: str) -> None:
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > cap:
        raise FetchError(f"{what} is larger than {cap // MB} MB, so lookfirst didn't download it.")


_KEPT_HEADERS = frozenset(
    {"etag", "link", "content-type", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"}
)


@dataclass(frozen=True)
class Fetched:
    """A response whose status the caller handles itself (404 isn't an error here)."""

    status: int
    headers: dict[str, str]  # lowercase names; only the few lookfirst uses
    content: bytes

    def json(self) -> Any:
        try:
            return json.loads(self.content)
        except ValueError:
            return None


def fetch(
    client: httpx.Client,
    url: str,
    *,
    allowed_hosts: frozenset[str],
    what: str,
    headers: Mapping[str, str] | None = None,
    method: str = "GET",
    json_body: Any = None,
    max_bytes: int | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> Fetched:
    """Send a request and return its status, a few headers and the capped body."""
    response = _open(
        client,
        url,
        allowed_hosts=allowed_hosts,
        headers=headers,
        limits=limits,
        method=method,
        json_body=json_body,
    )
    try:
        cap = max_bytes or limits.max_json_bytes
        _check_declared_size(response, cap, what)
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > cap:
                raise FetchError(f"{what} is larger than {cap // MB} MB, so lookfirst stopped.")
        kept = {k.lower(): v for k, v in response.headers.items() if k.lower() in _KEPT_HEADERS}
        return Fetched(response.status_code, kept, bytes(body))
    finally:
        response.close()


def get_json(
    client: httpx.Client,
    url: str,
    *,
    allowed_hosts: frozenset[str],
    what: str,
    headers: Mapping[str, str] | None = None,
    not_found_hint: str | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> Any:
    """GET a JSON document, capped at limits.max_json_bytes."""
    response = _open(client, url, allowed_hosts=allowed_hosts, headers=headers, limits=limits)
    try:
        _raise_for_status(response, what, not_found_hint)
        cap = limits.max_json_bytes
        _check_declared_size(response, cap, what)
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > cap:
                raise FetchError(f"{what} is larger than {cap // MB} MB, so lookfirst stopped.")
    finally:
        response.close()
    try:
        return json.loads(body)
    except ValueError as exc:
        raise FetchError(f"{what}: the server's answer wasn't valid JSON.") from exc


def download(
    client: httpx.Client,
    url: str,
    dest: Path,
    *,
    allowed_hosts: frozenset[str],
    what: str,
    headers: Mapping[str, str] | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> Downloaded:
    """Stream a file to dest, capped at limits.max_download_bytes, hashing as it goes."""
    response = _open(client, url, allowed_hosts=allowed_hosts, headers=headers, limits=limits)
    hashes = {
        # sha1 only to compare with npm's legacy "shasum" when nothing stronger is published.
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }
    size = 0
    try:
        _raise_for_status(response, what, None)
        cap = limits.max_download_bytes
        _check_declared_size(response, cap, what)
        with dest.open("wb") as out:
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > cap:
                    raise FetchError(f"{what} is larger than {cap // MB} MB, so lookfirst stopped.")
                for h in hashes.values():
                    h.update(chunk)
                out.write(chunk)
        final_url = str(response.url)
    finally:
        response.close()
    return Downloaded(
        path=dest,
        size=size,
        sha1=hashes["sha1"].hexdigest(),
        sha256=hashes["sha256"].hexdigest(),
        sha512=hashes["sha512"].hexdigest(),
        final_url=final_url,
    )

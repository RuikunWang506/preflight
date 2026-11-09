"""Download remote scripts so they can be read. Nothing downloaded is ever run.

Safety limits:
- Only public internet addresses. Never localhost, private networks or cloud metadata
  addresses, checked at connect time, so DNS tricks can't point a download at your
  router or a local service.
- http and https only, at most 5 redirects, no proxies, no cookies, no tokens.
- At most 2 MB per script, 20 scripts and 15 seconds per check.

Scripts are requested with the same User-Agent the command would send (curl or wget),
so a server that shows scanners a harmless script and curl a different one has a
harder time fooling lookfirst.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Literal

import httpcore
import httpx

from lookfirst.core import http as lf_http

USER_AGENTS = {"curl": "curl/8.7.1", "wget": "Wget/1.25.0"}
_BINARY_MAGIC = (
    b"\x7fELF",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"MZ",
    b"PK\x03\x04",
    b"\x1f\x8b",
)

Status = Literal["ok", "binary", "failed", "refused", "too_large", "limit"]


@dataclass(frozen=True)
class FetchLimits:
    max_depth: int = 3
    max_scripts: int = 20
    max_bytes: int = 2 * 1024 * 1024
    total_seconds: float = 15.0
    request_timeout: float = 10.0
    max_redirects: int = 5


@dataclass(frozen=True)
class RemoteScript:
    url: str
    status: Status
    final_url: str | None = None
    text: str | None = None
    sha256: str | None = None
    size: int = 0
    reason: str | None = None

    @property
    def readable(self) -> bool:
        return self.status == "ok"


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


class PublicOnlyBackend(httpcore.SyncBackend):
    """Connects only after checking every address the name resolves to is public."""

    def connect_tcp(  # type: ignore[override]
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.NetworkStream:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpcore.ConnectError(f"couldn't look up {host}") from exc
        addresses = [info[4][0] for info in infos]
        if not addresses:
            raise httpcore.ConnectError(f"couldn't look up {host}")
        for ip in addresses:
            if not _is_public(ip):
                raise httpcore.ConnectError(f"refused: {host} points at a private address ({ip})")
        return super().connect_tcp(
            addresses[0],
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,  # type: ignore[arg-type]
        )


def make_public_transport() -> httpx.HTTPTransport:
    transport = httpx.HTTPTransport(trust_env=False, retries=0)
    pool = transport._pool  # httpx doesn't expose a way to pass a network backend
    pool._network_backend = PublicOnlyBackend()
    return transport


@dataclass
class RemoteReader:
    limits: FetchLimits = field(default_factory=FetchLimits)
    _cache: dict[str, RemoteScript] = field(default_factory=dict)
    _started: float | None = None
    _client: httpx.Client | None = None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                transport=lf_http._TRANSPORT or make_public_transport(),
                follow_redirects=False,
                trust_env=False,
            )
        return self._client

    def _remaining(self) -> float:
        if self._started is None:
            self._started = time.monotonic()
        return self.limits.total_seconds - (time.monotonic() - self._started)

    def get(self, url: str, *, tool: str | None = None) -> RemoteScript:
        if url in self._cache:
            return self._cache[url]
        result = self._fetch(url, tool)
        self._cache[url] = result
        return result

    def _fetch(self, url: str, tool: str | None) -> RemoteScript:
        fetched = sum(1 for r in self._cache.values() if r.status in ("ok", "binary"))
        if fetched >= self.limits.max_scripts:
            return RemoteScript(
                url,
                "limit",
                reason=f"lookfirst reads at most {self.limits.max_scripts} remote scripts",
            )
        headers = {
            "User-Agent": USER_AGENTS.get(tool or "curl", USER_AGENTS["curl"]),
            "Accept": "*/*",
        }
        current = httpx.URL(url)
        client = self._get_client()
        for _ in range(self.limits.max_redirects + 1):
            if current.scheme not in ("http", "https"):
                return RemoteScript(
                    url, "refused", reason="lookfirst only downloads http and https links"
                )
            remaining = self._remaining()
            if remaining <= 0:
                return RemoteScript(url, "limit", reason="lookfirst ran out of time for downloads")
            timeout = httpx.Timeout(min(self.limits.request_timeout, remaining))
            try:
                request = client.build_request("GET", current, headers=headers, timeout=timeout)
                response = client.send(request, stream=True)
            except httpx.ConnectError as exc:
                if "refused:" in str(exc):
                    return RemoteScript(
                        url,
                        "refused",
                        reason="it points at a private or local address",
                    )
                return RemoteScript(url, "failed", reason=f"couldn't connect to {current.host}")
            except httpx.TimeoutException:
                return RemoteScript(url, "failed", reason=f"{current.host} took too long to answer")
            except httpx.HTTPError as exc:
                return RemoteScript(url, "failed", reason=f"download failed ({type(exc).__name__})")
            try:
                if response.has_redirect_location:
                    location = response.headers.get("location", "")
                    if not location:
                        return RemoteScript(
                            url, "failed", reason="the server sent a redirect with nowhere to go"
                        )
                    current = current.join(location)
                    continue
                if response.status_code != 200:
                    return RemoteScript(
                        url,
                        "failed",
                        reason=f"the server answered with HTTP {response.status_code}",
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self.limits.max_bytes:
                        return RemoteScript(
                            url, "too_large", final_url=str(current), reason="it's larger than 2 MB"
                        )
            except httpx.HTTPError as exc:
                return RemoteScript(url, "failed", reason=f"download failed ({type(exc).__name__})")
            finally:
                response.close()
            data = bytes(body)
            digest = hashlib.sha256(data).hexdigest()
            if data.startswith(_BINARY_MAGIC) or b"\x00" in data[:8192]:
                return RemoteScript(
                    url, "binary", final_url=str(current), sha256=digest, size=len(data)
                )
            return RemoteScript(
                url,
                "ok",
                final_url=str(current),
                text=data.decode("utf-8", "replace"),
                sha256=digest,
                size=len(data),
            )
        return RemoteScript(url, "failed", reason="too many redirects")

"""What the identity check asks GitHub, with answers cached by ETag.

Every request is a read: GET on the REST API, plus one GraphQL query for the star
sample, which needs a token. With a token, a cached answer GitHub confirms unchanged
(HTTP 304) doesn't count against the rate limit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from lookfirst.core.errors import FetchError
from lookfirst.core.http import Fetched, fetch

API = "https://api.github.com"
_HOSTS = frozenset({"api.github.com"})
_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
_FULL_NAME = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_LAST_PAGE = re.compile(r'[?&]page=(\d+)[^>]*>;\s*rel="last"')
_STARGAZERS_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    stargazers(last: 100) {
      nodes { createdAt followers { totalCount } repositories { totalCount } }
    }
  }
}
"""


class RateLimited(FetchError):
    """GitHub's request limit for this connection is used up for now."""


def valid_full_name(name: object) -> bool:
    return isinstance(name, str) and bool(_FULL_NAME.match(name))


@dataclass
class GitHubData:
    client: httpx.Client
    has_token: bool
    cache: Path | None = None

    # --- plumbing -------------------------------------------------------------

    def _cache_file(self, url: str, accept: str) -> Path | None:
        if self.cache is None:
            return None
        key = hashlib.sha256(f"{url}|{accept}|{self.has_token}".encode()).hexdigest()
        return self.cache / "github" / f"{key}.json"

    def _get(
        self, path: str, *, accept: str | None = None, max_bytes: int = 5 * 1024 * 1024
    ) -> Fetched:
        url = API + path
        headers = dict(_HEADERS)
        if accept:
            headers["Accept"] = accept
        cache_file = self._cache_file(url, headers["Accept"])
        cached: Fetched | None = None
        if cache_file is not None and cache_file.is_file():
            try:
                entry = json.loads(cache_file.read_text())
                cached = Fetched(
                    entry["status"], entry["headers"], base64.b64decode(entry["content"])
                )
                if "etag" in cached.headers:
                    headers["If-None-Match"] = cached.headers["etag"]
            except (OSError, ValueError, KeyError):
                cached = None
        result = fetch(
            self.client,
            url,
            allowed_hosts=_HOSTS,
            what="GitHub",
            headers=headers,
            max_bytes=max_bytes,
        )
        if result.status == 304 and cached is not None:
            return cached
        if result.status in (403, 429) and result.headers.get("x-ratelimit-remaining") == "0":
            raise RateLimited(
                "GitHub's limit on requests from this connection is used up for now.",
                hint="Set GITHUB_TOKEN, or sign in with `gh auth login`, then try again.",
            )
        if result.status == 200 and "etag" in result.headers and cache_file is not None:
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(
                    json.dumps(
                        {
                            "status": result.status,
                            "headers": result.headers,
                            "content": base64.b64encode(result.content).decode(),
                        }
                    )
                )
            except OSError:
                pass  # a cache that can't be written just means more requests
        if result.status >= 500:
            raise FetchError(f"GitHub answered with HTTP {result.status}.")
        return result

    def _json(self, path: str) -> Any:
        result = self._get(path)
        return result.json() if result.status == 200 else None

    # --- what the identity check asks -------------------------------------------

    def repo(self, full_name: str) -> dict | None:
        if not valid_full_name(full_name):
            return None
        data = self._json(f"/repos/{full_name}")
        return data if isinstance(data, dict) else None

    def user(self, login: str) -> dict | None:
        data = self._json(f"/users/{quote(login)}")
        return data if isinstance(data, dict) else None

    def readme(self, full_name: str) -> str | None:
        if not valid_full_name(full_name):
            return None
        result = self._get(
            f"/repos/{full_name}/readme", accept="application/vnd.github.raw", max_bytes=512 * 1024
        )
        return result.content.decode("utf-8", "replace") if result.status == 200 else None

    def releases(self, full_name: str) -> list[dict]:
        data = self._json(f"/repos/{full_name}/releases?per_page=10")
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []

    def commit_count(self, full_name: str) -> int | None:
        """Commits on the default branch, from the page count of a one-per-page listing."""
        result = self._get(f"/repos/{full_name}/commits?per_page=1")
        if result.status != 200:
            return None
        m = _LAST_PAGE.search(result.headers.get("link", ""))
        if m:
            return int(m.group(1))
        listing = result.json()
        return len(listing) if isinstance(listing, list) else None

    def search_same_name(self, name: str) -> list[dict]:
        query = quote(f"{name} in:name", safe="")
        data = self._json(f"/search/repositories?q={query}&sort=stars&order=desc&per_page=10")
        items = data.get("items") if isinstance(data, dict) else None
        return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []

    def changed_files(
        self, base: str, base_branch: str, head_owner: str, head_branch: str
    ) -> list[str] | None:
        """Files a fork changed compared with its parent."""
        head = f"{quote(head_owner, safe='')}:{quote(head_branch, safe='')}"
        path = f"/repos/{base}/compare/{quote(base_branch, safe='')}...{head}"
        data = self._json(path)
        files = data.get("files") if isinstance(data, dict) else None
        if not isinstance(files, list):
            return None
        return [str(f.get("filename")) for f in files if isinstance(f, dict) and f.get("filename")]

    def recent_stargazers(self, full_name: str) -> list[dict] | None:
        """The last 100 accounts that starred the repo. Needs a token (GraphQL)."""
        if not self.has_token:
            return None
        owner, name = full_name.split("/", 1)
        result = fetch(
            self.client,
            f"{API}/graphql",
            allowed_hosts=_HOSTS,
            what="GitHub",
            method="POST",
            json_body={"query": _STARGAZERS_QUERY, "variables": {"owner": owner, "name": name}},
            headers={"Accept": "application/json"},
        )
        data = result.json() if result.status == 200 else None
        try:
            nodes = data["data"]["repository"]["stargazers"]["nodes"]  # type: ignore[index]
        except (TypeError, KeyError):
            return None
        return [n for n in nodes if isinstance(n, dict)]

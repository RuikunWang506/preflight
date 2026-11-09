"""The popular-repos list: the projects impersonators are most likely to copy.

A snapshot ships inside lookfirst (lookfirst/registry/popular.csv.gz). `lookfirst
update-index` rebuilds it from GitHub search into the cache folder; whichever copy was
built more recently is used. The file is a gzipped CSV:

    # built 2026-11-09
    full_name,stars,created
    ollama/ollama,186424,2023-06-26

The 12-year GitHub Trending archive can be merged in later (data/seed/).
"""

from __future__ import annotations

import csv
import gzip
import io
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib.resources import files
from pathlib import Path

import httpx

from lookfirst.core.config import cache_dir
from lookfirst.core.errors import FetchError
from lookfirst.core.http import get_json
from lookfirst.identity.names import NameMatch, compare, squash, without_added_words

FILE_NAME = "popular.csv.gz"
_API_HOSTS = frozenset({"api.github.com"})
_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


@dataclass(frozen=True)
class PopularRepo:
    full_name: str
    stars: int
    created: str  # YYYY-MM-DD

    @property
    def owner(self) -> str:
        return self.full_name.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/", 1)[1]


def _parse(data: bytes) -> tuple[str, list[PopularRepo]]:
    text = gzip.decompress(data).decode("utf-8")
    built = ""
    lines = text.splitlines()
    if lines and lines[0].startswith("# built "):
        built = lines[0].removeprefix("# built ").strip()
        lines = lines[1:]
    repos = []
    for row in csv.DictReader(lines):
        try:
            repos.append(PopularRepo(row["full_name"], int(row["stars"]), row["created"]))
        except (KeyError, ValueError):
            continue
    return built, repos


def serialize(repos: Iterable[PopularRepo], built: str) -> bytes:
    out = io.StringIO()
    out.write(f"# built {built}\n")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["full_name", "stars", "created"])
    for r in sorted(repos, key=lambda r: (-r.stars, r.full_name.lower())):
        writer.writerow([r.full_name, r.stars, r.created])
    return gzip.compress(out.getvalue().encode("utf-8"), mtime=0)


class PopularIndex:
    def __init__(self, repos: Iterable[PopularRepo], built: str = "") -> None:
        self.repos = list(repos)
        self.built = built
        self._by_name: dict[str, list[PopularRepo]] = defaultdict(list)
        self._by_squash: dict[str, list[PopularRepo]] = defaultdict(list)
        for r in self.repos:
            self._by_name[r.name.lower()].append(r)
            self._by_squash[squash(r.name)].append(r)

    def __len__(self) -> int:
        return len(self.repos)

    def get(self, full_name: str) -> PopularRepo | None:
        owner, _, name = full_name.lower().partition("/")
        return next((r for r in self._by_name.get(name, []) if r.owner.lower() == owner), None)

    def lookalikes(
        self, owner: str, repo: str, limit: int = 5
    ) -> list[tuple[PopularRepo, list[NameMatch]]]:
        """Popular repos whose name the target's resembles, most-starred first."""
        pool: dict[str, PopularRepo] = {}
        for r in self._by_name.get(repo.lower(), []) + self._by_squash.get(squash(repo), []):
            pool[r.full_name] = r
        stripped, removed = without_added_words(repo)
        if removed:
            for r in self._by_squash.get(stripped, []):
                pool[r.full_name] = r
        target_squash = squash(repo)
        if len(target_squash) >= 6:  # near-misses only for names long enough to mean something
            for key, rs in self._by_squash.items():
                if abs(len(key) - len(target_squash)) <= 2 and key != target_squash:
                    for r in rs:
                        pool[r.full_name] = r
        found = []
        for r in pool.values():
            if r.full_name.lower() == f"{owner}/{repo}".lower():
                continue
            matches = [
                m for m in compare(owner, repo, r.owner, r.name) if m.kind != "lookalike_owner"
            ]
            if matches:
                found.append((r, compare(owner, repo, r.owner, r.name)))
        found.sort(key=lambda item: -item[0].stars)
        return found[:limit]


def _packaged() -> tuple[str, list[PopularRepo]]:
    resource = files("lookfirst.registry").joinpath(FILE_NAME)
    if not resource.is_file():
        return "", []
    return _parse(resource.read_bytes())


@cache
def load_index() -> PopularIndex:
    built, repos = _packaged()
    cached = cache_dir() / FILE_NAME
    if cached.is_file():
        try:
            cached_built, cached_repos = _parse(cached.read_bytes())
        except (OSError, ValueError, EOFError):
            cached_built, cached_repos = "", []
        if cached_repos and cached_built > built:
            built, repos = cached_built, cached_repos
    return PopularIndex(repos, built)


# --- building it from GitHub search ----------------------------------------------------


def _queries(today: datetime) -> list[str]:
    recent = (today - timedelta(days=90)).strftime("%Y-%m-%d")
    return [
        "stars:>=20000",
        "stars:10000..19999",
        "stars:5000..9999",
        "stars:3000..4999",
        "stars:2000..2999",
        f"created:>={recent} stars:>=300",  # fast-rising new projects, the ones copied most
    ]


def build(client: httpx.Client, *, today: datetime | None = None, pause: float = 2.1) -> bytes:
    """Search GitHub for the most-starred and fastest-rising repos. Needs a token: search
    allows 30 requests a minute with one. Returns the gzipped CSV."""
    today = today or datetime.now(UTC)
    repos: dict[str, PopularRepo] = {}
    for query in _queries(today):
        for page in range(1, 11):  # search returns at most 1,000 results per query
            url = str(
                httpx.URL(
                    "https://api.github.com/search/repositories",
                    params={
                        "q": query,
                        "sort": "stars",
                        "order": "desc",
                        "per_page": "100",
                        "page": str(page),
                    },
                )
            )
            try:
                data = get_json(
                    client, url, allowed_hosts=_API_HOSTS, headers=_HEADERS, what="GitHub search"
                )
            except FetchError:
                time.sleep(60)  # the per-minute search limit: wait once, then go on
                data = get_json(
                    client, url, allowed_hosts=_API_HOSTS, headers=_HEADERS, what="GitHub search"
                )
            items = (data.get("items") or []) if isinstance(data, dict) else []
            for item in items:
                full = item.get("full_name")
                if isinstance(full, str) and not item.get("fork"):
                    repos[full.lower()] = PopularRepo(
                        full,
                        int(item.get("stargazers_count") or 0),
                        str(item.get("created_at", ""))[:10],
                    )
            if len(items) < 100:
                break
            time.sleep(pause)
    return serialize(repos.values(), today.strftime("%Y-%m-%d"))


def save_to_cache(data: bytes) -> Path:
    path = cache_dir() / FILE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    load_index.cache_clear()
    return path

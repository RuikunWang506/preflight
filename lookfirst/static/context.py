"""What the rules need to know about the project: which sites and repo are its own."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from lookfirst.registry.installers import Installer, match_installer
from lookfirst.static.files import read_text
from lookfirst.targets.models import ResolvedTarget
from lookfirst.targets.packages import normalize_source_repo

_SHA = re.compile(r"^[0-9a-f]{40}$")
_GITHUB_PATH = re.compile(r"^/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})(/.*)?$")
# Big shared hosts: owning one page there doesn't make the whole host the project's.
_SHARED_HOSTS = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "pypi.org",
        "npmjs.com",
        "www.npmjs.com",
        "readthedocs.io",
        "github.io",
    }
)

UrlKind = Literal["known_installer", "project", "project_unpinned", "release", "unknown"]


@dataclass(frozen=True)
class UrlClass:
    kind: UrlKind
    installer: Installer | None = None


@dataclass
class RuleContext:
    project_repo: str | None = None  # "owner/repo", lowercase
    project_hosts: set[str] = field(default_factory=set)

    def add_url(self, url: object) -> None:
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return
        host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
        if host and host not in _SHARED_HOSTS:  # "owner.github.io" counts; "github.com" doesn't
            self.project_hosts.add(host)

    def set_repo(self, repo: str | None) -> None:
        if repo and "/" in repo and not repo.startswith("http"):
            self.project_repo = repo.lower()
            owner = repo.split("/", 1)[0].lower()
            self.project_hosts.add(f"{owner}.github.io")

    def classify(self, url: str) -> UrlClass:
        installer = match_installer(url)
        if installer is not None:
            return UrlClass("known_installer", installer)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().removeprefix("www.")
        path = parts.path
        m = _GITHUB_PATH.match(path)
        if host == "github.com" and m:
            repo = f"{m.group(1)}/{m.group(2)}".lower()
            rest = m.group(3) or ""
            if rest.startswith("/releases/download/"):
                return UrlClass("project" if repo == self.project_repo else "release")
            if repo == self.project_repo:
                ref = (
                    rest.split("/")[2]
                    if rest.startswith(("/raw/", "/blob/")) and rest.count("/") >= 2
                    else ""
                )
                return UrlClass("project" if _SHA.match(ref) else "project_unpinned")
        if host == "objects.githubusercontent.com":
            return UrlClass("release")
        if host == "raw.githubusercontent.com" and m:
            repo = f"{m.group(1)}/{m.group(2)}".lower()
            if repo == self.project_repo:
                ref = (m.group(3) or "/").split("/")[1] if m.group(3) else ""
                return UrlClass("project" if _SHA.match(ref) else "project_unpinned")
        if host and any(host == h or host.endswith("." + h) for h in self.project_hosts):
            return UrlClass("project")
        return UrlClass("unknown")


def _from_package_json(ctx: RuleContext, root: Path) -> None:
    text = read_text(root, "package.json")
    if not text:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    if isinstance(data, dict):
        ctx.set_repo(normalize_source_repo(data.get("repository")))
        ctx.add_url(data.get("homepage"))


def _from_pyproject(ctx: RuleContext, root: Path) -> None:
    text = read_text(root, "pyproject.toml")
    if not text:
        return
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    urls = (data.get("project") or {}).get("urls") or {}
    if isinstance(urls, dict):
        for value in urls.values():
            ctx.add_url(value)
            if ctx.project_repo is None:
                repo = normalize_source_repo(value)
                if repo and "/" in repo and not repo.startswith("http"):
                    ctx.set_repo(repo)


def build_context(target: ResolvedTarget) -> RuleContext:
    ctx = RuleContext()
    meta = target.metadata
    kind = target.spec.kind
    if kind == "github" and "repo" in meta:
        repo = meta["repo"]
        ctx.set_repo(repo.get("full_name"))
        ctx.add_url(repo.get("homepage"))
    elif "npm" in meta:
        ctx.set_repo(target.source_repo)
        ctx.add_url(meta["npm"].get("homepage"))
    elif "pypi" in meta:
        ctx.set_repo(target.source_repo)
        info = meta["pypi"].get("info") or {}
        ctx.add_url(info.get("home_page"))
        for value in (info.get("project_urls") or {}).values():
            ctx.add_url(value)
    if target.root is not None:
        if ctx.project_repo is None:
            _from_package_json(ctx, target.root)
        if ctx.project_repo is None:
            _from_pyproject(ctx, target.root)
    return ctx

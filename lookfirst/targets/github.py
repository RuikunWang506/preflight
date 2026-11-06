"""GitHub repos: `owner/repo`, `owner/repo@ref`, or a github.com URL.

The code is downloaded as a tarball of one exact commit. There's no
`git clone`, so git never runs anything from the repo, and nothing is
fetched beyond that commit's files.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

import httpx

from lookfirst.core.archive import unpack
from lookfirst.core.config import Limits
from lookfirst.core.errors import FetchError, TargetError
from lookfirst.core.http import download, get_json
from lookfirst.core.textsafe import one_line
from lookfirst.targets.models import ResolvedTarget, TargetSpec

API = "https://api.github.com"
_API_HOSTS = frozenset({"api.github.com"})
_TARBALL_HOSTS = frozenset({"api.github.com", "codeload.github.com"})
_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

# GitHub user and org names: letters, digits and single hyphens, up to 39 characters.
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}"
_REPO = r"[A-Za-z0-9._-]{1,100}"
_SHORT = re.compile(rf"^(?P<owner>{_OWNER})/(?P<repo>{_REPO})(?:@(?P<ref>\S+))?$")
_URL = re.compile(
    rf"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>{_OWNER})/(?P<repo>{_REPO}?)(?:\.git)?"
    r"(?P<rest>/[^?#\s]*)?(?:[?#]\S*)?$",
    re.IGNORECASE,
)
_FULL_NAME = re.compile(rf"^{_OWNER}/{_REPO}$")
# Git ref names: no leading "-" (it would read as an option) or "." (git forbids it).
_REF = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,254}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _check_ref(ref: str, raw: str) -> str:
    bad = (
        not _REF.match(ref)
        or any(part in ref for part in ("..", "//", "/.", "/-"))
        or ref.endswith(("/", ".", ".lock"))
    )
    if bad:
        raise TargetError(
            f"{one_line(ref, 80)} isn't a valid branch, tag or commit name in {one_line(raw, 120)}."
        )
    return ref


def _spec(raw: str, owner: str, repo: str, ref: str | None) -> TargetSpec:
    if repo in (".", ".."):
        raise TargetError(f"{one_line(raw, 120)} isn't a GitHub repo name.")
    return TargetSpec(
        kind="github",
        raw=raw,
        owner=owner,
        repo=repo,
        ref=_check_ref(ref, raw) if ref else None,
    )


def parse_github_url(raw: str) -> TargetSpec | None:
    """Parse a github.com URL, or return None if it isn't one."""
    m = _URL.match(raw)
    if not m:
        return None
    owner, repo, rest = m["owner"], m["repo"], (m["rest"] or "").strip("/")
    ref = None
    if rest:
        parts = rest.split("/")
        if parts[0] == "tree" and len(parts) >= 2:
            ref = "/".join(parts[1:])  # branch names may contain slashes
        elif parts[0] in ("commit", "blob") and len(parts) >= 2:
            ref = parts[1]
        elif parts[:2] == ["releases", "tag"] and len(parts) >= 3:
            ref = parts[2]
        else:
            raise TargetError(
                "That's a page on GitHub, not a repo.",
                hint=f"Try https://github.com/{owner}/{repo}",
            )
    return _spec(raw, owner, repo, ref)


def parse_github_short(raw: str) -> TargetSpec | None:
    """Parse `owner/repo` or `owner/repo@ref`, or return None if it doesn't look like one."""
    m = _SHORT.match(raw)
    if not m:
        return None
    repo = m["repo"].removesuffix(".git")
    return _spec(raw, m["owner"], repo, m["ref"])


def fetch_github(
    spec: TargetSpec, client: httpx.Client, workdir: Path, limits: Limits
) -> ResolvedTarget:
    if not (spec.owner and spec.repo):
        raise TargetError(f"{one_line(spec.raw, 120)} isn't a GitHub repo.")
    name = f"{spec.owner}/{spec.repo}"
    meta = get_json(
        client,
        f"{API}/repos/{quote(spec.owner)}/{quote(spec.repo)}",
        allowed_hosts=_API_HOSTS,
        headers=_HEADERS,
        what=f"The GitHub repo {name}",
        not_found_hint=(
            "Check the spelling. If it's private, set GITHUB_TOKEN to a token that can read it."
        ),
        limits=limits,
    )
    full_name = meta.get("full_name") if isinstance(meta, dict) else None
    if not isinstance(full_name, str) or not _FULL_NAME.match(full_name):
        raise FetchError(f"GitHub sent an unexpected answer about {name}.")

    ref = spec.ref or meta.get("default_branch")
    if not isinstance(ref, str) or not ref:
        raise FetchError(f"GitHub didn't say which branch {full_name} uses.")
    ref = _check_ref(ref, full_name)
    commit = get_json(
        client,
        f"{API}/repos/{full_name}/commits/{quote(ref, safe='/')}",
        allowed_hosts=_API_HOSTS,
        headers=_HEADERS,
        what=f"The branch, tag or commit {one_line(ref, 80)} in {full_name}",
        not_found_hint="Check the branch, tag or commit name.",
        limits=limits,
    )
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise FetchError(
            f"GitHub sent an unexpected answer about {full_name} at {one_line(ref, 80)}."
        )

    archive = workdir / "source.tar.gz"
    download(
        client,
        f"{API}/repos/{full_name}/tarball/{sha}",
        archive,
        allowed_hosts=_TARBALL_HOSTS,
        headers=_HEADERS,
        what=f"The code of {full_name}",
        limits=limits,
    )
    src = workdir / "src"
    manifest = unpack(archive, src, limits=limits)
    archive.unlink()
    committed = (commit.get("commit") or {}).get("committer") or {}
    return ResolvedTarget(
        spec=spec,
        root=src / manifest.root if manifest.root else src,
        resolved=f"{full_name}@{sha}",
        metadata={"repo": meta, "commit": {"sha": sha, "date": committed.get("date")}},
        manifest=manifest,
    )

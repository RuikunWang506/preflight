"""Packages: `npm:<name>[@version]`, `pypi:<name>[==version]`, and runner commands.

A runner command (`npx -y <pkg>`, `uvx <pkg>`, `pipx run <pkg>`, ...) is how
MCP servers are usually started. It's checked as the package it runs.

The package archive is downloaded only from the registry's own hosts and
checked against the hash the registry publishes for it.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx

from lookfirst.core.archive import unpack
from lookfirst.core.config import Limits
from lookfirst.core.errors import FetchError, TargetError
from lookfirst.core.http import Downloaded, download, get_json
from lookfirst.core.textsafe import one_line
from lookfirst.targets.models import Ecosystem, PackageSpec, ResolvedTarget, TargetSpec

NPM_REGISTRY = "https://registry.npmjs.org"
_NPM_HOSTS = frozenset({"registry.npmjs.org"})
PYPI_JSON = "https://pypi.org/pypi"
_PYPI_HOSTS = frozenset({"pypi.org"})
_PYPI_FILE_HOSTS = frozenset({"files.pythonhosted.org"})

_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.IGNORECASE)
_NPM_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")  # an exact version or a tag
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_PYPI_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")  # PEP 440 characters
_NPM_VERSION_HINT = (
    "Use an exact version, like npm:is-number@7.0.0, or leave it out for the latest."
)
_PYPI_VERSION_HINT = "Use an exact version, like pypi:six==1.17.0, or leave it out for the latest."
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_COMPOUND = re.compile(r"[|;&<>`$()]")

_GITHUB_SOURCE = re.compile(
    r"github\.com[/:](?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:[/#?].*)?$",
    re.IGNORECASE,
)
_SHORTHAND_SOURCE = re.compile(
    r"^(?:github:)?(?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9._-]{1,100})$"
)


# --- parsing ---------------------------------------------------------------


def parse_package_spec(ecosystem: Ecosystem, text: str, raw: str) -> PackageSpec:
    """Parse `name`, `name@version` (npm) or `name==version` (PyPI)."""
    text = text.strip()
    if ecosystem == "npm":
        at = text.find("@", 1)  # a scoped name starts with "@"
        name, version = (text[:at], text[at + 1 :]) if at > 0 else (text, None)
        if not name or len(name) > 214 or not _NPM_NAME.match(name):
            raise TargetError(f"{one_line(raw, 120)} isn't a valid npm package name.")
        if version == "":
            raise TargetError(
                f"{one_line(raw, 120)} is missing the version.", hint=_NPM_VERSION_HINT
            )
        if version is not None and not _NPM_VERSION.match(version):
            raise TargetError(
                f"{one_line(version, 60)} isn't an exact version or a tag.",
                hint=_NPM_VERSION_HINT,
            )
        return PackageSpec("npm", name, version or None)

    name, sep, version = text.partition("==")
    if not sep and "@" in text:  # uvx allows tool@version
        name, sep, version = text.partition("@")
    if sep and not version:
        raise TargetError(
            f"{one_line(raw, 120)} is missing the version.",
            hint=_PYPI_VERSION_HINT,
        )
    if not name or not _PYPI_NAME.match(name):
        raise TargetError(
            f"{one_line(raw, 120)} isn't a valid PyPI package name.",
            hint=_PYPI_VERSION_HINT,
        )
    if version and not _PYPI_VERSION.match(version):
        raise TargetError(
            f"{one_line(version, 60)} isn't an exact version.",
            hint=_PYPI_VERSION_HINT,
        )
    return PackageSpec("pypi", name, version or None)


def parse_package_target(raw: str) -> TargetSpec | None:
    """Parse `npm:...` or `pypi:...`, or return None if raw doesn't start with one."""
    for prefix, ecosystem in (("npm:", "npm"), ("pypi:", "pypi")):
        if raw.startswith(prefix):
            package = parse_package_spec(ecosystem, raw[len(prefix) :], raw)  # type: ignore[arg-type]
            return TargetSpec(kind=ecosystem, raw=raw, package=package)  # type: ignore[arg-type]
    return None


# Options that take a value, so the next word isn't the package.
_NPM_VALUE_OPTIONS = {"--package", "-p", "--registry", "--cache", "--userconfig", "--prefix"}
_PY_VALUE_OPTIONS = {
    "--from",
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--default-index",
    "--constraint",
    "-c",
    "--spec",
    "--pip-args",
}
# Options that name the package itself. "-p" means --package for npx but --python for uvx.
_PACKAGE_OPTIONS: dict[str, set[str]] = {"npm": {"--package", "-p"}, "pypi": {"--from", "--spec"}}


def _runner(words: list[str]) -> tuple[Ecosystem, list[str]] | None:
    if not words:
        return None
    first = PurePosixPath(words[0]).name
    if first in ("npx", "bunx"):
        return "npm", words[1:]
    if first == "uvx":
        return "pypi", words[1:]
    if len(words) >= 2:
        pair = (first, words[1])
        if pair in (("pnpm", "dlx"), ("yarn", "dlx"), ("bun", "x")):
            return "npm", words[2:]
        if pair == ("pipx", "run"):
            return "pypi", words[2:]
        if pair == ("uv", "tool") and len(words) >= 3 and words[2] == "run":
            return "pypi", words[3:]
    return None


def parse_runner_command(raw: str) -> TargetSpec | None:
    """Parse a package runner command like `npx -y <pkg>`, or return None if it isn't one."""
    if _COMPOUND.search(raw):
        return None  # pipes, redirects and the like: a general one-liner
    try:
        words = shlex.split(raw)
    except ValueError:
        return None
    while words and _ENV_ASSIGNMENT.match(words[0]):
        words = words[1:]  # FOO=bar npx ...
    found = _runner(words)
    if found is None:
        return None
    ecosystem, args = found
    value_options = _NPM_VALUE_OPTIONS if ecosystem == "npm" else _PY_VALUE_OPTIONS
    package_options = _PACKAGE_OPTIONS[ecosystem]
    if ecosystem == "npm" and any(a in ("-c", "--call") for a in args):
        return None  # `npx -c '<shell>'` runs a shell command: a general one-liner
    package_text = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            break
        option, eq, inline = arg.partition("=")
        if arg.startswith("-") and option in value_options:
            value = inline if eq else (args[i + 1] if i + 1 < len(args) else "")
            if option in package_options and package_text is None:
                package_text = value
            i += 1 if eq else 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        break
    if package_text is None and i < len(args):
        package_text = args[i]
    if not package_text:
        raise TargetError(f"Couldn't tell which package {one_line(raw, 120)} runs.")
    package = parse_package_spec(ecosystem, package_text, raw)
    return TargetSpec(kind="mcp_command", raw=raw, package=package, command=raw)


# --- fetching --------------------------------------------------------------


def normalize_source_repo(value: Any) -> str | None:
    """A package's declared source repo as `owner/repo` for GitHub, else the URL. Untrusted."""
    url = value.get("url") if isinstance(value, dict) else value
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip()
    m = _SHORTHAND_SOURCE.match(url) or _GITHUB_SOURCE.search(url)
    if m:
        return f"{m['owner']}/{m['repo'].removesuffix('.git')}"
    return one_line(url.removeprefix("git+"), 300)


def _pick_pypi_source(info: dict[str, Any]) -> str | None:
    urls = info.get("project_urls") or {}
    candidates: list[str] = []
    if isinstance(urls, dict):
        preferred = ("source", "source code", "repository", "code", "github")
        ordered = sorted(urls.items(), key=lambda kv: str(kv[0]).lower() not in preferred)
        candidates = [str(v) for _, v in ordered if isinstance(v, str)]
    if isinstance(info.get("home_page"), str):
        candidates.append(info["home_page"])
    for url in candidates:
        if _GITHUB_SOURCE.search(url):
            return normalize_source_repo(url)
    return normalize_source_repo(candidates[0]) if candidates else None


def _verify_npm(got: Downloaded, dist: dict[str, Any], what: str) -> None:
    integrity = dist.get("integrity")
    if isinstance(integrity, str):
        for item in integrity.split():
            algorithm, _, b64 = item.partition("-")
            if algorithm != "sha512":
                continue
            try:
                expected = base64.b64decode(b64, validate=True).hex()
            except (binascii.Error, ValueError):
                continue
            if expected == got.sha512:
                return
            raise FetchError(f"{what} doesn't match the hash the registry published for it.")
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and shasum:
        if shasum.lower() == got.sha1:
            return
        raise FetchError(f"{what} doesn't match the hash the registry published for it.")
    raise FetchError(
        f"The registry didn't publish a hash for {what}, so lookfirst can't verify it."
    )


def fetch_npm(
    spec: TargetSpec, package: PackageSpec, client: httpx.Client, workdir: Path, limits: Limits
) -> ResolvedTarget:
    version = package.version or "latest"
    label = f"The npm package {package.name}" + (f"@{package.version}" if package.version else "")
    meta = get_json(
        client,
        f"{NPM_REGISTRY}/{quote(package.name, safe='@')}/{quote(version)}",
        allowed_hosts=_NPM_HOSTS,
        what=label,
        not_found_hint="Check the package name and version.",
        limits=limits,
    )
    dist = meta.get("dist") if isinstance(meta, dict) else None
    resolved_version = meta.get("version") if isinstance(meta, dict) else None
    if (
        not isinstance(dist, dict)
        or not isinstance(dist.get("tarball"), str)
        or not isinstance(resolved_version, str)
    ):
        raise FetchError(f"The npm registry sent an unexpected answer about {package.name}.")
    archive = workdir / "package.tgz"
    what = f"The npm package {package.name}@{resolved_version}"
    got = download(
        client, dist["tarball"], archive, allowed_hosts=_NPM_HOSTS, what=what, limits=limits
    )
    _verify_npm(got, dist, what)
    src = workdir / "src"
    manifest = unpack(archive, src, limits=limits)
    archive.unlink()
    return ResolvedTarget(
        spec=spec,
        root=src / manifest.root if manifest.root else src,
        resolved=f"{package.name}@{one_line(resolved_version, 60)}",
        source_repo=normalize_source_repo(meta.get("repository")),
        metadata={"npm": meta},
        manifest=manifest,
    )


def _pick_pypi_file(files: list[Any]) -> dict[str, Any] | None:
    """Prefer the source distribution: it holds setup.py, the code that runs at install time."""
    usable = [f for f in files if isinstance(f, dict) and isinstance(f.get("url"), str)]
    for f in usable:
        if f.get("packagetype") == "sdist":
            return f
    wheels = [f for f in usable if f.get("packagetype") == "bdist_wheel"]
    universal = [f for f in wheels if str(f.get("filename", "")).endswith("-none-any.whl")]
    return (universal or wheels or [None])[0]


def fetch_pypi(
    spec: TargetSpec, package: PackageSpec, client: httpx.Client, workdir: Path, limits: Limits
) -> ResolvedTarget:
    path = (
        f"{quote(package.name)}/{quote(package.version)}"
        if package.version
        else quote(package.name)
    )
    label = f"The PyPI package {package.name}" + (f"=={package.version}" if package.version else "")
    data = get_json(
        client,
        f"{PYPI_JSON}/{path}/json",
        allowed_hosts=_PYPI_HOSTS,
        what=label,
        not_found_hint="Check the package name and version.",
        limits=limits,
    )
    info = data.get("info") if isinstance(data, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("version"), str):
        raise FetchError(f"PyPI sent an unexpected answer about {package.name}.")
    name = str(info.get("name") or package.name)
    what = f"The PyPI package {name}=={info['version']}"
    chosen = _pick_pypi_file(data.get("urls") or [])
    if chosen is None:
        raise FetchError(f"{what} has no files to download.")
    expected = (chosen.get("digests") or {}).get("sha256")
    if not isinstance(expected, str) or not expected:
        raise FetchError(f"PyPI didn't publish a hash for {what}, so lookfirst can't verify it.")
    archive = workdir / "package.download"
    got = download(
        client, chosen["url"], archive, allowed_hosts=_PYPI_FILE_HOSTS, what=what, limits=limits
    )
    if got.sha256 != expected.lower():
        raise FetchError(f"{what} doesn't match the hash PyPI published for it.")
    src = workdir / "src"
    manifest = unpack(archive, src, limits=limits)
    archive.unlink()
    return ResolvedTarget(
        spec=spec,
        root=src / manifest.root if manifest.root else src,
        resolved=f"{one_line(name, 120)}=={one_line(info['version'], 60)}",
        source_repo=_pick_pypi_source(info),
        metadata={"pypi": {"info": info, "file": chosen}},
        manifest=manifest,
    )


def fetch_package(
    spec: TargetSpec, client: httpx.Client, workdir: Path, limits: Limits
) -> ResolvedTarget:
    package = spec.package
    if package is None:
        raise TargetError(f"{one_line(spec.raw, 120)} isn't a package.")
    fetch = fetch_npm if package.ecosystem == "npm" else fetch_pypi
    target = fetch(spec, package, client, workdir, limits)
    if spec.kind == "mcp_command" and target.resolved:
        target.resolved = f"{package.ecosystem}:{target.resolved}"
    return target

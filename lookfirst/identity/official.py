"""The official sources of popular projects (lookfirst/registry/official.yaml)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib.resources import files

import yaml

from lookfirst.identity.names import squash


@dataclass(frozen=True)
class OfficialProject:
    name: str
    repos: tuple[str, ...]  # as written ("Comfy-Org/ComfyUI"); compare lowercased
    orgs: tuple[str, ...]  # lowercase
    keywords: tuple[str, ...]  # squashed
    domains: tuple[str, ...]  # lowercase
    npm: tuple[str, ...]
    npm_scopes: tuple[str, ...]
    pypi: tuple[str, ...]  # lowercase, normalized
    pypi_orgs: tuple[str, ...]  # PyPI organizations, lowercase
    installers: tuple[str, ...]

    @property
    def canonical(self) -> str:
        return self.repos[0]

    def owns_repo(self, full_name: str) -> bool:
        lower = full_name.lower()
        return lower in {r.lower() for r in self.repos} or lower.split("/", 1)[0] in self.orgs

    def owns_host(self, host: str) -> bool:
        host = host.lower().removeprefix("www.")
        return any(host == d or host.endswith("." + d) for d in self.domains)

    def owns_package(self, ecosystem: str, name: str) -> bool:
        if ecosystem == "npm":
            return name in self.npm or any(
                name.startswith(scope + "/") for scope in self.npm_scopes
            )
        return _pypi_normal(name) in self.pypi

    def owns_pypi_org(self, org: str) -> bool:
        return org.lower() in self.pypi_orgs


def _pypi_normal(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _tuple(value: object) -> tuple[str, ...]:
    return tuple(str(v) for v in value) if isinstance(value, list) else ()


@cache
def load_official() -> tuple[OfficialProject, ...]:
    text = files("lookfirst.registry").joinpath("official.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    projects = []
    for entry in data.get("projects", []):
        packages = entry.get("packages") or {}
        projects.append(
            OfficialProject(
                name=str(entry["name"]),
                repos=_tuple(entry.get("repos")),
                orgs=tuple(o.lower() for o in _tuple(entry.get("orgs"))),
                keywords=tuple(squash(k) for k in _tuple(entry.get("keywords"))),
                domains=tuple(d.lower() for d in _tuple(entry.get("domains"))),
                npm=_tuple(packages.get("npm")),
                npm_scopes=_tuple(packages.get("npm_scopes")),
                pypi=tuple(_pypi_normal(p) for p in _tuple(packages.get("pypi"))),
                pypi_orgs=tuple(o.lower() for o in _tuple(packages.get("pypi_orgs"))),
                installers=_tuple(entry.get("installers")),
            )
        )
    return tuple(projects)


def project_owning_repo(full_name: str) -> OfficialProject | None:
    return next((p for p in load_official() if p.owns_repo(full_name)), None)


def project_owning_package(ecosystem: str, name: str) -> OfficialProject | None:
    return next((p for p in load_official() if p.owns_package(ecosystem, name)), None)


def project_with_pypi_org(org: str) -> OfficialProject | None:
    return next((p for p in load_official() if p.owns_pypi_org(org)), None)


def projects_named_in(*names: str) -> list[OfficialProject]:
    """Projects whose keyword appears in any of these names (a repo, owner or host)."""
    squashed = [squash(n) for n in names if n]
    return [p for p in load_official() if any(k in s for k in p.keywords for s in squashed)]

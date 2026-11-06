"""What a target is before and after it's fetched."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from lookfirst.core.archive import ArchiveManifest
from lookfirst.verdict.schema import Target, TargetKind

Ecosystem = Literal["npm", "pypi"]


@dataclass(frozen=True)
class PackageSpec:
    ecosystem: Ecosystem
    name: str
    version: str | None = None  # an exact version (or an npm tag); None means the latest


@dataclass(frozen=True)
class TargetSpec:
    """A parsed target. Nothing has been fetched yet."""

    kind: TargetKind
    raw: str
    owner: str | None = None  # github
    repo: str | None = None  # github
    ref: str | None = None  # github: branch, tag or commit
    path: Path | None = None  # local
    package: PackageSpec | None = None  # npm, pypi, mcp_command
    command: str | None = None  # oneliner, mcp_command


@dataclass
class ResolvedTarget:
    """A target that's been fetched (or found) and is ready to read. Never run."""

    spec: TargetSpec
    root: Path | None  # the folder to read; None for a one-liner on its own
    resolved: str | None
    source_repo: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)  # raw registry data, untrusted
    manifest: ArchiveManifest | None = None

    def to_schema(self) -> Target:
        return Target(
            kind=self.spec.kind,
            raw=self.spec.raw,
            resolved=self.resolved,
            source_repo=self.source_repo,
        )

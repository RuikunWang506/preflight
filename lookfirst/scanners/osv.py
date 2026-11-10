"""osv-scanner: known vulnerabilities and known malware in the packages a project pins.

osv-scanner reads lockfiles and manifests and asks osv.dev about each package version it
finds: names and versions only, never code. lookfirst always runs it with
- --no-resolve: only the versions the files pin. Guessing unpinned versions online is
  slow (93 seconds on one repo) and isn't what an install would get anyway.
- --no-call-analysis=all: call analysis builds the project, and for Rust runs its build
  scripts. lookfirst never runs a target's code on this computer.

Exit codes: 0 nothing found, 1 vulnerabilities found, 128 nothing it could read.
Known malware shows up as OpenSSF "MAL-" entries or as advisories tagged CWE-506
("embedded malicious code"). RustSec notices that a crate is unmaintained or unsound are
"informational", not vulnerabilities, and are left out.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lookfirst.core.textsafe import one_line
from lookfirst.scanners.base import ToolFailed, ToolOutput, last_line, run_tool

ARGS = ["scan", "source", "-r", "--no-resolve", "--no-call-analysis=all", "--format", "json"]
NOTHING_TO_SCAN = 128
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_FOUND = re.compile(r"\bfound (\d+) packages?\b")
_NETWORK = re.compile(
    r"osv\.dev|dial tcp|no such host|connection refused|i/o timeout|TLS handshake|"
    r"network is unreachable|context deadline",
    re.IGNORECASE,
)
# Names and versions written into the one-line lockfile for a package target.
_NPM_NAME = re.compile(r"^(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+$")
_PYPI_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,99}$")


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    malware: bool
    score: float | None  # the worst CVSS base score osv.dev knows for it
    fixed: tuple[str, ...]  # versions that fix it

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"


@dataclass(frozen=True)
class Hit:
    """A package version osv.dev has advisories for, and the file that pins it."""

    ecosystem: str
    name: str
    version: str
    lockfile: str  # relative to the scanned folder
    advisories: tuple[Advisory, ...]

    @property
    def malware(self) -> tuple[Advisory, ...]:
        return tuple(a for a in self.advisories if a.malware)

    @property
    def vulnerabilities(self) -> tuple[Advisory, ...]:
        return tuple(a for a in self.advisories if not a.malware)

    @property
    def worst(self) -> float | None:
        scores = [a.score for a in self.vulnerabilities if a.score is not None]
        return max(scores) if scores else None


@dataclass
class OsvRun:
    hits: list[Hit]
    asked_about: int  # package versions osv-scanner sent to osv.dev
    nothing_to_scan: bool = False


def scan(executable: Path, folder: Path) -> OsvRun:
    """Every lockfile and manifest in the folder, including subfolders."""
    return _run(executable, folder, folder)


def scan_package(
    executable: Path, ecosystem: str, name: str, version: str, tarball: str | None
) -> OsvRun | None:
    """The package version itself, through a one-line lockfile. None if its name or version
    can't be written safely."""
    if not _VERSION.match(version):
        return None
    with tempfile.TemporaryDirectory(prefix="lookfirst-osv-") as tmp:
        folder = Path(tmp)
        if ecosystem == "pypi" and _PYPI_NAME.match(name):
            (folder / "requirements.txt").write_text(f"{name}=={version}\n")
        elif ecosystem == "npm" and _NPM_NAME.match(name):
            entry: dict[str, Any] = {"version": version}
            if tarball and tarball.startswith("https://registry.npmjs.org/"):
                entry["resolved"] = tarball
            lock = {
                "name": "lookfirst-package-lookup",
                "version": "0.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {"name": "lookfirst-package-lookup"},
                    f"node_modules/{name}": entry,
                },
            }
            (folder / "package-lock.json").write_text(json.dumps(lock))
        else:
            return None
        return _run(executable, folder, folder)


def _run(executable: Path, folder: Path, root: Path) -> OsvRun:
    out = run_tool(executable, [*ARGS, str(folder)])
    if out.returncode == NOTHING_TO_SCAN:
        return OsvRun([], 0, nothing_to_scan=True)
    if out.returncode not in (0, 1):
        raise ToolFailed(_failure(out))
    asked = sum(int(n) for n in _FOUND.findall(out.stderr))
    if not out.stdout.strip():
        return OsvRun([], asked)
    try:
        data = json.loads(out.stdout)
    except ValueError as exc:
        raise ToolFailed("its output couldn't be read") from exc
    return OsvRun(parse(data, root), asked)


def _failure(out: ToolOutput) -> str:
    if _NETWORK.search(out.stderr):
        return "couldn't reach osv.dev"
    detail = one_line(last_line(out.stderr), 120)
    return f"stopped with an error ({detail})" if detail else "stopped with an error"


def parse(data: Any, root: Path) -> list[Hit]:
    hits: list[Hit] = []
    results = data.get("results") if isinstance(data, dict) else None
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        source = (result.get("source") or {}).get("path")
        lockfile = _relative(str(source or ""), root)
        for pkg in result.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            hit = _hit(pkg, lockfile)
            if hit is not None:
                hits.append(hit)
    return hits


def _hit(pkg: dict, lockfile: str) -> Hit | None:
    info = pkg.get("package") or {}
    name, version = str(info.get("name") or ""), str(info.get("version") or "")
    ecosystem = str(info.get("ecosystem") or "")
    if not name:
        return None
    records = {
        v["id"]: v for v in pkg.get("vulnerabilities") or [] if isinstance(v, dict) and "id" in v
    }
    groups = pkg.get("groups") or [{"ids": [i]} for i in records]
    advisories = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        ids = [i for i in group.get("ids") or [] if isinstance(i, str) and _ID.match(i)]
        if not ids:
            continue
        members = [records[i] for i in ids if i in records]
        malware = any(i.startswith("MAL-") for i in ids) or any(map(_malware, members))
        if not malware and members and all(map(_informational, members)):
            continue  # a RustSec notice ("unmaintained", "unsound"), not a vulnerability
        advisories.append(
            Advisory(
                id=_lead(ids),
                summary=_summary(members),
                malware=malware,
                score=_score(group.get("max_severity")),
                fixed=_fixed(members, name),
            )
        )
    return Hit(ecosystem, name, version, lockfile, tuple(advisories)) if advisories else None


def _lead(ids: list[str]) -> str:
    """The id to show: an OpenSSF malware entry, then a GitHub advisory, then the first."""
    for prefix in ("MAL-", "GHSA-"):
        for i in ids:
            if i.startswith(prefix):
                return i
    return ids[0]


def _malware(record: dict) -> bool:
    cwes = (record.get("database_specific") or {}).get("cwe_ids") or []
    return str(record.get("id", "")).startswith("MAL-") or "CWE-506" in cwes


def _informational(record: dict) -> bool:
    """RustSec marks notices that aren't vulnerabilities as informational."""
    for affected in record.get("affected") or []:
        specific = affected.get("database_specific") if isinstance(affected, dict) else None
        if isinstance(specific, dict) and specific.get("informational"):
            return True
    return False


def _summary(members: list[dict]) -> str:
    for record in members:
        text = record.get("summary") or str(record.get("details") or "").strip().split("\n")[0]
        if text:
            return one_line(str(text), 120)
    return ""


def _score(value: object) -> float | None:
    try:
        score = float(str(value))
    except ValueError:
        return None
    return score if 0 <= score <= 10 else None


def _fixed(members: list[dict], name: str) -> tuple[str, ...]:
    found: list[str] = []
    for record in members:
        for affected in record.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            package = affected.get("package") or {}
            if str(package.get("name", "")).lower() not in (name.lower(), ""):
                continue
            for rng in affected.get("ranges") or []:
                if not isinstance(rng, dict) or rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                for event in rng.get("events") or []:
                    fixed = event.get("fixed") if isinstance(event, dict) else None
                    if isinstance(fixed, str) and _VERSION.match(fixed) and fixed not in found:
                        found.append(fixed)
    return tuple(sorted(found, key=version_key)[:3])


def version_key(version: str) -> tuple[int, ...]:
    """Dotted numbers in order ("2.9" before "2.10"); anything else sorts as 0."""
    return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.+-]", version))


def _relative(path: str, root: Path) -> str:
    if not path:
        return "(unknown file)"
    try:
        rel = Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
    except ValueError:
        return one_line(Path(path).name, 200)
    return one_line(rel.as_posix(), 200)

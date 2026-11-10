"""The package check: run the outside scanners and turn what they report into findings.

How their results count (M4 decisions, docs/PLAN-v0.1.md):
1. Known malware in a dependency is Don't run, but only when the normal install would
   fetch it from the registry. In example, test or fixture folders, or when the
   project's own local package just shares the name, it's worth knowing.
2. Ordinary known vulnerabilities are one worth-knowing summary.
3. GuardDog's patterns are worth knowing at most; those in tests, examples, docs and dev
   scripts are only counted.
4. An npm or PyPI package is also looked up itself: a version reported as malware is
   Don't run.
"""

from __future__ import annotations

import re
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from lookfirst.core.textsafe import one_line
from lookfirst.scanners import base, guarddog, osv
from lookfirst.scanners.base import ToolFailed
from lookfirst.scanners.lockfiles import fetched_from_registry
from lookfirst.static.files import exists
from lookfirst.static.rules_catalog import rule
from lookfirst.targets.models import ResolvedTarget
from lookfirst.verdict.schema import CheckKind, Evidence, Finding, NotChecked, ToolRun

OSV = "osv-scanner"
GUARDDOG = "GuardDog"
OSV_WHAT = "Known vulnerabilities and malware in its packages"
GUARDDOG_WHAT = "Code patterns that malware uses"
OSV_HINT = "brew install osv-scanner"
# Folders that a normal install doesn't use: their lockfiles and code are only counted.
ELSEWHERE = frozenset(
    {
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "test",
        "tests",
        "testing",
        "__tests__",
        "spec",
        "specs",
        "fixture",
        "fixtures",
        "testdata",
        "test_data",
        "doc",
        "docs",
        "documentation",
        "website",
        "benchmark",
        "benchmarks",
        "bench",
        "e2e",
        "playground",
        "playgrounds",
        ".github",
        "devscripts",
    }
)
# Manifests whose dependency versions are only chosen at install time without a lockfile.
_MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "Cargo.toml", "Gemfile")
MAX_PACKAGE_EVIDENCE = 50
MAX_PATTERN_EVIDENCE = 10


_TEST_FILE = re.compile(r"(?:^|[_.-])tests?(?:[_.-]|$)", re.IGNORECASE)


def elsewhere(path: str) -> bool:
    """Whether a file sits in a folder a normal install doesn't use, or is named for tests
    ("requirements-test.txt", "syntax_test_requirements.txt")."""
    parts = PurePosixPath(path).parts
    if any(part.lower() in ELSEWHERE for part in parts[:-1]):
        return True
    return bool(parts) and bool(_TEST_FILE.search(parts[-1]))


def count(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n:,} {singular if n == 1 else (plural or singular + 's')}"


@dataclass
class PackageOutcome:
    findings: list[Finding] = field(default_factory=list)
    ran: bool = False
    gaps: list[NotChecked] = field(default_factory=list)
    tools: list[ToolRun] = field(default_factory=list)


def run_package_check(target: ResolvedTarget) -> PackageOutcome:
    out = PackageOutcome()
    root = target.root
    if root is None:
        return out  # a one-liner on its own: nothing to scan
    osv_exe = base.locate("osv-scanner")
    gd_exe = base.locate("guarddog")
    ecosystems = guarddog.ecosystems_for(target)
    lookup = _package_lookup(target)
    with ThreadPoolExecutor(max_workers=4) as pool:
        folder_job = pool.submit(osv.scan, osv_exe, root) if osv_exe else None
        lookup_job = pool.submit(osv.scan_package, osv_exe, *lookup) if osv_exe and lookup else None
        gd_jobs = (
            {eco: pool.submit(guarddog.scan, gd_exe, eco, root) for eco in ecosystems}
            if gd_exe
            else {}
        )
        osv_version = base.tool_version(osv_exe) if osv_exe else None
        gd_version = base.tool_version(gd_exe) if gd_exe and ecosystems else None

    if osv_exe is None:
        out.gaps.append(_gap(OSV_WHAT, "osv-scanner isn't installed", OSV_HINT))
        out.tools.append(ToolRun(name=OSV, status="not_installed"))
    else:
        _osv_results(out, target, folder_job, lookup_job, osv_version)

    if ecosystems and gd_exe is None:
        out.gaps.append(_gap(GUARDDOG_WHAT, "GuardDog isn't installed", guarddog.INSTALL_HINT))
        out.tools.append(ToolRun(name=GUARDDOG, status="not_installed"))
    elif ecosystems:
        _guarddog_results(out, gd_jobs, gd_version)
    return out


def _gap(what: str, reason: str, how: str | None = None) -> NotChecked:
    return NotChecked(check=CheckKind.package, what=what, reason=reason, how_to_enable=how)


def _package_lookup(target: ResolvedTarget) -> tuple[str, str, str, str | None] | None:
    """(ecosystem, name, version, tarball) of an npm or PyPI target, from its registry."""
    if "npm" in target.metadata:
        meta = target.metadata["npm"]
        dist = meta.get("dist") if isinstance(meta, dict) else None
        tarball = dist.get("tarball") if isinstance(dist, dict) else None
        name, version = meta.get("name"), meta.get("version")
        if isinstance(name, str) and isinstance(version, str):
            return "npm", name, version, tarball if isinstance(tarball, str) else None
    if "pypi" in target.metadata:
        info = (target.metadata["pypi"] or {}).get("info") or {}
        name, version = info.get("name"), info.get("version")
        if isinstance(name, str) and isinstance(version, str):
            return "pypi", name, version, None
    return None


def _osv_results(
    out: PackageOutcome,
    target: ResolvedTarget,
    folder_job: Future | None,
    lookup_job: Future | None,
    version: str | None,
) -> None:
    root = target.root
    if root is None:
        return
    asked, failures, nothing = 0, [], False
    for job, is_lookup in ((folder_job, False), (lookup_job, True)):
        if job is None:
            continue
        try:
            run = job.result()
        except ToolFailed as exc:
            failures.append(str(exc))
            continue
        out.ran = True
        if run is None:
            continue
        asked += run.asked_about
        if is_lookup:
            out.findings += _package_itself(run.hits, version)
        else:
            nothing = run.nothing_to_scan
            out.findings += _osv_findings(run.hits, root, version)
    if failures:
        out.gaps.append(_gap(OSV_WHAT, f"osv-scanner {failures[0]}"))
    if not out.ran:
        out.tools.append(ToolRun(name=OSV, version=version, status="failed", detail=failures[0]))
        return
    detail = (
        f"asked osv.dev about {count(asked, 'package version')} (names and versions only)"
        if asked
        else "found no lockfiles to check"
    )
    status = "nothing_to_scan" if nothing and lookup_job is None else "ran"
    out.tools.append(ToolRun(name=OSV, version=version, status=status, detail=detail))
    manifest = any(exists(root, m) for m in _MANIFESTS)
    if nothing and target.spec.kind in ("github", "local") and manifest:
        out.gaps.append(
            _gap(
                "Which package versions it installs",
                "it has no lockfile, so they're only chosen when you install",
            )
        )


def _finding(
    rule_id: str, evidence: list[Evidence], source: str, version: str | None, **values: Any
) -> Finding:
    r = rule(rule_id)
    return Finding(
        id=r.id,
        check=r.check,
        severity=r.severity,
        title=one_line(r.title.format(**values), 90),
        evidence=evidence,
        explanation=r.explanation,
        recommendation=r.recommendation,
        source=source,
        source_version=version,
    )


def _package_data(hit: osv.Hit) -> dict[str, str | int | float | bool]:
    return {
        "package": one_line(hit.name, 200),
        "version": one_line(hit.version, 100),
        "ecosystem": one_line(hit.ecosystem, 40),
    }


def _osv_findings(hits: list[osv.Hit], root: Any, version: str | None) -> list[Finding]:
    findings: list[Finding] = []
    buckets: dict[str, list[Evidence]] = {
        "known_malware": [],
        "malware_name_local": [],
        "known_malware_elsewhere": [],
    }
    # One line per package version in each lockfile, with all its malware advisories.
    merged: dict[tuple[str, str, str], tuple[osv.Hit, list[osv.Advisory]]] = {}
    for hit in hits:
        for advisory in hit.malware:
            _, found = merged.setdefault((hit.lockfile, hit.name, hit.version), (hit, []))
            if advisory.id not in {a.id for a in found}:
                found.append(advisory)
    for hit, advisories in merged.values():
        if elsewhere(hit.lockfile):
            bucket = "known_malware_elsewhere"
        elif fetched_from_registry(root, hit.lockfile, hit.name, hit.version) is False:
            bucket = "malware_name_local"
        else:
            bucket = "known_malware"
        # An OpenSSF entry ("Malicious code in ...") says it most plainly.
        lead = min(advisories, key=lambda a: (not a.id.startswith("MAL-"), a.id))
        summary = lead.summary or "reported as malware"
        buckets[bucket].append(
            Evidence(
                type="file",
                ref=hit.lockfile,
                data={
                    "what": one_line(f"{hit.name} {hit.version}: {summary}", 200),
                    **_package_data(hit),
                    "advisories": ", ".join(
                        [lead.id] + [a.id for a in advisories if a.id != lead.id]
                    ),
                },
            )
        )
    for bucket, evidence in buckets.items():
        if evidence:
            findings.append(
                _finding(f"package.{bucket}", evidence[:MAX_PACKAGE_EVIDENCE], OSV, version)
            )

    main: dict[tuple[str, str, str], list[osv.Hit]] = {}
    other: dict[tuple[str, str, str], list[osv.Hit]] = {}
    for hit in hits:
        if hit.vulnerabilities:
            group = other if elsewhere(hit.lockfile) else main
            group.setdefault((hit.ecosystem, hit.name, hit.version), []).append(hit)
    other = {k: v for k, v in other.items() if k not in main}
    for rule_id, group in (
        ("package.known_vulnerabilities", main),
        ("package.known_vulnerabilities_elsewhere", other),
    ):
        if group:
            findings.append(
                _finding(
                    rule_id,
                    _vulnerability_evidence(group),
                    OSV,
                    version,
                    packages=count(len(group), "package version"),
                )
            )
    return findings


def _vulnerability_evidence(group: dict[tuple[str, str, str], list[osv.Hit]]) -> list[Evidence]:
    rows = []
    for hits in group.values():
        advisories: dict[str, osv.Advisory] = {}
        for hit in hits:
            for a in hit.vulnerabilities:
                advisories.setdefault(a.id, a)
        scores = [a.score for a in advisories.values() if a.score is not None]
        worst = max(scores) if scores else None
        fixed: list[str] = []
        for a in advisories.values():
            fixed += [f for f in a.fixed if f not in fixed]
        fixed.sort(key=osv.version_key)
        rows.append((hits, list(advisories.values()), worst, fixed))
    rows.sort(key=lambda r: (-(r[2] if r[2] is not None else -1), r[0][0].name))
    evidence = []
    for hits, advisories, worst, fixed in rows[:MAX_PACKAGE_EVIDENCE]:
        hit = hits[0]
        n = count(len(advisories), "advisory", "advisories")
        what = f"{hit.name} {hit.version}: {n}"
        if worst is not None:
            what += f", worst score {worst:g}"
        if fixed:
            what += f", fixed in {', '.join(fixed[:3])}"
        ids = [a.id for a in sorted(advisories, key=lambda a: -(a.score or 0))]
        data: dict[str, str | int | float | bool] = {
            "what": one_line(what, 200),
            **_package_data(hit),
            "advisories": ", ".join(ids[:5]) + (" …" if len(ids) > 5 else ""),
        }
        if worst is not None:
            data["worst"] = worst
        if fixed:
            data["fixed"] = one_line(", ".join(fixed[:3]), 100)
        if len(hits) > 1:
            data["files"] = len({h.lockfile for h in hits})
        evidence.append(Evidence(type="file", ref=hit.lockfile, data=data))
    if len(rows) > MAX_PACKAGE_EVIDENCE:
        last = evidence[-1]
        evidence[-1] = last.model_copy(
            update={"data": {**last.data, "more": len(rows) - MAX_PACKAGE_EVIDENCE}}
        )
    return evidence


def _package_itself(hits: list[osv.Hit], version: str | None) -> list[Finding]:
    """What osv.dev knows about the package version the user asked about."""
    advisories: dict[str, osv.Advisory] = {}
    for hit in hits:
        for a in hit.advisories:
            advisories.setdefault(a.id, a)
    findings = []
    malware = [a for a in advisories.values() if a.malware]
    if malware:
        findings.append(
            _finding(
                "package.target_is_malware",
                [_advisory_evidence(a) for a in malware[:10]],
                OSV,
                version,
            )
        )
    vulns = sorted((a for a in advisories.values() if not a.malware), key=lambda a: -(a.score or 0))
    if vulns:
        findings.append(
            _finding(
                "package.target_vulnerable",
                [_advisory_evidence(a) for a in vulns[:10]],
                OSV,
                version,
                vulnerabilities=count(len(vulns), "known vulnerability", "known vulnerabilities"),
            )
        )
    return findings


def _advisory_evidence(a: osv.Advisory) -> Evidence:
    what = f"{a.id}: {a.summary}" if a.summary else a.id
    data: dict[str, str | int | float | bool] = {"what": one_line(what, 200), "advisories": a.id}
    if a.score is not None:
        data["worst"] = a.score
    if a.fixed:
        data["fixed"] = one_line(", ".join(a.fixed), 100)
    return Evidence(type="url", ref=a.url, data=data)


def _guarddog_results(out: PackageOutcome, jobs: dict[str, Future], version: str | None) -> None:
    risks: dict[tuple[str, str, int | None], guarddog.Risk] = {}
    failures = []
    for job in jobs.values():
        try:
            for r in job.result():
                risks.setdefault((r.rule, r.path, r.line), r)
        except ToolFailed as exc:
            failures.append(str(exc))
    if failures:
        out.gaps.append(_gap(GUARDDOG_WHAT, f"GuardDog {failures[0]}"))
    if len(failures) == len(jobs):
        out.tools.append(
            ToolRun(name=GUARDDOG, version=version, status="failed", detail=failures[0])
        )
        return
    out.ran = True
    out.tools.append(
        ToolRun(
            name=GUARDDOG, version=version, status="ran", detail="read the code on this computer"
        )
    )
    found = list(risks.values())
    main = [r for r in found if not elsewhere(r.path)]
    other = [r for r in found if elsewhere(r.path)]
    if main:
        evidence = [_risk_evidence(r) for r in main[:MAX_PATTERN_EVIDENCE]]
        extra: dict[str, str | int | float | bool] = {}
        if len(main) > MAX_PATTERN_EVIDENCE:
            extra["more"] = len(main) - MAX_PATTERN_EVIDENCE
        if other:
            extra["elsewhere"] = len(other)
        if extra:
            evidence[-1] = evidence[-1].model_copy(update={"data": {**evidence[-1].data, **extra}})
        out.findings.append(
            _finding(
                "package.code_patterns",
                evidence,
                GUARDDOG,
                version,
                patterns=count(len(main), "code pattern"),
            )
        )
    elif other:
        out.findings.append(
            _finding(
                "package.code_patterns_elsewhere",
                [_risk_evidence(r) for r in other[:5]],
                GUARDDOG,
                version,
                patterns=count(len(other), "code pattern"),
            )
        )


def _risk_evidence(r: guarddog.Risk) -> Evidence:
    return Evidence(
        type="file",
        ref=r.path,
        line=r.line,
        excerpt=r.code or None,
        data={"what": f"The code {r.meaning}", "guarddog_rule": r.rule},
    )

"""Shared pieces for the static checks: where code came from, and collecting findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from lookfirst.core.textsafe import one_line
from lookfirst.static.rules_catalog import rule
from lookfirst.verdict.schema import Evidence, Finding, Severity

MAX_EVIDENCE = 5


@dataclass(frozen=True)
class Origin:
    """Where a piece of code came from, and when it would run."""

    path: str  # repo-relative path, a URL for a remote script, or "command"
    line: int  # line in that file where this code starts (1-based)
    runs: str  # plain English, e.g. "when you run npm install"
    remote: bool = False
    depth: int = 0  # how many downloads deep a remote script is


@dataclass(frozen=True)
class Snippet:
    text: str
    origin: Origin
    root_command: bool = False  # the one-liner the user asked lookfirst to check
    report_unparsed: bool = True  # False for commands guessed from other languages' code


@dataclass
class _Pending:
    rule_id: str
    path: str
    evidence: list[Evidence] = field(default_factory=list)
    more: int = 0


class Collector:
    """Collects findings. The same rule in the same file becomes one finding with several
    pieces of evidence, so a script with ten bad lines isn't ten separate findings."""

    def __init__(self) -> None:
        self._pending: dict[tuple[str, str], _Pending] = {}
        self._seen: set[tuple[str, str, int | None, str | None]] = set()

    def add(
        self,
        rule_id: str,
        *,
        path: str,
        line: int | None = None,
        excerpt: str | None = None,
        runs: str | None = None,
        data: dict[str, str | int | float | bool] | None = None,
        group: str | None = None,
    ) -> None:
        """Add evidence for a rule. Evidence for the same rule merges per file, or per group if
        one is given (for findings that list several files)."""
        rule(rule_id)  # fail fast on a typo in a rule id
        key = (rule_id, path, line, excerpt)
        if key in self._seen:
            return
        self._seen.add(key)
        bucket = group or path
        pending = self._pending.setdefault((rule_id, bucket), _Pending(rule_id, bucket))
        if len(pending.evidence) >= MAX_EVIDENCE:
            pending.more += 1
            return
        extra = dict(data or {})
        if runs:
            extra["runs"] = runs
        if path == "command":
            kind = "command"
        elif path.startswith(("https://", "http://")):
            kind = "url"
        else:
            kind = "file"
        pending.evidence.append(
            Evidence(
                type=kind,
                ref=path if path != "command" else "the command",
                line=line,
                excerpt=one_line(excerpt, 200) if excerpt else None,
                data=extra,
            )
        )

    def has(self, rule_id: str) -> bool:
        return any(p.rule_id == rule_id for p in self._pending.values())

    def findings(self) -> list[Finding]:
        out = []
        for pending in self._pending.values():
            r = rule(pending.rule_id)
            evidence = pending.evidence
            if pending.more and evidence:
                last = evidence[-1]
                evidence = [
                    *evidence[:-1],
                    last.model_copy(update={"data": {**last.data, "more": pending.more}}),
                ]
            out.append(
                Finding(
                    id=r.id,
                    check=r.check,
                    severity=r.severity,
                    title=r.title,
                    evidence=evidence,
                    explanation=r.explanation,
                    recommendation=r.recommendation,
                )
            )
        return out


def worst(findings: list[Finding]) -> Severity | None:
    order = [Severity.critical, Severity.high, Severity.medium, Severity.info]
    present = {f.severity for f in findings}
    return next((s for s in order if s in present), None)

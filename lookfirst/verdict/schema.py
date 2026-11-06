"""The findings schema: what a check reports, and the report lookfirst outputs.

This is a public contract. The JSON form (`lookfirst check --json`) is what
agents and the MCP server read, so every change bumps SCHEMA_VERSION and the
generated file in docs/schema/.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "1.0"
DISCLAIMER = "lookfirst lowers risk; it doesn't guarantee safety."


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    info = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.info: 3,
}


class CheckKind(StrEnum):
    identity = "identity"
    install_path = "install_path"
    agent_config = "agent_config"
    injection = "injection"
    package = "package"
    sandbox = "sandbox"


class VerdictLabel(StrEnum):
    looks_ok = "looks_ok"
    caution = "caution"
    dont_run = "dont_run"


VERDICT_TEXT: dict[VerdictLabel, str] = {
    VerdictLabel.looks_ok: "Looks OK",
    VerdictLabel.caution: "Caution",
    VerdictLabel.dont_run: "Don't run",
}

EXIT_CODES: dict[VerdictLabel, int] = {
    VerdictLabel.looks_ok: 0,
    VerdictLabel.caution: 10,
    VerdictLabel.dont_run: 20,
}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Evidence(_Model):
    """One piece of evidence. Everything in it may come from the target, so it's untrusted."""

    type: Literal["url", "file", "command", "network", "process", "filesystem", "metric"]
    ref: str = Field(min_length=1, max_length=2048)  # URL, repo-relative path, or host:port
    line: int | None = Field(default=None, ge=1)
    excerpt: str | None = Field(default=None, max_length=300)
    data: dict[str, str | int | float | bool] = Field(default_factory=dict)


class Finding(_Model):
    id: str = Field(pattern=r"^[a-z_]+\.[a-z0-9_]+$")  # e.g. "identity.readme_copy"
    check: CheckKind
    severity: Severity
    title: str = Field(min_length=1, max_length=90)  # from our templates, never repo text
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    source: str = "lookfirst"  # or the tool that found it, e.g. "osv-scanner"
    source_version: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def _serious_findings_have_evidence(self) -> Finding:
        if self.severity in (Severity.critical, Severity.high) and not self.evidence:
            raise ValueError("critical and high findings need at least one piece of evidence")
        return self


TargetKind = Literal["github", "local", "oneliner", "npm", "pypi", "mcp_command"]


class Target(_Model):
    kind: TargetKind
    raw: str  # exactly what was asked for
    resolved: str | None = None  # "owner/repo@<sha>", "name@1.2.3", "name==1.2.3", a folder path
    source_repo: str | None = None  # a package's declared source repo, untrusted


class IdentityResult(_Model):
    status: Literal["original", "fork_benign", "unrelated", "likely_impersonation"]
    original: str | None = None  # "owner/repo"
    confidence: float = Field(ge=0, le=1)
    top_signals: list[str] = Field(default_factory=list, max_length=3)  # finding ids


class SandboxRun(_Model):
    command: str
    image_digest: str
    duration_s: float = Field(ge=0)
    exit_code: int | None = None
    timed_out: bool = False
    network: Literal["sinkhole", "passthrough", "offline"]


class NotChecked(_Model):
    check: CheckKind
    what: str  # plain-English name of the check
    reason: str  # "not built yet", "not requested", "GuardDog isn't installed"
    how_to_enable: str | None = None  # "add --sandbox", "uv tool install --python 3.12 guarddog"


class Report(_Model):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    tool_version: str
    generated_at: datetime
    target: Target
    verdict: VerdictLabel
    exit_code: Literal[0, 10, 20]
    summary: list[str] = Field(default_factory=list, max_length=3)  # finding titles
    findings: list[Finding] = Field(default_factory=list)  # most severe first
    identity: IdentityResult | None = None
    sandbox: SandboxRun | None = None
    checked: list[CheckKind] = Field(default_factory=list)
    not_checked: list[NotChecked] = Field(default_factory=list)
    disclaimer: str = DISCLAIMER

    @model_validator(mode="after")
    def _exit_code_matches_verdict(self) -> Report:
        if self.exit_code != EXIT_CODES[self.verdict]:
            raise ValueError(f"exit_code {self.exit_code} doesn't match verdict {self.verdict}")
        return self


def report_json_schema() -> dict:
    """The JSON Schema for Report, as published in docs/schema/."""
    return Report.model_json_schema()

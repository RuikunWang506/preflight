import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from lookfirst.verdict.schema import (
    SCHEMA_VERSION,
    CheckKind,
    Evidence,
    Finding,
    Report,
    Severity,
    Target,
    VerdictLabel,
    report_json_schema,
)

SCHEMA_FILE = Path(__file__).parent.parent / "docs" / "schema" / f"report-{SCHEMA_VERSION}.json"


def finding(severity: Severity = Severity.info, *, evidence: bool = True, **kwargs) -> Finding:
    fields = {
        "id": "identity.readme_copy",
        "check": CheckKind.identity,
        "severity": severity,
        "title": "README is 94% identical to original-owner/viral-tool",
        "evidence": [Evidence(type="url", ref="https://github.com/original-owner/viral-tool")]
        if evidence
        else [],
        "explanation": "Impersonation campaigns copy a popular project's README into a new repo.",
        "recommendation": "Use the original repo unless you know why this copy exists.",
    }
    fields.update(kwargs)
    return Finding(**fields)


def report(**kwargs) -> Report:
    fields = {
        "tool_version": "0.1.0",
        "generated_at": datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
        "target": Target(kind="github", raw="o/r", resolved="o/r@" + "a" * 40),
        "verdict": VerdictLabel.looks_ok,
        "exit_code": 0,
    }
    fields.update(kwargs)
    return Report(**fields)


@pytest.mark.parametrize(
    "bad_id", ["readme_copy", "Identity.readme", "identity.", "identity.readme-copy"]
)
def test_finding_ids_follow_the_check_dot_name_pattern(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        finding(id=bad_id)


@pytest.mark.parametrize("severity", [Severity.critical, Severity.high])
def test_serious_findings_need_evidence(severity: Severity) -> None:
    with pytest.raises(ValidationError, match="evidence"):
        finding(severity, evidence=False)


@pytest.mark.parametrize("severity", [Severity.medium, Severity.info])
def test_minor_findings_may_have_no_evidence(severity: Severity) -> None:
    assert finding(severity, evidence=False).evidence == []


def test_titles_are_short() -> None:
    with pytest.raises(ValidationError):
        finding(title="x" * 91)


def test_excerpts_are_capped() -> None:
    with pytest.raises(ValidationError):
        Evidence(type="file", ref="README.md", excerpt="x" * 301)


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Target(kind="github", raw="o/r", surprise="!")  # type: ignore[call-arg]


def test_exit_code_must_match_the_verdict() -> None:
    with pytest.raises(ValidationError, match="exit_code"):
        report(verdict=VerdictLabel.dont_run, exit_code=0)


def test_report_survives_a_json_round_trip() -> None:
    original = report(
        verdict=VerdictLabel.caution,
        exit_code=10,
        findings=[finding(Severity.high)],
        summary=["README is 94% identical to original-owner/viral-tool"],
        checked=[CheckKind.identity],
    )
    again = Report.model_validate_json(original.model_dump_json())
    assert again == original
    assert json.loads(original.model_dump_json())["schema_version"] == "1.0"


def test_summary_holds_at_most_three_reasons() -> None:
    with pytest.raises(ValidationError):
        report(summary=["a", "b", "c", "d"])


def test_published_schema_file_is_up_to_date() -> None:
    expected = json.dumps(report_json_schema(), indent=2, sort_keys=True) + "\n"
    assert SCHEMA_FILE.exists(), "Run: uv run python scripts/export_schema.py"
    assert SCHEMA_FILE.read_text() == expected, (
        "The report schema changed. If that's intended, bump SCHEMA_VERSION when the change "
        "isn't backwards compatible, then run: uv run python scripts/export_schema.py"
    )

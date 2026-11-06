import pytest

from lookfirst.verdict.schema import (
    EXIT_CODES,
    CheckKind,
    Evidence,
    Finding,
    Severity,
    Target,
    VerdictLabel,
)
from lookfirst.verdict.scoring import build_report, sort_findings, top_reasons, verdict_for


def make(severity: Severity, title: str = "A finding", fid: str = "install_path.x") -> Finding:
    return Finding(
        id=fid,
        check=CheckKind.install_path,
        severity=severity,
        title=title,
        evidence=[Evidence(type="file", ref="install.sh", line=3)],
        explanation="Why it matters.",
        recommendation="What to do.",
    )


@pytest.mark.parametrize(
    ("severities", "verdict"),
    [
        ([], VerdictLabel.looks_ok),
        ([Severity.info], VerdictLabel.looks_ok),
        ([Severity.medium, Severity.info], VerdictLabel.looks_ok),
        ([Severity.high], VerdictLabel.caution),
        ([Severity.high, Severity.medium], VerdictLabel.caution),
        ([Severity.critical], VerdictLabel.dont_run),
        ([Severity.info, Severity.high, Severity.critical], VerdictLabel.dont_run),
    ],
)
def test_verdict_rule(severities: list[Severity], verdict: VerdictLabel) -> None:
    assert verdict_for(make(s) for s in severities) is verdict


def test_exit_codes() -> None:
    assert {
        VerdictLabel.looks_ok: 0,
        VerdictLabel.caution: 10,
        VerdictLabel.dont_run: 20,
    } == EXIT_CODES


def test_findings_are_sorted_most_severe_first() -> None:
    found = [
        make(Severity.info, fid="a.a"),
        make(Severity.critical, fid="b.b"),
        make(Severity.high, fid="c.c"),
    ]
    assert [f.severity for f in sort_findings(found)] == [
        Severity.critical,
        Severity.high,
        Severity.info,
    ]


def test_top_reasons_are_the_three_most_serious_titles() -> None:
    found = [
        make(Severity.medium, "medium one", "a.a"),
        make(Severity.high, "high one", "b.b"),
        make(Severity.critical, "critical one", "c.c"),
        make(Severity.high, "high two", "d.d"),
        make(Severity.critical, "critical two", "e.e"),
    ]
    assert top_reasons(found) == ["critical one", "critical two", "high one"]


def test_minor_findings_are_never_given_as_reasons() -> None:
    assert top_reasons([make(Severity.medium), make(Severity.info)]) == []


def test_build_report_is_consistent() -> None:
    target = Target(kind="local", raw=".", resolved="/tmp/x")
    report = build_report(
        target=target,
        findings=[make(Severity.info, fid="a.a"), make(Severity.high, "high one", "b.b")],
        checked=[CheckKind.install_path],
        not_checked=[],
    )
    assert report.verdict is VerdictLabel.caution
    assert report.exit_code == 10
    assert report.summary == ["high one"]
    assert [f.id for f in report.findings] == ["b.b", "a.a"]
    assert report.disclaimer == "lookfirst lowers risk; it doesn't guarantee safety."

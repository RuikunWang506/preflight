"""The package check (SPEC section 7, M4 decisions): osv-scanner and GuardDog, run as
separate programs. Their output is recorded in tests/fixtures/scanners; no real scanner
runs in the tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import guarddog_output, osv_output

from lookfirst.pipeline import run_check
from lookfirst.scanners import base
from lookfirst.scanners.base import ToolFailed, ToolOutput, find_tool, run_tool, tool_env
from lookfirst.scanners.check import elsewhere, run_package_check
from lookfirst.scanners.guarddog import WORDING, ecosystems_for
from lookfirst.targets.models import PackageSpec, ResolvedTarget, TargetSpec
from lookfirst.verdict.schema import Severity

NOTHING = ToolOutput(128, "", "No package sources found")


def folder(root: Path) -> ResolvedTarget:
    return ResolvedTarget(TargetSpec(kind="local", raw=str(root), path=root), root, str(root))


def by_id(findings) -> dict:
    return {f.id: f for f in findings}


# --- running tools ----------------------------------------------------------------------


def test_tools_get_no_secrets_in_their_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.setenv(name, "secret-value")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    env = tool_env()
    assert "secret-value" not in env.values()
    assert env["PATH"].startswith("/usr/bin:/bin")
    assert str(Path.home() / ".local" / "bin") in env["PATH"]  # where uv puts GuardDog


def test_tools_are_found_outside_path_too(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tool = tmp_path / "guarddog"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", "/nonexistent")
    assert find_tool("guarddog", (tmp_path,)) == tool
    assert find_tool("osv-scanner", (tmp_path,)) is None


def test_a_tool_that_runs_too_long_is_stopped(tmp_path: Path) -> None:
    slow = tmp_path / "slow-tool"  # a stand-in written by this test, not a fixture
    slow.write_text("#!/bin/sh\nsleep 10\n")
    slow.chmod(0o755)
    with pytest.raises(ToolFailed, match="didn't finish within 1 second"):
        run_tool(slow, [], timeout=1)


def test_tool_output_is_captured_without_a_shell(tmp_path: Path) -> None:
    echo = tmp_path / "echo-tool"
    echo.write_text('#!/bin/sh\nprintf "%s\\n" "$1"\necho progress >&2\n')
    echo.chmod(0o755)
    out = run_tool(echo, ["$(touch should-not-exist)"])
    assert out.stdout == "$(touch should-not-exist)\n"  # passed as text, never run
    assert out.stderr == "progress\n"
    assert not (tmp_path / "should-not-exist").exists()


# --- osv-scanner --------------------------------------------------------------------------


def test_osv_is_never_asked_to_resolve_or_build_anything(fake_tools, tmp_path: Path) -> None:
    fake_tools.handlers["osv-scanner"] = lambda args: NOTHING
    run_package_check(folder(tmp_path))
    (call,) = [args for tool, args in fake_tools.calls if args != ["--version"]]
    assert {"--no-resolve", "--no-call-analysis=all", "-r"} <= set(call)
    assert call[-1] == str(tmp_path)


def test_known_vulnerabilities_are_one_worth_knowing_summary(fake_tools, tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\npyyaml==5.3\nflask==2.3.3\n")
    fake_tools.handlers["osv-scanner"] = lambda args: osv_output("osv_vulnerable.json", tmp_path)
    outcome = run_package_check(folder(tmp_path))
    (finding,) = outcome.findings
    assert finding.id == "package.known_vulnerabilities"
    assert finding.severity is Severity.medium
    assert finding.title == "Uses 3 package versions with known vulnerabilities"
    assert (finding.source, finding.source_version) == ("osv-scanner", "2.7.0")
    worst_first = [ev.data["package"] for ev in finding.evidence]
    assert worst_first[0] == "pyyaml" and set(worst_first) == {"pyyaml", "requests", "flask"}
    pyyaml = finding.evidence[0]
    assert pyyaml.ref == "requirements.txt"
    assert pyyaml.data["worst"] == 9.8 and pyyaml.data["fixed"].startswith("5.3.1")
    # Two issues, each known by two ids (PYSEC and GHSA): two advisories.
    assert pyyaml.data["what"] == "pyyaml 5.3: 2 advisories, worst score 9.8, fixed in 5.3.1, 5.4"
    (tool,) = outcome.tools
    assert (tool.name, tool.version, tool.status) == ("osv-scanner", "2.7.0", "ran")
    assert tool.detail == "asked osv.dev about 3 package versions (names and versions only)"
    assert outcome.ran and outcome.gaps == []


def test_known_malware_the_install_fetches_is_dont_run(fake_tools, tmp_path: Path) -> None:
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "app"}}}
    for name, version in (("flatmap-stream", "0.1.1"), ("event-stream", "3.3.6")):
        lock["packages"][f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    fake_tools.handlers["osv-scanner"] = lambda args: osv_output("osv_malware.json", tmp_path)
    report = run_check(str(tmp_path), cwd=tmp_path)
    assert report.verdict == "dont_run"
    malware = by_id(report.findings)["package.known_malware"]
    assert malware.severity is Severity.critical
    flagged = {ev.data["package"] for ev in malware.evidence}
    assert flagged == {"coa", "event-stream", "flatmap-stream", "node-ipc", "rc", "ua-parser-js"}
    assert len(malware.evidence) == 6  # one line per package version, not per advisory
    (flatmap,) = [ev for ev in malware.evidence if ev.data["package"] == "flatmap-stream"]
    assert flatmap.data["advisories"] == (
        "MAL-2025-20690, GHSA-9x64-5r7x-2q53, GHSA-mh6f-8j2x-4483"
    )
    assert flatmap.data["what"] == "flatmap-stream 0.1.1: Malicious code in flatmap-stream (npm)"
    assert report.summary[0] == "Depends on a package known to be malware"


def test_malware_only_in_example_or_test_folders_is_worth_knowing(
    fake_tools, tmp_path: Path
) -> None:
    def output(args: list[str]) -> object:
        out = osv_output("osv_malware.json", tmp_path)
        text = out.stdout.replace(
            f"{tmp_path}/package-lock.json", f"{tmp_path}/fixtures/ssr/package-lock.json"
        )
        return ToolOutput(1, text, out.stderr)

    fake_tools.handlers["osv-scanner"] = output
    outcome = run_package_check(folder(tmp_path))
    found = by_id(outcome.findings)
    assert "package.known_malware" not in found
    assert found["package.known_malware_elsewhere"].severity is Severity.medium
    assert (
        found["package.known_malware_elsewhere"].evidence[0].ref == "fixtures/ssr/package-lock.json"
    )


def test_a_local_package_that_shares_a_malware_name_isnt_called_malware(
    fake_tools, tmp_path: Path
) -> None:
    # React's own eslint plugin is linked from the repo; a malicious npm package took its name.
    (tmp_path / "yarn.lock").write_text(
        "# yarn lockfile v1\n\n\n"
        '"eslint-plugin-react-internal@link:./scripts/eslint-rules":\n'
        '  version "0.0.0"\n  uid ""\n'
    )
    result = {
        "results": [
            {
                "source": {"path": f"{tmp_path}/yarn.lock", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "eslint-plugin-react-internal",
                            "version": "0.0.0",
                            "ecosystem": "npm",
                        },
                        "groups": [{"ids": ["MAL-2025-19860"], "max_severity": ""}],
                        "vulnerabilities": [
                            {
                                "id": "MAL-2025-19860",
                                "summary": "Malicious code in eslint-plugin-react-internal (npm)",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    fake_tools.handlers["osv-scanner"] = lambda args: ToolOutput(1, json.dumps(result), "")
    outcome = run_package_check(folder(tmp_path))
    (finding,) = outcome.findings
    assert finding.id == "package.malware_name_local" and finding.severity is Severity.medium


def test_an_npm_package_is_looked_up_itself(fake_tools, tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    seen = {}

    def osv(args: list[str]) -> object:
        scanned = Path(args[-1])
        if scanned == root:
            return NOTHING  # the package ships no lockfile
        seen["lock"] = json.loads((scanned / "package-lock.json").read_text())
        hit = {
            "source": {"path": f"{scanned}/package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "evil-pkg", "version": "1.0.0", "ecosystem": "npm"},
                    "groups": [{"ids": ["MAL-2026-1"], "max_severity": ""}],
                    "vulnerabilities": [
                        {"id": "MAL-2026-1", "summary": "Malicious code in evil-pkg (npm)"}
                    ],
                }
            ],
        }
        return ToolOutput(1, json.dumps({"results": [hit]}), "Scanned x file and found 1 package\n")

    fake_tools.handlers["osv-scanner"] = osv
    tarball = "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
    target = ResolvedTarget(
        TargetSpec(kind="npm", raw="npm:evil-pkg", package=PackageSpec("npm", "evil-pkg")),
        root,
        "evil-pkg@1.0.0",
        metadata={"npm": {"name": "evil-pkg", "version": "1.0.0", "dist": {"tarball": tarball}}},
    )
    outcome = run_package_check(target)
    assert seen["lock"]["packages"]["node_modules/evil-pkg"] == {
        "version": "1.0.0",
        "resolved": tarball,
    }
    (finding,) = outcome.findings
    assert finding.id == "package.target_is_malware" and finding.severity is Severity.critical
    assert finding.evidence[0].ref == "https://osv.dev/vulnerability/MAL-2026-1"
    assert (
        outcome.tools[0].detail == "asked osv.dev about 1 package version (names and versions only)"
    )


def test_a_package_whose_name_cant_be_written_safely_isnt_looked_up(
    fake_tools, tmp_path: Path
) -> None:
    fake_tools.handlers["osv-scanner"] = lambda args: NOTHING
    target = ResolvedTarget(
        TargetSpec(kind="pypi", raw="pypi:x", package=PackageSpec("pypi", "x")),
        tmp_path,
        "x==1",
        metadata={"pypi": {"info": {"name": "x\n--index-url evil", "version": "1"}}},
    )
    run_package_check(target)
    assert len([a for _, a in fake_tools.calls if a != ["--version"]]) == 1  # the folder only


def test_no_lockfile_next_to_a_manifest_is_listed_as_not_checked(
    fake_tools, tmp_path: Path
) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "^4"}}')
    fake_tools.handlers["osv-scanner"] = lambda args: NOTHING
    outcome = run_package_check(folder(tmp_path))
    assert outcome.ran and outcome.findings == []
    assert (
        "Which package versions it installs",
        "it has no lockfile, so they're only chosen when you install",
    ) in [(g.what, g.reason) for g in outcome.gaps]
    assert outcome.tools[0].status == "nothing_to_scan"


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        (
            "dial tcp: lookup api.osv.dev: no such host",
            "osv-scanner couldn't reach osv.dev",
        ),
        ("panic: something broke", "osv-scanner stopped with an error (panic: something broke)"),
    ],
)
def test_an_osv_failure_is_not_checked_not_a_crash(
    fake_tools, tmp_path: Path, stderr: str, reason: str
) -> None:
    fake_tools.handlers["osv-scanner"] = lambda args: ToolOutput(127, "", stderr)
    outcome = run_package_check(folder(tmp_path))
    assert not outcome.ran
    assert [g.reason for g in outcome.gaps] == [reason]
    assert outcome.tools[0].status == "failed"


def test_missing_tools_are_listed_with_how_to_install_them(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(name='x')\n")
    outcome = run_package_check(folder(tmp_path))
    assert [(g.reason, g.how_to_enable) for g in outcome.gaps] == [
        ("osv-scanner isn't installed", "brew install osv-scanner"),
        ("GuardDog isn't installed", "uv tool install --python 3.12 guarddog"),
    ]
    assert [(t.name, t.status) for t in outcome.tools] == [
        ("osv-scanner", "not_installed"),
        ("GuardDog", "not_installed"),
    ]


def test_a_one_liner_has_nothing_to_scan(capsys) -> None:
    report = run_check("echo hi", cwd=Path.cwd())
    (gap,) = [n for n in report.not_checked if n.check == "package"]
    assert gap.reason == "doesn't apply to a shell command"
    assert report.tools == []


# --- GuardDog -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("files", "ecosystems"),
    [
        (["package.json"], ["npm"]),
        (["pyproject.toml"], ["pypi"]),
        (["setup.py", "package.json"], ["npm", "pypi"]),
        (["action.yml"], ["github_action"]),
        (["README.md", "install.sh"], []),
    ],
)
def test_guarddog_runs_where_it_applies(tmp_path: Path, files: list[str], ecosystems) -> None:
    for name in files:
        (tmp_path / name).write_text("{}\n")
    assert ecosystems_for(folder(tmp_path)) == ecosystems


def test_guarddog_patterns_are_worth_knowing_at_most(fake_tools, tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("x = 1\n")
    fake_tools.handlers["guarddog"] = lambda args: guarddog_output("guarddog_probe.json")
    outcome = run_package_check(folder(tmp_path))
    (finding,) = outcome.findings
    assert finding.id == "package.code_patterns" and finding.severity is Severity.medium
    assert (finding.source, finding.source_version) == ("GuardDog", "3.2.0")
    first = finding.evidence[0]
    assert (first.ref, first.line) == ("setup.py", 10)
    assert first.data["what"] == "The code downloads a file and runs it"  # GuardDog said "high"
    assert ["guarddog", "pypi", "scan", str(tmp_path), "--output-format=json"] in [
        [tool, *args] for tool, args in fake_tools.calls
    ]


def test_guarddog_hits_in_tests_and_dev_scripts_are_only_counted(
    fake_tools, tmp_path: Path
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    fake_tools.handlers["guarddog"] = lambda args: guarddog_output("guarddog_yt_dlp.json")
    outcome = run_package_check(folder(tmp_path))
    (finding,) = outcome.findings
    listed = {ev.ref for ev in finding.evidence}
    assert all(path.startswith("yt_dlp/") for path in listed)
    assert finding.title == "GuardDog found 10 code patterns that malware also uses"
    assert finding.evidence[-1].data["elsewhere"] == 6  # test/ and devscripts/


def test_guarddog_with_nothing_found_adds_no_finding(fake_tools, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    fake_tools.handlers["guarddog"] = lambda args: guarddog_output("guarddog_clean.json")
    outcome = run_package_check(folder(tmp_path))
    assert outcome.findings == [] and outcome.ran
    assert [(t.name, t.status) for t in outcome.tools][-1] == ("GuardDog", "ran")


def test_every_guarddog_threat_rule_has_plain_wording() -> None:
    assert len(WORDING) >= 43
    assert all(not text.endswith(".") and text == text.strip() for text in WORDING.values())


@pytest.mark.parametrize(
    ("path", "outside"),
    [
        ("fixtures/ssr/yarn.lock", True),
        ("examples/celery/requirements.txt", True),
        ("compiler/apps/playground/yarn.lock", True),
        (".github/scripts/pnpm-lock.yaml", True),
        ("test/test_utils.py", True),
        ("package-lock.json", False),
        ("app/ui/app/package-lock.json", False),
        ("scripts/install.sh", False),
    ],
)
def test_which_folders_a_normal_install_doesnt_use(path: str, outside: bool) -> None:
    assert elsewhere(path) is outside


# --- the whole check ---------------------------------------------------------------------


def test_the_report_credits_the_tools_and_says_what_was_sent(
    capsys, fake_tools, tmp_path: Path
) -> None:
    from lookfirst.cli import main

    (tmp_path / "requirements.txt").write_text("flask==2.3.3\n")
    fake_tools.handlers["osv-scanner"] = lambda args: osv_output("osv_vulnerable.json", tmp_path)
    assert main(["check", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Uses 3 package versions with known vulnerabilities" in out
    flat = " ".join(out.split())
    assert (
        "Also checked with osv-scanner 2.7.0, which asked osv.dev about 3 package versions "
        "(names and versions only)." in flat
    )


def test_tool_versions_are_read_once(fake_tools, tmp_path: Path) -> None:
    fake_tools.handlers["osv-scanner"] = lambda args: NOTHING
    run_package_check(folder(tmp_path))
    run_package_check(folder(tmp_path))
    assert [a for _, a in fake_tools.calls].count(["--version"]) == 1
    assert base.tool_version(Path("/fake/bin/osv-scanner")) == "2.7.0"
    assert os.environ.get("GITHUB_TOKEN") is None


def test_rustsec_notices_arent_counted_as_vulnerabilities(fake_tools, tmp_path: Path) -> None:
    def record(advisory: str, informational: str | None) -> dict:
        specific = {"informational": informational} if informational else {}
        return {
            "id": advisory,
            "summary": advisory,
            "affected": [{"package": {"name": "c"}, "database_specific": specific}],
        }

    result = {
        "results": [
            {
                "source": {"path": f"{tmp_path}/Cargo.lock"},
                "packages": [
                    {
                        "package": {"name": name, "version": "1.0.0", "ecosystem": "crates.io"},
                        "groups": [{"ids": [advisory], "max_severity": ""}],
                        "vulnerabilities": [record(advisory, informational)],
                    }
                    for name, advisory, informational in (
                        ("bincode", "RUSTSEC-2025-0141", "unmaintained"),
                        ("faster-hex", "RUSTSEC-2026-0306", "unsound"),
                        ("hyper", "RUSTSEC-2021-0079", None),
                    )
                ],
            }
        ]
    }
    fake_tools.handlers["osv-scanner"] = lambda args: ToolOutput(1, json.dumps(result), "")
    (finding,) = run_package_check(folder(tmp_path)).findings
    assert finding.title == "Uses 1 package version with known vulnerabilities"
    assert [ev.data["package"] for ev in finding.evidence] == ["hyper"]


def test_fixed_versions_sort_by_number() -> None:
    from lookfirst.scanners.osv import version_key

    versions = ["2.15.1", "2.15.0", "2.20.0", "2.9", "10.0.0-rc1"]
    assert sorted(versions, key=version_key) == ["2.9", "2.15.0", "2.15.1", "2.20.0", "10.0.0-rc1"]

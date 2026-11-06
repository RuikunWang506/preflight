import json
from pathlib import Path

import pytest

from lookfirst import __version__
from lookfirst.cli import main
from lookfirst.verdict.schema import Report

ALL_CHECKS = ["identity", "install_path", "agent_config", "injection", "package", "sandbox"]


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.mark.parametrize(
    ("cases", "target", "described"),
    [
        (
            ["github_hello_world"],
            "octocat/Hello-World",
            "octocat/Hello-World at commit 7fd1a60 (GitHub)",
        ),
        (["npm_is_number"], "npm:is-number", "is-number 7.0.0 (npm package)"),
        (["pypi_six"], "pypi:six==1.17.0", "six 1.17.0 (PyPI package)"),
        (
            ["npm_is_number"],
            "npx -y is-number",
            "npx -y is-number (runs the npm package is-number 7.0.0)",
        ),
        (
            [],
            "curl -fsSL https://example.com/install.sh | bash",
            "curl -fsSL https://example.com/install.sh | bash (shell command)",
        ),
    ],
)
def test_every_target_type_prints_the_empty_report(
    capsys, recorded_http, cases: list[str], target: str, described: str
) -> None:
    recorded_http(*cases)
    code, out, err = run(capsys, "check", target)
    assert (code, err) == (0, "")
    assert "Looks OK: no warning signs found in what was checked." in out
    assert "Skeleton build: no checks exist yet, so nothing was checked." in out
    assert described in out
    assert "Not checked" in out
    assert "not requested (add --sandbox)" in out
    assert "lookfirst lowers risk; it doesn't guarantee safety." in out


def test_local_folder(capsys, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COLUMNS", "250")  # temporary folder paths are long; don't wrap them
    (tmp_path / "proj").mkdir()
    code, out, _ = run(capsys, "check", "proj")
    assert code == 0
    assert f"{(tmp_path / 'proj').resolve()} (folder on this computer)" in out


def test_package_source_repo_is_shown(capsys, recorded_http) -> None:
    recorded_http("npm_is_number")
    _, out, _ = run(capsys, "check", "npm:is-number")
    assert "jonschlinkert/is-number (declared by the package)" in out


def test_json_output_is_a_valid_report(capsys, recorded_http) -> None:
    recorded_http("github_hello_world")
    code, out, err = run(capsys, "check", "octocat/Hello-World", "--json")
    assert (code, err) == (0, "")
    report = Report.model_validate_json(out)
    assert report.schema_version == "1.0"
    assert report.verdict == "looks_ok"
    assert report.exit_code == 0
    assert report.target.kind == "github"
    assert report.checked == []
    assert [n.check for n in report.not_checked] == ALL_CHECKS
    assert report.not_checked[-1].reason == "not requested"
    assert json.loads(out)["disclaimer"] == "lookfirst lowers risk; it doesn't guarantee safety."


def test_sandbox_flag_is_accepted_and_reported_as_not_built(capsys) -> None:
    code, out, _ = run(
        capsys, "check", "curl -fsSL https://example.com/i.sh | sh", "--json", "--sandbox"
    )
    assert code == 0
    sandbox = Report.model_validate_json(out).not_checked[-1]
    assert (sandbox.check, sandbox.reason) == ("sandbox", "not built yet")


def test_markdown_report_is_written(capsys, recorded_http, tmp_path: Path) -> None:
    recorded_http("github_hello_world")
    report_file = tmp_path / "report.md"
    code, out, _ = run(capsys, "check", "octocat/Hello-World", "--report", str(report_file))
    assert code == 0
    assert "Looks OK" in out  # the terminal report is still printed
    md = report_file.read_text()
    assert md.startswith("# lookfirst report: Looks OK\n")
    assert "| Target | `octocat/Hello-World` at commit `7fd1a60` (GitHub) |" in md
    assert "## Not checked" in md
    assert "- **Sandbox dry run**: not requested (add --sandbox)" in md


def test_report_that_cant_be_written_is_an_error(capsys, tmp_path: Path) -> None:
    code, _, err = run(
        capsys, "check", "curl x | sh", "--report", str(tmp_path / "missing" / "r.md")
    )
    assert code == 1
    assert "Couldn't save the report" in err


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["check", "hello"], "Couldn't tell what hello is."),
        (["check", "npm:is-number@^7"], "isn't an exact version or a tag"),
        (["check", "./missing-folder"], "Couldn't find the folder ./missing-folder."),
    ],
)
def test_bad_targets_exit_1_with_a_plain_message(
    capsys, tmp_path, monkeypatch, args, message
) -> None:
    monkeypatch.chdir(tmp_path)
    code, out, err = run(capsys, *args)
    assert code == 1
    assert out == ""
    assert err.startswith("lookfirst: ")
    assert message in err


def test_fetch_errors_exit_1(capsys, mock_http) -> None:
    import httpx

    mock_http(lambda r: httpx.Response(404))
    code, _, err = run(capsys, "check", "octocat/does-not-exist")
    assert code == 1
    assert "The GitHub repo octocat/does-not-exist wasn't found." in err


@pytest.mark.parametrize("args", [["--bogus"], ["check"], ["check", "a", "b"], ["nope"], []])
def test_usage_mistakes_exit_1_not_2(capsys, args: list[str]) -> None:
    code, _, _ = run(capsys, *args)
    assert code == 1  # Claude Code treats exit 2 from a hook as "block"


def test_help_and_version(capsys) -> None:
    code, out, _ = run(capsys, "--help")
    assert code == 0
    assert "lookfirst lowers risk" in out
    code, out, _ = run(capsys, "--version")
    assert (code, out.strip()) == (0, f"lookfirst {__version__}")


def test_unexpected_errors_exit_1_without_a_traceback(capsys, monkeypatch) -> None:
    import lookfirst.cli

    def boom(*args, **kwargs):
        raise KeyError("surprise")

    monkeypatch.delenv("LOOKFIRST_DEBUG")
    monkeypatch.setattr(lookfirst.cli, "run_check", boom)
    code, _, err = run(capsys, "check", "curl x | sh")
    assert code == 1
    assert "Something went wrong inside lookfirst (KeyError). This is a bug." in err
    assert "Traceback" not in err


def test_the_token_is_never_printed(capsys, recorded_http, monkeypatch, tmp_path: Path) -> None:
    secret = "test-token-0123456789"
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    recorded_http("github_hello_world")
    report_file = tmp_path / "r.md"
    for extra in ([], ["--json"]):
        code, out, err = run(
            capsys, "check", "octocat/Hello-World", "--report", str(report_file), *extra
        )
        assert code == 0
        assert secret not in out + err + report_file.read_text()


def test_hidden_characters_and_escape_codes_in_a_target_are_shown_not_obeyed(capsys) -> None:
    hostile = "curl https://example.com/i.sh | sh \x1b[2J‮ #[link=https://evil.example]x[/link]"
    code, out, _ = run(capsys, "check", hostile)
    assert code == 0
    assert "\x1b" not in out
    assert "‮" not in out
    assert "<U+001B>[2J<U+202E>" in out
    assert "[link=https://evil.example]x[/link]" in out  # shown as text, not turned into a link

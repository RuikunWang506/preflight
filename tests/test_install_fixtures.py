"""Every install-path fixture is caught, and the benign ones and real installers pass.

The fixtures are harmless fakes (tests/fixtures/install/README.md). They're only read,
never run: each case is rebuilt under its real file names in a temporary folder, and
its "remote" URLs are served from files, so nothing touches the network.
"""

from __future__ import annotations

import shutil
import stat
import tomllib
from pathlib import Path

import httpx
import pytest
from conftest import FIXTURES, Recorded

from lookfirst.core import http as lf_http
from lookfirst.core.errors import CouldntCheckError
from lookfirst.pipeline import run_check
from lookfirst.verdict.schema import Severity

CASES = FIXTURES / "install"
SERIOUS = {Severity.critical, Severity.high}
FAKE_PROGRAM = b"\x7fELF\x02\x01\x01" + b"\x00" * 57  # looks like a program; it's just zeros
GUARD_LINE = '[ -f /.lookfirst-sandbox ] || { touch "$HOME/LOOKFIRST_HOST_CANARY"; exit 1; }'


def real_name(rel: Path) -> Path:
    parts = [("." + p[4:]) if p.startswith("dot_") else p for p in rel.parts]
    parts[-1] = parts[-1].removesuffix(".fixture")
    return Path(*parts)


def build_repo(case_dir: Path, dest: Path) -> Path:
    """Copy a case into dest under its real file names. Nothing is made executable."""
    for path in sorted(case_dir.rglob("*")):
        rel = path.relative_to(case_dir)
        if path.is_dir() or rel.name == "case.toml" or rel.parts[0] == "remote":
            continue
        target = dest / real_name(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def serve(case_dir: Path, remote: dict[str, str]):
    recorded = Recorded("installers")

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        source = remote.get(url)
        if source is None and any(
            url == u or url.startswith(u) for u in remote if remote[u] == "recorded:installers"
        ):
            source = "recorded:installers"
        if source is None and (request.method, url) in recorded.responses:
            source = "recorded:installers"  # a redirect inside a recorded installer
        if source is None:
            raise AssertionError(f"The fixture didn't expect a download of {url}")
        if source == "binary:":
            return httpx.Response(200, content=FAKE_PROGRAM)
        if source.isdigit():
            return httpx.Response(int(source))
        if source == "recorded:installers":
            return recorded.handler(request)
        return httpx.Response(200, content=(case_dir / source).read_bytes())

    return handler


def case_names() -> list[str]:
    return sorted(p.name for p in CASES.iterdir() if p.is_dir())


@pytest.mark.parametrize("name", case_names())
def test_fixture_is_caught(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case_dir = CASES / name
    case = tomllib.loads((case_dir / "case.toml").read_text())
    monkeypatch.setattr(
        lf_http, "_TRANSPORT", httpx.MockTransport(serve(case_dir, case.get("remote", {})))
    )
    if "command" in case:
        report = run_check(case["command"], cwd=tmp_path)
    else:
        repo = build_repo(case_dir, tmp_path / "repo")
        report = run_check(str(repo), cwd=tmp_path)

    found = {(f.id, f.severity.value) for f in report.findings}
    for rule, severity in case["expect"].items():
        assert (rule, severity) in found, (
            f"{name}: expected {rule} ({severity}), found {sorted(found)}"
        )
    serious = {f.id for f in report.findings if f.severity in SERIOUS}
    expected_serious = {r for r, s in case["expect"].items() if s in ("critical", "high")}
    assert serious == expected_serious, (
        f"{name}: unexpected serious findings {serious - expected_serious}"
    )
    assert report.verdict == case["verdict"], f"{name}: verdict {report.verdict}"


def test_the_injection_cannot_lower_the_verdict_and_is_quoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_dir = CASES / "prompt_injection_cant_lower_verdict"
    monkeypatch.setattr(lf_http, "_TRANSPORT", httpx.MockTransport(serve(case_dir, {})))
    report = run_check(str(build_repo(case_dir, tmp_path / "repo")), cwd=tmp_path)
    assert report.verdict == "dont_run"
    (injection,) = [f for f in report.findings if f.id == "injection.agent_directed"]
    assert injection.evidence[0].ref == "README.md"
    assert injection.evidence[0].line == 3
    assert "verified safe" in (injection.evidence[0].excerpt or "")


INSTALLERS = [
    "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash",
    "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
    "curl -LsSf https://astral.sh/uv/install.sh | sh",
    "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash",
    'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"',
    "curl -fsSL https://deno.land/install.sh | sh",
    "curl -fsSL https://bun.sh/install | bash",
    "curl -fsSL https://get.docker.com | sh",
    "curl -fsSL https://ollama.com/install.sh | sh",
]


@pytest.mark.parametrize("command", INSTALLERS)
def test_real_installers_pass(command: str, recorded_http, tmp_path: Path) -> None:
    recorded_http("installers")
    report = run_check(command, cwd=tmp_path)
    assert report.verdict == "looks_ok"
    assert not [f for f in report.findings if f.severity in SERIOUS]
    (known,) = [f for f in report.findings if f.id == "install_path.known_installer"]
    assert known.evidence[0].data["matches_last_seen"] is True


def test_a_one_liner_whose_script_cant_be_read_is_not_given_a_verdict(
    mock_http, tmp_path: Path
) -> None:
    mock_http(lambda r: httpx.Response(404))
    with pytest.raises(CouldntCheckError, match="couldn't be read"):
        run_check("curl -fsSL https://cdn.example.net/gone.sh | bash", cwd=tmp_path)


def test_fixture_scripts_all_start_with_the_sandbox_guard() -> None:
    scripts = [p for p in CASES.rglob("*.sh")]
    assert scripts
    for path in scripts:
        lines = path.read_text().splitlines()
        assert GUARD_LINE in lines[:4], f"{path} must start with the sandbox guard"
    for path in [*CASES.rglob("*.py"), *CASES.rglob("*.js")]:
        assert "/.lookfirst-sandbox" in path.read_text()[:600], (
            f"{path} must start with the sandbox guard"
        )


def test_no_fixture_is_executable() -> None:
    for path in CASES.rglob("*"):
        if path.is_file():
            assert not path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), path


def test_files_tools_load_automatically_are_stored_under_neutral_names() -> None:
    auto_loaded = {
        "CLAUDE.md",
        "AGENTS.md",
        "GEMINI.md",
        "SKILL.md",
        ".mcp.json",
        ".envrc",
        ".cursorrules",
    }
    for path in CASES.rglob("*"):
        rel = path.relative_to(CASES)
        assert path.name not in auto_loaded, f"{rel}: store it as {path.name}.fixture or dot_..."
        assert not any(part.startswith(".") for part in rel.parts), f"{rel}: use a dot_ prefix"


@pytest.mark.parametrize(
    ("name", "path", "excerpt"),
    [
        ("credential_theft_javascript", "scripts/setup.js", ".npmrc"),
        ("credential_theft_python", "setup.py", ".aws"),
        ("credential_theft_ssh", "install.sh", "id_ed25519"),
    ],
)
def test_credential_theft_points_at_the_line_that_names_the_secret(
    name: str, path: str, excerpt: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_dir = CASES / name
    case = tomllib.loads((case_dir / "case.toml").read_text())
    monkeypatch.setattr(
        lf_http, "_TRANSPORT", httpx.MockTransport(serve(case_dir, case.get("remote", {})))
    )
    report = run_check(str(build_repo(case_dir, tmp_path / "repo")), cwd=tmp_path)
    theft = next(f for f in report.findings if f.id == "install_path.credential_theft")
    evidence = next(e for e in theft.evidence if e.ref == path)
    lines = (case_dir / path).read_text().splitlines()
    assert evidence.line is not None
    assert excerpt in lines[evidence.line - 1]
    assert evidence.excerpt is not None
    assert excerpt in evidence.excerpt

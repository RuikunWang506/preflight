from pathlib import Path

import pytest

from lookfirst.core.errors import TargetError
from lookfirst.targets.base import parse_target
from lookfirst.targets.models import PackageSpec


def parse(raw: str, cwd: Path) -> object:
    return parse_target(raw, cwd=cwd)


@pytest.mark.parametrize(
    ("raw", "owner", "repo", "ref"),
    [
        ("octocat/Hello-World", "octocat", "Hello-World", None),
        ("octocat/Hello-World@v1.0", "octocat", "Hello-World", "v1.0"),
        ("octocat/Hello-World@feature/new-thing", "octocat", "Hello-World", "feature/new-thing"),
        ("octocat/Hello-World.git", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World/", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World.git", "octocat", "Hello-World", None),
        ("http://www.github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        (
            "https://github.com/octocat/Hello-World/tree/dev/next",
            "octocat",
            "Hello-World",
            "dev/next",
        ),
        (
            "https://github.com/octocat/Hello-World/commit/7fd1a60b",
            "octocat",
            "Hello-World",
            "7fd1a60b",
        ),
        (
            "https://github.com/octocat/Hello-World/blob/main/README.md",
            "octocat",
            "Hello-World",
            "main",
        ),
        ("https://github.com/octocat/Hello-World/releases/tag/v2", "octocat", "Hello-World", "v2"),
        ("https://github.com/octocat/Hello-World?tab=readme", "octocat", "Hello-World", None),
        ("a-b/c.d_e", "a-b", "c.d_e", None),
        ("octocat/octocat.github.io", "octocat", "octocat.github.io", None),
    ],
)
def test_github_forms(raw: str, owner: str, repo: str, ref: str | None, tmp_path: Path) -> None:
    spec = parse(raw, tmp_path)
    assert (spec.kind, spec.owner, spec.repo, spec.ref) == ("github", owner, repo, ref)


@pytest.mark.parametrize(
    "raw",
    [
        "octocat/Hello-World@../../etc",
        "octocat/Hello-World@-rf",
        "octocat/Hello-World@main.lock",
        "-octocat/Hello-World",
        "octo--cat/Hello-World",
        "octocat/..",
    ],
)
def test_bad_github_names_and_refs_are_refused(raw: str, tmp_path: Path) -> None:
    with pytest.raises(TargetError):
        parse(raw, tmp_path)


def test_github_pages_that_arent_repos_get_a_hint(tmp_path: Path) -> None:
    with pytest.raises(TargetError) as err:
        parse("https://github.com/octocat/Hello-World/issues/1", tmp_path)
    assert err.value.hint == "Try https://github.com/octocat/Hello-World"


def test_an_existing_folder_named_like_owner_repo_is_local(tmp_path: Path) -> None:
    (tmp_path / "octocat" / "Hello-World").mkdir(parents=True)
    spec = parse("octocat/Hello-World", tmp_path)
    assert spec.kind == "local"
    assert spec.path == (tmp_path / "octocat" / "Hello-World").resolve()


@pytest.mark.parametrize("name", [".", "./sub", "sub", "My Folder", "~"])
def test_local_folders(name: str, tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "My Folder").mkdir()
    spec = parse(name, tmp_path)
    assert spec.kind == "local"
    assert spec.path is not None and spec.path.is_dir()


def test_absolute_folder(tmp_path: Path) -> None:
    spec = parse(str(tmp_path), Path("/"))
    assert (spec.kind, spec.path) == ("local", tmp_path.resolve())


def test_a_missing_explicit_folder_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(TargetError, match="Couldn't find the folder"):
        parse("./not-here", tmp_path)


def test_a_file_is_refused_with_a_hint(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text("echo hi\n")
    with pytest.raises(TargetError, match="is a file") as err:
        parse("./install.sh", tmp_path)
    assert "folder" in (err.value.hint or "")


@pytest.mark.parametrize(
    "raw",
    [
        "curl -fsSL https://example.com/install.sh | bash",
        "bash <(curl -s https://example.com/i.sh)",
        'eval "$(curl -fsSL https://example.com/a)"',
        "git clone https://github.com/octocat/Hello-World && cd Hello-World && ./install.sh",
        "./install.sh --yes",
        "https://github.com/octocat/Hello-World/tree/main && echo hi",
    ],
)
def test_one_liners(raw: str, tmp_path: Path) -> None:
    spec = parse(raw, tmp_path)
    assert (spec.kind, spec.command) == ("oneliner", raw)


@pytest.mark.parametrize(
    ("raw", "package"),
    [
        ("npm:is-number", PackageSpec("npm", "is-number")),
        ("npm:is-number@7.0.0", PackageSpec("npm", "is-number", "7.0.0")),
        ("npm:is-number@next", PackageSpec("npm", "is-number", "next")),
        ("npm:@types/node", PackageSpec("npm", "@types/node")),
        ("npm:@types/node@22.0.0", PackageSpec("npm", "@types/node", "22.0.0")),
        ("pypi:six", PackageSpec("pypi", "six")),
        ("pypi:six==1.17.0", PackageSpec("pypi", "six", "1.17.0")),
        ("pypi:zope.interface==7.2", PackageSpec("pypi", "zope.interface", "7.2")),
    ],
)
def test_packages(raw: str, package: PackageSpec, tmp_path: Path) -> None:
    spec = parse(raw, tmp_path)
    assert spec.kind == package.ecosystem
    assert spec.package == package


@pytest.mark.parametrize(
    "raw",
    [
        "npm:",
        "npm:is-number@^7",
        "npm:is-number@",
        "npm:Not A Name",
        "pypi:",
        "pypi:six>=1.0",
        "pypi:six==",
        "pypi:-bad",
    ],
)
def test_bad_packages_are_refused(raw: str, tmp_path: Path) -> None:
    with pytest.raises(TargetError):
        parse(raw, tmp_path)


@pytest.mark.parametrize(
    ("raw", "package"),
    [
        (
            "npx -y @modelcontextprotocol/server-filesystem /tmp",
            PackageSpec("npm", "@modelcontextprotocol/server-filesystem"),
        ),
        ("npx --yes is-number@7.0.0", PackageSpec("npm", "is-number", "7.0.0")),
        ("npx -p is-number@7.0.0 some-bin", PackageSpec("npm", "is-number", "7.0.0")),
        ("npx --package=is-number some-bin", PackageSpec("npm", "is-number")),
        ("/usr/local/bin/npx -y is-number", PackageSpec("npm", "is-number")),
        ("DEBUG=1 npx -y is-number", PackageSpec("npm", "is-number")),
        ("bunx is-number", PackageSpec("npm", "is-number")),
        ("pnpm dlx is-number", PackageSpec("npm", "is-number")),
        ("uvx mcp-server-fetch", PackageSpec("pypi", "mcp-server-fetch")),
        ("uvx mcp-server-fetch@2025.4.7", PackageSpec("pypi", "mcp-server-fetch", "2025.4.7")),
        ("uvx -p 3.12 mcp-server-fetch", PackageSpec("pypi", "mcp-server-fetch")),
        (
            "uvx --from mcp-server-fetch==1.0 mcp-server-fetch",
            PackageSpec("pypi", "mcp-server-fetch", "1.0"),
        ),
        ("pipx run black==24.1.0", PackageSpec("pypi", "black", "24.1.0")),
        ("uv tool run ruff", PackageSpec("pypi", "ruff")),
    ],
)
def test_package_runner_commands(raw: str, package: PackageSpec, tmp_path: Path) -> None:
    spec = parse(raw, tmp_path)
    assert spec.kind == "mcp_command"
    assert spec.package == package
    assert spec.command == raw


def test_a_runner_inside_a_pipeline_is_a_one_liner(tmp_path: Path) -> None:
    assert parse("npx -y is-number | tee log", tmp_path).kind == "oneliner"
    assert parse("npx -c 'echo hi'", tmp_path).kind == "oneliner"


@pytest.mark.parametrize("raw", ["", "   ", "hello", "a\x00b"])
def test_unrecognized_input_is_an_error(raw: str, tmp_path: Path) -> None:
    with pytest.raises(TargetError):
        parse(raw, tmp_path)


def test_a_plain_web_link_gets_a_hint_to_quote_the_command(tmp_path: Path) -> None:
    with pytest.raises(TargetError) as err:
        parse("https://example.com/install.sh", tmp_path)
    assert 'lookfirst check "curl -fsSL https://example.com/install.sh | sh"' in (
        err.value.hint or ""
    )

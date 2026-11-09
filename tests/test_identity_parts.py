"""The identity check's building blocks: names, README similarity, official sources, the
popular-repos list, and what happens when GitHub can't be reached."""

from __future__ import annotations

import gzip
from pathlib import Path

import httpx
import pytest

from lookfirst.identity import official, popular_index
from lookfirst.identity.names import compare, distance, fold, squash, without_added_words
from lookfirst.identity.popular_index import PopularIndex, PopularRepo, load_index, serialize
from lookfirst.identity.readme_sim import readme_words, similarity
from lookfirst.pipeline import run_check
from lookfirst.static.fetch import RemoteReader

# --- names -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "same"),
    [
        ("ollama", "o1lama", True),
        ("ollama", "0llama", True),
        ("modern", "modem", True),
        ("swiper", "svviper", True),
        ("Yt_D1p", "yt-dlp", True),
        ("ollama", "llama", False),
        ("react", "preact", False),
    ],
)
def test_lookalike_letters_fold_together(a: str, b: str, same: bool) -> None:
    assert (squash(a) == squash(b)) is same


def test_fold_keeps_case_insensitive_names_comparable() -> None:
    assert fold("RipGrep") == fold("ripgrep")


@pytest.mark.parametrize(
    ("a", "b", "d"),
    [
        ("ripgrep", "ripgrep", 0),
        ("ripgrep", "rlpgrep", 1),
        ("ripgrep", "ripgerp", 1),
        ("ripgrep", "grep", 3),
    ],
)
def test_distance(a: str, b: str, d: int) -> None:
    assert distance(a, b, limit=2) == min(d, 3)


@pytest.mark.parametrize(
    ("name", "stripped", "removed"),
    [
        ("ComfyUI-pro", "comfyul", ["pro"]),
        ("yt-dlp-free-2026", "ytdlp", ["free", "2026"]),
        ("ollama-webui", "ollamawebul", []),
    ],
)
def test_added_words(name: str, stripped: str, removed: list[str]) -> None:
    assert without_added_words(name) == (stripped, removed)


@pytest.mark.parametrize(
    ("target", "original", "kinds"),
    [
        ("someone/ollama", "ollama/ollama", ["same_name"]),
        ("0llama-dev/ollama", "ollama/ollama", ["same_name", "lookalike_owner"]),
        ("someone/o1lama", "ollama/ollama", ["lookalike_name"]),
        ("someone/ComfyUI-Pro", "Comfy-Org/ComfyUI", ["added_word"]),
        ("someone/ripgerp", "BurntSushi/ripgrep", ["near_name"]),
        ("someone/react-native", "facebook/react", []),
        ("someone/tool", "other/thing", []),
    ],
)
def test_compare(target: str, original: str, kinds: list[str]) -> None:
    t_owner, t_repo = target.split("/")
    o_owner, o_repo = original.split("/")
    assert [m.kind for m in compare(t_owner, t_repo, o_owner, o_repo)] == kinds


def test_short_names_are_not_called_near_misses() -> None:
    assert compare("someone", "bat", "sharkdp", "cat") == []


# --- README similarity ---------------------------------------------------------------------

ORIGINAL = " ".join(f"word{i} means something different in sentence {i}." for i in range(80))


def test_a_copy_with_an_added_download_section_is_copied() -> None:
    s = similarity(ORIGINAL + "\n## Download\nGet Setup.7z, archive password: 1234\n", ORIGINAL)
    assert s.copied and s.percent >= 95


def test_unrelated_and_partly_quoted_readmes_are_not_copied() -> None:
    assert not similarity(
        "A tiny notebook for your terminal: write, tag and search notes.", ORIGINAL
    ).copied
    quoted = (
        " ".join(ORIGINAL.split()[:60]) + " " + " ".join(f"other{i} text here" for i in range(200))
    )
    assert not similarity(quoted, ORIGINAL).copied


def test_badges_links_and_html_are_ignored() -> None:
    words = readme_words(
        '[![CI](https://x/badge.svg)](https://x) <img src="a.png"> See [the docs](https://d) at https://e'
    )
    assert words == ["see", "the", "docs", "at"]


# --- official sources ------------------------------------------------------------------------


def test_official_projects_load_and_own_their_repos_hosts_and_packages() -> None:
    projects = {p.name: p for p in official.load_official()}
    assert len(projects) == 10
    ollama = projects["Ollama"]
    assert ollama.owns_repo("ollama/ollama-python")  # every repo under the org
    assert not ollama.owns_repo("0llama-dev/ollama")
    assert ollama.owns_host("ollama.com") and ollama.owns_host("www.ollama.com")
    assert not ollama.owns_host("ollama.com.evil.example")
    assert projects["Claude Code"].owns_package("npm", "@anthropic-ai/claude-code")
    assert projects["MCP reference servers"].owns_package("npm", "@modelcontextprotocol/server-git")
    assert not projects["Claude Code"].owns_package("npm", "claude-code")


def test_keywords_find_projects_in_names() -> None:
    assert [p.name for p in official.projects_named_in("ollama-install.dev")] == ["Ollama"]
    assert [p.name for p in official.projects_named_in("comfyui-pro")] == ["ComfyUI"]
    assert official.projects_named_in("codex") == []  # too common a word to mean OpenAI's
    assert official.project_owning_repo("comfyanonymous/ComfyUI").name == "ComfyUI"


# --- the popular-repos list --------------------------------------------------------------------


def test_the_shipped_list_loads_and_holds_the_viral_projects() -> None:
    index = load_index()
    assert len(index) > 1000
    for project in official.load_official():
        assert index.get(project.canonical) is not None, project.canonical


def test_lookalikes_come_most_starred_first() -> None:
    index = PopularIndex(
        [
            PopularRepo("a/ollama", 10, "2020-01-01"),
            PopularRepo("ollama/ollama", 1000, "2020-01-01"),
        ]
    )
    assert [r.full_name for r, _ in index.lookalikes("0llama-dev", "ollama")] == [
        "ollama/ollama",
        "a/ollama",
    ]
    assert index.lookalikes("ollama", "ollama") == [
        (index.repos[0], index.lookalikes("ollama", "ollama")[0][1])
    ]


def test_a_newer_list_in_the_cache_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOOKFIRST_CACHE_DIR", str(tmp_path))
    popular_index.load_index.cache_clear()
    try:
        (tmp_path / popular_index.FILE_NAME).write_bytes(
            serialize([PopularRepo("x/y", 5, "2026-01-01")], "2099-01-01")
        )
        index = load_index()
        assert [r.full_name for r in index.repos] == ["x/y"] and index.built == "2099-01-01"
        (tmp_path / popular_index.FILE_NAME).write_bytes(
            serialize([PopularRepo("x/y", 5, "2026-01-01")], "2000-01-01")
        )
        popular_index.load_index.cache_clear()
        assert len(load_index()) > 1000  # an older cache loses to the shipped list
    finally:
        popular_index.load_index.cache_clear()


def test_the_list_file_format_round_trips() -> None:
    data = serialize(
        [PopularRepo("b/b", 1, "2020-01-01"), PopularRepo("a/a", 9, "2019-01-01")], "2026-11-09"
    )
    assert gzip.decompress(data).decode().splitlines()[:3] == [
        "# built 2026-11-09",
        "full_name,stars,created",
        "a/a,9,2019-01-01",
    ]


# --- failures --------------------------------------------------------------------------------


def test_a_304_from_a_remote_server_isnt_mistaken_for_a_redirect(mock_http) -> None:
    mock_http(lambda r: httpx.Response(304))
    result = RemoteReader().get("https://x.example/i.sh")
    assert (result.status, result.reason) == ("failed", "the server answered with HTTP 304")


SEARCH_HELLO = "https://api.github.com/search/repositories?q=Hello-World%20in%3Aname&sort=stars&order=desc&per_page=10"


def test_when_github_is_down_identity_is_not_checked_but_the_rest_is(
    recorded_http, tmp_path: Path
) -> None:
    recorded = recorded_http("github_hello_world")
    recorded.override("https://api.github.com/users/octocat", lambda r: httpx.Response(503))
    report = run_check("octocat/Hello-World", cwd=tmp_path)
    assert "identity" not in report.checked and "install_path" in report.checked
    (gap,) = [n for n in report.not_checked if n.check == "identity"]
    assert gap.what == "Is this the real project?"
    assert gap.reason == "couldn't reach GitHub: GitHub answered with HTTP 503"


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (
            httpx.Response(403, headers={"x-ratelimit-remaining": "0"}),
            "GitHub's search limit is used up for now; it resets within a minute",
        ),
        (httpx.Response(502), "couldn't search GitHub: GitHub answered with HTTP 502"),
    ],
)
def test_without_search_the_identity_check_still_uses_its_lists(
    recorded_http, tmp_path: Path, response: httpx.Response, reason: str
) -> None:
    recorded = recorded_http("github_hello_world")
    recorded.override(SEARCH_HELLO, lambda r: response)
    report = run_check("octocat/Hello-World", cwd=tmp_path)
    assert "identity" in report.checked and report.identity is not None
    gaps = {n.what: n.reason for n in report.not_checked if n.check == "identity"}
    assert gaps["Repos with the same name"] == reason

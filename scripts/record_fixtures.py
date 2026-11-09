"""Record the HTTP responses the tests replay, so the tests never use the network.

Run on demand. It uses the network:

    uv run python scripts/record_fixtures.py

It runs lookfirst's own code, so the recordings match the requests the code really makes.
Only the status, a few harmless headers and the bodies are saved. Request headers, where
a token would be, are never saved, and bodies that look like they hold a token are
refused. A GitHub token (from `gh`) is used only to stay under GitHub's rate limits; the
identity check still follows its no-token path, the one the tests replay.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx

from lookfirst import pipeline
from lookfirst.core import http as lf_http
from lookfirst.core.http import github_token, make_client
from lookfirst.identity.check import check_identity
from lookfirst.identity.github import GitHubData
from lookfirst.identity.popular_index import load_index
from lookfirst.pipeline import run_check
from lookfirst.static.fetch import make_public_transport
from lookfirst.targets.models import ResolvedTarget, TargetSpec

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "http"
KEEP_HEADERS = ("content-type", "location", "etag", "last-modified", "link")
SIGNED_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")
TOKEN_PATTERN = re.compile(rb"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")

# Small, stable, permissively licensed targets (see THIRD_PARTY.md).
CHECKS: dict[str, list[str]] = {
    "github_hello_world": ["octocat/Hello-World"],
    "npm_is_number": ["npm:is-number", "npm:is-number@7.0.0"],
    "pypi_six": ["pypi:six==1.17.0"],
    # The real installers, for "benign installers pass" (allowlisted in installers.yaml).
    # Each is open source; their licenses are listed in THIRD_PARTY.md.
    "installers": [
        "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash",
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
        "curl -LsSf https://astral.sh/uv/install.sh | sh",
        "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash",
        'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"',
        "curl -fsSL https://deno.land/install.sh | sh",
        "curl -fsSL https://bun.sh/install | bash",
        "curl -fsSL https://get.docker.com | sh",
        "curl -fsSL https://ollama.com/install.sh | sh",
        # Not Claude Code's installer: it isn't open source, so it isn't copied into this repo.
    ],
}

# The originals the lookalike pairs copy. Only open-source projects, because their README
# text is recorded (licenses in THIRD_PARTY.md).
ORIGINALS = ["ollama/ollama", "ggml-org/llama.cpp", "yt-dlp/yt-dlp", "openai/codex"]

# Popular, trusted repos the identity check must never call impersonations (SPEC section 12).
# Their README text isn't recorded: for an original, lookfirst finds no more-established
# look-alike, so it never fetches one.
BENIGN = [
    "facebook/react",
    "microsoft/vscode",
    "torvalds/linux",
    "python/cpython",
    "golang/go",
    "rust-lang/rust",
    "kubernetes/kubernetes",
    "pytorch/pytorch",
    "django/django",
    "pallets/flask",
    "expressjs/express",
    "vercel/next.js",
    "tailwindlabs/tailwindcss",
    "home-assistant/core",
    "denoland/deno",
    "ohmyzsh/ohmyzsh",
    "nvm-sh/nvm",
    "sharkdp/bat",
    "jqlang/jq",
    "BurntSushi/ripgrep",
]
RECORDED_ON = datetime(2026, 11, 9, tzinfo=UTC)


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.inner = make_public_transport()
        self.entries: list[dict] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self.inner.handle_request(request)
        body = response.read()  # decoded, so content-encoding is dropped below
        response.close()
        headers = {k: response.headers[k] for k in KEEP_HEADERS if k in response.headers}
        self.entries.append(
            {
                "method": request.method,
                "url": str(request.url),
                "status": response.status_code,
                "headers": headers,
                "body": body,
            }
        )
        return httpx.Response(response.status_code, headers=headers, content=body, request=request)

    def close(self) -> None:
        self.inner.close()


class _NoStarSample(GitHubData):
    """Follow the no-token path (no GraphQL star sample) even though a token is used."""

    def __init__(
        self, client: httpx.Client, has_token: bool = False, cache: Path | None = None
    ) -> None:
        super().__init__(client, False, cache)


def record(case: str, run: Callable[[], None], *, keep_readmes: bool = True) -> None:
    recorder = RecordingTransport()
    lf_http._TRANSPORT = recorder
    try:
        run()
    finally:
        lf_http._TRANSPORT = None
        recorder.close()

    # Release downloads redirect to signed, short-lived addresses. They're harmless, but
    # secret scanners flag them, so drop their query string everywhere they appear.
    def unsign(url: str) -> str:
        if any(h in url for h in SIGNED_HOSTS):
            return url.split("?", 1)[0]
        return url

    for entry in recorder.entries:
        entry["url"] = unsign(entry["url"])
        if "location" in entry["headers"]:
            entry["headers"]["location"] = unsign(entry["headers"]["location"])

    case_dir = OUT / case
    shutil.rmtree(case_dir, ignore_errors=True)
    case_dir.mkdir(parents=True)
    index, seen = [], set()
    for entry in recorder.entries:
        key = (entry["method"], entry["url"])
        if key in seen:
            continue
        seen.add(key)
        body: bytes = entry["body"]
        if TOKEN_PATTERN.search(body):
            raise SystemExit(
                f"Refusing to save {entry['url']}: the body looks like it holds a token."
            )
        if not keep_readmes and entry["url"].endswith("/readme"):
            raise SystemExit(
                f"{case} fetched a README ({entry['url']}); its text must not be recorded."
            )
        name = None
        if body:
            number = len(index)
            if "json" in entry["headers"].get("content-type", ""):
                name = f"{number:02d}.json"
                trimmed = _trim(entry["url"], json.loads(body))
                pretty = json.dumps(trimmed, indent=2, ensure_ascii=False) + "\n"
                (case_dir / name).write_text(pretty, encoding="utf-8")
            else:
                name = f"{number:02d}.bin"
                (case_dir / name).write_bytes(body)
        index.append(
            {**{k: entry[k] for k in ("method", "url", "status", "headers")}, "body": name}
        )
    (case_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"{case}: {len(index)} responses")


def _trim(url: str, data: object) -> object:
    """Keep only the fields lookfirst reads from release lists, search results and
    account profiles: the rest is megabytes of asset details, or personal details."""
    if "/releases" in url and isinstance(data, list):
        return [
            {
                "tag_name": r.get("tag_name"),
                "assets": [{"name": a.get("name")} for a in r.get("assets", [])],
            }
            for r in data
            if isinstance(r, dict)
        ]
    if "/users/" in url and isinstance(data, dict):
        # Only what the identity check reads: no names, emails or locations.
        keep = ("login", "type", "created_at", "public_repos", "followers")
        return {k: data.get(k) for k in keep}
    if "/search/repositories" in url and isinstance(data, dict):
        keep = ("full_name", "stargazers_count", "created_at", "default_branch", "fork")
        items = [{k: i.get(k) for k in keep} for i in data.get("items", []) if isinstance(i, dict)]
        return {"total_count": data.get("total_count"), "items": items}
    return data


def _originals() -> None:
    with make_client(token=os.environ.get("GITHUB_TOKEN")) as client:
        data = _NoStarSample(client, has_token=False)
        for full in ORIGINALS:
            data.repo(full)
            data.readme(full)
            data.releases(full)


def _benign() -> None:
    with make_client(token=os.environ.get("GITHUB_TOKEN")) as client:
        data = _NoStarSample(client, has_token=False)
        for full in BENIGN:
            meta = data.repo(full)
            assert meta, full
            target = ResolvedTarget(
                TargetSpec(kind="github", raw=full),
                root=None,
                resolved=full,
                metadata={"repo": meta},
            )
            check_identity(target, data, load_index(), now=RECORDED_ON)


def main() -> None:
    token = github_token()
    for var in ("GH_TOKEN", "LOOKFIRST_NO_GH_TOKEN"):
        os.environ.pop(var, None)
    if token:
        os.environ["GITHUB_TOKEN"] = token  # only ever sent to api.github.com
    os.environ["LOOKFIRST_CACHE_DIR"] = tempfile.mkdtemp(prefix="lookfirst-record-")  # no 304s
    pipeline.GitHubData = _NoStarSample  # type: ignore[misc]
    for case, targets in CHECKS.items():
        record(case, lambda targets=targets: [run_check(raw, cwd=ROOT) for raw in targets] and None)
    record("identity_originals", _originals)
    record("identity_benign", _benign, keep_readmes=False)


if __name__ == "__main__":
    main()

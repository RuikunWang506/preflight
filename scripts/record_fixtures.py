"""Record the HTTP responses the tests replay, so the tests never use the network.

Run on demand. It uses the network, without any token:

    uv run python scripts/record_fixtures.py

It runs lookfirst's own fetchers, so the recordings match the requests the
code really makes. Only the status, a few harmless headers and the bodies
are saved. Request headers, where a token would be, are never saved.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import httpx

from lookfirst.core import http as lf_http
from lookfirst.pipeline import run_check
from lookfirst.static.fetch import make_public_transport

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "http"
KEEP_HEADERS = ("content-type", "location", "etag", "last-modified")
SIGNED_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")
TOKEN_PATTERN = re.compile(rb"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")

# Small, stable, permissively licensed targets (see THIRD_PARTY.md).
CASES: dict[str, list[str]] = {
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


def record(case: str, targets: list[str]) -> None:
    recorder = RecordingTransport()
    lf_http._TRANSPORT = recorder
    try:
        for raw in targets:
            run_check(raw, cwd=ROOT)
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
        name = None
        if body:
            number = len(index)
            if "json" in entry["headers"].get("content-type", ""):
                name = f"{number:02d}.json"
                pretty = json.dumps(json.loads(body), indent=2, ensure_ascii=False) + "\n"
                (case_dir / name).write_text(pretty, encoding="utf-8")
            else:
                name = f"{number:02d}.bin"
                (case_dir / name).write_bytes(body)
        index.append(
            {**{k: entry[k] for k in ("method", "url", "status", "headers")}, "body": name}
        )
    (case_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"{case}: {len(index)} responses")


def main() -> None:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        os.environ.pop(var, None)
    os.environ["LOOKFIRST_NO_GH_TOKEN"] = "1"  # noqa: S105 - record without any token
    for case, targets in CASES.items():
        record(case, targets)


if __name__ == "__main__":
    main()

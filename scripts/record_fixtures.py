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
from lookfirst.targets.base import open_target, parse_target

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "http"
KEEP_HEADERS = ("content-type", "location", "etag", "last-modified")
TOKEN_PATTERN = re.compile(rb"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")

# Small, stable, permissively licensed targets (see THIRD_PARTY.md).
CASES: dict[str, list[str]] = {
    "github_hello_world": ["octocat/Hello-World"],
    "npm_is_number": ["npm:is-number", "npm:is-number@7.0.0"],
    "pypi_six": ["pypi:six==1.17.0"],
}


class RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.inner = httpx.HTTPTransport()
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
            with open_target(parse_target(raw, cwd=ROOT)):
                pass
    finally:
        lf_http._TRANSPORT = None
        recorder.close()

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

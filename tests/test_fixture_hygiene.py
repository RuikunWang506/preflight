"""The recorded fixtures must never hold a token, and every recording must be complete."""

import json
import re

from conftest import FIXTURES, HTTP_FIXTURES

TOKEN_PATTERN = re.compile(rb"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")


def test_no_fixture_contains_a_github_token() -> None:
    offenders = [
        p for p in FIXTURES.rglob("*") if p.is_file() and TOKEN_PATTERN.search(p.read_bytes())
    ]
    assert offenders == []


def test_every_recorded_body_exists_and_nothing_is_left_over() -> None:
    for case_dir in HTTP_FIXTURES.iterdir():
        index = json.loads((case_dir / "index.json").read_text())
        named = {entry["body"] for entry in index if entry["body"]}
        on_disk = {p.name for p in case_dir.iterdir() if p.name != "index.json"}
        assert named == on_disk, case_dir.name
        for entry in index:
            assert entry["url"].startswith("https://"), entry["url"]
            assert "authorization" not in {k.lower() for k in entry["headers"]}

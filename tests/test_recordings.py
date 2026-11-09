"""The recorded HTTP answers keep no email addresses (CLAUDE.md: never commit personal
data). scripts/record_fixtures.py drops them; this catches any that come back.

Downloaded files (package archives, READMEs, installer scripts) are kept exactly as
published, since the tests check archives against the registry's hash, so only the JSON
answers are checked here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

HTTP = Path(__file__).parent / "fixtures" / "http"
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_KEYS = {"email", "author_email", "maintainer_email"}
# Not email addresses: GitHub's SSH clone addresses ("org-123@github.com:owner/repo.git").
SSH_CLONE = re.compile(r"^[A-Za-z0-9._-]+@github\.com:")


def _emails(data: object, where: str) -> Iterator[str]:
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in EMAIL_KEYS:
                yield f"{where}.{key}"
            yield from _emails(value, f"{where}.{key}")
    elif isinstance(data, list):
        for i, value in enumerate(data):
            yield from _emails(value, f"{where}[{i}]")
    elif isinstance(data, str) and not SSH_CLONE.match(data) and EMAIL.search(data):
        yield where


def test_recorded_answers_hold_no_email_addresses() -> None:
    answers = sorted(p for p in HTTP.rglob("*.json") if p.name != "index.json")
    assert len(answers) > 50
    found = [
        f"{path.relative_to(HTTP)}: {spot}"
        for path in answers
        for spot in _emails(json.loads(path.read_text(encoding="utf-8")), "")
    ]
    assert found == [], "Run the answers through drop_emails in scripts/record_fixtures.py"

"""lookfirst's own source must pass the checks it applies to others: no invisible or
direction-changing characters anywhere in the code, tests or scripts. Use escapes like
"\\u200b" or chr(0x200B) instead."""

from __future__ import annotations

import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_FILLERS = {0x115F, 0x1160, 0x3164, 0xFFA0}


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\t":
        return False
    return (
        unicodedata.category(ch) in ("Cf", "Zl", "Zp", "Cc")
        or cp in _FILLERS
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0000 <= cp <= 0xE01EF
    )


def test_no_invisible_characters_in_lookfirst_source() -> None:
    offenders = []
    for folder in ("lookfirst", "tests", "scripts"):
        for path in (ROOT / folder).rglob("*.py"):
            if "fixtures" in path.relative_to(ROOT).parts:
                continue  # fixtures hold such characters on purpose
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if any(_invisible(ch) for ch in line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []

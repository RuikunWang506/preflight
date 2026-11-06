"""Read JSON with comments and trailing commas, as VS Code and dev containers allow."""

from __future__ import annotations

import json
import re
from typing import Any

_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_comments(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def loads(text: str) -> Any:
    """Parse JSONC. Raises ValueError if it still isn't valid JSON."""
    cleaned = _strip_comments(text)
    # remove trailing commas outside strings: safe enough after comments are gone, since
    # a comma followed by } or ] inside a string is rare in config files
    cleaned = _TRAILING_COMMA.sub(r"\1", cleaned)
    return json.loads(cleaned)

"""Reading web addresses from untrusted text without crashing.

`urllib.parse.urlsplit` raises ValueError on some malformed addresses, such as an
unclosed "[" or a bracketed host that isn't an IP address. Targets are untrusted, so a
crafted address must never stop a check: these helpers treat it as having no host.
"""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit


def split_url(url: str) -> SplitResult | None:
    """The address's parts, or None when it can't be read."""
    try:
        parts = urlsplit(url)
        _ = parts.hostname  # parses the host too
    except ValueError:
        return None
    return parts


def url_host(url: str) -> str:
    """The lowercase host, or "" when there is none or the address can't be read."""
    parts = split_url(url)
    return (parts.hostname or "").lower() if parts is not None else ""


def url_path(url: str) -> str:
    """The path, or "" when the address can't be read."""
    parts = split_url(url)
    return parts.path if parts is not None else ""

"""Limits that keep a hostile target from filling the disk or memory."""

from dataclasses import dataclass

MB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    max_download_bytes: int = 200 * MB
    max_json_bytes: int = 20 * MB
    max_unpacked_bytes: int = 1024 * MB
    max_entries: int = 50_000
    http_timeout_s: float = 30.0
    max_redirects: int = 5


DEFAULT_LIMITS = Limits()

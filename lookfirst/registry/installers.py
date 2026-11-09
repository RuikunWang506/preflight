"""The allowlist of well-known installers (installers.yaml)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib.resources import files

import yaml


@dataclass(frozen=True)
class Installer:
    name: str
    urls: tuple[str, ...]
    prefixes: tuple[str, ...]
    sha256: str | None
    seen: str | None


def _normalize(url: str) -> str:
    return url.strip().rstrip("/")


@cache
def load_installers() -> tuple[Installer, ...]:
    text = files("lookfirst.registry").joinpath("installers.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    out = []
    for entry in data.get("installers", []):
        out.append(
            Installer(
                name=str(entry["name"]),
                urls=tuple(_normalize(u) for u in entry.get("urls", [])),
                prefixes=tuple(str(p) for p in entry.get("prefixes", [])),
                sha256=str(entry["sha256"]).lower() if entry.get("sha256") else None,
                seen=str(entry["seen"]) if entry.get("seen") else None,
            )
        )
    return tuple(out)


def match_installer(url: str) -> Installer | None:
    """The installer this exact URL (or an official versioned path) belongs to, if any."""
    if not url.startswith("https://"):
        return None  # only the https address counts as official
    normalized = _normalize(url)
    for installer in load_installers():
        if normalized in installer.urls:
            return installer
        if any(url.startswith(prefix) for prefix in installer.prefixes):
            return installer
    return None

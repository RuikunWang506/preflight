"""Read a target's files without trusting them.

Links are never followed: a "README.md" that's really a link to ~/.ssh/id_rsa must not
end up quoted in a report. Files are read with size caps, and folder walks skip the
usual dependency and build folders.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

MAX_FILE_BYTES = 1024 * 1024
SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "vendor",
        "target",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "site-packages",
        ".next",
        "coverage",
    }
)


def _is_inside_without_links(root: Path, path: Path) -> bool:
    """True if path is inside root and no part of it (below root) is a link."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return False
    return True


def read_text(root: Path, rel: str, *, max_bytes: int = MAX_FILE_BYTES) -> str | None:
    """Read root/rel as text, or None if it's missing, a link, not a file, or too big."""
    path = root / rel
    if not _is_inside_without_links(root, path):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        try:
            if not os.path.isfile(path) or os.fstat(f.fileno()).st_size > max_bytes:
                return None
        except OSError:
            return None
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes or b"\x00" in data[:8192]:
        return None  # too big, or not text
    return data.decode("utf-8", "replace")


def exists(root: Path, rel: str) -> bool:
    path = root / rel
    return _is_inside_without_links(root, path) and path.is_file()


def walk(
    root: Path, *, max_files: int = 20_000, suffixes: frozenset[str] | None = None
) -> Iterator[str]:
    """Yield relative POSIX paths of regular files under root, never following links."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink()
        )
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink() or not path.is_file():
                continue
            if (
                suffixes is not None
                and path.suffix.lower() not in suffixes
                and name not in suffixes
            ):
                continue
            yield path.relative_to(root).as_posix()
            count += 1
            if count >= max_files:
                return

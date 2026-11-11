"""Moving files into and out of containers as tar streams (`docker cp`), so no folder is ever
mounted. Files from the target are copied without following links: a link to ~/.ssh in a
project can't pull your real key into the sandbox."""

from __future__ import annotations

import io
import os
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

UID = GID = 1000  # the sandbox user
MAX_COPY_BYTES = 200 * 1024 * 1024
MAX_COPY_FILES = 50_000
# Installed dependencies and caches: the install makes its own.
SKIP = frozenset(
    {".git", "node_modules", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox"}
)


class TooBig(Exception):
    """The target is bigger than the sandbox copies."""


@dataclass(frozen=True)
class Entry:
    path: str  # inside the container, without the leading "/"
    data: bytes | None = None  # None for a folder
    mode: int = 0o644


def project_entries(root: Path) -> list[Entry]:
    """The target's files, relative to its folder: regular files and folders only, never
    links."""
    entries: list[Entry] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP and not (here / d).is_symlink())
        rel_dir = here.relative_to(root).as_posix()
        if rel_dir != ".":
            entries.append(Entry(rel_dir, None, 0o755))
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink() or not path.is_file():
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                continue
            with os.fdopen(fd, "rb") as f:
                data = f.read(MAX_COPY_BYTES + 1)
            total += len(data)
            if total > MAX_COPY_BYTES or len(entries) > MAX_COPY_FILES:
                raise TooBig(
                    f"over {MAX_COPY_BYTES // (1024 * 1024)} MB or {MAX_COPY_FILES:,} files"
                )
            executable = os.stat(path, follow_symlinks=False).st_mode & 0o111
            rel = path.relative_to(root).as_posix()
            entries.append(Entry(rel, data, 0o755 if executable else 0o644))
    return entries


def pack(entries: list[Entry]) -> bytes:
    """A tar stream owned by the sandbox user, with the folders each file needs."""
    buffer = io.BytesIO()
    made: set[str] = set()
    now = int(time.time())  # tools such as mitmproxy ignore files dated 1970
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for entry in entries:
            parts = entry.path.split("/")
            for i in range(1, len(parts) if entry.data is not None else len(parts) + 1):
                folder = "/".join(parts[:i])
                if folder and folder not in made:
                    made.add(folder)
                    info = tarfile.TarInfo(folder)
                    info.type, info.mode, info.uid, info.gid = tarfile.DIRTYPE, 0o755, UID, GID
                    info.mtime = now
                    tar.addfile(info)
            if entry.data is None:
                continue
            info = tarfile.TarInfo(entry.path)
            info.size, info.mode, info.uid, info.gid = len(entry.data), entry.mode, UID, GID
            info.mtime = now
            tar.addfile(info, io.BytesIO(entry.data))
    return buffer.getvalue()


def first_file(stream: bytes, max_bytes: int) -> bytes | None:
    """The first regular file in a `docker cp CONTAINER:PATH -` stream."""
    try:
        with tarfile.open(fileobj=io.BytesIO(stream), mode="r:") as tar:
            for member in tar:
                if member.isfile():
                    handle = tar.extractfile(member)
                    return handle.read(max_bytes) if handle else None
    except tarfile.TarError:
        return None
    return None

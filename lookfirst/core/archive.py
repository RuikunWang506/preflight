"""Unpack a downloaded archive without trusting it.

Only regular files and folders are written. Links, devices and entries that
would land outside the destination are skipped and recorded in the manifest,
so later checks can report them. Nothing unpacked is ever executable: files
are written 0644 and each file's original permissions are kept as data.
"""

from __future__ import annotations

import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Literal

from lookfirst.core.config import DEFAULT_LIMITS, MB, Limits
from lookfirst.core.errors import UnsafeArchiveError

FILE_MODE = 0o644
_CHUNK = 1024 * 1024
_DRIVE = re.compile(r"^[A-Za-z]:$")
_MAX_NAME_IN_MANIFEST = 300


@dataclass(frozen=True)
class ArchiveFile:
    path: str  # relative POSIX path inside the archive
    size: int
    mode: int  # permission bits recorded in the archive (not applied on disk)

    @property
    def executable(self) -> bool:
        return bool(self.mode & 0o111)


@dataclass(frozen=True)
class ArchiveLink:
    path: str
    target: str
    kind: Literal["symlink", "hardlink"]


@dataclass(frozen=True)
class SkippedEntry:
    path: str
    reason: str


@dataclass
class ArchiveManifest:
    files: list[ArchiveFile] = field(default_factory=list)
    links: list[ArchiveLink] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    total_bytes: int = 0
    root: str = ""  # the single top-level folder, if everything was inside one
    _entries: int = field(default=0, repr=False)
    _by_casefold: dict[str, str] = field(default_factory=dict, repr=False)
    _file_index: dict[str, int] = field(default_factory=dict, repr=False)

    def skip(self, name: str, reason: str) -> None:
        self.skipped.append(SkippedEntry(name[:_MAX_NAME_IN_MANIFEST], reason))


def safe_relpath(name: str) -> str | None:
    """Return a clean relative POSIX path for an archive entry, or None if it's unsafe."""
    if not name or "\x00" in name:
        return None
    if name.startswith("/"):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or ".." in parts or _DRIVE.match(parts[0]):
        return None
    return "/".join(parts)


def unpack(archive: Path, dest: Path, *, limits: Limits = DEFAULT_LIMITS) -> ArchiveManifest:
    """Unpack a zip, tar, tar.gz or other compressed tar into dest."""
    dest.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive):
        manifest = _unpack_zip(archive, dest, limits)
    elif _is_tar(archive):
        manifest = _unpack_tar(archive, dest, limits)
    else:
        raise UnsafeArchiveError(
            "The download isn't a zip or tar archive, so lookfirst can't read it."
        )
    manifest.root = _single_root(manifest)
    return manifest


def _is_tar(archive: Path) -> bool:
    try:
        return tarfile.is_tarfile(archive)
    except (OSError, tarfile.TarError, EOFError):
        return False


def _count(manifest: ArchiveManifest, limits: Limits) -> None:
    manifest._entries += 1
    if manifest._entries > limits.max_entries:
        raise UnsafeArchiveError(
            f"The archive has more than {limits.max_entries:,} entries, "
            "so lookfirst stopped unpacking it."
        )


def _make_dir(dest: Path, rel: str, manifest: ArchiveManifest) -> None:
    try:
        dest.joinpath(*rel.split("/")).mkdir(parents=True, exist_ok=True)
    except OSError:
        manifest.skip(rel, "clashes with a file of the same name")


def _write_file(
    dest: Path, rel: str, source: IO[bytes], mode: int, manifest: ArchiveManifest, limits: Limits
) -> None:
    other = manifest._by_casefold.get(rel.casefold())
    if other is not None and other != rel:
        # On a Mac's default disk these two names would be the same file.
        manifest.skip(rel, f"name differs from {other[:_MAX_NAME_IN_MANIFEST]} only in letter case")
        return
    target = dest.joinpath(*rel.split("/"))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, FILE_MODE)
    except OSError:
        manifest.skip(rel, "clashes with a folder or file of the same name")
        return
    size = 0
    with os.fdopen(fd, "wb") as out:
        while chunk := source.read(_CHUNK):
            size += len(chunk)
            manifest.total_bytes += len(chunk)
            if manifest.total_bytes > limits.max_unpacked_bytes:
                raise UnsafeArchiveError(
                    f"The archive unpacks to more than {limits.max_unpacked_bytes // MB} MB, "
                    "so lookfirst stopped unpacking it."
                )
            out.write(chunk)
    entry = ArchiveFile(path=rel, size=size, mode=mode & 0o7777)
    manifest._by_casefold[rel.casefold()] = rel
    if rel in manifest._file_index:  # the same name twice: the later copy wins, as with tar
        manifest.files[manifest._file_index[rel]] = entry
    else:
        manifest._file_index[rel] = len(manifest.files)
        manifest.files.append(entry)


def _unpack_tar(archive: Path, dest: Path, limits: Limits) -> ArchiveManifest:
    manifest = ArchiveManifest()
    try:
        with tarfile.open(archive, mode="r:*") as tar:
            for member in tar:
                _count(manifest, limits)
                rel = safe_relpath(member.name)
                if rel is None:
                    manifest.skip(member.name, "path points outside the archive's folder")
                elif member.issym():
                    manifest.links.append(ArchiveLink(rel, member.linkname, "symlink"))
                elif member.islnk():
                    manifest.links.append(ArchiveLink(rel, member.linkname, "hardlink"))
                elif member.isdir():
                    _make_dir(dest, rel, manifest)
                elif not member.isfile():
                    manifest.skip(rel, "not a regular file (a device, pipe or other special file)")
                else:
                    source = tar.extractfile(member)
                    if source is None:
                        manifest.skip(rel, "couldn't be read from the archive")
                        continue
                    with source:
                        _write_file(dest, rel, source, member.mode, manifest, limits)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise UnsafeArchiveError(
            "The archive is damaged or in a format lookfirst can't read."
        ) from exc
    return manifest


def _unpack_zip(archive: Path, dest: Path, limits: Limits) -> ArchiveManifest:
    manifest = ArchiveManifest()
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                _count(manifest, limits)
                # Zip files made on Windows may use backslashes as folder separators.
                rel = safe_relpath(info.filename.replace("\\", "/"))
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if rel is None:
                    manifest.skip(info.filename, "path points outside the archive's folder")
                elif stat.S_ISLNK(unix_mode):
                    with zf.open(info) as source:
                        link_target = source.read(4096).decode("utf-8", "replace")
                    manifest.links.append(ArchiveLink(rel, link_target, "symlink"))
                elif info.is_dir():
                    _make_dir(dest, rel, manifest)
                elif info.flag_bits & 0x1:
                    manifest.skip(rel, "encrypted, so it can't be read")
                elif stat.S_IFMT(unix_mode) not in (0, stat.S_IFREG):
                    manifest.skip(rel, "not a regular file (a device, pipe or other special file)")
                else:
                    with zf.open(info) as source:
                        _write_file(dest, rel, source, unix_mode or FILE_MODE, manifest, limits)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, OSError) as exc:
        raise UnsafeArchiveError(
            "The archive is damaged or in a format lookfirst can't read."
        ) from exc
    return manifest


def _single_root(manifest: ArchiveManifest) -> str:
    tops = {f.path.split("/", 1)[0] for f in manifest.files if "/" in f.path}
    loose = [f for f in manifest.files if "/" not in f.path]
    if len(tops) == 1 and not loose:
        return tops.pop()
    return ""

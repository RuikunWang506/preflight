"""Builders for harmless test archives. They hold short text, and nothing in them is ever run."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TarEntry:
    name: str
    data: bytes = b""
    type: bytes = tarfile.REGTYPE
    mode: int = 0o644
    linkname: str = ""


def make_tar(path: Path, entries: list[TarEntry], *, compress: bool = True) -> Path:
    with tarfile.open(path, "w:gz" if compress else "w") as tar:
        for e in entries:
            info = tarfile.TarInfo(e.name)
            info.type = e.type
            info.mode = e.mode
            info.linkname = e.linkname
            if e.type == tarfile.REGTYPE:
                info.size = len(e.data)
                tar.addfile(info, io.BytesIO(e.data))
            else:
                tar.addfile(info)
    return path


@dataclass
class ZipEntry:
    name: str
    data: bytes = b""
    mode: int = stat.S_IFREG | 0o644
    flag_bits: int = 0


def make_zip(path: Path, entries: list[ZipEntry]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for e in entries:
            info = zipfile.ZipInfo(e.name)
            info.external_attr = e.mode << 16
            zf.writestr(info, e.data)
    extra_flags = 0
    for e in entries:
        extra_flags |= e.flag_bits
    if extra_flags:
        # zipfile resets flag bits when writing, so set them in the bytes: the
        # flags field sits 6 bytes into each local header and 8 into each
        # central directory header.
        data = bytearray(path.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (at := data.find(signature, start)) != -1:
                flags = int.from_bytes(data[at + offset : at + offset + 2], "little") | extra_flags
                data[at + offset : at + offset + 2] = flags.to_bytes(2, "little")
                start = at + 4
        path.write_bytes(bytes(data))
    return path

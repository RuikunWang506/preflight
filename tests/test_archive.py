"""Hostile archives, built here from harmless text. Nothing in them is ever run."""

import stat
import tarfile
from pathlib import Path

import pytest
from helpers import TarEntry, ZipEntry, make_tar, make_zip

from lookfirst.core.archive import FILE_MODE, safe_relpath, unpack
from lookfirst.core.config import Limits
from lookfirst.core.errors import UnsafeArchiveError


def files_on_disk(root: Path) -> set[str]:
    return {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()
    }


def test_a_normal_tarball_unpacks_under_its_top_folder(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "a.tar.gz",
        [
            TarEntry("pkg-1.0/", type=tarfile.DIRTYPE, mode=0o755),
            TarEntry("pkg-1.0/README.md", b"# hello\n"),
            TarEntry("pkg-1.0/src/main.py", b"print('hi')\n"),
        ],
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert manifest.root == "pkg-1.0"
    assert files_on_disk(dest) == {"pkg-1.0/README.md", "pkg-1.0/src/main.py"}
    assert (dest / "pkg-1.0/README.md").read_bytes() == b"# hello\n"
    assert manifest.total_bytes == len(b"# hello\n") + len(b"print('hi')\n")


def test_nothing_unpacked_is_executable_but_the_original_mode_is_kept(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [TarEntry("install.sh", b"echo hi\n", mode=0o4755)])
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    on_disk = stat.S_IMODE((dest / "install.sh").stat().st_mode)
    assert on_disk & 0o111 == 0
    assert on_disk & ~FILE_MODE == 0
    (entry,) = manifest.files
    assert entry.mode == 0o4755
    assert entry.executable


@pytest.mark.parametrize(
    "name", ["../evil.txt", "a/../../evil.txt", "/tmp/evil.txt", "C:/evil.txt"]
)
def test_paths_that_escape_are_skipped_and_recorded(name: str, tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [TarEntry(name, b"x"), TarEntry("ok.txt", b"ok")])
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert files_on_disk(dest) == {"ok.txt"}
    assert [s.path for s in manifest.skipped] == [name]
    assert not (tmp_path / "evil.txt").exists()


def test_links_are_recorded_and_never_created(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "a.tar.gz",
        [
            TarEntry("passwd", type=tarfile.SYMTYPE, linkname="/etc/passwd"),
            TarEntry("hard", type=tarfile.LNKTYPE, linkname="../../outside"),
            TarEntry("ok.txt", b"ok"),
        ],
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert files_on_disk(dest) == {"ok.txt"}
    assert [(link.path, link.target, link.kind) for link in manifest.links] == [
        ("passwd", "/etc/passwd", "symlink"),
        ("hard", "../../outside", "hardlink"),
    ]


@pytest.mark.parametrize("kind", [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE])
def test_special_files_are_skipped(kind: bytes, tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [TarEntry("dev", type=kind)])
    manifest = unpack(archive, tmp_path / "out")
    assert files_on_disk(tmp_path / "out") == set()
    assert "special file" in manifest.skipped[0].reason


def test_names_that_differ_only_in_case_keep_the_first(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "a.tar.gz", [TarEntry("README.md", b"first"), TarEntry("readme.md", b"second")]
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert [f.path for f in manifest.files] == ["README.md"]
    assert (dest / "README.md").read_bytes() == b"first"
    assert "letter case" in manifest.skipped[0].reason


def test_the_same_name_twice_keeps_the_later_copy(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "a.tar.gz", [TarEntry("a.txt", b"one"), TarEntry("a.txt", b"two")]
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert (dest / "a.txt").read_bytes() == b"two"
    assert [(f.path, f.size) for f in manifest.files] == [("a.txt", 3)]


def test_a_file_where_a_folder_should_be_is_skipped(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [TarEntry("a", b"file"), TarEntry("a/b.txt", b"x")])
    manifest = unpack(archive, tmp_path / "out")
    assert [f.path for f in manifest.files] == ["a"]
    assert manifest.skipped[0].path == "a/b.txt"


def test_too_many_entries_stops_unpacking(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [TarEntry(f"f{i}.txt", b"") for i in range(11)])
    with pytest.raises(UnsafeArchiveError, match="more than 10 entries"):
        unpack(archive, tmp_path / "out", limits=Limits(max_entries=10))


def test_too_many_bytes_stops_unpacking(tmp_path: Path) -> None:
    # Compresses to a few hundred bytes but unpacks to 3 MB.
    archive = make_tar(tmp_path / "a.tar.gz", [TarEntry("big.txt", b"\0" * 3 * 1024 * 1024)])
    with pytest.raises(UnsafeArchiveError, match="more than 2 MB"):
        unpack(archive, tmp_path / "out", limits=Limits(max_unpacked_bytes=2 * 1024 * 1024))


def test_a_zip_unpacks_like_a_tarball(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "a.whl",
        [ZipEntry("pkg/__init__.py", b"x = 1\n"), ZipEntry("pkg/data.txt", b"d")],
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert manifest.root == "pkg"
    assert files_on_disk(dest) == {"pkg/__init__.py", "pkg/data.txt"}


def test_zip_backslash_paths_cant_escape(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "a.zip", [ZipEntry("..\\evil.txt", b"x"), ZipEntry("ok.txt", b"ok")]
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert files_on_disk(dest) == {"ok.txt"}
    assert manifest.skipped[0].path == "..\\evil.txt"


def test_zip_symlinks_are_recorded_and_never_created(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "a.zip", [ZipEntry("link", b"/etc/passwd", mode=stat.S_IFLNK | 0o777)]
    )
    dest = tmp_path / "out"
    manifest = unpack(archive, dest)
    assert files_on_disk(dest) == set()
    assert [(link.path, link.target) for link in manifest.links] == [("link", "/etc/passwd")]


def test_encrypted_zip_entries_are_skipped(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "a.zip", [ZipEntry("secret.txt", b"x", flag_bits=0x1)])
    manifest = unpack(archive, tmp_path / "out")
    assert files_on_disk(tmp_path / "out") == set()
    assert "encrypted" in manifest.skipped[0].reason


def test_something_that_isnt_an_archive_is_refused(tmp_path: Path) -> None:
    junk = tmp_path / "junk.tgz"
    junk.write_bytes(b"this is not an archive")
    with pytest.raises(UnsafeArchiveError, match="isn't a zip or tar"):
        unpack(junk, tmp_path / "out")


def test_a_damaged_tarball_is_refused(tmp_path: Path) -> None:
    good = make_tar(tmp_path / "a.tar", [TarEntry("a.txt", b"x" * 5000)], compress=False)
    damaged = tmp_path / "damaged.tar"
    damaged.write_bytes(good.read_bytes()[:1200])
    with pytest.raises(UnsafeArchiveError):
        unpack(damaged, tmp_path / "out")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a/b.txt", "a/b.txt"),
        ("./a//b.txt", "a/b.txt"),
        ("a/./b.txt", "a/b.txt"),
        ("", None),
        (".", None),
        ("..", None),
        ("a/../b", None),
        ("/abs", None),
        ("C:", None),
        ("a\x00b", None),
    ],
)
def test_safe_relpath(name: str, expected: str | None) -> None:
    assert safe_relpath(name) == expected

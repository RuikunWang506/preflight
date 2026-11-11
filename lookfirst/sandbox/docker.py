"""Driving Docker through its command-line tool (M5 decision 1), the way lookfirst runs its
other outside tools: no Python Docker library, commands as lists and never a shell
string, a time limit on every call, and no GitHub token or other secrets passed on.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from lookfirst.scanners import base

# Docker's own settings, kept on top of the scanners' minimal environment.
_DOCKER_ENV = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "DOCKER_API_VERSION",
)
MAX_OUTPUT = 512 * 1024 * 1024  # a big install's trace can run to hundreds of MB
_ARCHES = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64"}


class DockerError(Exception):
    """A docker command failed. The message says which, in plain English."""


class DockerTimeout(DockerError):
    """A docker command didn't finish in time."""


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: str


@dataclass(frozen=True)
class Attached:
    """What `docker start --attach` left behind: the container's output, in two files."""

    stdout: Path
    stderr: Path
    timed_out: bool


class Docker:
    def __init__(self, executable: Path) -> None:
        self.executable = executable

    def env(self) -> dict[str, str]:
        env = base.tool_env()
        env.update({k: v for k, v in os.environ.items() if k in _DOCKER_ENV})
        return env

    def run(
        self,
        args: list[str],
        *,
        timeout: float = 120,
        stdin: bytes | None = None,
        check: bool = True,
    ) -> Result:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.run(  # noqa: S603 - the docker CLI, list args, no shell
                    [str(self.executable), *args],
                    input=stdin,
                    stdin=None if stdin is not None else subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    env=self.env(),
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise DockerTimeout(f"`docker {args[0]}` didn't finish in time") from exc
            except OSError as exc:
                raise DockerError(f"Docker couldn't be started ({exc.strerror or exc})") from exc
            if os.fstat(out.fileno()).st_size > MAX_OUTPUT:
                raise DockerError(f"`docker {args[0]}` printed more than lookfirst reads")
            out.seek(0)
            err.seek(0)
            result = Result(proc.returncode, out.read(), err.read().decode("utf-8", "replace"))
        if check and result.returncode != 0:
            detail = base.last_line(result.stderr) or f"exit code {result.returncode}"
            raise DockerError(f"`docker {args[0]}` failed: {detail[:300]}")
        return result

    def start_attached(self, container: str, *, timeout: float, folder: Path) -> Attached:
        """Start a created container and wait for it, its output going to two files. On a
        timeout the container keeps running; the caller decides what to do with it."""
        stdout, stderr = folder / "stdout", folder / "stderr"
        with stdout.open("wb") as out, stderr.open("wb") as err:
            try:
                subprocess.run(  # noqa: S603 - the docker CLI, list args, no shell
                    [str(self.executable), "start", "--attach", container],
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    env=self.env(),
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return Attached(stdout, stderr, timed_out=True)
            except OSError as exc:
                raise DockerError(f"Docker couldn't be started ({exc.strerror or exc})") from exc
        return Attached(stdout, stderr, timed_out=False)

    def engine(self) -> tuple[str, str] | None:
        """(version, architecture) of the Docker engine, or None if it isn't running."""
        try:
            result = self.run(
                ["version", "--format", "{{.Server.Version}} {{.Server.Arch}}"],
                timeout=20,
                check=False,
            )
        except DockerError:
            return None
        parts = result.stdout.decode("utf-8", "replace").split()
        if result.returncode != 0 or len(parts) != 2:
            return None
        return parts[0], _ARCHES.get(parts[1], parts[1])


def find_docker() -> Docker | None:
    executable = base.locate("docker")
    return Docker(executable) if executable else None

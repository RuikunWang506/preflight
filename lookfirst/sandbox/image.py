"""The two images a run needs: the sandbox, built on this computer from the Dockerfile
next to this file, and the recording proxy, pulled by digest."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from functools import cache
from importlib.resources import files

from lookfirst.sandbox.docker import Docker, DockerError

# mitmproxy 12.3.1 (MIT), pinned by digest: an index covering arm64 and amd64.
PROXY_IMAGE = (
    "mitmproxy/mitmproxy:12.3.1"
    "@sha256:2711066c855659b5af8b1dbb84494ed3eff69b42ece439c60b4fe09a2db829d4"
)
LABEL = "lookfirst.sandbox"
BUILD_TIMEOUT = 20 * 60
PULL_TIMEOUT = 10 * 60


@cache
def dockerfile() -> str:
    return files("lookfirst.sandbox").joinpath("Dockerfile").read_text(encoding="utf-8")


def sandbox_tag(arch: str) -> str:
    """Named after the recipe, so a changed Dockerfile builds a new image."""
    digest = hashlib.sha256(dockerfile().encode()).hexdigest()[:12]
    return f"lookfirst-sandbox:{digest}-{arch}"


def image_id(docker: Docker, image: str) -> str | None:
    result = docker.run(["image", "inspect", image, "--format", "{{.Id}}"], check=False)
    text = result.stdout.decode("utf-8", "replace").strip()
    return text if result.returncode == 0 and text else None


def ensure_sandbox_image(
    docker: Docker, arch: str, *, on_build: Callable[[], None] | None = None
) -> str:
    """The sandbox image's id, building it first if this computer doesn't have it."""
    tag = sandbox_tag(arch)
    found = image_id(docker, tag)
    if found:
        return found
    if on_build is not None:
        on_build()
    docker.run(
        ["build", "--platform", f"linux/{arch}", "--tag", tag, "--label", f"{LABEL}=image", "-"],
        stdin=dockerfile().encode(),
        timeout=BUILD_TIMEOUT,
    )
    built = image_id(docker, tag)
    if not built:
        raise DockerError("the sandbox image was built but can't be found")
    return built


def ensure_proxy_image(docker: Docker) -> None:
    if image_id(docker, PROXY_IMAGE) is None:
        docker.run(["pull", "--quiet", PROXY_IMAGE], timeout=PULL_TIMEOUT)

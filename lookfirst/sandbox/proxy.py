"""The recording proxy, from lookfirst's side: start mitmproxy in its own container with
lookfirst's addon, collect its certificate authority (made fresh for every run), and
read back what it recorded.

The proxy runs as the image's ordinary `mitmproxy` user with no capabilities, started
straight into mitmdump: the image's own start-up script needs root to switch users.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass
from importlib.resources import files

from lookfirst.sandbox.docker import Docker, DockerError
from lookfirst.sandbox.image import PROXY_IMAGE
from lookfirst.sandbox.transfer import Entry, first_file, pack

PORT = 8080
HOME = "/home/mitmproxy"
CA_FILE = f"{HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
READY_FILE = f"{HOME}/lookfirst/ready"  # the addon writes it when it loads
FLOWS_FILE = f"{HOME}/lookfirst/flows.jsonl"
MAX_FLOWS_BYTES = 64 * 1024 * 1024
START_TIMEOUT = 30.0


@dataclass(frozen=True)
class Flow:
    kind: str  # "http", "tcp" or "tls_refused"
    method: str
    scheme: str  # "http" or "https" for a request
    host: str
    port: int | None
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    size: int
    action: str  # "forwarded", "answered", "held", "closed" or "refused"

    def text(self) -> str:
        """Everything a secret could hide in: the address, the headers and the body."""
        head = "\n".join(f"{k}: {v}" for k, v in self.headers)
        return f"{self.host}{self.path}\n{head}\n{self.body.decode('latin-1')}"


def addon_source() -> bytes:
    return files("lookfirst.sandbox").joinpath("mitm_addon.py").read_bytes()


def create(
    docker: Docker, *, name: str, labels: list[str], internal: str, egress: str, config: dict
) -> None:
    docker.run(
        [
            "create",
            "--name",
            name,
            *labels,
            "--network",
            internal,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--user",
            "1000:1000",
            "--env",
            "PYTHONUNBUFFERED=1",
            "--entrypoint",
            "mitmdump",
            PROXY_IMAGE,
            "--listen-host",
            "0.0.0.0",  # noqa: S104 - inside its container, on the sandbox's private network
            "--listen-port",
            str(PORT),
            "--set",
            "connection_strategy=lazy",  # answer made-up hosts without connecting first
            "--set",
            "termlog_verbosity=warn",
            "-s",
            f"{HOME}/lookfirst/mitm_addon.py",
        ]
    )
    docker.run(["network", "connect", egress, name])  # only the proxy can reach out
    files_ = [
        Entry("lookfirst/mitm_addon.py", addon_source()),
        Entry("lookfirst/config.json", json.dumps(config).encode()),
    ]
    docker.run(["cp", "--archive", "-", f"{name}:{HOME}"], stdin=pack(files_))


def start(docker: Docker, name: str, *, timeout: float = START_TIMEOUT) -> bytes:
    """Start the proxy and return its certificate authority (PEM)."""
    docker.run(["start", name])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = docker.run(
            ["exec", name, "test", "-f", CA_FILE, "-a", "-f", READY_FILE], check=False, timeout=15
        )
        if ready.returncode == 0:
            stream = docker.run(["cp", f"{name}:{CA_FILE}", "-"], timeout=30).stdout
            ca = first_file(stream, 64 * 1024)
            if ca and b"BEGIN CERTIFICATE" in ca:
                return ca
        running = docker.run(
            ["inspect", "--format", "{{.State.Running}}", name], check=False, timeout=15
        )
        if running.stdout.strip() != b"true":
            raise DockerError("the recording proxy stopped while starting")
        time.sleep(0.25)
    raise DockerError("the recording proxy didn't start in time, or its addon didn't load")


def read_flows(docker: Docker, name: str) -> list[Flow]:
    result = docker.run(["cp", f"{name}:{FLOWS_FILE}", "-"], check=False, timeout=60)
    if result.returncode != 0:
        return []  # nothing was requested
    data = first_file(result.stdout, MAX_FLOWS_BYTES) or b""
    return parse_flows(data.decode("utf-8", "replace"))


def parse_flows(text: str) -> list[Flow]:
    flows = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
            body = base64.b64decode(record.get("body") or "", validate=True)
        except (ValueError, binascii.Error):
            continue
        if not isinstance(record, dict):
            continue
        headers = tuple(
            (str(h[0]), str(h[1]))
            for h in record.get("headers") or []
            if isinstance(h, list) and len(h) == 2
        )
        port = record.get("port")
        flows.append(
            Flow(
                kind=str(record.get("kind") or ""),
                method=str(record.get("method") or ""),
                scheme=str(record.get("scheme") or "http"),
                host=str(record.get("host") or "").lower().rstrip("."),
                port=port if isinstance(port, int) else None,
                path=str(record.get("path") or ""),
                headers=headers,
                body=body,
                size=int(record.get("size") or len(body)),
                action=str(record.get("action") or ""),
            )
        )
    return flows

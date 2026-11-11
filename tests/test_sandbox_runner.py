"""The sandbox runner, against a fake Docker that records every command: how the containers
are locked down, what's copied in, and that everything is removed whatever happens. The
real thing runs in tests/test_sandbox_fixtures.py (opt in, needs Docker)."""

from __future__ import annotations

import io
import tarfile
import time
from pathlib import Path

import pytest

from lookfirst.sandbox import runner
from lookfirst.sandbox.docker import Attached, DockerError, Result
from lookfirst.sandbox.proxy import FLOWS_FILE
from lookfirst.sandbox.runner import SandboxOptions, run_sandbox
from lookfirst.sandbox.transfer import Entry, pack
from lookfirst.targets.models import ResolvedTarget, TargetSpec

TRACE = (
    '1 execve("/bin/sh", ["sh", "-c", "cd /work && exec /bin/bash /tmp/lookfirst/run.sh"], 0x1 /* 9 vars */) = 0\n'
    '1 execve("/bin/bash", ["/bin/bash", "/tmp/lookfirst/run.sh"], 0x1 /* 9 vars */) = 0\n'
)
CA = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"


class FakeDocker:
    def __init__(
        self,
        *,
        trace: str = TRACE,
        timed_out: bool = False,
        fail_at_start: bool = False,
        engine: tuple[str, str] | None = ("29.8.2", "arm64"),
        leftovers: str = "",
    ) -> None:
        self.calls: list[list[str]] = []
        self.stdin: dict[str, bytes] = {}
        self.trace, self.timed_out, self.fail_at_start = trace, timed_out, fail_at_start
        self._engine, self.leftovers = engine, leftovers

    def engine(self) -> tuple[str, str] | None:
        return self._engine

    def run(self, args, *, timeout=120, stdin=None, check=True) -> Result:
        self.calls.append(list(args))
        if stdin is not None:
            self.stdin[args[-1]] = stdin
        out = b""
        if args[:2] == ["image", "inspect"]:
            out = b"sha256:" + b"a" * 64
        elif args[0] == "cp" and args[1].endswith("mitmproxy-ca-cert.pem"):
            out = pack([Entry("ca.pem", CA)])
        elif args[0] == "cp" and args[1].endswith(FLOWS_FILE):
            return Result(1, b"", "no such file")
        elif args[0] == "cp" and args[1].endswith("output.log"):
            out = pack([Entry("output.log", b"installed\n")])
        elif args[0] == "inspect" and "{{.State.Running}}" in args:
            out = b"true\n"
        elif args[0] == "inspect" and "{{.State.ExitCode}}" in args:
            out = b"0\n"
        elif args[0] == "inspect":
            out = b"192.168.97.2\n"
        elif args[0] == "top":
            out = b"COMMAND\nstrace -f node slow.js\nnode slow.js\n"
        elif args[0] in ("ps", "network") and "--format" in args:
            out = self.leftovers.encode()
        return Result(0, out, "")

    def start_attached(self, container: str, *, timeout: float, folder: Path) -> Attached:
        self.calls.append(["start", "--attach", container])
        if self.fail_at_start:
            raise DockerError("`docker start` failed: no space left on device")
        (folder / "stdout").write_bytes(b"")
        (folder / "stderr").write_text(self.trace)
        return Attached(folder / "stdout", folder / "stderr", self.timed_out)

    def created(self, kind: str) -> list[str]:
        """The `docker create` for the container named ...-sandbox or ...-proxy."""
        (args,) = [
            c
            for c in self.calls
            if c[0] == "create" and c[c.index("--name") + 1].endswith(f"-{kind}")
        ]
        return args

    def names(self) -> list[str]:
        return [c[c.index("--name") + 1] for c in self.calls if c[0] == "create"]


def project(tmp_path: Path) -> ResolvedTarget:
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "index.js").write_text("module.exports = 1\n")
    (tmp_path / "secret-link").symlink_to(Path.home() / ".ssh")  # must never be followed
    return ResolvedTarget(
        TargetSpec(kind="local", raw=str(tmp_path), path=tmp_path), tmp_path, str(tmp_path)
    )


def tar_names(data: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {m.name: m for m in tar.getmembers()}


def test_the_sandbox_is_locked_down_and_nothing_is_mounted(tmp_path: Path) -> None:
    docker = FakeDocker()
    outcome = run_sandbox(project(tmp_path), docker=docker)
    assert outcome.gaps == [] and outcome.run is not None
    box = docker.created("sandbox")
    joined = " ".join(box)
    for flag in (
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 1000:1000",
        "--pids-limit 512",
        "--memory 2g",
        "--cpus 2",
        "--platform linux/arm64",
    ):
        assert flag in joined, flag
    for forbidden in ("-v", "--volume", "--mount", "--privileged", "--cap-add", "docker.sock"):
        assert not any(
            arg == forbidden or forbidden in arg for arg in box if arg != "--cap-drop"
        ), forbidden
    internal = box[box.index("--network") + 1]
    assert next(c for c in docker.calls if internal in c)[:3] == ["network", "create", "--internal"]
    assert box[box.index("strace") :][:6] == ["strace", "-f", "-qq", "-s", "512", "-o"]
    assert "HTTPS_PROXY=http://" in joined and "https_proxy=http://" in joined


def test_the_proxy_is_locked_down_too(tmp_path: Path) -> None:
    docker = FakeDocker()
    run_sandbox(project(tmp_path), docker=docker)
    proxy = docker.created("proxy")
    joined = " ".join(proxy)
    for flag in (
        "--cap-drop ALL",
        "--user 1000:1000",
        "--entrypoint mitmdump",
        "connection_strategy=lazy",
        "--security-opt no-new-privileges",
    ):
        assert flag in joined, flag
    name = proxy[proxy.index("--name") + 1]
    outside = [c for c in docker.calls if c[:2] == ["network", "connect"]]
    assert outside == [["network", "connect", outside[0][2], name]]  # only the proxy goes out


def test_files_and_decoys_are_copied_in_never_links(tmp_path: Path) -> None:
    docker = FakeDocker()
    outcome = run_sandbox(project(tmp_path), docker=docker)
    box = docker.created("sandbox")[docker.created("sandbox").index("--name") + 1]
    work = tar_names(docker.stdin[f"{box}:/work"])
    assert {"package.json", "lib", "lib/index.js", ".env"} <= set(work)
    assert "secret-link" not in work
    assert all(m.uid == 1000 and m.mtime > 1_000_000_000 for m in work.values())
    home = tar_names(docker.stdin[f"{box}:/home/sandbox"])
    assert home[".ssh/id_ed25519"].mode == 0o600
    run_files = tar_names(docker.stdin[f"{box}:/tmp"])
    assert {"lookfirst/run.sh", "lookfirst/ca.pem", "lookfirst-app"} <= set(run_files)
    assert outcome.run.command == "npm install"
    assert outcome.output == "installed\n"


def test_everything_is_removed_after_a_run(tmp_path: Path) -> None:
    docker = FakeDocker()
    run_sandbox(project(tmp_path), docker=docker)
    removed = [c for c in docker.calls if c[0] == "rm" or c[:2] == ["network", "rm"]]
    names = {c[-1] for c in removed}
    assert {
        n for n in names if n.endswith(("-sandbox", "-proxy", "-internal", "-outside"))
    } == names
    assert len(names) == 4


def test_everything_is_removed_when_the_run_fails(tmp_path: Path) -> None:
    docker = FakeDocker(fail_at_start=True)
    outcome = run_sandbox(project(tmp_path), docker=docker)
    assert outcome.run is None
    assert outcome.gaps == [
        (
            "Sandbox dry run",
            "the sandbox couldn't run: `docker start` failed: no space left on device",
            None,
        )
    ]
    assert len([c for c in docker.calls if c[0] == "rm" or c[:2] == ["network", "rm"]]) == 4


def test_a_run_past_its_time_limit_is_stopped_and_reported(tmp_path: Path) -> None:
    docker = FakeDocker(timed_out=True)
    outcome = run_sandbox(project(tmp_path), SandboxOptions(timeout=30), docker=docker)
    assert [
        "kill",
        docker.created("sandbox")[docker.created("sandbox").index("--name") + 1],
    ] in docker.calls
    (finding,) = [f for f in outcome.findings if f.id == "sandbox.still_running"]
    assert [e.ref for e in finding.evidence] == ["node slow.js"]  # not the tracer itself
    assert outcome.run.timed_out and outcome.run.exit_code is None


def test_offline_has_no_proxy_and_no_way_out(tmp_path: Path) -> None:
    docker = FakeDocker()
    outcome = run_sandbox(project(tmp_path), SandboxOptions(network="offline"), docker=docker)
    assert outcome.run.network == "offline"
    assert [n.rsplit("-", 1)[1] for n in docker.names()] == ["sandbox"]
    assert len([c for c in docker.calls if c[:2] == ["network", "create"]]) == 1
    assert "HTTPS_PROXY" not in " ".join(docker.created("sandbox"))


def test_a_tracer_that_never_started_is_not_checked_not_clean(tmp_path: Path) -> None:
    docker = FakeDocker(trace="strace: invalid system call 'x'\n")
    outcome = run_sandbox(project(tmp_path), docker=docker)
    assert outcome.findings == [] and outcome.run is None
    assert outcome.gaps == [
        ("Sandbox dry run", "the dry run didn't start (strace: invalid system call 'x')", None)
    ]


def test_leftovers_from_an_interrupted_run_are_swept(tmp_path: Path) -> None:
    old, recent = int(time.time()) - 2 * 3600, int(time.time())
    docker = FakeDocker(leftovers=f"abc123 {old}\ndef456 {recent}\n")
    run_sandbox(project(tmp_path), docker=docker)
    assert ["rm", "--force", "abc123"] in docker.calls
    assert ["rm", "--force", "def456"] not in docker.calls  # maybe another run's, still going


@pytest.mark.parametrize(
    ("docker", "reason", "how"),
    [
        (None, "Docker isn't installed", "install OrbStack or Docker Desktop"),
        (
            FakeDocker(engine=None),
            "Docker isn't running",
            "start OrbStack or Docker Desktop, then try again",
        ),
    ],
)
def test_without_docker_the_dry_run_is_not_checked(
    tmp_path: Path, docker, reason: str, how: str
) -> None:
    outcome = run_sandbox(project(tmp_path), docker=docker)
    assert outcome.gaps == [("Sandbox dry run", reason, how)]


def test_without_an_install_command_it_asks_for_one(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello\n")
    target = ResolvedTarget(
        TargetSpec(kind="local", raw=str(tmp_path), path=tmp_path), tmp_path, str(tmp_path)
    )
    outcome = run_sandbox(target, docker=FakeDocker())
    assert outcome.gaps == [
        (
            "Sandbox dry run",
            "lookfirst couldn't tell how to install it",
            'add --cmd "the install command"',
        )
    ]


def test_the_projects_own_sites_and_registries_are_allowed(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"homepage": "https://tool.example.org/docs"}')
    target = ResolvedTarget(
        TargetSpec(kind="github", raw="o/tool", owner="o", repo="tool"),
        tmp_path,
        "o/tool@" + "a" * 40,
    )
    chosen = runner.Chosen("curl -fsSL https://get.tool.example.com/i.sh | sh\nnpm install", "x")
    rules = runner.allowed_sites(target, chosen)
    hosts = {(r["host"], r["path"]) for r in rules}
    assert ("registry.npmjs.org", "") in hosts and ("github.com", "/o/tool") in hosts
    assert ("get.tool.example.com", "") in hosts
    assert ("github.com", "") not in hosts  # never all of GitHub


def test_under_emulation_without_a_trace_the_network_record_still_counts(tmp_path: Path) -> None:
    # strace can't follow programs under amd64 emulation on Apple Silicon; the proxy still sees.
    docker = FakeDocker(trace="", engine=("29.8.2", "arm64"))
    outcome = run_sandbox(project(tmp_path), SandboxOptions(arch="amd64"), docker=docker)
    assert outcome.run is not None and outcome.run.arch == "amd64"
    assert outcome.gaps == [
        (
            "What it ran and which files it opened",
            "strace can't follow programs under amd64 emulation on this computer",
            "leave out --arch to use this computer's own architecture",
        )
    ]
    assert "--platform linux/amd64" in " ".join(docker.created("sandbox"))


def test_file_changes_leave_out_orbstack_and_lookfirst_itself() -> None:
    # What `docker diff` showed after a real run that only read a file and sent it.
    orbstack = {
        "A /etc/ca-certificates/trust-source",
        "A /etc/ca-certificates/trust-source/anchors",
        "C /etc",
        "C /etc/ca-certificates",
        "C /etc/ssl",
        "C /etc/ssl/certs",
        "C /etc/ssl/certs/ca-certificates.crt",
        "C /usr",
        "C /usr/local",
        "C /usr/local/share",
        "C /usr/local/share/ca-certificates",
        "A /tmp/lookfirst/output.log",
    }
    assert runner.files_changed(set(), orbstack) == 0
    installed = orbstack | {
        "A /work/node_modules",
        "A /work/node_modules/x/index.js",
        "C /home/sandbox/.bashrc",
    }
    assert runner.files_changed(set(), installed) == 2
    assert runner.files_changed({"C /home/sandbox/.bashrc"}, installed) == 1

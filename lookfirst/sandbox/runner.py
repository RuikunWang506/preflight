"""One sandbox dry run, from start to finish (SPEC section 8, M5 decisions).

1. Two private Docker networks: an internal one for the sandbox, and an outside one that
   only the recording proxy joins. With `--network offline` there's no proxy at all.
2. The proxy starts with a fresh certificate authority. The sandbox container is created
   with no capabilities, as an ordinary user, with memory, CPU and process limits, and
   no folders mounted. The target, the decoy home and the command are copied in.
3. strace runs the command with a time limit. Its record streams out on the container's
   error output, which the command itself can't reach.
4. lookfirst collects the trace, the proxy's records and `docker diff`, then removes the
   containers and networks, whatever happened. Leftovers from an interrupted run are
   swept up next time.
"""

from __future__ import annotations

import re
import secrets
import shlex
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from lookfirst.core.urls import split_url
from lookfirst.identity.check import github_remote
from lookfirst.identity.github import valid_full_name
from lookfirst.sandbox import analyze, image, proxy
from lookfirst.sandbox.command import APP, Chosen, choose_command
from lookfirst.sandbox.docker import Docker, DockerError, find_docker
from lookfirst.sandbox.honeytokens import HOME, Decoy, DecoyEnv, make_decoys, search_terms
from lookfirst.sandbox.trace_parse import STRACE_FILTER, parse_trace
from lookfirst.sandbox.transfer import Entry, TooBig, first_file, pack, project_entries
from lookfirst.static.context import build_context
from lookfirst.static.files import exists
from lookfirst.targets.models import ResolvedTarget
from lookfirst.verdict.schema import Finding, SandboxRun

Network = Literal["sinkhole", "passthrough", "offline"]
WHAT = "Sandbox dry run"
DEFAULT_TIMEOUT = 180
STALE_AFTER = 60 * 60  # a run's leftovers older than this are from an interrupted run
REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org")
# Sites many projects share: only the project's own part of them is its own.
_SHARED = ("github.com", "raw.githubusercontent.com", "codeload.github.com", "gist.github.com")
_URL = re.compile(r"https?://[^\s'\"`)<>|;]+")
RUN_DIR = "/tmp/lookfirst"
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
OUTPUT_TAIL = 8 * 1024
CA_PATH = f"{RUN_DIR}/ca.pem"
_CA_ENV = (
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "PIP_CERT",
    "NODE_EXTRA_CA_CERTS",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
)
# OrbStack adds its own certificate to every container as it starts, after lookfirst's
# "before" snapshot. An ordinary user can't write to these places anyway.
_BASELINE_DIFF = re.compile(
    r"orbstack|^[ACD] /etc/ca-certificates(?:/|$)|^[ACD] /etc/ssl/certs(?:/|$)"
    r"|^[ACD] /usr/local/share/ca-certificates$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SandboxOptions:
    command: str | None = None
    network: Network = "sinkhole"
    arch: str | None = None  # None: the Docker engine's own
    timeout: int = DEFAULT_TIMEOUT
    keep: Path | None = None  # for developers: save the raw trace, records and diff here


@dataclass
class SandboxOutcome:
    findings: list[Finding] = field(default_factory=list)
    run: SandboxRun | None = None
    gaps: list[tuple[str, str, str | None]] = field(default_factory=list)  # what, reason, how
    output: str = ""  # the end of what the install printed, untrusted


def _gap(reason: str, how: str | None = None) -> SandboxOutcome:
    return SandboxOutcome(gaps=[(WHAT, reason, how)])


def _project_repo(target: ResolvedTarget) -> str | None:
    spec = target.spec
    if spec.kind == "github" and spec.owner and spec.repo:
        return f"{spec.owner}/{spec.repo}"
    if valid_full_name(target.source_repo):
        return target.source_repo
    return github_remote(target.root)


def allowed_sites(target: ResolvedTarget, chosen: Chosen) -> list[dict]:
    """What the proxy forwards in sinkhole mode: package registries and the project's own
    sites, including the ones its install command names."""
    rules = [{"host": h, "path": ""} for h in REGISTRIES]
    repo = _project_repo(target)
    if repo:
        part = f"/{repo.lower()}"
        rules += [
            {"host": "github.com", "path": part},
            {"host": "codeload.github.com", "path": part},
            {"host": "raw.githubusercontent.com", "path": part},
            {"host": "api.github.com", "path": f"/repos{part}"},
            {"host": "release-assets.githubusercontent.com", "path": ""},
            {"host": "objects.githubusercontent.com", "path": ""},
        ]
    hosts = set(build_context(target).project_hosts)
    for url in _URL.findall(chosen.command):
        parts = split_url(url)
        host = (parts.hostname or "").lower() if parts else ""
        if not host:
            continue
        if host in _SHARED:
            segments = [s for s in parts.path.split("/") if s][:2] if parts else []
            if len(segments) == 2:
                rules.append({"host": host, "path": "/" + "/".join(segments).lower()})
        else:
            hosts.add(host)
    rules += [{"host": h, "path": ""} for h in sorted(hosts) if h not in _SHARED]
    return rules


def _sweep(docker: Docker) -> None:
    """Remove containers and networks an interrupted run left behind."""
    now = time.time()
    for listing, remove in (
        (["ps", "--all", "--filter", f"label={image.LABEL}"], ["rm", "--force"]),
        (["network", "ls", "--filter", f"label={image.LABEL}"], ["network", "rm"]),
    ):
        result = docker.run(
            [*listing, "--format", '{{.ID}} {{.Label "lookfirst.created"}}'], check=False
        )
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            ident, _, created = line.partition(" ")
            if ident and created.isdigit() and now - int(created) > STALE_AFTER:
                docker.run([*remove, ident], check=False)


def _diff(docker: Docker, name: str) -> set[str]:
    result = docker.run(["diff", name], check=False)
    return {line.strip() for line in result.stdout.decode().splitlines() if line.strip()}


def files_changed(before: set[str], after: set[str]) -> int:
    """Files the run changed: not lookfirst's own, not what OrbStack adds as a container
    starts, and not the folders above either, which docker diff lists as changed too."""
    changed = after - before
    ignored = [
        line[2:] for line in changed if _BASELINE_DIFF.search(line) or line[2:].startswith(RUN_DIR)
    ]
    paths = sorted(
        p
        for p in (line[2:] for line in changed)
        if p not in ignored and not any(i.startswith(p + "/") for i in ignored)
    )
    return sum(
        1 for i, p in enumerate(paths) if not any(q.startswith(p + "/") for q in paths[i + 1 :])
    )


def _still_running(docker: Docker, name: str) -> list[str]:
    result = docker.run(["top", name, "-eo", "args"], check=False, timeout=30)
    lines = result.stdout.decode("utf-8", "replace").splitlines()[1:]
    return [
        line.strip() for line in lines if line.strip() and not line.strip().startswith("strace ")
    ]


def _proxy_ip(docker: Docker, name: str, network: str) -> str | None:
    template = f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}'
    result = docker.run(["inspect", "--format", template, name], check=False)
    ip = result.stdout.decode("utf-8", "replace").strip()
    return ip or None


def _decoy_entries(decoys: list[Decoy]) -> tuple[list[Entry], list[Entry]]:
    home, work = [], []
    for d in decoys:
        if d.path.startswith(HOME + "/"):
            home.append(Entry(d.path[len(HOME) + 1 :], d.content, d.mode))
        elif d.path.startswith("/work/"):
            work.append(Entry(d.path[len("/work/") :], d.content, d.mode))
    return home, work


def _env(proxy_name: str | None, env_decoys: list[DecoyEnv]) -> list[str]:
    env = {"HOME": HOME, "USER": "sandbox", "NO_PROXY": "localhost,127.0.0.1,::1"}
    env["no_proxy"] = env["NO_PROXY"]
    if proxy_name:
        address = f"http://{proxy_name}:{proxy.PORT}"
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[key] = address  # curl only reads the lowercase http_proxy
        for key in _CA_ENV:
            env[key] = CA_PATH
    for decoy in env_decoys:
        env[decoy.name] = decoy.secret
    args = []
    for key, value in env.items():
        args += ["--env", f"{key}={value}"]
    return args


def run_sandbox(
    target: ResolvedTarget,
    options: SandboxOptions = SandboxOptions(),  # noqa: B008 - frozen, so a safe default
    *,
    docker: Docker | None = None,
    on_build: Callable[[], None] | None = None,
) -> SandboxOutcome:
    docker = docker or find_docker()
    if docker is None:
        return _gap("Docker isn't installed", "install OrbStack or Docker Desktop")
    engine = docker.engine()
    if engine is None:
        return _gap("Docker isn't running", "start OrbStack or Docker Desktop, then try again")
    arch = options.arch or engine[1]
    if arch not in ("arm64", "amd64"):
        return _gap(f"the sandbox runs on arm64 or amd64, not {arch}")
    chosen = choose_command(target, options.command)
    if chosen is None:
        return _gap("lookfirst couldn't tell how to install it", 'add --cmd "the install command"')
    try:
        work = project_entries(target.root) if target.root is not None else []
    except TooBig as exc:
        return _gap(f"it's too big to copy into the sandbox ({exc})")
    try:
        image_id = image.ensure_sandbox_image(docker, arch, on_build=on_build)
        if options.network != "offline":
            image.ensure_proxy_image(docker)
        _sweep(docker)
        return _run(
            docker, target, options, chosen, work, image_id, arch, emulated=arch != engine[1]
        )
    except DockerError as exc:
        return _gap(f"the sandbox couldn't run: {exc}")


def _run(
    docker: Docker,
    target: ResolvedTarget,
    options: SandboxOptions,
    chosen: Chosen,
    work: list[Entry],
    image_id: str,
    arch: str,
    *,
    emulated: bool = False,
) -> SandboxOutcome:
    run_id = secrets.token_hex(4)
    box, proxy_name = f"lookfirst-{run_id}-sandbox", f"lookfirst-{run_id}-proxy"
    inside, outside = f"lookfirst-{run_id}-internal", f"lookfirst-{run_id}-outside"
    labels = [
        "--label",
        f"{image.LABEL}={run_id}",
        "--label",
        f"lookfirst.created={int(time.time())}",
    ]
    use_proxy = options.network != "offline"
    has_env = target.root is not None and exists(target.root, ".env")
    decoys, env_decoys = make_decoys(project_has_env=has_env)
    allow = allowed_sites(target, chosen)
    made: list[list[str]] = []  # how to remove what was made, newest last
    try:
        docker.run(["network", "create", "--internal", *labels, inside])
        made.append(["network", "rm", inside])
        proxy_ip, ca = None, b""
        if use_proxy:
            docker.run(["network", "create", *labels, outside])
            made.append(["network", "rm", outside])
            config = {
                "mode": options.network,
                "allow": allow,
                "terms": search_terms([d.secret for d in decoys] + [e.secret for e in env_decoys]),
            }
            made.append(["rm", "--force", proxy_name])
            proxy.create(
                docker,
                name=proxy_name,
                labels=labels,
                internal=inside,
                egress=outside,
                config=config,
            )
            ca = proxy.start(docker, proxy_name)
            proxy_ip = _proxy_ip(docker, proxy_name, inside)

        script = f"cd {shlex.quote(chosen.folder)} && exec /bin/bash {RUN_DIR}/run.sh"
        script += f" >{RUN_DIR}/output.log 2>&1 </dev/null"
        made.append(["rm", "--force", box])
        docker.run(
            [
                "create",
                "--name",
                box,
                *labels,
                "--network",
                inside,
                "--hostname",
                "sandbox",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "512",
                "--memory",
                "2g",
                "--memory-swap",
                "2g",
                "--cpus",
                "2",
                "--user",
                "1000:1000",
                "--platform",
                f"linux/{arch}",
                *_env(proxy_name if use_proxy else None, env_decoys),
                image_id,
                "strace",
                "-f",
                "-qq",
                "-s",
                "512",
                "-o",
                "/dev/stderr",
                "-e",
                STRACE_FILTER,
                "/bin/sh",
                "-c",
                script,
            ]
        )
        home_files, work_decoys = _decoy_entries(decoys)
        run_files = [Entry("lookfirst/run.sh", chosen.command.encode() + b"\n", 0o644)]
        if ca:
            run_files.append(Entry("lookfirst/ca.pem", ca))
        run_files.append(Entry(APP.removeprefix("/tmp/"), None, 0o755))
        for files, folder in (
            (work + work_decoys, "/work"),
            (home_files, HOME),
            (run_files, "/tmp"),
        ):
            if files:
                docker.run(
                    ["cp", "--archive", "-", f"{box}:{folder}"], stdin=pack(files), timeout=300
                )
        before = _diff(docker, box)

        with tempfile.TemporaryDirectory(prefix="lookfirst-sandbox-") as tmp:
            started = time.monotonic()
            attached = docker.start_attached(box, timeout=options.timeout, folder=Path(tmp))
            duration = time.monotonic() - started
            still_running = _still_running(docker, box) if attached.timed_out else []
            if attached.timed_out:
                docker.run(["kill", box], check=False)
            state = docker.run(["inspect", "--format", "{{.State.ExitCode}}", box], check=False)
            code_text = state.stdout.decode().strip()
            exit_code = (
                None
                if attached.timed_out or not code_text.lstrip("-").isdigit()
                else int(code_text)
            )
            after = _diff(docker, box)
            flows = proxy.read_flows(docker, proxy_name) if use_proxy else []
            printed = docker.run(["cp", f"{box}:{RUN_DIR}/output.log", "-"], check=False)
            output = (first_file(printed.stdout, MAX_OUTPUT_BYTES) or b"")[-OUTPUT_TAIL:]
            decoy_paths = {d.path for d in decoys}
            if options.keep is not None:
                options.keep.mkdir(parents=True, exist_ok=True)
                (options.keep / "strace.log").write_bytes(attached.stderr.read_bytes())
                raw_flows = docker.run(["cp", f"{proxy_name}:{proxy.FLOWS_FILE}", "-"], check=False)
                if use_proxy and raw_flows.returncode == 0:
                    flows_bytes = first_file(raw_flows.stdout, proxy.MAX_FLOWS_BYTES) or b""
                    (options.keep / "flows.jsonl").write_bytes(flows_bytes)
                (options.keep / "diff.txt").write_text("\n".join(sorted(after - before)) + "\n")
            with attached.stderr.open(encoding="utf-8", errors="replace") as lines:
                trace = parse_trace(lines, keep_read=decoy_paths.__contains__)
            gaps: list[tuple[str, str, str | None]] = []
            if not trace.execs and emulated:
                # Under another architecture's emulation (amd64 on Apple Silicon) strace
                # can't follow programs. The install still ran in the sandbox, and the
                # proxy still recorded every request.
                gaps.append(
                    (
                        "What it ran and which files it opened",
                        f"strace can't follow programs under {arch} emulation on this computer",
                        "leave out --arch to use this computer's own architecture",
                    )
                )
            elif not trace.execs:
                # strace records the command it starts, so no programs at all means the
                # tracing itself failed: never report that as "nothing seen".
                with attached.stderr.open(encoding="utf-8", errors="replace") as lines:
                    first = next((ln.strip() for ln in lines if ln.strip()), "")
                return _gap(
                    "the dry run didn't start"
                    + (f" ({first[:160]})" if first.startswith("strace:") else "")
                )
    finally:
        for remove in reversed(made):
            docker.run(remove, check=False, timeout=60)

    observed = analyze.Observed(
        trace=trace,
        flows=flows,
        decoys=decoys,
        env_decoys=env_decoys,
        allow=allow,
        proxy_ip=proxy_ip,
        exit_code=exit_code,
        timed_out=attached.timed_out,
        network=options.network,
        still_running=still_running,
    )
    run = SandboxRun(
        command=chosen.command[:500],
        why=chosen.why,
        image_digest=image_id,
        duration_s=round(duration, 1),
        exit_code=exit_code,
        timed_out=attached.timed_out,
        network=options.network,
        arch=arch,  # type: ignore[arg-type]
        hosts=analyze.hosts_contacted(flows),
        files_changed=files_changed(before, after),
    )
    return SandboxOutcome(analyze.judge(observed), run, gaps, output.decode("utf-8", "replace"))

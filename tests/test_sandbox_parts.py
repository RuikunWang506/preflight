"""The sandbox's parts that need no Docker: reading strace, the decoys, choosing what to run,
and judging what a run saw. Real traces from the fixtures' dry runs are in
tests/fixtures/sandbox_traces."""

from __future__ import annotations

import base64
import binascii
import gzip
import json
from pathlib import Path

import pytest
from conftest import FIXTURES

from lookfirst.sandbox.analyze import Observed, allowed, judge
from lookfirst.sandbox.command import choose_command
from lookfirst.sandbox.honeytokens import encodings, find, make_decoys, search_terms
from lookfirst.sandbox.proxy import Flow, parse_flows
from lookfirst.sandbox.runner import REGISTRIES
from lookfirst.sandbox.trace_parse import parse_trace, program_name
from lookfirst.targets.models import PackageSpec, ResolvedTarget, TargetSpec
from lookfirst.verdict.schema import Severity
from lookfirst.verdict.scoring import verdict_for

TRACES = FIXTURES / "sandbox_traces"
REGISTRY_RULES = [{"host": h, "path": ""} for h in REGISTRIES]


def recorded(name: str) -> list[str]:
    path = TRACES / f"{name}.log"
    if path.exists():
        return path.read_text().splitlines(True)
    return gzip.decompress((TRACES / f"{name}.log.gz").read_bytes()).decode().splitlines(True)


def flow(host: str, action: str, body: bytes = b"", method: str = "GET", path: str = "/") -> Flow:
    return Flow("http", method, "https", host, 443, path, (), body, len(body), action)


def observe(trace_name: str, flows: list[Flow], decoys=None, **kw) -> list:
    decoys, env = decoys or make_decoys()
    paths = {d.path for d in decoys}
    trace = parse_trace(recorded(trace_name), keep_read=paths.__contains__)
    o = Observed(
        trace=trace,
        flows=flows,
        decoys=decoys,
        env_decoys=env,
        allow=REGISTRY_RULES,
        proxy_ip="192.168.97.2",
        exit_code=kw.get("exit_code", 0),
        timed_out=kw.get("timed_out", False),
        network="sinkhole",
        still_running=kw.get("still_running", []),
    )
    return judge(o)


def ids(findings) -> dict[str, Severity]:
    return {f.id: f.severity for f in findings}


# --- what the fixtures' real dry runs saw -------------------------------------------------


def test_decoy_key_theft() -> None:
    decoys, env = make_decoys()
    key = next(d for d in decoys if d.path.endswith("id_ed25519"))
    stolen = flow("collect.example.net", "held", key.content, "POST", "/upload")
    findings = observe("decoy_key_theft", [stolen], (decoys, env))
    assert ids(findings) == {
        "sandbox.decoy_sent": Severity.critical,
        "sandbox.decoy_read": Severity.high,
        "sandbox.contacted_other_sites": Severity.medium,
    }
    assert verdict_for(findings) == "dont_run"
    sent = findings[0].evidence[0]
    assert sent.ref == "POST https://collect.example.net/upload"
    assert sent.data["what"] == "the decoy SSH key, encoded as base64; the sandbox held it back"
    read = findings[1].evidence[0]
    assert (read.ref, read.data["what"]) == (key.path, "the decoy SSH key, read by cat")


def test_cron_entry() -> None:
    findings = observe("cron_entry", [])
    assert ids(findings) == {"sandbox.persistence": Severity.high}
    (ev,) = findings[0].evidence
    assert ev.ref == "/etc/cron.d/lookfirst-fixture"
    assert ev.data["what"] == "tried; that folder doesn't exist in the sandbox, by bash"


def test_download_and_run() -> None:
    findings = observe("download_and_run_tmp", [flow("downloads.example.net", "answered")])
    assert ids(findings) == {
        "sandbox.ran_downloaded_program": Severity.high,
        "sandbox.contacted_other_sites": Severity.medium,
    }
    (ran,) = findings[0].evidence
    assert ran.ref == "/tmp/lookfirst-helper"
    assert ran.data["what"] == "saved during the install, then run (it didn't start: ENOEXEC)"


def test_an_ordinary_npm_install_is_clean() -> None:
    # npm reads ~/.npmrc (a decoy) itself: that's its own file. It runs as `node /usr/bin/npm`.
    findings = observe("benign_npm_install", [flow("registry.npmjs.org", "forwarded")])
    assert findings == []


def test_an_ordinary_pip_install_is_clean() -> None:
    pypi = [flow("pypi.org", "forwarded"), flow("files.pythonhosted.org", "forwarded")]
    assert observe("benign_pip_install", pypi) == []


# --- reading strace -------------------------------------------------------------------------


def test_programs_run_through_node_are_named_by_their_script() -> None:
    assert program_name("/usr/bin/node", ("node", "/usr/bin/npm", "install")) == "npm"
    assert program_name("/usr/bin/node", ("node", "/usr/lib/npm/bin/npx-cli.js")) == "npx"
    assert program_name("/usr/bin/node", ("node", "evil.js")) == "node"
    assert program_name("/usr/bin/curl", ("curl", "x")) == "curl"


def test_split_lines_folders_and_escapes() -> None:
    lines = [
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101\n",
        '101 chdir("/home/sandbox") = 0\n',
        '101 execve("/usr/bin/cat", ["cat", ".ssh/id_ed25519"], 0xa /* 8 vars */) = 0\n',
        '101 openat(AT_FDCWD, ".ssh/id_ed25519", O_RDONLY <unfinished ...>\n',
        '102 openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)\n',
        "101 <... openat resumed>) = 3\n",
        '103 openat(AT_FDCWD, "a\\"b\\x2fc", O_RDONLY) = 3\n',
        '104 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH (Network is unreachable)\n',
        "not a strace line\n",
    ]
    trace = parse_trace(lines, keep_read=lambda p: True)
    by_path = {o.path: o for o in trace.opens}
    assert by_path["/home/sandbox/.ssh/id_ed25519"].program == "cat"
    assert by_path["/home/sandbox/.ssh/id_ed25519"].ok
    assert by_path["/etc/cron.d/x"].write and by_path["/etc/cron.d/x"].error == "EACCES"
    assert '/work/a"b/c' in by_path  # relative to /work, where every run starts
    (conn,) = trace.connects
    assert (conn.address, conn.port, conn.ok) == ("1.2.3.4", 443, False)
    assert trace.unparsed == 1


# --- decoys ---------------------------------------------------------------------------------


def test_decoys_are_new_every_run_and_look_real() -> None:
    first, second = make_decoys(), make_decoys()
    assert {d.secret for d in first[0]}.isdisjoint({d.secret for d in second[0]})
    contents = b"".join(d.content for d in first[0])
    assert b"AKIA" in contents and b"gho_" in contents and b"BEGIN OPENSSH PRIVATE KEY" in contents
    assert {e.name for e in first[1]} == {"GITHUB_TOKEN", "NPM_TOKEN"}


def test_the_projects_own_env_file_is_left_alone() -> None:
    decoys, _ = make_decoys(project_has_env=True)
    assert all(d.path != "/work/.env" for d in decoys)
    assert any(d.path == "/work/.env" for d in make_decoys()[0])


@pytest.mark.parametrize("prefix", ["", "x", "xy", "a longer prefix: "])
def test_a_secret_is_found_in_every_common_encoding(prefix: str) -> None:
    secret = make_decoys()[0][0].secret
    blob = f"{prefix}{secret} and more".encode()
    assert find(blob.decode(), secret) == "as plain text"
    assert find(base64.b64encode(blob).decode(), secret) == "encoded as base64"
    assert find(base64.urlsafe_b64encode(blob).decode(), secret) is not None
    assert find(binascii.hexlify(blob).decode(), secret) == "encoded as hex"
    assert find(binascii.hexlify(blob).decode().upper(), secret) == "encoded as hex"
    assert find("hello world", secret) is None


def test_the_proxy_gets_every_form_of_every_secret() -> None:
    secrets_ = ["a" * 30, "b" * 30]
    terms = search_terms(secrets_)
    for secret in secrets_:
        for forms in encodings(secret).values():
            assert set(forms) <= set(terms)


# --- the proxy's records --------------------------------------------------------------------


def test_flow_records_are_read_defensively() -> None:
    good = {
        "kind": "http",
        "method": "POST",
        "scheme": "https",
        "host": "X.Example.NET.",
        "port": 443,
        "path": "/u",
        "headers": [["a", "b"], "junk"],
        "body": base64.b64encode(b"hi").decode(),
        "size": 2,
        "action": "held",
    }
    text = "\n".join([json.dumps(good), "{not json", json.dumps({**good, "body": "%%%"})])
    (record,) = parse_flows(text)
    assert (record.host, record.body, record.headers, record.action) == (
        "x.example.net",
        b"hi",
        (("a", "b"),),
        "held",
    )


@pytest.mark.parametrize(
    ("host", "path", "ok"),
    [
        ("registry.npmjs.org", "/is-number", True),
        ("evil-registry.npmjs.org.example", "/", False),
        ("github.com", "/owner/repo/archive/main.zip", True),
        ("github.com", "/owner/repo.git/info/refs", True),
        ("github.com", "/owner/repository-two", False),
        ("github.com", "/other/repo", False),
    ],
)
def test_allowed_sites_match_on_host_and_repo(host: str, path: str, ok: bool) -> None:
    rules = [*REGISTRY_RULES, {"host": "github.com", "path": "/owner/repo"}]
    assert allowed(host, path, rules) is ok


# --- choosing what to run -------------------------------------------------------------------


def folder_target(tmp_path: Path, files: dict[str, str]) -> ResolvedTarget:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    spec = TargetSpec(kind="local", raw=str(tmp_path), path=tmp_path)
    return ResolvedTarget(spec, tmp_path, str(tmp_path))


def test_the_readme_install_block_wins(tmp_path: Path) -> None:
    readme = (
        "# Tool\n\n## Install\n\n```sh\ngit clone https://github.com/o/tool\ncd tool\n"
        "sudo make install\n```\n"
    )
    chosen = choose_command(folder_target(tmp_path, {"README.md": readme, "package.json": "{}"}))
    assert chosen.command == "make install"  # the clone is already in the sandbox; no sudo there
    assert chosen.why == "the install instructions in README.md (line 6)"


@pytest.mark.parametrize(
    ("files", "command"),
    [
        ({"package.json": "{}"}, "npm install"),
        ({"pyproject.toml": "[project]\nname='x'\n"}, "pip install ."),
        ({"Makefile": "all:\n\techo\ninstall:\n\tcp x /usr/local/bin\n"}, "make install"),
        ({"install.sh": "echo hi\n"}, "bash install.sh"),
        ({"notes.txt": "hello\n"}, None),
    ],
)
def test_without_a_readme_block_the_project_files_decide(
    tmp_path: Path, files: dict[str, str], command: str | None
) -> None:
    chosen = choose_command(folder_target(tmp_path, files))
    assert (chosen.command if chosen else None) == command


def test_packages_are_installed_by_name_and_version(tmp_path: Path) -> None:
    npm = ResolvedTarget(
        TargetSpec(kind="npm", raw="npm:x", package=PackageSpec("npm", "x")),
        tmp_path,
        "x@1.0.0",
        metadata={"npm": {"name": "x; rm -rf /", "version": "1.0.0"}},
    )
    chosen = choose_command(npm)
    assert chosen.command == "npm install 'x; rm -rf /@1.0.0'"  # quoted, never run as shell
    assert chosen.folder == "/tmp/lookfirst-app"
    pypi = ResolvedTarget(
        TargetSpec(kind="pypi", raw="pypi:six", package=PackageSpec("pypi", "six")),
        tmp_path,
        "six==1.17.0",
        metadata={"pypi": {"info": {"name": "six", "version": "1.17.0"}}},
    )
    assert choose_command(pypi).command == "pip install six==1.17.0"


def test_a_given_command_and_a_one_liner_run_as_they_are(tmp_path: Path) -> None:
    target = folder_target(tmp_path, {"package.json": "{}"})
    assert choose_command(target, "make dev").command == "make dev"
    one = ResolvedTarget(
        TargetSpec(kind="oneliner", raw="curl x | sh", command="curl https://x.example/i.sh | sh"),
        None,
        None,
    )
    assert choose_command(one).command == "curl https://x.example/i.sh | sh"

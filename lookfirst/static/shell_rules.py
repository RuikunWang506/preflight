"""The install-path rules for shell code (SPEC section 5), and the analyzer that follows
the scripts a command downloads. Nothing is ever run: downloaded scripts are read with
the same rules, up to 3 levels deep.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from lookfirst.static.context import RuleContext
from lookfirst.static.fetch import RemoteReader, RemoteScript
from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.shell_parse import DYNAMIC, Command, ParsedScript, parse_shell

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish"})
SCRIPT_RUNNERS = frozenset({"python", "python3", "python2", "perl", "ruby", "node", "php"})
SOURCE = frozenset({"source", "."})
SUDO = frozenset({"sudo", "doas", "pkexec", "run0"})
_SIMPLE_WRAPPERS = frozenset(
    {
        "nohup",
        "exec",
        "command",
        "builtin",
        "time",
        "nice",
        "caffeinate",
        "stdbuf",
        "unbuffer",
        "chronic",
    }
)
_NOT_A_READ = frozenset(
    {
        "mkdir",
        "chmod",
        "chown",
        "touch",
        "rm",
        "ls",
        "stat",
        "ssh-keygen",
        "ssh-add",
        "test",
        "[",
        "[[",
        "echo",
        "printf",
        "ln",
        "install",
    }
)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # noqa: S104 - a list, not a bind

_CURL_SHORT_VALUE = set("oduFTXHAebcwxKmEryYzCDPQtU")
_CURL_LONG_VALUE = frozenset(
    {
        "--output",
        "--data",
        "--data-binary",
        "--data-raw",
        "--data-ascii",
        "--data-urlencode",
        "--json",
        "--form",
        "--form-string",
        "--upload-file",
        "--request",
        "--header",
        "--user-agent",
        "--user",
        "--referer",
        "--cookie",
        "--cookie-jar",
        "--write-out",
        "--proxy",
        "--config",
        "--max-time",
        "--connect-timeout",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "--proto",
        "--proto-redir",
        "--url",
        "--range",
        "--output-dir",
        "--cacert",
        "--cert",
        "--key",
        "--resolve",
        "--connect-to",
        "--dump-header",
        "--limit-rate",
        "--max-filesize",
        "--interface",
        "--dns-servers",
        "--tls-max",
        "--ciphers",
        "--variable",
        "--expand-url",
        "--oauth2-bearer",
        "--aws-sigv4",
    }
)
_CURL_SENDS = frozenset(
    {
        "-d",
        "--data",
        "--data-binary",
        "--data-raw",
        "--data-ascii",
        "--data-urlencode",
        "--json",
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
    }
)
_WGET_SHORT_VALUE = set("OoPUeitTwaQAR")
_WGET_LONG_VALUE = frozenset(
    {
        "--output-document",
        "--output-file",
        "--directory-prefix",
        "--user-agent",
        "--header",
        "--post-data",
        "--post-file",
        "--body-data",
        "--body-file",
        "--method",
        "--tries",
        "--timeout",
        "--user",
        "--password",
        "--input-file",
        "--wait",
        "--execute",
        "--quota",
        "--accept",
        "--reject",
    }
)
_URL = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_SCHEMELESS = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?::\d+)?/\S*$")
_SECRET_ENV = re.compile(
    r"\$\{?(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|"
    r"PYPI_TOKEN|TWINE_PASSWORD|OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|SLACK_TOKEN|"
    r"STRIPE_SECRET_KEY|DOCKER_PASSWORD|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)\b"
)
# A secret going to its own service is normal; to anywhere else it's theft.
_SECRET_HOME = {
    "GITHUB_TOKEN": ("github.com", "githubusercontent.com"),
    "GH_TOKEN": ("github.com",),
    "GITLAB_TOKEN": ("gitlab.com",),
    "NPM_TOKEN": ("npmjs.org", "npmjs.com"),
    "PYPI_TOKEN": ("pypi.org",),
    "TWINE_PASSWORD": ("pypi.org",),
    "OPENAI_API_KEY": ("openai.com",),
    "ANTHROPIC_API_KEY": ("anthropic.com",),
    "HF_TOKEN": ("huggingface.co",),
    "SLACK_TOKEN": ("slack.com",),
    "STRIPE_SECRET_KEY": ("stripe.com",),
    "AWS_SECRET_ACCESS_KEY": ("amazonaws.com",),
    "AWS_SESSION_TOKEN": ("amazonaws.com",),
}


def basename(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def peel(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split off wrappers like sudo, env and nohup: (wrappers, the real command and its args)."""
    wrappers: list[str] = []
    i = 0
    while i < len(argv):
        name = basename(argv[i])
        if name in SUDO:
            wrappers.append(name)
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                flag = argv[i]
                i += 1
                if flag in (
                    "-u",
                    "-g",
                    "-h",
                    "-p",
                    "-U",
                    "-C",
                    "-T",
                    "-r",
                    "-t",
                    "--user",
                    "--group",
                    "--host",
                    "--prompt",
                ):
                    i += 1
                if flag == "--":
                    break
            continue
        if name == "env":
            wrappers.append(name)
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or "=" in argv[i]):
                i += 2 if argv[i] in ("-u", "-C", "-S", "--unset", "--chdir") else 1
            continue
        if name in _SIMPLE_WRAPPERS:
            wrappers.append(name)
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in ("-n", "-i", "-o", "-e") else 1
            continue
        if name == "timeout":
            wrappers.append(name)
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 1
            i += 1  # the duration
            continue
        break
    return wrappers, argv[i:]


def reads_stdin(rest: list[str]) -> bool:
    """Whether an interpreter call reads its program from standard input."""
    if not rest:
        return False
    name, args = basename(rest[0]), rest[1:]
    if name in SHELLS:
        s_flag = False
        i = 0
        while i < len(args):
            a = args[i]
            short = a.startswith("-") and not a.startswith("--") and len(a) > 1
            if a == "-c" or (short and "c" in a[1:]):
                return False
            if a == "-s" or (short and "s" in a[1:]):
                s_flag = True
            if a == "--":
                return s_flag or i + 1 >= len(args)
            if a in ("-o", "-O", "+o", "+O"):
                i += 2
                continue
            if not a.startswith(("-", "+")):
                return s_flag or a == "-"
            i += 1
        return True
    if name in SCRIPT_RUNNERS:
        for a in args:
            if a in ("-c", "-e", "-E", "--eval", "-p", "--print", "-r"):
                return False
            if a == "-":
                return True
            if not a.startswith("-"):
                return False
        return True
    return False


def _url_like(word: str) -> str | None:
    if DYNAMIC in word or "${" in word:
        return DYNAMIC
    if _URL.match(word):
        return word
    if _SCHEMELESS.match(word):
        return "http://" + word  # curl and wget treat a bare address as http
    return None


@dataclass
class Download:
    cmd: Command
    tool: str
    urls: list[str]
    to_stdout: bool
    out_files: list[str]
    sends: bool


def _options(
    args: list[str], short_value: set[str], long_value: frozenset[str]
) -> tuple[list[tuple[str, str]], list[str]]:
    """Split args into (option, value) pairs and plain words."""
    opts: list[tuple[str, str]] = []
    words: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            words += args[i + 1 :]
            break
        if a.startswith("--"):
            opt, eq, val = a.partition("=")
            if opt in long_value and not eq:
                val = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            opts.append((opt, val))
        elif a.startswith("-") and len(a) > 1:
            letters = a[1:]
            for j, ch in enumerate(letters):
                if ch in short_value:
                    val = letters[j + 1 :]
                    if not val:
                        val = args[i + 1] if i + 1 < len(args) else ""
                        i += 1
                    opts.append(("-" + ch, val))
                    break
                opts.append(("-" + ch, ""))
        else:
            words.append(a)
        i += 1
    return opts, words


def as_download(cmd: Command) -> Download | None:
    _, rest = peel(cmd.argv)
    if not rest:
        return None
    name = basename(rest[0])
    if name == "curl":
        opts, words = _options(rest[1:], _CURL_SHORT_VALUE, _CURL_LONG_VALUE)
        urls = [u for u in (_url_like(w) for w in words) if u]
        urls += [u for o, v in opts if o == "--url" and (u := _url_like(v))]
        outs = [v for o, v in opts if o in ("-o", "--output") and v != "-"]
        remote_name = any(o in ("-O", "--remote-name", "--remote-name-all") for o, _ in opts)
        if remote_name:
            outs += [basename(urlsplit(u).path) or "index.html" for u in urls if u != DYNAMIC]
        sends = any(o in _CURL_SENDS for o, _ in opts) or any(
            o in ("-X", "--request") and v.upper() in ("POST", "PUT", "PATCH") for o, v in opts
        )
        redirected = any(r.op in (">", ">>", "&>") for r in cmd.redirects)
        outs += [r.target for r in cmd.redirects if r.op in (">", ">>", "&>")]
        return Download(
            cmd, "curl", urls, not outs and not remote_name and not redirected, outs, sends
        )
    if name == "wget":
        opts, words = _options(rest[1:], _WGET_SHORT_VALUE, _WGET_LONG_VALUE)
        urls = [u for u in (_url_like(w) for w in words) if u]
        doc = [v for o, v in opts if o in ("-O", "--output-document")]
        to_stdout = "-" in doc
        outs = [v for v in doc if v != "-"]
        if not doc:
            outs += [basename(urlsplit(u).path) or "index.html" for u in urls if u != DYNAMIC]
        sends = any(
            o in ("--post-data", "--post-file", "--body-data", "--body-file") for o, _ in opts
        )
        return Download(cmd, "wget", urls, to_stdout, outs, sends)
    return None


def is_network_send(cmd: Command) -> bool:
    _, rest = peel(cmd.argv)
    if any("/dev/tcp/" in r.target or "/dev/udp/" in r.target for r in cmd.redirects):
        return True
    if not rest:
        return False
    name, args = basename(rest[0]), rest[1:]
    if name in (
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "telnet",
        "ftp",
        "sftp",
        "mail",
        "sendmail",
        "mutt",
    ):
        return True
    if name in ("scp", "rsync") and any(":" in a and not a.startswith("-") for a in args):
        return True
    if name == "ssh" and any(not a.startswith("-") for a in args):
        return True
    if name == "openssl" and "s_client" in args:
        return True
    if name in SCRIPT_RUNNERS and re.search(
        r"urllib|requests\.|http\.client|socket|fetch\(|https?\.request|net\.", " ".join(args)
    ):
        return True
    return name in ("aws", "gsutil", "rclone") and any(
        a in ("cp", "sync", "copy", "mv") for a in args
    )


def normalize_home(text: str) -> str:
    text = text.replace("${HOME}", "~").replace("$HOME", "~")
    return re.sub(r"^(?:/Users/[^/]+|/home/[^/]+|/root)(?=/|$)", "~", text)


_BROWSER = (
    "library/application support/google/chrome",
    "/google-chrome/",
    "bravesoftware",
    "microsoft edge",
    "firefox/profiles",
    ".mozilla/firefox",
    "library/cookies",
    "login data",
    "/cookies.binarycookies",
    "web data",
    "library/safari/",
)
_WALLETS = (
    "exodus/",
    "electrum/",
    "wallet.dat",
    ".bitcoin/",
    ".ethereum/keystore",
    "ledger live",
    "nkbihfbeogaeaoehlefnkodbefgpgknn",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "atomic/local storage",
    "coinomi",
    ".config/solana/id.json",
)
_CREDENTIAL_FILES = (
    ("~/.aws", "AWS keys"),
    ("~/.config/gh", "your GitHub login"),
    ("~/.npmrc", "your npm token"),
    ("~/.pypirc", "your PyPI token"),
    ("~/.docker/config.json", "your Docker login"),
    ("~/.netrc", "saved passwords"),
    ("~/.git-credentials", "saved git passwords"),
    ("~/.kube/config", "Kubernetes credentials"),
    ("~/.config/gcloud", "Google Cloud credentials"),
    ("~/.azure", "Azure credentials"),
    ("~/.gnupg", "GPG keys"),
    ("~/.terraform.d/credentials", "Terraform credentials"),
)


def credential_kind(word: str) -> str | None:
    """What kind of secret a path points at, if any."""
    t = normalize_home(word.strip("'\"@=")).lower()
    t = t.split("=@", 1)[-1].lstrip("@")
    if "~/.ssh" in t:
        after = t.split("~/.ssh", 1)[1]
        if re.search(r"\.pub\b|known_hosts|authorized_keys|/config\b", after):
            return None
        return "SSH keys"
    for prefix, kind in _CREDENTIAL_FILES:
        if prefix in t:
            if prefix == "~/.aws" and "/config" in t.split("~/.aws", 1)[1]:
                return None
            return kind
    if "library/keychains" in t or ".keychain-db" in t or "login.keychain" in t:
        return "the macOS Keychain"
    if any(p in t for p in _BROWSER):
        return "browser passwords and cookies"
    if any(p in t for p in _WALLETS):
        return "crypto wallets"
    if re.search(r"(?:^|/)\.env$", t):
        return "a .env file, which often holds API keys"
    return None


def _script_text(cmd: Command) -> str:
    return " ".join(cmd.argv[1:]) + " " + (cmd.heredoc or "")


_RC_NAMES = (
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    "config.fish",
)
_RC_SYSTEM = ("/etc/profile", "/etc/zshrc", "/etc/zprofile", "/etc/bashrc", "/etc/bash.bashrc")
_LAUNCH = ("~/library/launchagents", "/library/launchagents", "/library/launchdaemons")
_CRON = ("/etc/cron", "/var/spool/cron", "/var/at/tabs", "/usr/lib/cron/tabs")
_SERVICES = (
    "/etc/systemd/system",
    "~/.config/systemd/user",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/init.d",
    "/etc/rc.local",
)
_FETCHES = re.compile(r"\b(?:curl|wget|nc|ncat)\b|/dev/tcp|base64[^\n]*\|\s*(?:ba|z)?sh")


def _is_rc(path: str) -> bool:
    name = basename(path)
    return (
        (path.startswith("~/") and name in _RC_NAMES)
        or path.startswith(_RC_SYSTEM)
        or path.startswith("/etc/profile.d/")
    )


def _is_decoder(cmd: Command) -> bool:
    _, rest = peel(cmd.argv)
    if not rest:
        return False
    name, args = basename(rest[0]), rest[1:]
    if name == "base64":
        return any(
            a in ("-d", "-D", "--decode")
            or (a.startswith("-") and not a.startswith("--") and "d" in a)
            for a in args
        )
    if name == "openssl":
        return ("base64" in args or "enc" in args) and "-d" in args
    if name == "xxd":
        return any(a.startswith("-r") for a in args)
    if name in ("uudecode", "gunzip", "zcat", "bzcat", "bunzip2", "unxz", "xzcat"):
        return True
    if name in ("gzip", "xz", "bzip2", "zstd") and any(
        a in ("-d", "--decompress", "-dc", "-cd") for a in args
    ):
        return True
    if name == "rev":
        return True
    if name in ("printf", "echo"):
        text = " ".join(args)
        return len(re.findall(r"\\x[0-9A-Fa-f]{2}|\\[0-7]{3}", text)) >= 3
    if name == "tr":
        return bool(re.search(r"n-za-m|N-ZA-M", " ".join(args)))
    if name in SCRIPT_RUNNERS:
        return bool(
            re.search(
                r"b64decode|decodebytes|fromhex|zlib\.decompress|Buffer\.from\([^)]*base64|atob\(",
                " ".join(args),
            )
        )
    return False


@dataclass
class _Run:
    runner: Command
    download: Download | None  # the download that's run, if any
    via: str  # "pipe", "substitution", "process" or "file"
    sudo: bool
    excerpt: str


@dataclass
class ShellAnalyzer:
    """Applies the rules to shell code, following downloaded scripts with the reader."""

    ctx: RuleContext
    out: Collector
    reader: RemoteReader | None
    core_unreadable: list[str] = field(default_factory=list)
    _analyzed: set[str] = field(default_factory=set)

    def analyze(self, snippet: Snippet) -> None:
        if len(snippet.text) > 2 * 1024 * 1024:
            return
        parsed = parse_shell(snippet.text)
        origin = snippet.origin

        def at(cmd: Command) -> int | None:
            return None if snippet.root_command else origin.line + cmd.line - 1

        for start, end in parsed.unreadable if snippet.report_unparsed else []:
            first = origin.line + start - 1
            last = origin.line + end - 1
            lines = snippet.text.splitlines()
            self.out.add(
                "install_path.unparsed",
                path=origin.path,
                line=None if snippet.root_command else first,
                excerpt=lines[start - 1] if 0 < start <= len(lines) else None,
                runs=origin.runs,
                data={"lines": f"{first}-{last}" if last > first else str(first)},
            )
        downloads = {c.index: d for c in parsed.commands if (d := as_download(c))}
        self._simple_rules(parsed, origin, at, downloads)
        self._credential_rules(parsed, origin, at)
        self._persistence_rules(parsed, origin, at)
        for run in self._find_runs(parsed, downloads):
            self._handle_run(run, snippet, at)
        self._nested(parsed, snippet)

    # --- simple pattern rules ----------------------------------------------

    def _simple_rules(
        self, parsed: ParsedScript, origin: Origin, at, downloads: dict[int, Download]
    ) -> None:
        add = self.out.add
        for c in parsed.commands:
            wrappers, rest = peel(c.argv)
            if not rest:
                continue
            name, args = basename(rest[0]), rest[1:]
            where = {"path": origin.path, "line": at(c), "excerpt": c.raw, "runs": origin.runs}
            if c.obfuscated:
                add(
                    "install_path.decode_and_run",
                    **where,
                    data={"what": "a command name spelled with escape codes"},
                )
            if name == "xattr" and (
                (
                    "com.apple.quarantine" in args
                    and any(a.startswith("-") and ("d" in a or "w" in a) for a in args)
                )
                or any(a in ("-c", "-cr", "-rc") for a in args)
            ):
                add("install_path.quarantine_removed", **where)
            if name == "spctl" and any(a in ("--master-disable", "--global-disable") for a in args):
                add("install_path.gatekeeper_off", **where)
            if name == "defaults" and "LSQuarantine" in args:
                add("install_path.gatekeeper_off", **where)
            if name == "osascript":
                script = _script_text(c).lower()
                if "hidden answer" in script or (
                    "display dialog" in script
                    and "password" in script
                    and "default answer" in script
                ):
                    add("install_path.fake_password_prompt", **where)
            if self._is_global_install(name, args, wrappers):
                add("install_path.global_install", **where)
            if name == "systemctl" and "enable" in args:
                add("install_path.background_service", **where)
            urls = list(downloads[c.index].urls) if c.index in downloads else []
            if name == "git" and "clone" in args:
                urls += [a for a in args if a.startswith("http://")]
            for url in urls:
                if url.startswith("http://") and (urlsplit(url).hostname or "") not in _LOCAL_HOSTS:
                    add("install_path.plain_http", **where, data={"what": url[:200]})

    @staticmethod
    def _is_global_install(name: str, args: list[str], wrappers: list[str]) -> bool:
        if (
            name in ("npm", "pnpm")
            and any(a in ("install", "i", "add") for a in args)
            and any(a in ("-g", "--global") for a in args)
        ):
            return True
        if name == "yarn" and args[:2] == ["global", "add"]:
            return True
        sudo = any(w in SUDO for w in wrappers)
        if sudo and name in ("pip", "pip3", "npm", "gem", "pnpm", "yarn", "easy_install"):
            return True
        if sudo and name in ("python", "python3") and args[:2] == ["-m", "pip"]:
            return True
        return name in ("pip", "pip3") and "--break-system-packages" in args

    # --- keys and passwords ----------------------------------------------------

    def _credential_rules(self, parsed: ParsedScript, origin: Origin, at) -> None:
        reads: list[tuple[Command, str]] = []
        thefts: list[tuple[Command, str]] = []
        for c in parsed.commands:
            bare = bool(c.argv) and basename(c.argv[0]) in ("env", "printenv")
            if bare and all("=" in a or a.startswith("-") for a in c.argv[1:]):
                # A bare `env` or `printenv` prints every environment variable. peel() would
                # treat env as a wrapper with nothing after it, so check it here.
                if c.pipeline is not None or c.redirects or c.parent is not None:
                    reads.append((c, "all your environment variables, which often hold tokens"))
                continue
            _, rest = peel(c.argv)
            if not rest:
                continue
            name = basename(rest[0])
            if name == "security" and any(
                a in ("find-generic-password", "find-internet-password", "dump-keychain", "export")
                for a in rest[1:]
            ):
                reads.append((c, "passwords in the macOS Keychain"))
            if name not in _NOT_A_READ:
                candidates = rest[1:] + [r.target for r in c.redirects if r.op.startswith("<")]
                for word in candidates:
                    kind = credential_kind(word)
                    if kind:
                        reads.append((c, kind))
                        break
            if is_network_send(c):
                for m in _SECRET_ENV.finditer(c.raw):
                    hosts = [
                        urlsplit(u).hostname or "" for u in re.findall(r"https?://[^\s'\"]+", c.raw)
                    ]
                    allowed = _SECRET_HOME.get(m.group(1), ())
                    if hosts and all(
                        any(h == a or h.endswith("." + a) for a in allowed) for h in hosts
                    ):
                        continue
                    thefts.append((c, f"the secret in ${m.group(1)}"))
        sends = [c for c in parsed.commands if is_network_send(c)]
        for c, kind in thefts:
            self.out.add(
                "install_path.credential_theft",
                path=origin.path,
                line=at(c),
                excerpt=c.raw,
                runs=origin.runs,
                data={"what": kind},
            )
        if reads and sends:
            for c, kind in reads:
                self.out.add(
                    "install_path.credential_theft",
                    path=origin.path,
                    line=at(c),
                    excerpt=c.raw,
                    runs=origin.runs,
                    data={"what": kind},
                )
            first_send = sends[0]
            self.out.add(
                "install_path.credential_theft",
                path=origin.path,
                line=at(first_send),
                excerpt=first_send.raw,
                runs=origin.runs,
                data={"what": "sends data over the network"},
            )
        elif reads:
            for c, kind in reads:
                self.out.add(
                    "install_path.credential_read",
                    path=origin.path,
                    line=at(c),
                    excerpt=c.raw,
                    runs=origin.runs,
                    data={"what": kind},
                )

    # --- running again later -------------------------------------------------

    def _written_content(self, c: Command, parsed: ParsedScript) -> str:
        parts = [c.heredoc or "", c.herestring or ""]
        _, rest = peel(c.argv)
        if rest and basename(rest[0]) in ("echo", "printf"):
            parts.append(" ".join(rest[1:]))
        if c.pipeline is not None:
            for other in parsed.pipeline(c.pipeline):
                if other.position < c.position:
                    parts.append(" ".join(other.argv) + " " + (other.heredoc or ""))
        return " ".join(parts)

    def _persistence_rules(self, parsed: ParsedScript, origin: Origin, at) -> None:
        add = self.out.add
        for c in parsed.commands:
            _, rest = peel(c.argv)
            if not rest:
                continue
            name, args = basename(rest[0]), rest[1:]
            where = {"path": origin.path, "line": at(c), "excerpt": c.raw, "runs": origin.runs}
            plain = [a for a in args if not a.startswith("-")]
            writes = [
                r.target for r in c.redirects if r.op in (">", ">>", "&>", ">|", "&>>", "1>", "1>>")
            ]
            if name == "tee":
                writes += plain
            if name in ("cp", "mv", "install", "ln", "rsync", "ditto") and len(plain) >= 2:
                writes.append(plain[-1])
            if name == "sed" and any(a.startswith("-i") for a in args) and plain:
                writes.append(plain[-1])
            if name == "launchctl" and any(
                a in ("load", "bootstrap", "enable", "submit") for a in args
            ):
                add("install_path.persistence", **where, data={"what": "a login item (launchctl)"})
            if name == "crontab" and not any(a in ("-l", "-r", "-e", "-u") for a in args):
                add("install_path.persistence", **where, data={"what": "a scheduled job (crontab)"})
            if name == "osascript" and "login item" in _script_text(c).lower():
                add("install_path.persistence", **where, data={"what": "a login item"})
            for target in writes:
                path = normalize_home(target).lower()
                if path.startswith(_LAUNCH):
                    add(
                        "install_path.persistence",
                        **where,
                        data={"what": "a login item (LaunchAgent)"},
                    )
                elif path.startswith(_CRON):
                    add(
                        "install_path.persistence", **where, data={"what": "a scheduled job (cron)"}
                    )
                elif "~/.ssh/authorized_keys" in path:
                    add(
                        "install_path.persistence",
                        **where,
                        data={"what": "a key that lets someone log in over SSH"},
                    )
                elif _is_rc(path):
                    if _FETCHES.search(self._written_content(c, parsed)):
                        add(
                            "install_path.persistence",
                            **where,
                            data={"what": "a startup file that downloads code"},
                        )
                    else:
                        add("install_path.shell_rc_change", **where, data={"what": target[:120]})
                elif path.startswith(_SERVICES):
                    add("install_path.background_service", **where)

    # --- downloading and running ---------------------------------------------

    def _find_runs(self, parsed: ParsedScript, downloads: dict[int, Download]) -> list[_Run]:
        runs: list[_Run] = []
        decoded: set[int] = set()
        for c in parsed.commands:
            wrappers, rest = peel(c.argv)
            if not rest:
                continue
            sudo = any(w in SUDO for w in wrappers)
            name = basename(rest[0])
            # 1. curl ... | sh
            if c.pipeline is not None and c.position > 0 and reads_stdin(rest):
                earlier = [o for o in parsed.pipeline(c.pipeline) if o.position < c.position]
                text = " | ".join(o.raw for o in sorted([*earlier, c], key=lambda o: o.position))
                for o in earlier:
                    if o.index in downloads and downloads[o.index].to_stdout:
                        runs.append(_Run(c, downloads[o.index], "pipe", sudo, text))
                    if _is_decoder(o) and c.index not in decoded:
                        decoded.add(c.index)
                        runs.append(_Run(c, None, "decode", sudo, text))
            # 2. bash -c "$(curl ...)", eval "$(...)", source <(curl ...), bash <(curl ...)
            runs_code = name == "eval" or name in SOURCE or (name in SHELLS | SCRIPT_RUNNERS)
            if runs_code:
                for child in parsed.children(c.index):
                    if (
                        child.subst == "command"
                        and name in SHELLS
                        and not self._is_dash_c_arg(c, child.parent_arg)
                    ):
                        continue  # "$(...)" used as an ordinary argument, not as the program
                    if child.subst == "command" and name in SCRIPT_RUNNERS:
                        continue
                    if child.subst not in ("command", "process_in"):
                        continue
                    for member in self._substitution_members(parsed, child):
                        if member.index in downloads and downloads[member.index].to_stdout:
                            runs.append(
                                _Run(c, downloads[member.index], "substitution", sudo, c.raw)
                            )
                        if _is_decoder(member) and c.index not in decoded:
                            decoded.add(c.index)
                            runs.append(_Run(c, None, "decode", sudo, c.raw))
            # 3. "$(echo ... | base64 -d)" used as the command itself
            if c.argv and c.argv[0].startswith(f"$({DYNAMIC}") and c.index not in decoded:
                for child in parsed.children(c.index):
                    if child.parent_arg == 0 and any(
                        _is_decoder(m) for m in self._substitution_members(parsed, child)
                    ):
                        decoded.add(c.index)
                        runs.append(_Run(c, None, "decode", sudo, c.raw))
                        break
        # 4. curl -o file URL; chmod +x file; ./file  (handled below, after de-duplication)
        unique: dict[tuple[int, int | None, str], _Run] = {}
        for run in runs:
            key = (run.runner.index, run.download.cmd.index if run.download else None, run.via)
            unique.setdefault(key, run)
        runs = list(unique.values())
        saved: dict[str, Download] = {}
        for c in parsed.commands:
            if c.index in downloads:
                for f in downloads[c.index].out_files:
                    saved[f.removeprefix("./")] = downloads[c.index]
                continue
            wrappers, rest = peel(c.argv)
            if not rest or not saved:
                continue
            program = rest[0].removeprefix("./")
            target = None
            if program in saved:
                target = program
            elif basename(rest[0]) in SHELLS | SCRIPT_RUNNERS | SOURCE:
                positional = [a for a in rest[1:] if not a.startswith("-")]
                if positional and positional[0].removeprefix("./") in saved:
                    target = positional[0].removeprefix("./")
            elif basename(rest[0]) in ("open", "installer"):
                for a in rest[1:]:
                    if a.removeprefix("./") in saved:
                        target = a.removeprefix("./")
            if target is not None:
                d = saved[target]
                runs.append(
                    _Run(c, d, "file", any(w in SUDO for w in wrappers), f"{d.cmd.raw} … {c.raw}")
                )
        return runs

    @staticmethod
    def _is_dash_c_arg(cmd: Command, arg_index: int | None) -> bool:
        if arg_index is None or arg_index < 1:
            return False
        previous = cmd.argv[arg_index - 1] if arg_index - 1 < len(cmd.argv) else ""
        return previous == "-c" or (
            previous.startswith("-") and not previous.startswith("--") and "c" in previous
        )

    @staticmethod
    def _substitution_members(parsed: ParsedScript, first: Command) -> list[Command]:
        members = [first]
        if first.pipeline is not None:
            members = parsed.pipeline(first.pipeline)
        nested = [c for m in members for c in parsed.children(m.index)]
        return members + nested

    def _handle_run(self, run: _Run, snippet: Snippet, at) -> None:
        origin = snippet.origin
        where = {
            "path": origin.path,
            "line": at(run.runner),
            "excerpt": run.excerpt,
            "runs": origin.runs,
        }
        if run.via == "decode":
            self.out.add("install_path.decode_and_run", **where)
            return
        download = run.download
        if download is None:
            return
        if run.sudo and run.via in ("pipe", "substitution"):
            self.out.add("install_path.sudo_piped_download", **where)
        for url in download.urls or [DYNAMIC]:
            if url == DYNAMIC:
                self.out.add(
                    "install_path.remote_unreadable",
                    **where,
                    data={"reason": "its address is only known when it runs"},
                )
                if snippet.root_command:
                    self.core_unreadable.append("its address is only known when it runs")
                continue
            result = self._fetch(url, download.tool, origin)
            cls = self.ctx.classify(url)
            if run.via == "file" and result is not None and result.status == "binary":
                if cls.kind == "known_installer" or cls.kind in ("project", "project_unpinned"):
                    self.out.add(
                        "install_path.own_remote_script", **where, data={"what": url[:200]}
                    )
                elif cls.kind == "release":
                    self.out.add(
                        "install_path.download_and_run_release", **where, data={"what": url[:200]}
                    )
                else:
                    self.out.add(
                        "install_path.download_and_run_binary", **where, data={"what": url[:200]}
                    )
                continue
            data: dict[str, str | int | float | bool] = {"what": url[:200]}
            if cls.kind == "known_installer" and cls.installer is not None:
                data["installer"] = cls.installer.name
                if result is not None and result.sha256 and cls.installer.sha256:
                    data["matches_last_seen"] = result.sha256 == cls.installer.sha256
                    if cls.installer.seen:
                        data["last_seen"] = cls.installer.seen
                self.out.add("install_path.known_installer", **where, data=data)
            elif cls.kind == "project":
                self.out.add("install_path.own_remote_script", **where, data=data)
            elif cls.kind == "project_unpinned":
                self.out.add("install_path.unpinned_remote_script", **where, data=data)
            else:
                self.out.add("install_path.remote_script_unknown_site", **where, data=data)
            if result is None:
                continue
            if result.readable:
                if result.url not in self._analyzed:
                    self._analyzed.add(result.url)
                    runs_text = (
                        "when the command downloads and runs it"
                        if origin.path == "command"
                        else f"when {origin.path} downloads and runs it"
                    )
                    self.analyze(
                        Snippet(
                            result.text or "",
                            Origin(
                                path=url,
                                line=1,
                                runs=runs_text[:200],
                                remote=True,
                                depth=origin.depth + 1,
                            ),
                        )
                    )
            else:
                reason = result.reason or (
                    "it's a program, not a script"
                    if result.status == "binary"
                    else "it couldn't be downloaded"
                )
                self.out.add(
                    "install_path.remote_unreadable",
                    **where,
                    data={"what": url[:200], "reason": reason},
                )
                if snippet.root_command and run.via in ("pipe", "substitution"):
                    self.core_unreadable.append(f"{url}: {reason}")

    def _fetch(self, url: str, tool: str, origin: Origin) -> RemoteScript | None:
        if self.reader is None:
            return None
        if origin.depth + 1 > self.reader.limits.max_depth:
            return RemoteScript(
                url, "limit", reason="lookfirst follows downloads at most 3 levels deep"
            )
        return self.reader.get(url, tool=tool)

    # --- code inside code --------------------------------------------------

    def _nested(self, parsed: ParsedScript, snippet: Snippet) -> None:
        origin = snippet.origin
        for c in parsed.commands:
            _, rest = peel(c.argv)
            if not rest:
                continue
            name, args = basename(rest[0]), rest[1:]
            inner = None
            if name in SHELLS or name == "su":
                for i, a in enumerate(args[:-1]):
                    if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a):
                        candidate = args[i + 1]
                        if DYNAMIC not in candidate:
                            inner = candidate
                        break
            elif name == "eval" and args and not c.dynamic:
                inner = " ".join(args)
            later_shell = c.pipeline is not None and any(
                o.position > c.position and reads_stdin(peel(o.argv)[1])
                for o in parsed.pipeline(c.pipeline)
            )
            if c.heredoc and (reads_stdin(rest) or later_shell):
                self.analyze(
                    Snippet(
                        c.heredoc,
                        Origin(
                            origin.path,
                            (origin.line + c.line) if not snippet.root_command else 1,
                            origin.runs,
                            origin.remote,
                            origin.depth,
                        ),
                        snippet.root_command,
                    )
                )
            if inner and inner.strip() and inner != snippet.text:
                line = 1 if snippet.root_command else origin.line + c.line - 1
                self.analyze(
                    Snippet(
                        inner,
                        Origin(origin.path, line, origin.runs, origin.remote, origin.depth),
                        snippet.root_command,
                    )
                )

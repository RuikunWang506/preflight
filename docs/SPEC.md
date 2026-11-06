# lookfirst v0.1 specification

Named lookfirst at M1 (section 14); the working title was Preflight. The sections below are the design Claude Code builds from. Where a detail is marked **decide**, propose options in the plan and wait for an answer.

## 1. The problem in one paragraph

People and AI agents now run code from strangers all day: a repo that trended this morning, a `curl -fsSL … | bash` line from a README, an MCP server an agent suggested, a skill folder someone shared. Attackers know it. They copy the README of a viral project into a new account, inflate its stars, attach a "setup" archive or an install script that steals credentials, and wait for people or agents to find it. FakeGit research by the security firm Island counted about 7,600 such repos, more than 800 of them posing as AI skills or MCP servers. Today you can scan a package, read a script, or run code in a sandbox, but no tool answers the two questions that matter before you run something: is it real, and what will it do?

## 2. Users and the demo moment

- **Primary:** developers and AI-tool users who install things from GitHub, and their coding agents (Claude Code, Codex, Cursor).
- **Demo moment:** Claude Code is about to run the installer of a fake copy of a viral repo. lookfirst's hook stops it and shows three lines of evidence: a copied README, a three-day-old account, and decoy SSH key contents seen leaving the sandbox.

## 3. Targets

| Input | How it's resolved |
| --- | --- |
| `https://github.com/owner/repo`, `owner/repo`, `owner/repo@ref` | GitHub REST API for metadata; shallow clone or tarball download into a temp dir (never executed on the host) |
| A local folder | Read in place, read-only |
| A shell one-liner in quotes | Parsed; every URL it fetches is downloaded (not run) and analyzed recursively, to depth 3 |
| `npm:<name>[@version]`, `pypi:<name>[==version]` | Package metadata and tarball; its declared source repo also gets the identity check |
| An MCP server command such as `npx -y <pkg>` or `uvx <pkg>` | Treated as a package target plus a one-liner |

## 4. Identity check (the main new piece)

**Goal:** tell whether the target is a lookalike of a popular project, and name the original.

**Candidate originals**, in this order:

1. `lookfirst/registry/official.yaml`: canonical repos, domains and package names for popular projects. It's community-maintained, and contributors add entries by pull request.
2. The popular-repos index (`data/popular.parquet`).
   - Seed it from the user's 12-year GitHub Trending archive: `trending_repos_tagged.csv.gz` (76,892 repos) in the ideas package.
   - Add the GitHub search API's top repos by stars. Refresh weekly.
3. A live GitHub search for repos with the same name, sorted by stars.
4. A package registry's `repository` field, when the README names an npm or PyPI package.

**Signals** (each becomes a finding with evidence):

| Signal | Rule of thumb (tune on fixtures) |
| --- | --- |
| Name | Same repo name under a different owner; edit distance of 2 or less; homoglyphs (`rn`/`m`, `l`/`I`/`1`, `0`/`o`); suffixes such as `-pro`, `-free`, `-official`, `-download`, `-crack`, `-fixed`; an owner name that looks like the original owner's |
| README copy | MinHash Jaccard of 5-word shingles against the candidate's README; 0.6 or above = substantially copied |
| Age and history | Repo or account under 30 days old while the original is older than 6 months; 3 commits or fewer; a single contributor; history unrelated to the original's |
| Stars | Star count implausible for age; sample up to 100 stargazers and flag when over 50% are accounts under 30 days old or with no repos and no followers |
| Releases | Release assets (zip, 7z, rar, exe, dmg, pkg, msi) that the original doesn't ship; README asks for an archive password; download links outside GitHub (file hosts, paste sites, chat CDNs); README asks you to disable Gatekeeper or antivirus |
| Official sources | The original's README or `official.yaml` lists official sources, and the target isn't one of them |
| Forks | A fork whose release assets or install scripts differ from the parent's |

**Output:** one of `original`, `fork (benign)`, `unrelated`, or `likely impersonation of <owner/repo>` with a confidence and the top three signals.

**Budget:** unauthenticated GitHub allows 60 requests an hour, so v0.1 asks for an optional read-only token (`GITHUB_TOKEN` or `gh auth token`) and caches responses with ETags in `~/.cache/lookfirst/`.

## 5. Install-path check (static, nothing runs)

**Find everything that would run** when someone follows the README or opens the folder:

- **README:** code blocks under install, quick-start or usage headings (shell lines only).
- **Scripts:** `install.sh`, `setup.sh`, `Makefile` (default target and install), `justfile`, `Dockerfile` `RUN` lines.
- **npm:** `package.json` scripts `preinstall`, `install`, `postinstall` and `prepare`, plus any `bin` entries.
- **Python:** `setup.py` (custom commands), `pyproject.toml` build backend and hooks, and requirements lines pointing at URLs or git.
- **Auto-run on open:**
  - `.vscode/tasks.json` with `"runOn": "folderOpen"`
  - `.devcontainer` `postCreateCommand`, `postStartCommand` and `onCreateCommand`
  - `.envrc` (direnv)
- **Agent configs shipped in the repo:** see section 6.

**Analyze each command and script:**

1. **Parse with tree-sitter-bash** to extract commands, pipes, redirections and URLs. Regions the parser can't read become an info finding ("couldn't fully read lines X–Y"), never a silent skip. Download each fetched URL and analyze it the same way, to depth 3, with size and count limits. Never run anything. (Changed from bashlex on 5 Nov 2026: bashlex is GPL-3.0 and failed on all 10 real installers tested.)
2. **Run ShellCheck** when installed, for parse errors and obviously broken scripts.
3. **Apply the rules below.** Each rule has an id, a severity and a plain-English explanation.

| Severity | Examples |
| --- | --- |
| critical | Reads credential paths (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.npmrc`, `~/.docker/config.json`, browser profile folders, crypto-wallet folders, `security find-generic-password`) and also has a network send. Fake password prompts (`osascript … with hidden answer`). Writes persistence (LaunchAgents or LaunchDaemons, crontab, shell rc files that fetch code) |
| high | Decodes and runs code (`base64 -d \| sh`, `eval "$(curl …)"`, printf or hex decoding into a shell); downloads a binary from outside the project's releases and runs it; removes quarantine attributes from downloads; turns off Gatekeeper; `sudo` on a piped download |
| medium | `curl \| bash` from a domain the project doesn't own; unpinned remote scripts; global installs; downloads over plain http |
| info | `curl \| bash` from the project's own domain or a well-known installer (Homebrew, rustup, uv, nvm) whose URL is on an allowlist |

**False positives matter as much as catches.** Keep an allowlist of well-known installers by URL, and record the hash each was last seen with.

## 6. Agent-attack check

- **Repo-shipped agent configs.** List and flag executable entries in:
  - `.claude/settings.json` (hooks with commands), `.claude/commands/`, `.claude/agents/`, `.claude/skills/`
  - `.mcp.json`, `.cursor/` (rules and `mcp.json`)
  - `AGENTS.md`, `CLAUDE.md`
  - `SKILL.md` files that tell an agent to run commands
- **Prompt injection aimed at agents**, in READMEs, docs, code comments, issue templates and `SKILL.md`:
  - instructions addressed to AI assistants, such as asking it to run commands, fetch URLs or ignore earlier instructions
  - hidden text: HTML comments holding instructions, zero-width and bidirectional Unicode characters, long base64 blobs in Markdown
  - instructions placed in image alt text
- **Reporting:** quote the exact text with file and line, and never act on it. The injection fixture proves this.

## 7. Package check (wrap existing tools)

- **osv-scanner** (Apache-2.0, tested with 2.7.0): `osv-scanner scan source -r --format json <dir>`, for known vulnerabilities in lockfiles and manifests.
  - Exit code 1 means "vulnerabilities found", not a failure.
  - A `package.json` without a lockfile yields nothing.
  - It sends package names and versions to osv.dev (and deps.dev for transitive resolution). Say so in the report.
- **GuardDog** (Apache-2.0, tested with 3.2.0), for malicious-package heuristics, with `--output-format=json`:
  - a folder or archive: `guarddog pypi scan <dir-or-archive>` or `guarddog npm scan <dir>`
  - requirements files: `guarddog pypi verify requirements.txt`
  - GitHub Actions: `guarddog github_action scan <target>` (there is no `verify` subcommand for actions)
  - Its npm scan did not flag a `postinstall` that pipes curl into bash, so section 5's own rules must cover lifecycle scripts.
  - Install hint to print: `uv tool install --python 3.12 guarddog` (the default Python fails to build pygit2). Look for it in `~/.local/bin` too.
- **If a tool is missing,** say so in the report and print how to install it. Never vendor these tools.
- **Credit** each finding to the tool that produced it, with the tool's version.
- **Socket's MCP and SafeDep:** deferred to v0.2 (decided 5 Nov 2026).

## 8. Sandbox dry run (`--sandbox`)

**Engine:** the Docker API against Docker Desktop or OrbStack on the Mac. Linux-only in v0.1.

**Image:** `lookfirst-sandbox`, built from `lookfirst/sandbox/Dockerfile`.

- Debian slim with git, curl, ca-certificates, python3, pip, uv, nodejs, npm, build-essential, strace and procps.
- Built locally and pinned by digest.

**Isolation:**

- **No host mounts.** Copy the target into `/work` with `docker cp` or a tar stream.
- **Container settings:** not privileged; all capabilities dropped except `SYS_PTRACE` (for strace); pids, memory and CPU limits; a hard timeout (default 180 seconds).
- **Network:** an internal Docker network whose only way out is a mitmproxy sidecar (`mitmproxy/mitmproxy`, pinned by digest).
  - Set `HTTP_PROXY` and `HTTPS_PROXY`. Generate a fresh mitmproxy CA for each run and install it in the sandbox trust store.
  - **Sinkhole by default** (decided 5 Nov 2026): requests to the package registries and the project's own domains pass through. Every other request is recorded in full (so honeytoken markers are still caught) and answered locally with a stub, so nothing leaves the Mac.
  - `--network=passthrough` lets all traffic through the proxy, as an explicit opt-in.
  - Anything that tries to bypass the proxy fails, and strace records the attempt.
- **`--offline`** removes even the proxy.
- **Architecture:** arm64 by default (native on Apple Silicon). `--arch amd64` runs under emulation, which is slower but runs the many payloads built only for amd64.

**Decoy home** (honeytokens, each holding a unique random marker):

- `~/.ssh/id_ed25519` (fake key)
- `~/.aws/credentials` (a fake `AKIA…` pair)
- `~/.config/gh/hosts.yml`
- `~/.npmrc` with a fake token
- `.env` files in `/work`
- a fake Chrome profile (`Login Data`, `Cookies`)
- a fake wallet folder

**Run:**

1. **Choose the command.** Use `--cmd` if given. Otherwise pick the best guess from section 5: the one-liner itself, the README's install block, `npm install`, `pip install .`, `make install`, or `./install.sh`. Show the chosen command in the report.
2. **Trace it:** wrap it in `strace -f -e trace=execve,openat,connect,unlinkat,renameat2 -o /trace/strace.log`.
3. **Diff the filesystem:** after it exits or times out, collect `docker diff`.
4. **Collect network logs:** proxy flows (method, host, path, size, and whether any body contains a honeytoken marker) plus DNS lookups and connect() targets from strace.

**Findings from the run:**

| Severity | Finding |
| --- | --- |
| critical | A honeytoken marker appears in outbound traffic |
| high | A honeytoken file is read by anything other than the tool that legitimately owns it, for example ssh reading `~/.ssh` during a git-over-ssh clone; writes to persistence locations (shell rc files, `/etc/cron*`, systemd units); a downloaded binary is executed from `/tmp` or the home folder |
| medium | Connections to domains other than the package registries and the project's own domains; processes still running at the timeout |

**Limits stated in the report:** the dry run is a Linux container, so macOS-only payloads (for example fake password dialogs) won't fire there; the static rules in section 5 cover them. Malware can detect sandboxes or wait before acting, so "nothing seen" doesn't mean safe.

**v0.2 (not now):** macOS virtual machines on Apple Silicon (for example Tart; check its license first).

## 9. Findings, verdict and output

**Finding** (pydantic model, versioned JSON schema):

```json
{
  "id": "identity.readme_copy",
  "check": "identity",
  "severity": "high",
  "title": "README is 94% identical to original-owner/viral-tool",
  "evidence": [{"type": "url", "ref": "https://github.com/original-owner/viral-tool", "excerpt": "..."}],
  "explanation": "Impersonation campaigns copy a popular project's README into a new repo.",
  "recommendation": "Use the original repo unless you know why this copy exists.",
  "source": "lookfirst"
}
```

**Verdict:**

- any critical finding → **Don't run** (exit code 20)
- otherwise, any high finding → **Caution** (exit code 10)
- otherwise → **Looks OK** (exit code 0)
- errors → exit code 1

Every verdict lists what was not checked (for example "sandbox not run", "GuardDog not installed").

**Outputs:**

- **Terminal:** rich text with the verdict first, then the top three reasons, then details folded below them.
- **JSON:** `--json`, with a stable schema and a schema version number.
- **Markdown:** `--report FILE`, shareable, with links to the evidence.

**Wording:** plain English, about 15 words a line. Never say "safe"; say "Looks OK: no warning signs found in what was checked".

## 10. Agent integration

**MCP server** (`lookfirst mcp`, stdio, official Python SDK v2: `mcp>=2.3,<3`, `MCPServer`):

- The server returns quoted repo text only as escaped, length-capped excerpts marked as quoted data. Summaries come from templates only, so our own output can't carry an injection to the calling agent.

- `lookfirst_check(target: str, sandbox: bool = false)` returns the verdict, the findings and a 3-line summary.
- `lookfirst_explain(finding_id: str)` explains one finding.

**Claude Code hook** (`lookfirst hook`, a PreToolUse handler for the Bash tool):

- **Input:** it reads the hook JSON from stdin; the command is at `tool_input.command`.
- **Fast path:** if the command doesn't look like an install or remote-execution command, exit 0 within 50 ms. Install-like commands include:
  - `curl` or `wget` piped to a shell, and `bash <(curl …)`
  - `pip install`, `uv pip install`, `uv add`, `npm install <pkg>`, `npx -y`, `uvx`
  - `git clone` chained with run or install steps
  - `./install.sh` in a freshly cloned folder
- **Fast-path speed:** the fast path imports only the Python standard library. Measured on 5 Nov 2026: bare Python starts in 17–25 ms; importing pydantic adds about 40 ms and `mcp` about 440 ms. Load everything else lazily.
- **Otherwise,** run the static check with a 20-second budget, then exit 0 and print JSON on stdout (decided 5 Nov 2026; exit 2 can only block, it can't ask):
  - **Don't run:** `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "<verdict, top three reasons, and: tell the user and don't retry with a workaround>"}}`
  - **Caution:** `"permissionDecision": "ask"`, with the findings as the reason, so the user gets a real permission prompt.
  - **Looks OK:** no output and exit 0, so the normal permission flow applies.
  - **If the hook itself errors or runs past its budget:** let the command through, with a visible `systemMessage` warning that the check didn't finish (fail open). A broken hook must never stop the agent from working.
- The Bash tool's `tool_input` also carries `description`, `timeout` and `run_in_background`; ignore them.
- **Config** (project or user `settings.json`, or the plugin's `hooks/hooks.json` using `${CLAUDE_PLUGIN_ROOT}`):

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "lookfirst hook", "timeout": 30}]}
    ]
  }
}
```

**Skill** (`plugin/skills/lookfirst/SKILL.md`):

- **When to call it:** before cloning and running unfamiliar repos, adding MCP servers or skills, installing packages that aren't in the lockfile, or running a remote script.
- **How to act on the verdict:**
  - **Don't run:** stop and tell the user.
  - **Caution:** show the findings and ask.
  - **Looks OK:** go ahead and mention the check.

**Plugin:** `plugin/.claude-plugin/plugin.json` bundles the hook, the skill and the MCP server config. Document how to install it.

## 11. Tests and fixtures

**Recorded HTTP fixtures:** the tests never call GitHub, npm or PyPI live. A small recorder script refreshes the recordings on demand.

**Lookalike pairs:** synthetic pairs built from recorded metadata.

- **Copied README:** a new account, few commits, plus a release archive the original doesn't ship.
- **Homoglyph owner:** an owner name that looks like the original's.
- **Benign cases:** legitimate forks and same-named unrelated projects.

**Benign set:** recorded metadata for 20 popular, trusted repos. None may get Don't run.

**Install-path fixtures:** one harmless script per rule in section 5, each touching only decoy paths, plus benign installers on the allowlist.

**Sandbox fixtures:** they run only inside Docker, and CI runs them on Linux.

- one that reads the decoy SSH key and posts it to a local test server
- one that writes a cron entry
- one that downloads and runs a binary from `/tmp`
- one benign `npm install` and one benign `pip install .`

**Injection fixture:** a README telling AI assistants to run a command. The verdict must not change, and the finding must quote it.

**Host canary:** a fixture that would create `~/LOOKFIRST_HOST_CANARY` if it ever ran on the host. A test asserts that file never exists after the full suite.

## 12. Definition of done (v0.1)

1. **Static speed:** `lookfirst check owner/repo` finishes in under 30 seconds with a token on a typical repo, and every Caution or Don't-run reason has evidence.
2. **Sandbox:** `--sandbox` finishes in under 3 minutes, catches the theft, persistence and binary-run fixtures, and passes both benign installs.
3. **Lookalikes:** every synthetic lookalike pair is flagged with the original named, and none of the 20 benign repos gets Don't run.
4. **Hook:** in a recorded Claude Code session, the hook blocks the malicious one-liner fixture with evidence, and adds under 100 ms to unrelated commands.
5. **Host safety:** the host canary test passes, and the injection fixture leaves the verdict unchanged.
6. **README:**
   - a 30-second demo
   - install steps for the CLI and the plugin
   - the threat model, what's checked and what isn't
   - the "lowers risk, doesn't guarantee safety" statement

## 13. Milestones (about 18 working days)

| # | Milestone | Done when |
| --- | --- | --- |
| M1 | Plan, name, skeleton, findings schema, CLI, target fetching | `lookfirst check` prints an empty report for each target type |
| M2 | Install-path analyzer, shell rules, fixtures, and the section 6 agent-attack check | Every install-path fixture is caught; benign installers pass |
| M3 | Identity check, popular index, `official.yaml` | Lookalike pairs flagged; benign set clean |
| M4 | osv-scanner and GuardDog wrappers, verdict, terminal/JSON/Markdown output | Three example reports reviewed (OK, Caution, Don't run) |
| M5 | Sandbox dry run | Sandbox fixtures caught; benign installs pass; limits printed |
| M6 | MCP server, hook, skill, plugin, demo recording | The hook blocks the fixture in a real Claude Code session |
| M7 | README, final name, pre-launch review, v0.1.0 release | Section 12 all green |

## 14. Name

"Preflight", the working title, is taken by several security tools, including SpectralOps/preflight (script verification), deepsafe-scan (a "preflight" scanner for AI coding agents) and agent-contracts/skill-preflight. "Airlock" is taken by sandbox tools (besoeasy/airlock, milankinen/airlock).

At M1, propose 10 short names that work as a command (`<name> check owner/repo`). Check each on GitHub, PyPI, npm and Homebrew, and against well-known security products. Reserve the chosen name's packages on day one, and add an "official sources" line to the README.

**Chosen 5 Nov 2026: `lookfirst`.** It's free on PyPI, npm and Homebrew; the GitHub user name is taken, so the org is `lookfirst-dev`. The 10 candidates are in `docs/PLAN-v0.1.md` section 3.

## 15. Competitors to stay compatible with, not copy

| Tool | Covers | What lookfirst adds |
| --- | --- | --- |
| SafeDep PMG, Socket Firewall, Aikido Safe Chain | Malicious packages at install time; PMG sandboxes package installs | Repos and one-liners, identity, one verdict |
| Repo Run Check (devx-agent, launched 30 Oct 2026) | Static reading of a repo's install steps (CLI, MCP, paid API). Its paid tier adds fake-star, new-owner and lookalike-owner signals. Closest competitor. | README-copy detection that names the original, release-asset comparison, sandbox run, hook |
| CloneGuard, RepoGuard, skillrx, agent-contracts/skill-preflight | Prompt-injection hooks, static repo or skill scanning | Identity check, sandbox, one verdict |
| vet (vet-run) | Shows a `curl \| bash` script before running it | Recursive analysis, verdict, sandbox |
| besoeasy/airlock, milankinen/airlock | Run untrusted code in a container or VM | Analysis and a verdict, not just isolation |
| deepsafe-scan | Scans an agent environment for leaked keys, injections, hook backdoors | Pre-install identity and behavior checks for new code |
| OpenSSF package-analysis | gVisor sandbox for packages at registry scale | Local, on demand, any repo |

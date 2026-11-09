# v0.1 plan (M1 review, 5 Nov 2026)

Status: **approved 5 Nov 2026.** All section 8 recommendations were accepted as defaults. SPEC.md and CLAUDE.md are updated to match. The next step is KICKOFF prompt 2 (skeleton).

## 1. Tool check results

Everything below was run on this Mac on 5 Nov 2026, against harmless probe files in a scratch folder. Nothing was executed from any downloaded script.

| Tool | Version | Works as the spec says? | What changes |
| --- | --- | --- | --- |
| osv-scanner | 2.7.0 (Homebrew), Apache-2.0 | **Yes.** `osv-scanner scan source -r --format json <dir>` gives `results[].packages[].{package, vulnerabilities, groups[].max_severity}`. | Exit code **1 means "vulnerabilities found"**, not an error. Treat it that way. A `package.json` without a lockfile yields nothing. The scan sends package names and versions to osv.dev, and to deps.dev for transitive resolution; say so in the report. |
| GuardDog | 3.2.0, Apache-2.0 | **Partly.** `guarddog pypi scan <dir> --output-format=json` and `guarddog pypi verify requirements.txt --output-format=json` both work. Scan returns `{issues, results, risk_score, risks[]}` with file:line; verify returns a list per dependency. | **`guarddog github_action verify` doesn't exist.** Only `scan` does, so SPEC section 7 needs fixing. `npm scan` on a folder whose `postinstall` is `curl … \| bash` reported **0 issues**, so our own rules must cover lifecycle scripts. The plain `uv tool install guarddog` **fails** on this Mac (no pygit2 wheel for the default Python); `uv tool install --python 3.12 guarddog` works. It installs to `~/.local/bin`, which isn't on PATH. Detect it there and print the working install line. |
| bashlex | 0.18, **GPL-3.0+** | **No.** It handles simple one-liners. It **failed on all 10 real installers**: Homebrew, rustup, nvm, uv, Oh My Zsh, Deno, Bun, get.docker.com, Ollama and Claude Code. It can't handle `case` patterns, `[[ ]]`, `$(( ))` or arrays. | It's also copyleft, which CLAUDE.md says to ask about. **Proposal: drop bashlex and use tree-sitter-bash (MIT) as the only parser.** It parsed 8 of 10 cleanly and the other 2 with a single localized error each (a regex in `[[ =~ ]]`, and `404$`), in 2–6 ms per script. Error regions get flagged "couldn't fully read", never silently skipped. |
| ShellCheck | installed (Homebrew) | Not exercised yet | Optional, as the spec says. |
| mitmproxy | image `mitmproxy/mitmproxy:12.3.1` (25 Oct 2026), MIT, amd64 + arm64 | **Not run: no Docker on this Mac yet** (see section 8). From the docs: CA files are in `/home/mitmproxy/.mitmproxy/` (`mitmproxy-ca-cert.pem`), and a new CA is generated per container unless that folder is mounted. | Generate a fresh CA per run, copy the cert into the sandbox trust store, and pin the image by digest. Confirm `mitmdump -s addon.py` in the container at M5. |
| MCP Python SDK | `mcp` 2.3.0 (2 Oct 2026), MIT, Python ≥ 3.10 | **Yes, but it's v2.** `mcp.server.fastmcp` is gone; it's now `from mcp.server import MCPServer` with `run(transport="stdio")`. | Pin `mcp>=2.3,<3`. Importing it takes **~460 ms**, so it must never load on the hook path. |
| Claude Code hooks | docs at code.claude.com/docs/en/hooks | **Yes.** stdin has `tool_name`, `tool_input.command` (plus `description`, `timeout`, `run_in_background`), `cwd`, `session_id`, `permission_mode`, `tool_use_id`. | **Exit 2 can only block, it can't ask.** Use JSON output instead: `hookSpecificOutput.permissionDecision` = `"deny"` for Don't run and `"ask"` for Caution, which shows the user a real permission prompt instead of relying on Claude to ask in prose. Any exit code other than 0 or 2, or a timeout, **fails open** (the command runs). Config `timeout` is in seconds. |
| Claude Code plugins | docs at code.claude.com/docs/en/plugins-reference | **Yes.** `.claude-plugin/plugin.json` (only `name` required), with `hooks/hooks.json`, `skills/<name>/SKILL.md` and `.mcp.json` at the plugin root, and `${CLAUDE_PLUGIN_ROOT}` in commands. Install via `/plugin marketplace add` + `/plugin install name@marketplace`; check with `claude plugin validate`. | Ship a `marketplace.json` in the repo so people can install from it. |

**Hook speed (measured):** Python with stdlib only starts in 17–25 ms. Importing pydantic makes it ~60 ms, typer+rich ~75 ms, `mcp` ~460 ms. So the hook's "not an install command" path must be **stdlib only** to meet SPEC's 50 ms. The full check loads only when needed.

## 2. Competitors (checked 5 Nov 2026)

| Tool | Latest | What it does now | Overlap |
| --- | --- | --- | --- |
| **Repo Run Check** (devx-agent/repo-run-check) | v1.1.0, created **30 Oct 2026**, 0 stars, MIT | "Is this repo safe for my AI coding agent?" CLI (`npx devx-repo-check`), local and remote MCP, 3-level verdict. Free tier: curl\|sh, base64, LOLBins, text aimed at agents. **Paid tier** (0.25 USDC/check via x402): lifecycle scripts, setup.py, VS Code autorun, Makefile, and fake-star / new-owner / lookalike-owner signals. | **Closest threat.** Most of the install-path check and weak identity signals. No README-copy detection, no release-asset comparison, no sandbox, no hook. |
| SafeDep PMG | v0.34.0, 2 Nov 2026, Apache-2.0 | Wraps npm/pip; malware feed; "cooldown" on new versions; OS sandbox (Seatbelt/Landlock/Bubblewrap); pitched at AI agents | Packages only. Its sandbox enforces; it doesn't watch and report. |
| Socket Firewall (sfw) | v1.16.0, 1 Nov 2026 | Proxy that blocks known-malicious packages and now VS Code extensions. An open PR adds a Claude Code PreToolUse hook to socket-mcp. | Packages only. Vendor-scale risk if it moves to repos. |
| Aikido Safe Chain | 1.5.27, 30 Oct 2026 | Local proxy for npm/pip/uv/poetry etc.; minimum package age | Packages only |
| vet | v1.0.2, Jul 2025 | Shows and lints a curl\|bash script before running | Dormant; narrow |
| besoeasy/airlock, milankinen/airlock | Sep 2026 / v2026.11.1 | Container / lightweight-VM isolation; milankinen has per-request network rules and agent hooks | Isolation only, no verdict |
| deepsafe-scan | v2.0.0-demo, last push May 2026, no license | Scans an agent environment and configs | Agent-config part only |
| OpenSSF package-analysis | rel-38, May 2026 | Registry-scale gVisor sandbox | Research infrastructure, not on demand |
| **New since the brief:** CloneGuard (prompt-injection hooks for Claude Code/Gemini), RepoGuard (static repo scanner, SARIF), skillrx, agent-contracts/skill-preflight v0.10.2 (skill scoring, 4 Nov 2026) | | | Static or hook pieces only |
| Impersonation-only: GHBuster (DataDog), StarScout, Gitxray | | Fake accounts and stars | No install-path analysis |

**The gap is still open.** No tool combines README-copy and lookalike detection, all install paths including agent configs, and a honeytoken dry run in one verdict across a CLI, MCP and a hook. It's narrower than a month ago, though: Repo Run Check launched a week ago with our pitch. Lead with what it lacks: *names the original it copies*, *shows decoy keys leaving the sandbox*, and *a hook that stops the agent*. Also, Apiiro now reports **17,610** FakeGit repos (BleepingComputer). Update the CLAUDE.md figure once you've read the source.

## 3. Names

Checked 5 Nov 2026 with live PyPI, npm and Homebrew lookups (404 = free) plus `gh` and a web search for security products. **Homebrew is free for all of them.** **The GitHub user/org is taken for every name except `sus`**, so plan on an org like `<name>-dev`.

| # | Name | PyPI | npm | GitHub | Security-product clash | Overall |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | **lookfirst** | free | free | user taken (308 repos); two 0-star repos with a similar idea | none found | **Clear**: says what it does |
| 2 | **deadringer** | free | free | user taken (0 repos); small PoCs | none | **Clear**: "exact lookalike" fits the identity half |
| 3 | **sniffcheck** | free | free | user taken (1 repo, 2 stars) | none | **Clear**, but `sniffcheck check` stutters |
| 4 | unmask | free | unpublished in 2019, probably reclaimable | user taken | EDGE "UNMASK" (law-enforcement product) | Workable with suffix |
| 5 | trialrun | free | taken (active README-runner, a nearby idea) | user taken | none | Workable with suffix |
| 6 | ringer | taken (abandoned 2019) | placeholder | org taken; NateBJones-Projects/ringer, 307 stars | none | Workable with suffix |
| 7 | spotcheck | taken (abandoned 2017) | taken | org taken | Orange Cyber Defense "Spot check" service | Workable with suffix |
| 8 | eyeball | taken (abandoned 2013) | taken | user taken | BishopFox "eyeballer" | Workable with suffix |
| 9 | squint | taken (active) | taken | squint-cljs, 929 stars | Quantum Squint | Avoid |
| 10 | sus | taken | taken | **free** | none, but unsearchable slang | Weak |

Rejected after checking: **doppel** (Doppel is a funded company selling impersonation protection), **vouch** (mitchellh/vouch, vouch-proxy), **truecopy** (askalf/truecopy vets agent skills and MCP servers), **gutcheck** (crowded in AI dev tools).

**Recommendation: `lookfirst`** (`lookfirst check owner/repo`). Reserve PyPI, npm and Homebrew tap names on day one, plus a GitHub org such as `lookfirst-dev`. Runner-up: `deadringer`.

## 4. Module layout

Close to CLAUDE.md, with five changes, marked ★.

```
preflight/                      (renamed to the chosen name at M1)
  cli.py                        Typer app: check, mcp, hook, index refresh
  core/ ★                       http.py (httpx client, ETag cache in ~/.cache, token redaction)
                                config.py  errors.py  textsafe.py (escape bidi/zero-width/control chars in excerpts)
  targets/                      base.py ★ (Target model + resolve())  github.py  local.py  oneliner.py  packages.py
  identity/                     popular_index.py  lookalike.py  readme_sim.py  stargazers.py  official.py  releases.py ★
  static/                       shell_parse.py ★ (tree-sitter-bash wrapper)  fetch.py ★ (recursive download-and-read, depth 3, size and count caps)
                                install_paths.py  shell_rules.py  autorun.py  agent_configs.py  injection.py
  scanners/                     base.py (tool detection, version, "not installed" note)  osv.py  guarddog.py
  sandbox/                      Dockerfile  runner.py  honeytokens.py  proxy.py (+ mitm_addon.py)  trace_parse.py
  verdict/                      schema.py  scoring.py  render_terminal.py  render_markdown.py  (JSON = model_dump)
  mcp_server.py
  hook.py                       ★ stdlib-only fast path; imports the rest only for install-like commands
plugin/                         .claude-plugin/plugin.json  hooks/hooks.json  skills/<name>/SKILL.md  .mcp.json
.claude-plugin/marketplace.json ★ so the repo itself is an installable marketplace
registry/                       official.yaml  installers.yaml ★ (allowlisted installer URLs + last-seen sha256)
data/seed/                      small popular-repos seed (the rest generated, gitignored)
tests/                          fixtures/{http,lookalike,install,sandbox,injection,canary}/  test_*.py
scripts/                        record_fixtures.py (refresh HTTP recordings on demand)
docs/                           SPEC.md  KICKOFF.md  THREAT_MODEL.md  PLAN-v0.1.md
THIRD_PARTY.md  IDEAS.md  README.md  LICENSE
```

## 5. Findings schema (pydantic v2)

```python
SCHEMA_VERSION = "1.0"

class Severity(StrEnum):   critical, high, medium, info        # SPEC section 5's four levels
class CheckKind(StrEnum):  identity, install_path, agent_config, injection, package, sandbox
class VerdictLabel(StrEnum): looks_ok, caution, dont_run       # rendered "Looks OK" / "Caution" / "Don't run"

class Evidence(BaseModel):
    type: Literal["url", "file", "command", "network", "process", "filesystem", "metric"]
    ref: str                      # URL, repo-relative path, or host:port
    line: int | None = None
    excerpt: str | None = None    # untrusted text: ≤ 300 chars, passed through textsafe before rendering
    data: dict[str, str | int | float | bool] = {}   # e.g. {"jaccard": 0.94}, {"account_age_days": 3}

class Finding(BaseModel):
    id: str = Field(pattern=r"^[a-z_]+\.[a-z0-9_]+$")    # "identity.readme_copy"
    check: CheckKind
    severity: Severity
    title: str                    # ≤ 90 chars, from our templates only, never from repo text
    evidence: list[Evidence]      # validator: at least one item if severity is critical or high
    explanation: str
    recommendation: str
    source: str = "preflight"     # or "osv-scanner", "guarddog"
    source_version: str | None = None
    confidence: float | None = Field(None, ge=0, le=1)

class Target(BaseModel):
    kind: Literal["github", "local", "oneliner", "npm", "pypi", "mcp_command"]
    raw: str
    resolved: str | None          # "owner/repo@<sha>", "name@1.2.3", absolute path
    source_repo: str | None       # declared repo of a package, for the identity check

class IdentityResult(BaseModel):
    status: Literal["original", "fork_benign", "unrelated", "likely_impersonation"]
    original: str | None          # "owner/repo"
    confidence: float
    top_signals: list[str]        # up to 3 finding ids

class SandboxRun(BaseModel):
    command: str; image_digest: str; duration_s: float
    exit_code: int | None; timed_out: bool; network: Literal["proxy", "offline"]

class NotChecked(BaseModel):
    what: str                     # "Sandbox dry run"
    reason: str                   # "not requested" / "GuardDog not installed"
    how_to_enable: str | None     # "uv tool install --python 3.12 guarddog"

class Report(BaseModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    tool_version: str
    generated_at: datetime
    target: Target
    verdict: VerdictLabel
    exit_code: Literal[0, 10, 20]
    summary: list[str] = Field(max_length=3)   # built from finding titles, never repo text
    findings: list[Finding]       # sorted by severity
    identity: IdentityResult | None
    sandbox: SandboxRun | None
    not_checked: list[NotChecked]
    disclaimer: str = "Preflight lowers risk; it doesn't guarantee safety."
```

`scoring.py` stays a pure function, `(findings) -> (verdict, exit_code)`, exactly the SPEC section 9 rule. Exit code 1 (error) is never a `Report`; the CLI prints an error instead. The JSON Schema is exported to `docs/schema/report-1.0.json` and checked in a test, so changes are deliberate.

## 6. Milestones with dates

18 working days starting Fri 6 Nov, skipping US Thanksgiving (26–27 Nov), plus 2 buffer days.

| # | Milestone | Days | Dates | Done when |
| --- | --- | --- | --- | --- |
| M1 | Name, skeleton, schema, scoring, CLI, target fetching, CI | 2 | Fri 6 – Mon 9 Nov | `check` prints an empty report for each target type; names reserved |
| M2 | Install-path analyzer (tree-sitter), rules, recursive fetch, fixtures | 3 | Tue 10 – Thu 12 Nov | Every install-path fixture caught; 10 real installers pass as info |
| M3 | Identity: index, `official.yaml`, all section 4 signals | 4 | Fri 13 – Wed 18 Nov | Lookalike pairs flagged with original named; benign set clean |
| M4 | osv-scanner + GuardDog wrappers, three renderers | 2 | Thu 19 – Fri 20 Nov | You review the three example reports |
| M5 | Sandbox dry run | 4 | Mon 23 – Wed 25 Nov, Mon 30 Nov | Sandbox fixtures caught in < 3 min; benign installs pass |
| M6 | MCP server, hook, skill, plugin, recorded session | 2 | Tue 1 – Wed 2 Dec | Hook blocks the fixture in a real session |
| M7 | README, pre-launch review, v0.1.0 | 1 | Thu 3 Dec | SPEC section 12 all green |
| — | Buffer | 2 | Fri 4 – Mon 7 Dec | **v0.1.0 ready by Mon 7 Dec** |

Order note: M5 (sandbox) is the riskiest piece. If Docker isn't working by M2, I'll start the sandbox image and proxy spike in the background during M3.

## 7. Risks

1. **Competition moving fast.** Repo Run Check covers much of the static check already. *Mitigation:* the demo leads with the copied README naming the original and decoy keys seen leaving the sandbox, which it can't do.
2. **Lookalike false alarms** on forks, mirrors, translations and same-name projects. A 20-repo benign set is small. *Mitigation:* grow it to ~100 recorded repos, and require two independent signals before `likely_impersonation`.
3. **Preflight's own output as an injection vector.** We quote hostile text back to an agent through MCP and the hook. *Mitigation:* summaries and titles are templated only; excerpts are length-capped, escaped and fenced as untrusted data; a test feeds the injection fixture through the MCP tool.
4. **Sandbox traffic reaching the real internet.** A pass-through proxy lets a target actually download second stages or hit real hosts. *Decision 4 below.*
5. **Host safety.** No host mounts, never mount the Docker socket, drop capabilities, and run fixtures only via the Docker API, with the canary test. OrbStack and Docker Desktop run containers in a VM, which adds a layer.
6. **Architecture.** On Apple Silicon the sandbox runs arm64 Linux, but most real payloads are amd64 ELF. *Decision 5.*
7. **Hook speed and failure mode.** Python startup is already 17–25 ms, and any crash or timeout fails open. *Mitigation:* stdlib-only fast path, plus a benchmark test in CI. *Decision 3* covers fail-closed.
8. **GitHub rate limits.** Stargazer sampling plus README/tree/release calls exceed 60/h unauthenticated. Without a token, skip stargazers and say so under "not checked".
9. **Third-party tool drift.** The spec was already wrong about GuardDog's GitHub Action command and bashlex. *Mitigation:* the wrappers parse defensively and record each tool's version in the finding.
10. **Our own supply chain.** A security tool is a juicy impersonation target. Reserve names on day one, publish with PyPI Trusted Publishing, and put an "official sources" line in the README.
11. **Schedule.** Thanksgiving week, and no Docker on this Mac yet.

## 8. Decisions (all accepted as recommended, 5 Nov 2026)

| # | Decision | Outcome |
| --- | --- | --- |
| 1 | Name | `lookfirst`; GitHub org `lookfirst-dev` |
| 2 | Shell parser | tree-sitter-bash replaces bashlex |
| 3 | Hook | JSON `deny` (Don't run) / `ask` (Caution); if the hook errors or times out, it fails open with a visible warning |
| 4 | Sandbox network | Sinkhole by default; `--network=passthrough` is an opt-in |
| 5 | Sandbox architecture | arm64 by default, plus `--arch amd64` |
| 6 | License | Apache-2.0 |
| 7 | Socket / SafeDep | Deferred to v0.2 (IDEAS.md) |
| 8 | Docker | OrbStack (being installed by you) |
| 9 | Start | Fri 6 Nov; 26–27 Nov off; v0.1.0 ready by Mon 7 Dec |

The original questions, kept for the record:

1. **Name.** Recommend `lookfirst` (runner-up `deadringer`), plus a GitHub org name, e.g. `lookfirst-dev`.
2. **Shell parser.** Replace bashlex (GPL-3.0, fails on real installers) with tree-sitter-bash (MIT). This changes CLAUDE.md's Stack section.
3. **Hook behavior.** (a) Use JSON `deny` for Don't run and `ask` for Caution instead of exit 2 for both. Recommended. (b) When the hook itself errors or runs out its 20 s budget: fail open (command runs, with a warning) or fail closed (blocked). Recommend fail open with a visible warning, so a broken hook never bricks the agent.
4. **Sandbox network.** (a) Pass-through via mitmproxy, as the spec says, or (b) **sinkhole**: package registries and the project's own domains pass; every other request is recorded in full and answered with a stub, so decoy markers are caught without anything leaving. Recommend (b) as the default, with `--network=passthrough` as an opt-in.
5. **Sandbox architecture.** arm64 only in v0.1, or also run under amd64 emulation (slower, better at catching real payloads). Recommend arm64 by default plus an `--arch amd64` flag.
6. **License.** Apache-2.0, as KICKOFF assumes?
7. **Socket / SafeDep integration.** Recommend deferring to v0.2 (IDEAS.md).
8. **Docker.** OrbStack isn't installed: the Homebrew cask install sat waiting for your Mac password, so I stopped it. Run `brew install --cask orbstack` yourself, then open OrbStack once. Needed by M5, ideally before M2.
9. **Start date.** Tomorrow (Fri 6 Nov), and do you take 26–27 Nov off?

**Still to do by you:** reserve `lookfirst` on PyPI and npm, create a Homebrew tap and the `lookfirst-dev` GitHub org. These need your accounts. I can prepare minimal placeholder packages at M1 for you to publish.

## M2 decisions (all accepted as recommended, 6 Nov 2026)

| # | Decision | Outcome |
| --- | --- | --- |
| 1 | Agent check | SPEC section 6 (agent settings and hidden prompts) is built in M2 |
| 2 | Prompts aimed at agents | High when hidden or deceptive, or telling agents to run remote code or skip checks; ordinary instructions in AGENTS.md and CLAUDE.md are info only |
| 3 | Remote downloads | Sent with the User-Agent the command would send (curl or wget) |
| 4 | Download limits | Public addresses only (checked at connect time), 3 levels deep, 20 scripts, 2 MB each, 15 seconds per check, no proxies |
| 5 | Installer allowlist | "Well-known installer" is info, and every rule still reads it; a changed hash is noted, not alarmed on |
| 6 | "Couldn't check" | A one-liner whose piped script can't be read exits 1 instead of getting a verdict |
| 7 | Registry format | YAML, read with PyYAML (MIT) |

Found while building M2, and handled:

- **Fixture safety:** every fixture script starts with a guard that exits outside the sandbox and creates the host canary. Files that tools load automatically are stored under neutral names (`dot_claude/`, `AGENTS.md.fixture`) so no editor or AI agent working in this repo loads them.
- **False positives on real code**, each now covered by a test: nvm's `\.` alias escape, paths with `\ ` spaces, HTML comments and badge descriptions written for people, flag emoji built from tag characters, Persian text, a stray zero-width space in a name, "without notifying the user" in technical docs, right-to-left tests, and links that stay inside the repo.
- **Claude Code's installer** is allowlisted by address and hash, but its script isn't recorded in the fixtures because it isn't open source.
- **The registry** moved from `registry/` to `lookfirst/registry/`, so it ships inside the package.


## M3 decisions (all accepted as recommended, 9 Nov 2026)

| # | Decision | Outcome |
| --- | --- | --- |
| 1 | "Likely impersonation" | A resemblance (lookalike name or copied README) plus a sign of deception (new account or repo, inflated stars), or a lookalike name and a copied README together. Forks need a sign of deception plus something they ship. Don't run with a risky download, a README warning or inflated stars; Caution otherwise. Single signals are medium; README warnings (archive password, turn off antivirus) are high. Revised after the live sweep (below). |
| 2 | Libraries | None added: lookfirst's own edit distance and exact Jaccard instead of rapidfuzz and datasketch |
| 3 | Popular-repos list | csv.gz inside the package (`lookfirst/registry/popular.csv.gz`), not Parquet. Built without the trending archive for now |
| 4 | Star sample | GraphQL, so it needs a token; without one it's listed under "Not checked" |
| 5 | Lookalike pair owners | Made-up names, each checked not to exist on GitHub |
| 6 | README text in fixtures | Only the lookalike originals' (open source; licenses in THIRD_PARTY.md). None for the benign set |
| 7 | `official.yaml` | 10 projects: Ollama, Claude Code, OpenAI Codex CLI, ComfyUI, Open WebUI, yt-dlp, llama.cpp, n8n, MCP reference servers, Stable Diffusion web UI |

Live false-positive sweep, 9 Nov 2026: 50 popular repos (the top 25 and 25 at random from the list), 36 repos named like the official projects (ComfyUI custom nodes, claude-code-router, n8n-mcp, llama-cpp-python), 56 same-name repos for 14 popular names, the 20 most-starred forks on GitHub, 400 READMEs, 27 npm and PyPI packages, 13 real installer one-liners, and 6 full checks from the CLI. After the fixes below, none of these real projects gets Caution or Don't run from the identity check.

Found while building M3, and handled (each now covered by a test):

- **Forks:** 9 of the 20 most-starred forks (koboldcpp, qBittorrent Enhanced Edition, AlexeyAB/darknet, Proton-GE, bolt.diy and others) were Don't run, because shipping their own builds and changing build files counted as two signals. A fork now needs a sign of deception too.
- **Official SDKs:** packages from an official organization that aren't on the list (`@anthropic-ai/sdk`, `openai`, `mcp`, `gguf`, `n8n-workflow`) would have been told "says it comes from X, but isn't its official package". Now an npm scope or PyPI organization the project owns, or the registry's provenance record of the repo that built it, settles it.
- **Claude Code's npm package** names no repo, so it wasn't recognized. Official packages are now checked first.
- **README warnings:** a feature list mentioning "password-protected archives" (awesome-mac) counted as an archive password; now only a line that hands out a password counts. Links to file-sharing sites' home pages, blogs and API docs (public-apis, free-for-dev) no longer count as downloads.
- **Malformed addresses** such as an unclosed `[` crashed the check: in the identity check and in six places in the M2 static checks. They're now read as having no host.
- **GitHub's search limit** (10 a minute without a token, 30 with): running out stopped the whole identity check. Now it goes on without the same-name search and lists it under "Not checked".
- **M2's hidden-instructions check** flagged comfy-cli's official agent skills, which tell agents "do not tell the user their Python was matched", meaning don't make a false claim. "Don't tell the user" now counts only when it hides something ("about this step", "what you did").
- **Personal details in recordings:** account profiles are trimmed to the account's age and counts, and email addresses are dropped from every recorded answer, including the npm and PyPI answers recorded in M1. A test checks.

# lookfirst threat model (v0.1)

What lookfirst defends against, how, and where it stops. Written for v0.1.0; the design is in [SPEC.md](SPEC.md).

lookfirst lowers risk; it doesn't guarantee safety.

## What's being protected

- **Your secrets:** SSH keys, cloud and package-registry tokens, browser data, password stores and crypto wallets on the computer where you, or your agent, run code.
- **Your computer's integrity:** nothing should quietly start at login, add itself to your shell, or switch off macOS protections.
- **Your agent's judgment:** a repo shouldn't be able to steer your coding agent into running things you didn't ask for.

## Who attacks, and how

| Attacker | What they do | What lookfirst does about it |
| --- | --- | --- |
| **Copycat** | Re-posts a popular project under a new or lookalike account, copies its README, inflates its stars, and adds a release archive or install script that steals credentials | The identity check compares the target with popular projects and names the one it resembles, citing the copied README, the account's age, the name, the stars and the extra downloads |
| **Install-script author** | Hides the harmful part in an install step: a `postinstall` script, a downloaded script, a payload in base64, a Makefile target | The install-path check reads every step a README or a package would run, follows downloads up to 3 levels deep, decodes hidden payloads, and applies its rules. The sandbox runs the install with decoy secrets and watches what's read and sent |
| **Agent manipulator** | Writes instructions for AI agents into a README, a comment or a skill, often hidden, or ships agent settings that run commands or approve everything | The agent-attack check quotes the instructions with file and line and flags the settings. Its own output keeps those quotes marked as untrusted data |
| **Compromised package** | Publishes a malicious version of a dependency | osv-scanner (known malware and vulnerabilities) and GuardDog (code patterns), when installed |

## How lookfirst protects itself

lookfirst reads hostile input by design, so it's built to be hard to turn against you:

- **It never runs the target on your computer.** Static checks only read. The dry run happens only inside the Docker sandbox. Every harmful test fixture starts with a guard: anywhere but the sandbox, it only creates `~/LOOKFIRST_HOST_CANARY` and stops, and the test suite fails if that file exists.
- **The sandbox has nothing of yours.** No folders from your computer are mounted, and the Docker socket never is. The target is copied in. The container has no capabilities, runs as an ordinary user with process, memory, CPU and time limits, and reaches the network only through a logging proxy. The secrets inside are decoys.
- **Everything read is data, never instructions.** That includes READMEs, scripts, issues, package metadata, scanner output and model answers. A test proves that instructions in a README can't change the verdict.
- **Its own words come from templates.** Titles, summaries and advice are lookfirst's own text. Anything quoted from a target is length-capped, has invisible and direction-changing characters made visible, and is marked as quoted data, in the terminal, JSON, Markdown, the MCP tools and the hook.
- **It makes no accusations.** It says a repo "matches patterns used by impersonation campaigns", with evidence, not that it's malware.
- **Downloads are fenced in.** Scripts are fetched only from public addresses (checked when connecting, so a name can't be pointed at your local network), at most 20 scripts of 2 MB each, 3 levels deep, within 15 seconds.
- **Tokens stay narrow.** A GitHub token is optional, used only to read, never logged, and sent only to api.github.com. Scanners run without it.

## The Claude Code hook

- **What it stops:** before each shell command, it decides whether the command installs or runs code from elsewhere: piped downloads, decoded payloads, package installs, `npx`-style runners, clones, and installers in a repo cloned in the last 24 hours. Those are checked; everything else passes in about 30 ms.
- **Its answers:** Don't run blocks the command and gives the agent the evidence to show you. Caution, or a script lookfirst couldn't read, asks you first. Looks OK lets it run.
- **It fails open.** If the check crashes or takes more than 20 seconds, the command goes ahead with a warning, so a broken check never stops your work. If you'd rather block in that case, Claude Code's `"onFailure": "block"` setting does it.
- **It only sees commands.** It doesn't see code an agent writes and runs through other tools, programs that download more code after they start, or folders older than 24 hours that you installed before.

## What lookfirst can't defend against

- **Attacks it has no sign for.** Its rules and signals catch common patterns, not every possible one.
- **Code that waits or hides.** Malware that acts later, on a certain date, or only when it can't see a sandbox can pass the dry run.
- **macOS-only behaviour in the sandbox.** The sandbox is Linux, so macOS-only tricks don't run in it. lookfirst still reads them in scripts.
- **What happens after install.** lookfirst checks installing, not the program's behaviour later.
- **A trusted project that's been taken over.** If the real project's own install is compromised, the identity check rightly calls it the original. The install check and the sandbox are what can catch it.
- **Its own supply chain.** lookfirst depends on Python packages and, optionally, Docker, mitmproxy, osv-scanner and GuardDog. Dependencies are pinned in `uv.lock`, new versions wait 14 days before use, and container images are pinned by digest. That lowers the risk but doesn't remove it.

## Reporting a problem

- **A miss or a false alarm:** open an issue with the target and lookfirst's report.
- **A weakness in lookfirst itself,** such as a way to make it run a target or to put words in its mouth: please report it privately through GitHub's security advisories on the repository, not in a public issue.

# lookfirst 0.1.0

The first release. lookfirst checks a GitHub repo, a `curl | bash` line, a folder or an npm or PyPI package before you or your AI agent runs it, and answers with one verdict, **Looks OK**, **Caution** or **Don't run**, with the evidence behind it.

lookfirst lowers risk; it doesn't guarantee safety.

## What's in it

- **`lookfirst check <target>`**, for a GitHub repo (`owner/repo`, optionally `@branch`, tag or commit), a folder, a quoted shell command, `npm:<name>` or `pypi:<name>`. Output for the terminal, as JSON (`--json`) or as Markdown (`--report FILE`). Exit codes 0, 10 and 20 match the verdict; 1 means the check couldn't run.
- **Identity check:** spots copies of popular projects (a lookalike name or owner, a copied README, a new account, implausible stars, extra release archives, download passwords) and names the original. Ships with a list of popular repos and a community-edited list of official sources.
- **Install-path check:** reads every install step a README, script, Makefile, Dockerfile, `package.json` or Python build would run, without running it. Follows downloaded scripts 3 levels deep and decodes base64 and hex payloads.
- **Agent-attack check:** flags agent settings shipped in a repo and instructions hidden for AI agents, quoting them as untrusted data.
- **Package check:** runs osv-scanner and GuardDog when they're installed.
- **Sandbox dry run (`--sandbox`):** runs the install in a Linux container with decoy credentials, a logging proxy and a process tracer, and reports what it read, sent and changed.
- **Agent integration:** an MCP server (`lookfirst mcp`), a Claude Code hook (`lookfirst hook`) that checks risky shell commands before they run, and a Claude Code plugin with both plus a skill.

## Measured

- **A full static check:** 3 to 11 seconds on 12 well-known repos (median 4.7 s), against a target of 30 seconds.
- **The sandbox:** 4 to 10 seconds for each test install, after a one-time image build of about 90 seconds.
- **The hook:** about 30 ms for ordinary commands; 0.4 to 4 seconds for commands it checks.

## Known limits

- **The sandbox is Linux only,** so macOS-only behaviour doesn't run in it. There's no Windows support.
- **Code that waits, or notices the sandbox,** can pass the dry run.
- **The hook fails open:** if a check crashes or takes more than 20 seconds, the command goes ahead with a warning.
- **The hook block hasn't been recorded in a live session.** It's tested with the exact input Claude Code sends, but in every live try the agent read the install script and refused before the hook was needed.
- **Hidden agent instructions in issue templates** can give a well-known repo a Caution, such as a line some projects add to spot AI-written issues.

Full list: [README](../README.md#what-it-doesnt-check) and [threat model](THREAT_MODEL.md).

## Install

```bash
uv tool install lookfirst
```

For Claude Code: `/plugin marketplace add lookfirst-dev/lookfirst`, then `/plugin install lookfirst@lookfirst`.

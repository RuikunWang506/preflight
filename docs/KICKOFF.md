# Kickoff prompts: Preflight

Start with `claude --permission-mode plan`. Paste one prompt at a time. Approve each plan before it builds, and commit after each milestone. Milestones are defined in `docs/SPEC.md` section 13.

## 1. Plan and name (M1, plan mode)

Read CLAUDE.md and docs/SPEC.md in full.

Then check the tools the spec relies on, and tell me what you find:

- osv-scanner (`osv-scanner scan source -r`), and GuardDog's scan and verify commands with JSON output
- bashlex, and whether it parses real install scripts
- mitmproxy as a container
- the official MCP Python SDK
- the Claude Code hook input and output format, and plugin layout

Look at the current versions of the competitors in SPEC section 15, and confirm the gap is still open.

Propose 10 names (SPEC section 14) with their availability on GitHub, PyPI, npm and Homebrew.

Then propose:

- the module layout
- the findings schema as pydantic models
- the milestone plan with dates
- the risks
- what you need me to decide

Don't write code yet.

## 2. Skeleton (M1)

Set up the uv project:

- Typer CLI, ruff, pytest, LICENSE (Apache-2.0 unless I chose otherwise), THIRD_PARTY.md, IDEAS.md
- the findings schema and verdict scoring
- target parsing and fetching for every target type, using recorded HTTP fixtures in tests
- a GitHub Actions workflow with lint and tests on macOS, and a separate Linux job reserved for sandbox tests

`preflight check <target>` should print an empty report with the right verdict structure. Fill in the Commands section of CLAUDE.md.

## 3. Install-path analyzer (M2)

Write the install-path fixtures first: one harmless fake per rule in SPEC section 5, plus the benign allowlisted installers. Then build:

- discovery of every install and auto-run path
- bashlex parsing
- recursive download-and-read of remote scripts (never run)
- the rules, with plain-English explanations

Show me the terminal output for three fixtures.

## 4. Identity check (M3)

Build the popular-repos index:

- seed it from `trending_repos_tagged.csv.gz`, which I'll put in `data/seed/`
- add the GitHub search top repos
- create `registry/official.yaml` with 10 entries for viral projects

Then build the lookalike detector with every signal in SPEC section 4, including stargazer sampling and README MinHash. Test it on the synthetic lookalike pairs and the 20-repo benign set, and report false positives.

## 5. Scanners, verdict and output (M4)

Wrap osv-scanner and GuardDog, then finish the three outputs: terminal, JSON and Markdown. Show me example reports for Looks OK, Caution and Don't run as screenshots; I'll review the wording and layout before we freeze it.

## 6. Sandbox dry run (M5)

Build the sandbox as SPEC section 8 describes:

- image, isolation, decoy home and proxy sidecar
- strace, docker diff and network log parsing

Run the sandbox fixtures only inside Docker. Show me the report for the decoy-key theft fixture and for a benign `npm install`, and tell me the run times.

## 7. Agent integration (M6)

Build the MCP server, `preflight hook`, the skill and the plugin. Then record a Claude Code session in a scratch folder:

- the agent tries to run the malicious one-liner fixture and the hook blocks it with evidence
- a benign command passes with no noticeable delay

## 8. README, name and pre-launch review (M7)

Write the README:

- one-sentence pitch
- 30-second demo
- install steps for the CLI and plugin
- what's checked and what isn't
- threat model
- the "lowers risk, doesn't guarantee safety" statement
- an official-sources line

Check everything against SPEC section 12, fix the gaps, run all tests, and prepare the v0.1.0 release notes.

## Launch checklist

- Release v0.1.0. Publish the CLI under the chosen name on PyPI. List the plugin where Claude Code plugins are shared.
- **Demo:** "My coding agent was about to install a fake copy of a viral repo. Here's what stopped it."
- **Timing:** post right after the next fake-repo or supply-chain story, and keep the release ready until then.
- **Channels:** Show HN, r/programming, X and security newsletters. Answer every issue for the first 48 hours.
- **Flywheel:** invite pull requests to `registry/official.yaml` ("add your project's official sources"), and an issue template for "Preflight missed this" and "false alarm" reports.
- **Reporting fakes:** report confirmed malicious repos to GitHub instead of naming them in posts, unless a public report already has.

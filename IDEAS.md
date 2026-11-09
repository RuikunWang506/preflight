# Ideas

Things worth doing that are outside the v0.1 scope. Add new ideas here instead of building them.

## Decided for v0.2

- **Socket and SafeDep integration.** Call Socket's MCP or SafeDep when a user has them configured (decided 5 Nov 2026).
- **macOS virtual machine dry runs** on Apple Silicon, for macOS-only payloads such as fake password dialogs. Check Tart's license first.

## Open ideas

- **Check a single script file or script URL directly.** For example `lookfirst check https://example.com/install.sh` or `lookfirst check ./install.sh`. Today lookfirst asks you to quote the command or point at the folder.
- **Files whose names differ only in letter case.** The unpacker already records them. A finding could flag them, since on a Mac only one survives, which is a way to show reviewers one file and run another.
- **Non-GitHub hosts.** GitLab, Codeberg and Bitbucket repos as targets.
- **Ranges and git sources for packages.** `npm:pkg@^1.2`, `npx github:user/repo`, and PyPI extras such as `pkg[extra]`.
- **Machine-readable errors.** With `--json`, print errors as JSON too, so agents can tell a failed check from a crash.
- **Remote scripts behind a proxy.** lookfirst downloads remote scripts directly, never through a proxy, so it can check each address is public. Users behind a corporate proxy get "couldn't download" instead.
- **A JavaScript parser for install scripts.** npm lifecycle scripts that run JavaScript get pattern checks today, not a real parse.
- **Monorepos.** Read the package.json of each workspace, not just the root one.
- **Show what a known installer changed.** When an allowlisted installer's hash differs from the last one seen, show what changed.

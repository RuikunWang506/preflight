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
- **Add the trending archive to the popular-repos list.** Merge `trending_repos_tagged.csv.gz` (76,892 repos) into `popular.csv.gz` once it's in `data/seed/`. M3 shipped without it.
- **Trim the GitHub cache.** `~/.cache/lookfirst/github/` grows with every repo checked; drop entries not used for a month.
- **Check every package's claimed repo.** Today a package's `repository` field is checked against the registry's provenance record only when it names an official project's repo. Doing it for every package would catch packages that borrow a famous repo's name ("starjacking"), and the identity line could say "not confirmed" when there's no record.
- **Fork README warnings.** Count only the README warnings a fork added, not the ones it inherited from its parent.
- **Renamed organizations.** When an organization is renamed, its old name is free for anyone to take. Old names of official projects (such as `ollama-webui`) could go in `official.yaml` as names to watch.
- **Opt out of osv.dev lookups.** A flag, or osv-scanner's offline database, for people who don't want package names and versions sent anywhere.
- **Which lockfile an install uses.** Decide from the README's install commands (`cd app && npm install`), not only from folder names.
- **Scan the dependencies' own code.** `guarddog verify` downloads and scans every dependency; worth it with a longer time budget, or inside the sandbox.
- **"Fixed in" as one version.** Show the lowest version that fixes every advisory, which needs version comparison per ecosystem.
- **Links in local folders.** The scanners may follow symbolic links in a folder on this computer; copy it without links first.
- **Show what a known installer changed.** When an allowlisted installer's hash differs from the last one seen, show what changed.

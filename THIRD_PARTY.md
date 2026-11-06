# Third-party software and data

Every library, tool, container image and dataset lookfirst uses, with its license. Add an entry **before** using something new, and ask before adding anything copyleft (CLAUDE.md).

lookfirst itself is Apache-2.0 (`LICENSE`).

## Python libraries installed with lookfirst

Versions are the ones in `uv.lock`. uv only installs versions published at least 14 days before the `exclude-newer` date in `pyproject.toml`.

| Package | Version | License | Why |
| --- | --- | --- | --- |
| typer | 0.27.3 | MIT | Command-line interface. Includes a copy of Click (BSD-3-Clause, © Pallets) in `typer/_click/`. |
| rich | 15.0.0 | MIT | Terminal output |
| httpx | 0.28.1 | BSD-3-Clause | HTTP client |
| pydantic | 2.14.1 | MIT | Findings schema and JSON output |
| annotated-doc | 0.0.5 | MIT | Needed by typer |
| shellingham | 1.5.4 | ISC | Needed by typer |
| markdown-it-py | 4.2.0 | MIT | Needed by rich |
| mdurl | 0.1.2 | MIT | Needed by markdown-it-py |
| pygments | 2.21.0 | BSD-2-Clause | Needed by rich |
| anyio | 4.15.1 | MIT | Needed by httpx |
| httpcore | 1.0.9 | BSD-3-Clause | Needed by httpx |
| h11 | 0.16.0 | MIT | Needed by httpcore |
| idna | 3.20 | BSD-3-Clause | Needed by httpx |
| certifi | 2026.10.19 | **MPL-2.0** (weak copyleft) | Needed by httpx: Mozilla's list of trusted certificate authorities. Used unmodified. MPL obligations apply only to changes to certifi's own files, so lookfirst's code is unaffected. Flagged per CLAUDE.md, 6 Nov 2026. |
| pydantic-core | 2.50.1 | MIT | Needed by pydantic |
| annotated-types | 0.8.0 | MIT | Needed by pydantic |
| typing-inspection | 0.4.4 | MIT | Needed by pydantic |
| typing-extensions | 4.16.0 | PSF-2.0 | Needed by typer and pydantic |

## Development only (not installed for users)

| Package | Version | License | Why |
| --- | --- | --- | --- |
| pytest | 9.1.1 | MIT | Tests |
| iniconfig, pluggy | 2.3.1, 1.7.0 | MIT | Needed by pytest |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | Needed by pytest |
| ruff | 0.17.2 | MIT | Lint and formatting |

## GitHub Actions used in CI

Pinned to exact commits in `.github/workflows/ci.yml`.

| Action | Version | License |
| --- | --- | --- |
| actions/checkout | v7.0.1 | MIT |
| astral-sh/setup-uv | v10.3.2 | MIT |

## Optional tools lookfirst runs as separate programs

Never bundled or vendored. If one isn't installed, the report says so and shows how to install it.

| Tool | License | How lookfirst uses it | Since |
| --- | --- | --- | --- |
| osv-scanner | Apache-2.0 | Known vulnerabilities in lockfiles (M4) | planned |
| GuardDog | Apache-2.0 | Malicious-package heuristics (M4) | planned |
| ShellCheck | **GPL-3.0** (copyleft) | Shell script problems, only if installed (M2). Run as a separate program and never bundled; approved 6 Nov 2026 (skeleton plan, decision 5). | planned |
| gh (GitHub CLI) | MIT | Optional: `gh auth token` supplies a GitHub token for higher rate limits | M1 |

## Planned (record the exact version when it's added)

| Package or image | License | For |
| --- | --- | --- |
| tree-sitter, tree-sitter-bash | MIT | Shell parsing (M2) |
| rapidfuzz | MIT | Name distance (M3) |
| datasketch | MIT | README similarity (M3) |
| docker (docker-py) | Apache-2.0 | Sandbox (M5) |
| mitmproxy/mitmproxy image | MIT | Sandbox network proxy (M5) |
| mcp (official MCP Python SDK) | MIT | MCP server (M6) |

## Test fixtures

Recorded HTTP responses in `tests/fixtures/http/`, refreshed by `scripts/record_fixtures.py`. They include these small public archives:

| What | License |
| --- | --- |
| octocat/Hello-World at 7fd1a60 (GitHub's sample repo: one README) | No license file; a one-line sample README |
| is-number 7.0.0 (npm) | MIT, © Jon Schlinkert |
| six 1.17.0 (PyPI) | MIT, © Benjamin Peterson |

## Datasets

| Dataset | License | For |
| --- | --- | --- |
| `trending_repos_tagged.csv.gz` (12-year GitHub Trending archive) | The user's own | Popular-repos index seed (M3) |

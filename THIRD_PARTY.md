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
| tree-sitter | 0.26.0 | MIT | Reading shell scripts without running them (M2) |
| tree-sitter-bash | 0.25.1 | MIT | The bash grammar for tree-sitter (M2) |
| markdown-it-py | 4.2.0 | MIT | Finding install commands in READMEs (M2; also needed by rich) |
| PyYAML | 6.0.3 | MIT | Reading the registry files, such as `lookfirst/registry/installers.yaml` (M2) |
| annotated-doc | 0.0.5 | MIT | Needed by typer |
| shellingham | 1.5.4 | ISC | Needed by typer |
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
| osv-scanner | Apache-2.0 | Known vulnerabilities and known malware in the packages a project pins. Tested with 2.7.0; always run with `--no-resolve` and `--no-call-analysis=all` | M4 |
| GuardDog | Apache-2.0 | Code patterns that malware uses. Tested with 3.2.0 | M4 |
| ShellCheck | **GPL-3.0** (copyleft) | Shell script problems, only if installed (M2). Run as a separate program and never bundled; approved 6 Nov 2026 (skeleton plan, decision 5). | planned |
| gh (GitHub CLI) | MIT | Optional: `gh auth token` supplies a GitHub token for higher rate limits | M1 |

## Container images and the sandbox image (M5)

Pulled or built on your computer by `--sandbox` or `lookfirst sandbox build`. lookfirst ships only `lookfirst/sandbox/Dockerfile` and its own proxy addon, never the images.

| Image | License | How lookfirst uses it |
| --- | --- | --- |
| `debian` (trixie-slim), pinned by digest | Debian's free licenses (DFSG) | Base of the sandbox image |
| `mitmproxy/mitmproxy` 12.3.1, pinned by digest | MIT | The recording proxy |

Installed into the sandbox image from Debian (and uv from PyPI) when you build it. The GPL and LGPL tools here were approved on 11 Nov 2026 (M5 decision 4): they run inside a container image built on your computer and are never shipped by lookfirst.

| Package | License |
| --- | --- |
| git | **GPL-2.0** |
| build-essential (gcc, make) | **GPL-3.0** (gcc, with the GCC runtime exception), GPL-2.0+ (make) |
| strace | **LGPL-2.1+** |
| procps | **GPL-2.0+** and LGPL-2.0+ |
| curl | curl license (MIT-style) |
| ca-certificates | MPL-2.0 (the certificates) and GPL-2.0+ (the scripts) |
| python3, python3-pip, python3-venv | PSF-2.0 (Python), MIT (pip) |
| nodejs, npm | MIT (Node.js), Artistic-2.0 (npm) |
| uv 0.13.6 (from PyPI) | MIT OR Apache-2.0 |

## Planned (record the exact version when it's added)

M3 (the identity check) added no libraries: name distance and README similarity are lookfirst's own code, so rapidfuzz and datasketch are no longer planned.

| Package or image | License | For |
| --- | --- | --- |
| mcp (official MCP Python SDK) | MIT | MCP server (M6) |

## Test fixtures

Recorded HTTP responses in `tests/fixtures/http/`, refreshed by `scripts/record_fixtures.py`. Email addresses are dropped from the recorded registry and GitHub answers (`tests/test_recordings.py` checks). Downloaded files are kept exactly as published, because the tests check them against the registry's hash, so six's archive still holds its author's address, as it does on PyPI. They include these small public archives:

| What | License |
| --- | --- |
| octocat/Hello-World at 7fd1a60 (GitHub's sample repo: one README) | No license file; a one-line sample README |
| is-number 7.0.0 (npm) | MIT, © Jon Schlinkert |
| six 1.17.0 (PyPI) | MIT, © Benjamin Peterson |

The identity check's recordings (`tests/fixtures/http/identity_originals/`, `identity_benign/` and the GitHub answers in the cases above), recorded on 9 Nov 2026. Account profiles are trimmed to the account's age and counts, so no names or locations are kept.

| What | License |
| --- | --- |
| README of ollama/ollama | MIT, © Ollama |
| README of ggml-org/llama.cpp | MIT, © 2023-2026 The ggml authors |
| README of yt-dlp/yt-dlp | Unlicense (public domain) |
| README of openai/codex | Apache-2.0, © 2025 OpenAI (its NOTICE file) |
| README of leachim6/hello-world | MIT, © 2018-2022 Mike Donaghy |
| Repo details, release file names and search results for these and the 20 benign repos | Facts from GitHub's API; no README text is kept for the benign repos |

The lookalike pairs in `tests/fixtures/identity/pairs/` are made up for lookfirst (Apache-2.0). Their owner names were checked not to exist on GitHub. Where a pair copies an original's README, it reuses the recorded text above and appends its own lines.

The real installer scripts in `tests/fixtures/http/installers/`, recorded on 6 Nov 2026 to check that well-known installers pass. Only open-source ones are copied in; Claude Code's installer is allowlisted by address and hash but not recorded, because it isn't open source.

| Installer | License |
| --- | --- |
| Homebrew (Homebrew/install) | BSD-2-Clause |
| rustup | MIT OR Apache-2.0 |
| uv (astral-sh/uv) | MIT OR Apache-2.0 |
| nvm (nvm-sh/nvm) | MIT |
| Oh My Zsh (ohmyzsh/ohmyzsh) | MIT |
| Deno (denoland/deno_install) | MIT |
| Bun (oven-sh/bun) | MIT |
| Docker (docker/docker-install) | Apache-2.0 |
| Ollama (ollama/ollama) | MIT |

Recorded scanner output in `tests/fixtures/scanners/`, recorded on 9 Nov 2026 and trimmed to the fields lookfirst reads:

| What | License |
| --- | --- |
| Advisory ids, summaries and affected versions from osv.dev, which gathers them from the GitHub Advisory Database, the PyPA Advisory Database and OpenSSF Malicious Packages | CC-BY-4.0 (GitHub, PyPA) and Apache-2.0 (OpenSSF) |
| GuardDog's findings for yt-dlp 2026.10.26, quoting short lines of its code | Unlicense (public domain) |
| GuardDog's findings for a harmless sample package written for lookfirst | Apache-2.0, like the rest of the repo |

The sandbox fixtures in `tests/fixtures/sandbox/` are written from scratch for lookfirst (Apache-2.0). The harmless `npm install` one pins is-number 7.0.0 (MIT) in its lockfile; the package itself is downloaded only inside the sandbox. `tests/fixtures/sandbox_traces/` holds strace output from dry runs of those fixtures: paths, program names and arguments only.

The install-path fixtures in `tests/fixtures/install/` are written from scratch for lookfirst (Apache-2.0, like the rest of the repo). They're harmless fakes; see their README.

## Datasets

| Dataset | License | For |
| --- | --- | --- |
| `lookfirst/registry/popular.csv.gz`: names, star counts and creation dates of 5,941 repos, from GitHub's search API on 9 Nov 2026 | Facts from GitHub's API (GitHub's terms of service apply to the API) | Popular-repos list for the identity check (M3). Rebuilt with `scripts/build_popular_index.py`; users refresh their copy with `lookfirst update-index`. |
| `lookfirst/registry/official.yaml` | Written for lookfirst (Apache-2.0) from each project's own README, website and registry pages | Official repos, sites and packages of 10 projects (M3) |
| `trending_repos_tagged.csv.gz` (12-year GitHub Trending archive) | The user's own | Popular-repos list seed. Not added yet: M3 started without it, and it can be merged in later. |

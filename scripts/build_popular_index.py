"""Rebuild the popular-repos snapshot that ships inside lookfirst.

    uv run python scripts/build_popular_index.py

Searches GitHub for the most-starred and fastest-rising repos (about 3 minutes; needs a
token from $GITHUB_TOKEN or `gh auth token`) and writes lookfirst/registry/popular.csv.gz.
Users refresh their own copy with `lookfirst update-index`.
"""

from __future__ import annotations

from pathlib import Path

from lookfirst.core.http import github_token, make_client
from lookfirst.identity.popular_index import FILE_NAME, _parse, build

OUT = Path(__file__).resolve().parent.parent / "lookfirst" / "registry" / FILE_NAME


def main() -> None:
    token = github_token()
    if not token:
        raise SystemExit("This needs a GitHub token: set GITHUB_TOKEN or run `gh auth login`.")
    with make_client(token=token) as client:
        data = build(client)
    OUT.write_bytes(data)
    built, repos = _parse(data)
    print(f"wrote {OUT.name}: {len(repos):,} repos, built {built}, {len(data) // 1024} KB")


if __name__ == "__main__":
    main()

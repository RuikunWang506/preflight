"""Time `lookfirst check` on well-known public repos, for SPEC section 12, item 1
(under 30 seconds with a token on a typical repo, and evidence for every serious reason).

    uv run python scripts/time_check.py            the 12 repos below, one run each
    uv run python scripts/time_check.py owner/repo  just the repos you name

Uses the network and your GitHub token if you have one ($GITHUB_TOKEN, $GH_TOKEN or
`gh auth token`), exactly like `lookfirst check`. Nothing is run: the check only reads.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIMIT_SECONDS = 30.0
REPOS = [
    "psf/requests",
    "pallets/flask",
    "fastapi/fastapi",
    "expressjs/express",
    "axios/axios",
    "BurntSushi/ripgrep",
    "sharkdp/bat",
    "junegunn/fzf",
    "nvm-sh/nvm",
    "ohmyzsh/ohmyzsh",
    "ollama/ollama",
    "modelcontextprotocol/servers",
]


def check(repo: str) -> tuple[float, dict | None, str]:
    lookfirst = ROOT / ".venv" / "bin" / "lookfirst"
    start = time.perf_counter()
    done = subprocess.run(  # noqa: S603
        [str(lookfirst), "check", repo, "--json"],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
        check=False,
    )
    took = time.perf_counter() - start
    try:
        return took, json.loads(done.stdout), ""
    except json.JSONDecodeError:
        return took, None, (done.stderr.strip().splitlines() or ["no output"])[-1][:120]


def main() -> int:
    repos = sys.argv[1:] or REPOS
    times, slow, bare = [], [], []
    print(f"{'repo':30} {'seconds':>8}  verdict      findings (critical/high/medium)")
    for repo in repos:
        took, report, error = check(repo)
        times.append(took)
        if took > LIMIT_SECONDS:
            slow.append(repo)
        if report is None:
            print(f"{repo:30} {took:8.1f}  couldn't check: {error}")
            continue
        counts = {"critical": 0, "high": 0, "medium": 0}
        for finding in report["findings"]:
            if finding["severity"] in counts:
                counts[finding["severity"]] += 1
            if finding["severity"] in ("critical", "high", "medium") and not finding["evidence"]:
                bare.append(f"{repo}: {finding['id']}")
        shown = "/".join(str(n) for n in counts.values())
        print(f"{repo:30} {took:8.1f}  {report['verdict']:12} {shown}")
    print(
        f"\nmedian {statistics.median(times):.1f} s, slowest {max(times):.1f} s, "
        f"limit {LIMIT_SECONDS:.0f} s"
    )
    print("over the limit:", ", ".join(slow) or "none")
    print("serious findings without evidence:", ", ".join(bare) or "none")
    return 1 if slow or bare else 0


if __name__ == "__main__":
    sys.exit(main())

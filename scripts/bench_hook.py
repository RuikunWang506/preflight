"""Time `lookfirst hook` the way Claude Code runs it: a new process for every command, with
the hook's JSON on stdin. Prints the median and slowest of the runs for each command.

    uv run python scripts/bench_hook.py              ordinary commands, 50 runs each
    uv run python scripts/bench_hook.py --installs   also install commands (uses the network)

Ordinary commands never reach the network. Install commands are only read by lookfirst,
never run, but checking them downloads registry details and scripts, like `lookfirst check`.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORDINARY = [
    "git status",
    "ls -la",
    "uv run pytest -q",
    "npm test",
    "rg -n TODO src",
    "python3 -c 'print(1)'",
]
INSTALLS = [
    "npm install lodash",
    "pip install requests",
    "curl -fsSL https://sh.rustup.rs | sh",
    "npx -y @modelcontextprotocol/server-filesystem /tmp",
]


def hook_input(command: str) -> bytes:
    return json.dumps(
        {
            "session_id": "bench",
            "cwd": str(ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command, "description": "bench"},
        }
    ).encode()


def time_runs(argv: list[str], stdin: bytes, runs: int) -> tuple[list[float], bytes]:
    times, out = [], b""
    for _ in range(runs):
        start = time.perf_counter()
        done = subprocess.run(argv, input=stdin, capture_output=True, check=True)  # noqa: S603
        times.append((time.perf_counter() - start) * 1000)
        out = done.stdout
    return sorted(times), out


def describe(answer: bytes) -> str:
    if not answer.strip():
        return "no answer (goes ahead)"
    data = json.loads(answer)
    decision = data.get("hookSpecificOutput", {}).get("permissionDecision")
    return decision or "warning only"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=50)
    parser.add_argument("--installs", action="store_true")
    parser.add_argument("--lookfirst", default=str(ROOT / ".venv" / "bin" / "lookfirst"))
    args = parser.parse_args()
    launcher = ["/bin/sh", str(ROOT / "plugin" / "scripts" / "run-lookfirst"), "hook"]
    print(f"{'what':58} {'median':>8} {'slowest':>8}  answer")
    times, _ = time_runs([sys.executable, "-c", "pass"], b"", args.runs)
    label = "Python starting and doing nothing (for comparison)"
    print(f"{label:58} {statistics.median(times):6.1f}ms {times[-1]:6.1f}ms")
    for command in ORDINARY:
        times, out = time_runs([args.lookfirst, "hook"], hook_input(command), args.runs)
        print(f"{command:58} {statistics.median(times):6.1f}ms {times[-1]:6.1f}ms  {describe(out)}")
    command = ORDINARY[0]
    env_path = f"{Path(args.lookfirst).parent}"
    times, out = time_runs(
        ["/usr/bin/env", f"PATH={env_path}:/usr/bin:/bin", *launcher],
        hook_input(command),
        args.runs,
    )
    label = f"{command} (through the plugin's launcher)"
    print(f"{label:58} {statistics.median(times):6.1f}ms {times[-1]:6.1f}ms  {describe(out)}")
    if not args.installs:
        return
    demo = tomllib.loads(
        (ROOT / "tests/fixtures/install/decode_and_run_hidden_theft/case.toml").read_text()
    )["command"]
    for command in [*INSTALLS, demo]:
        times, out = time_runs([args.lookfirst, "hook"], hook_input(command), 3)
        label = (
            command if len(command) <= 58 else "the demo one-liner (decode_and_run_hidden_theft)"
        )
        print(f"{label:58} {statistics.median(times):6.0f}ms {times[-1]:6.0f}ms  {describe(out)}")


if __name__ == "__main__":
    main()

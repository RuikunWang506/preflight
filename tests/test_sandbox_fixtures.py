"""The sandbox fixtures (SPEC section 11), run for real inside Docker through lookfirst's
runner. Each must find exactly what its case.toml says, within the 3-minute target.

They only run when asked: LOOKFIRST_SANDBOX_TESTS=1 on this computer (Docker must be
running), and always in CI's Linux job. The host canary check covers them like every test.
"""

from __future__ import annotations

import os
import time
import tomllib

import pytest
from conftest import FIXTURES

from lookfirst.sandbox.docker import Docker
from lookfirst.sandbox.runner import run_sandbox
from lookfirst.scanners import base
from lookfirst.targets.models import ResolvedTarget, TargetSpec
from lookfirst.verdict.scoring import verdict_for

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(
        os.environ.get("LOOKFIRST_SANDBOX_TESTS") != "1",
        reason="runs fixtures in Docker; opt in with LOOKFIRST_SANDBOX_TESTS=1",
    ),
]
SANDBOX = FIXTURES / "sandbox"
CASES = sorted(p.name for p in SANDBOX.iterdir() if p.is_dir())


@pytest.fixture(scope="module")
def docker() -> Docker:
    # The tests' guard hides tools from lookfirst; these tests ask for the real Docker.
    executable = base.find_tool("docker", base._EXTRA_DIRS)
    if executable is None:
        pytest.skip("Docker isn't installed")
    engine = Docker(executable)
    if engine.engine() is None:
        pytest.skip("Docker isn't running")
    return engine


def test_there_are_five_fixtures() -> None:
    assert CASES == [
        "benign_npm_install",
        "benign_pip_install",
        "cron_entry",
        "decoy_key_theft",
        "download_and_run_tmp",
    ]


@pytest.mark.parametrize("case", CASES)
def test_sandbox_fixture(case: str, docker: Docker) -> None:
    folder = SANDBOX / case
    expected = tomllib.loads((folder / "case.toml").read_text())
    target = ResolvedTarget(
        TargetSpec(kind="local", raw=str(folder), path=folder), folder, str(folder)
    )
    started = time.monotonic()
    outcome = run_sandbox(target, docker=docker)
    took = time.monotonic() - started
    assert outcome.gaps == [], outcome.output
    assert {f.id: f.severity.value for f in outcome.findings} == expected["expect"], outcome.output
    assert verdict_for(outcome.findings).value == expected["verdict"]
    assert took < 180

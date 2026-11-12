"""The slow half of `lookfirst hook` (SPEC section 10).

It runs lookfirst's static check on what an install-like command would install or run,
within the time budget, and turns the verdicts into Claude Code's answer. hook.py loads
it only for install-like commands. Nothing is ever run here: the check only reads.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from lookfirst.core.errors import CouldntCheckError, FetchError, LookfirstError, TargetError
from lookfirst.hook import BUDGET_SECONDS, Planned
from lookfirst.verdict.render_agent import HookOutcome, hook_answer
from lookfirst.verdict.schema import Report

Checker = Callable[..., Report]
TIMED_OUT = f"it took longer than {BUDGET_SECONDS:.0f} seconds"


def answer(
    plans: Sequence[Planned], *, cwd: str, budget: float, checker: Checker | None = None
) -> tuple[dict | None, bool]:
    """(Claude Code's answer, whether a check is still running past the budget). Each
    check runs in a thread, so the hook can answer on time even if one hangs."""
    if checker is None:
        from lookfirst.pipeline import run_check

        checker = run_check
    deadline = time.monotonic() + budget
    outcomes: list[HookOutcome] = []
    still_running = False
    for plan in plans:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            outcomes.append(HookOutcome(plan.target, problem=TIMED_OUT))
            continue
        box: dict = {}
        worker = threading.Thread(target=_check, args=(checker, plan.target, cwd, box), daemon=True)
        worker.start()
        worker.join(remaining)
        if worker.is_alive():
            still_running = True
            outcomes.append(HookOutcome(plan.target, problem=TIMED_OUT))
            continue
        outcomes.append(HookOutcome(plan.target, **box))
    return hook_answer(outcomes), still_running


def _check(checker: Checker, target: str, cwd: str, box: dict) -> None:
    try:
        box["report"] = checker(target, cwd=Path(cwd))
    except (CouldntCheckError, FetchError) as exc:
        box["unreadable"] = exc.message
    except TargetError:
        box["skipped"] = True  # not something lookfirst can check: no answer either way
    except LookfirstError as exc:
        box["problem"] = exc.message
    except Exception as exc:
        box["problem"] = f"an internal error ({type(exc).__name__})"

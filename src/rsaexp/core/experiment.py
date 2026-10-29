"""Run an attack over seeded challenges and collect outcome statistics.

A campaign draws one seed per trial from the master seed, builds the trial
with ``make_challenge(random.Random(trial_seed)) -> (challenge, truth)``,
passes only the challenge to ``attack(challenge) -> guess``, and scores the
guess with ``check(guess, truth)`` (equality by default). Any trial can be
rebuilt on its own with ``make_challenge(random.Random(trial.seed))``.

Without a timeout or extra workers, attacks run in this process. Otherwise
they run in ``workers`` spawned processes, and a process whose trial overruns
is killed and replaced, since a long C call into gmpy2 or fpylll cannot be
interrupted any other way. Trials are scored by index, so a campaign gives the
same per-trial outcomes whatever the number of workers. Workers must import
``attack`` by name, so it has to be a module-level function (or a
``functools.partial`` of one), not a lambda or a notebook-defined function,
and scripts need an ``if __name__ == "__main__":`` guard. Challenges and
guesses must be picklable.
"""

from __future__ import annotations

import multiprocessing as mp
import random
import statistics
import time
from collections.abc import Callable
from multiprocessing.connection import wait
from dataclasses import dataclass
from enum import Enum
from operator import eq
from typing import Any

MakeChallenge = Callable[[random.Random], tuple[Any, Any]]
Attack = Callable[[Any], Any]
Check = Callable[[Any, Any], bool]

# (guess, attack seconds, error message); error is None when the attack returned.
_Result = tuple[Any, float | None, str | None]


class Outcome(Enum):
    SUCCESS = "success"
    FAILURE = "failure"  # the attack returned a wrong guess
    TIMEOUT = "timeout"
    ERROR = "error"  # the attack raised, or the worker died


@dataclass(frozen=True)
class Trial:
    index: int
    seed: int
    outcome: Outcome
    seconds: float | None  # attack time only; None on timeout or error
    error: str | None = None


@dataclass(frozen=True)
class Campaign:
    seed: int
    timeout: float | None
    trials: tuple[Trial, ...]
    workers: int = 1

    def count(self, outcome: Outcome) -> int:
        return sum(t.outcome is outcome for t in self.trials)

    def rate(self, outcome: Outcome) -> float:
        return self.count(outcome) / len(self.trials)

    @property
    def seconds(self) -> list[float]:
        """Attack times of the trials that returned a guess."""
        return [t.seconds for t in self.trials if t.seconds is not None]

    def __str__(self) -> str:
        rates = ", ".join(f"{o.value} {self.rate(o):.1%}" for o in Outcome)
        workers = f", {self.workers} workers" if self.workers > 1 else ""
        line = f"{len(self.trials)} trials (seed {self.seed}{workers}): {rates}"
        if self.seconds:
            line += (
                f"; attack time median {statistics.median(self.seconds):.3g}s,"
                f" max {max(self.seconds):.3g}s"
            )
        return line


def _call(attack: Attack, challenge: Any) -> _Result:
    start = time.perf_counter()
    try:
        guess = attack(challenge)
    except Exception as exc:
        return None, None, repr(exc)
    return guess, time.perf_counter() - start, None


def _serve(attack: Attack, conn) -> None:
    conn.send("ready")
    while True:
        try:
            challenge = conn.recv()
        except EOFError:
            return
        conn.send(_call(attack, challenge))


class _Worker:
    """An attack process, replaced after a timeout or crash.

    It starts without blocking and is ready once its start-up handshake has
    been received; ``trial`` is the index of the trial it is running, if any.
    """

    def __init__(self, attack: Attack) -> None:
        self._attack = attack
        self._spawn()

    def _spawn(self) -> None:
        ctx = mp.get_context("spawn")
        self.conn, child = ctx.Pipe()
        self._proc = ctx.Process(target=_serve, args=(self._attack, child), daemon=True)
        self._proc.start()
        child.close()
        self.ready = False
        self.trial: int | None = None
        self.deadline: float | None = None

    @property
    def idle(self) -> bool:
        return self.ready and self.trial is None

    def close(self) -> None:
        self.conn.close()
        self._proc.kill()
        self._proc.join()

    def respawn(self) -> None:
        self.close()
        self._spawn()

    def submit(self, index: int, challenge: Any, timeout: float | None) -> None:
        self.conn.send(challenge)
        self.trial = index
        self.deadline = None if timeout is None else time.monotonic() + timeout

    def receive(self) -> tuple[int, _Result] | None:
        """Read the start-up handshake (None) or the running trial's result."""
        try:
            message = self.conn.recv()
        except EOFError:
            if self.trial is None:
                raise RuntimeError(
                    "attack worker failed to start; attack must be importable by name"
                ) from None
            index = self.trial
            self.close()
            result = (None, None, f"worker died (exit code {self._proc.exitcode})")
            self._spawn()
            return index, result
        if self.trial is None:
            self.ready = True
            return None
        index, self.trial, self.deadline = self.trial, None, None
        return index, message


def _score(index: int, seed: int, result: _Result, truth: Any, check: Check) -> Trial:
    guess, seconds, error = result
    if error is not None:
        outcome = Outcome.ERROR
    elif check(guess, truth):
        outcome = Outcome.SUCCESS
    else:
        outcome = Outcome.FAILURE
    return Trial(index, seed, outcome, seconds, error)


def _run_inline(make_challenge, attack, check, seeds) -> list[Trial]:
    trials = []
    for i, trial_seed in enumerate(seeds):
        challenge, truth = make_challenge(random.Random(trial_seed))
        trials.append(_score(i, trial_seed, _call(attack, challenge), truth, check))
    return trials


def _run_pool(make_challenge, attack, check, seeds, timeout, n_workers) -> list[Trial]:
    trials: list[Trial | None] = [None] * len(seeds)
    truths: dict[int, Any] = {}
    next_trial = done = 0
    workers: list[_Worker] = []
    try:
        # Start every process before waiting on any, so Sage-sized imports overlap.
        workers = [_Worker(attack) for _ in range(n_workers)]
        while done < len(seeds):
            for w in workers:
                if w.idle and next_trial < len(seeds):
                    i, next_trial = next_trial, next_trial + 1
                    challenge, truths[i] = make_challenge(random.Random(seeds[i]))
                    w.submit(i, challenge, timeout)

            busy = {w.conn: w for w in workers if not w.idle}
            deadlines = [w.deadline for w in busy.values() if w.deadline is not None]
            wait_for = max(0.0, min(deadlines) - time.monotonic()) if deadlines else None
            for conn in wait(list(busy), wait_for):
                received = busy[conn].receive()
                if received is not None:
                    i, result = received
                    trials[i] = _score(i, seeds[i], result, truths.pop(i), check)
                    done += 1

            now = time.monotonic()
            for w in workers:
                # A result that arrived just before the deadline is read next round.
                if w.deadline is not None and w.deadline <= now and not w.conn.poll():
                    i = w.trial
                    trials[i] = Trial(i, seeds[i], Outcome.TIMEOUT, None)
                    truths.pop(i)
                    done += 1
                    w.respawn()
    finally:
        for w in workers:
            w.close()
    return trials


def run_campaign(
    make_challenge: MakeChallenge,
    attack: Attack,
    n_trials: int,
    *,
    seed: int = 0,
    check: Check = eq,
    timeout: float | None = None,
    workers: int = 1,
) -> Campaign:
    """Run ``attack`` on ``n_trials`` seeded challenges.

    ``timeout`` is per trial in seconds, counted from when the trial is handed
    to a worker; ``workers`` is the number of attack processes run at once.
    """
    if n_trials < 1:
        raise ValueError("n_trials must be at least 1")
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be positive")
    if workers < 1:
        raise ValueError("workers must be at least 1")
    rng = random.Random(seed)
    seeds = [rng.getrandbits(64) for _ in range(n_trials)]
    if timeout is None and workers == 1:
        trials = _run_inline(make_challenge, attack, check, seeds)
    else:
        workers = min(workers, n_trials)
        trials = _run_pool(make_challenge, attack, check, seeds, timeout, workers)
    return Campaign(seed, timeout, tuple(trials), workers)

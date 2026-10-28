"""Run an attack over seeded challenges and collect outcome statistics.

A campaign draws one seed per trial from the master seed, builds the trial
with ``make_challenge(random.Random(trial_seed)) -> (challenge, truth)``,
passes only the challenge to ``attack(challenge) -> guess``, and scores the
guess with ``check(guess, truth)`` (equality by default). Any trial can be
rebuilt on its own with ``make_challenge(random.Random(trial.seed))``.

Without a timeout, attacks run in this process. With one, they run in a
spawned worker process that is killed when a trial overruns, since a long C
call into gmpy2 or fpylll cannot be interrupted any other way. The worker
must import ``attack`` by name, so it has to be a module-level function (or a
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
        line = f"{len(self.trials)} trials (seed {self.seed}): {rates}"
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
    """A reusable attack process, replaced after a timeout or crash."""

    def __init__(self, attack: Attack) -> None:
        self._attack = attack
        self._start()

    def _start(self) -> None:
        ctx = mp.get_context("spawn")
        self._conn, child = ctx.Pipe()
        self._proc = ctx.Process(target=_serve, args=(self._attack, child), daemon=True)
        self._proc.start()
        child.close()
        # Wait out interpreter start-up and imports so they don't count
        # against the first trial's timeout.
        try:
            self._conn.recv()
        except EOFError:
            self._proc.join()
            raise RuntimeError(
                "attack worker failed to start; attack must be importable by name"
            ) from None

    def close(self) -> None:
        self._conn.close()
        self._proc.kill()
        self._proc.join()

    def run(self, challenge: Any, timeout: float) -> _Result:
        """Raises TimeoutError if the attack overruns."""
        self._conn.send(challenge)
        if not self._conn.poll(timeout):
            self.close()
            self._start()
            raise TimeoutError
        try:
            return self._conn.recv()
        except EOFError:
            self.close()
            exitcode = self._proc.exitcode
            self._start()
            return None, None, f"worker died (exit code {exitcode})"


def run_campaign(
    make_challenge: MakeChallenge,
    attack: Attack,
    n_trials: int,
    *,
    seed: int = 0,
    check: Check = eq,
    timeout: float | None = None,
) -> Campaign:
    """Run ``attack`` on ``n_trials`` seeded challenges; ``timeout`` is per trial in seconds."""
    if n_trials < 1:
        raise ValueError("n_trials must be at least 1")
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be positive")
    seeds = random.Random(seed)
    worker = _Worker(attack) if timeout is not None else None
    trials = []
    try:
        for i in range(n_trials):
            trial_seed = seeds.getrandbits(64)
            challenge, truth = make_challenge(random.Random(trial_seed))
            try:
                if worker is None:
                    guess, seconds, error = _call(attack, challenge)
                else:
                    guess, seconds, error = worker.run(challenge, timeout)
            except TimeoutError:
                trials.append(Trial(i, trial_seed, Outcome.TIMEOUT, None))
                continue
            if error is not None:
                outcome = Outcome.ERROR
            elif check(guess, truth):
                outcome = Outcome.SUCCESS
            else:
                outcome = Outcome.FAILURE
            trials.append(Trial(i, trial_seed, outcome, seconds, error))
    finally:
        if worker is not None:
            worker.close()
    return Campaign(seed, timeout, tuple(trials))

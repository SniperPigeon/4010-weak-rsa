import os
import random
import time

import gmpy2
import pytest

from rsaexp.core.experiment import Outcome, run_campaign
from rsaexp.core.keygen import generate_key

# Attacks are module-level so the spawned worker can import them.


def short_secret_challenge(rng):
    key = generate_key(bits=256, e=3, rng=rng)
    m = rng.getrandbits(80)
    return (key.public_key, key.public_key.encrypt(m)), m


def cube_root(challenge):
    _, c = challenge
    root, exact = gmpy2.iroot(c, 3)
    return int(root) if exact else None


def wrong_guess(challenge):
    return -1


def raise_error(challenge):
    raise ArithmeticError("no root")


def coin_challenge(rng):
    bit = rng.getrandbits(1)
    return bit, bit


def hang_on_one(bit):
    if bit:
        time.sleep(60)
    return bit


def die(challenge):
    os._exit(3)


def test_inline_success():
    campaign = run_campaign(short_secret_challenge, cube_root, 5, seed=1)
    assert campaign.rate(Outcome.SUCCESS) == 1.0
    assert len(campaign.seconds) == 5
    assert "success 100.0%" in str(campaign)


def test_seeds_are_reproducible_per_trial():
    a = run_campaign(short_secret_challenge, cube_root, 3, seed=7)
    b = run_campaign(short_secret_challenge, cube_root, 3, seed=7)
    c = run_campaign(short_secret_challenge, cube_root, 3, seed=8)
    assert [t.seed for t in a.trials] == [t.seed for t in b.trials]
    assert [t.seed for t in a.trials] != [t.seed for t in c.trials]
    # A single trial can be rebuilt from its own seed.
    trial = a.trials[2]
    assert short_secret_challenge(random.Random(trial.seed)) == short_secret_challenge(
        random.Random(trial.seed)
    )


def test_failure_and_error_are_classified():
    failed = run_campaign(short_secret_challenge, wrong_guess, 2)
    assert failed.count(Outcome.FAILURE) == 2
    errored = run_campaign(short_secret_challenge, raise_error, 2)
    assert errored.count(Outcome.ERROR) == 2
    assert "no root" in errored.trials[0].error
    assert errored.seconds == []


def test_custom_check():
    campaign = run_campaign(short_secret_challenge, wrong_guess, 2, check=lambda g, t: True)
    assert campaign.rate(Outcome.SUCCESS) == 1.0


def test_timeout_kills_and_recovers():
    campaign = run_campaign(coin_challenge, hang_on_one, 6, seed=3, timeout=0.5)
    bits = [coin_challenge(random.Random(t.seed))[0] for t in campaign.trials]
    assert 0 < sum(bits) < 6  # the seed gives both kinds of trial
    expected = [Outcome.TIMEOUT if bit else Outcome.SUCCESS for bit in bits]
    assert [t.outcome for t in campaign.trials] == expected


def test_isolated_worker_reports_errors_and_crashes():
    errored = run_campaign(short_secret_challenge, raise_error, 2, timeout=5)
    assert errored.count(Outcome.ERROR) == 2
    assert "no root" in errored.trials[0].error
    crashed = run_campaign(short_secret_challenge, die, 2, timeout=5)
    assert crashed.count(Outcome.ERROR) == 2
    assert "exit code 3" in crashed.trials[0].error


def test_isolated_success_matches_inline():
    inline = run_campaign(short_secret_challenge, cube_root, 3, seed=2)
    isolated = run_campaign(short_secret_challenge, cube_root, 3, seed=2, timeout=5)
    assert [t.outcome for t in isolated.trials] == [t.outcome for t in inline.trials]


@pytest.mark.parametrize("kwargs", [{"n_trials": 0}, {"n_trials": 1, "timeout": 0}])
def test_rejects_bad_arguments(kwargs):
    with pytest.raises(ValueError):
        run_campaign(short_secret_challenge, cube_root, **kwargs)

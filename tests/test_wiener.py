import random

import pytest

from rsaexp.attacks.wiener import check, make_challenge, wiener_cf
from rsaexp.core.experiment import Outcome, run_campaign
from rsaexp.core.keygen import generate_key
from rsaexp.core.rsa import PublicKey


def test_textbook_example():
    # N = 379 * 239, e = 17993, d = 5.
    key = wiener_cf(PublicKey(90581, 17993))
    assert key is not None
    assert key.d == 5
    assert {key.p, key.q} == {379, 239}


@pytest.mark.parametrize("d_bits", [64, 256, 500])
def test_recovers_small_d_2048(d_bits):
    pub, truth = make_challenge(random.Random(d_bits), d_bits=d_bits)
    assert check(wiener_cf(pub), truth)


def test_large_d_is_not_recovered():
    assert wiener_cf(generate_key(rng=random.Random(0)).public_key) is None


def test_check_ignores_prime_order():
    _, truth = make_challenge(random.Random(1), d_bits=128, bits=256)
    swapped = type(truth)(truth.q, truth.p, truth.e, truth.d)
    assert check(swapped, truth)
    assert not check(None, truth)


def test_runs_in_isolated_worker():
    campaign = run_campaign(make_challenge, wiener_cf, 3, seed=0, check=check, timeout=60)
    assert campaign.rate(Outcome.SUCCESS) == 1.0

import random
from functools import partial

import pytest

from rsaexp.attacks.hastad import (
    HastadChallenge,
    PADDING_LINEAR,
    PADDING_NONE,
    PADDING_OAEP,
    PADDING_RANDOM,
    check,
    hastad_broadcast,
    make_challenge,
)
from rsaexp.attacks.nt import int_to_text, text_to_int
from rsaexp.attacks.padding import modulus_bytes, oaep_decode, oaep_encode
from rsaexp.core.experiment import Outcome, run_campaign
from rsaexp.core.keygen import generate_key


def test_broadcast_recovers_pay_alice_on_2048():
    rng = random.Random(4010)
    keys = [generate_key(e=3, rng=rng) for _ in range(3)]
    m = text_to_int("Pay Alice 100")
    ciphertexts = tuple(k.public_key.encrypt(m) for k in keys)
    moduli = tuple(k.n for k in keys)
    guess = hastad_broadcast(HastadChallenge(3, ciphertexts, moduli))
    assert guess == m
    assert int_to_text(guess) == "Pay Alice 100"


def test_none_padding_succeeds():
    ch, truth = make_challenge(random.Random(1), e=3, bits=256, msg_bits=40, padding=PADDING_NONE)
    assert check(hastad_broadcast(ch), truth)


def test_linear_padding_still_recovers_m():
    ch, truth = make_challenge(
        random.Random(2), e=3, bits=256, msg_bits=40, padding=PADDING_LINEAR
    )
    assert check(hastad_broadcast(ch), truth)


def test_random_padding_stops_broadcast():
    ch, _ = make_challenge(
        random.Random(3), e=3, bits=256, msg_bits=40, padding=PADDING_RANDOM
    )
    assert hastad_broadcast(ch) is None


def test_oaep_stops_broadcast():
    ch, _ = make_challenge(
        random.Random(4), e=3, bits=1024, msg_bits=80, padding=PADDING_OAEP
    )
    assert hastad_broadcast(ch) is None


def test_owner_can_decrypt_oaep():
    rng = random.Random(5)
    key = generate_key(e=3, bits=1024, rng=rng)
    raw = b"Pay Alice 100"
    padded = oaep_encode(raw, modulus_bytes(key.n), rng)
    c = key.public_key.encrypt(padded)
    assert oaep_decode(key.decrypt(c), modulus_bytes(key.n)) == raw


def test_two_recipients_are_not_enough_for_e3():
    with pytest.raises(ValueError, match="at least e recipients"):
        make_challenge(
            random.Random(6), e=3, bits=256, recipients=2, msg_bits=40, padding=PADDING_NONE
        )


def test_none_padding_campaign():
    campaign = run_campaign(
        partial(make_challenge, bits=256, msg_bits=40),
        hastad_broadcast,
        3,
        seed=0,
        check=check,
    )
    assert campaign.rate(Outcome.SUCCESS) == 1.0


def test_random_padding_campaign_fails():
    campaign = run_campaign(
        partial(make_challenge, bits=256, msg_bits=40, padding=PADDING_RANDOM),
        hastad_broadcast,
        3,
        seed=0,
        check=check,
    )
    assert campaign.rate(Outcome.FAILURE) == 1.0

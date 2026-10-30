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
from rsaexp.attacks.padding import oaep_decrypt, oaep_encrypt
from rsaexp.attacks.short_secret import ShortSecretChallenge, short_secret
from rsaexp.core.experiment import Outcome, run_campaign
from rsaexp.core.keygen import generate_key
from rsaexp.core.rsa import PublicKey

# 256-bit moduli: m^3 must exceed N, so m needs more than ~86 bits.
SMALL = dict(e=3, bits=256, msg_bits=120)


def single_root_fails(ch: HastadChallenge) -> bool:
    """A Håstad challenge is only meaningful if one ciphertext alone does not leak m."""
    return all(
        short_secret(ShortSecretChallenge(PublicKey(n, ch.e), c)) is None
        for c, n in zip(ch.ciphertexts, ch.moduli)
    )


def test_broadcast_recovers_long_text_on_2048():
    rng = random.Random(4010)
    keys = [generate_key(e=3, rng=rng) for _ in range(3)]
    raw = b"Card 4010-0001: transfer 100 SGD from Alice to Bob, session token 7f3a9c2e5b1d4086, issued 2026-10-30"
    m = int.from_bytes(raw, "big")
    ciphertexts = tuple(k.public_key.encrypt(m) for k in keys)
    moduli = tuple(k.n for k in keys)
    ch = HastadChallenge(3, ciphertexts, moduli)
    assert single_root_fails(ch)
    guess = hastad_broadcast(ch)
    assert guess == m
    assert guess.to_bytes(len(raw), "big") == raw


@pytest.mark.parametrize("padding", [PADDING_NONE, PADDING_LINEAR])
def test_default_2048_needs_broadcast(padding):
    ch, truth = make_challenge(random.Random(10), padding=padding)
    assert single_root_fails(ch)
    assert check(hastad_broadcast(ch), truth)


def test_default_2048_random_padding_stops_both():
    ch, _ = make_challenge(random.Random(11), padding=PADDING_RANDOM)
    assert single_root_fails(ch)
    assert hastad_broadcast(ch) is None


def test_none_padding_succeeds():
    ch, truth = make_challenge(random.Random(1), padding=PADDING_NONE, **SMALL)
    assert single_root_fails(ch)
    assert check(hastad_broadcast(ch), truth)


def test_linear_padding_still_recovers_m():
    ch, truth = make_challenge(random.Random(2), padding=PADDING_LINEAR, **SMALL)
    assert single_root_fails(ch)
    assert check(hastad_broadcast(ch), truth)


def test_random_padding_stops_broadcast():
    ch, _ = make_challenge(random.Random(3), padding=PADDING_RANDOM, **SMALL)
    assert single_root_fails(ch)
    assert hastad_broadcast(ch) is None


def test_oaep_stops_broadcast():
    ch, _ = make_challenge(
        random.Random(4), e=3, bits=1024, msg_bits=400, padding=PADDING_OAEP
    )
    assert hastad_broadcast(ch) is None


def test_owner_can_decrypt_oaep():
    rng = random.Random(5)
    key = generate_key(e=3, bits=1024, rng=rng)
    raw = b"Pay Alice 100"
    c = oaep_encrypt(key.public_key, raw, rng)
    assert oaep_decrypt(key, c) == raw


def test_oaep_is_reproducible_from_rng():
    key = generate_key(e=3, bits=1024, rng=random.Random(6))
    c1 = oaep_encrypt(key.public_key, b"x", random.Random(7))
    c2 = oaep_encrypt(key.public_key, b"x", random.Random(7))
    c3 = oaep_encrypt(key.public_key, b"x", random.Random(8))
    assert c1 == c2 != c3


def test_two_recipients_are_not_enough_for_e3():
    with pytest.raises(ValueError, match="at least e recipients"):
        make_challenge(random.Random(6), recipients=2, padding=PADDING_NONE, **SMALL)


def test_none_padding_campaign():
    campaign = run_campaign(
        partial(make_challenge, bits=256, msg_bits=120),
        hastad_broadcast,
        3,
        seed=0,
        check=check,
    )
    assert campaign.rate(Outcome.SUCCESS) == 1.0


def test_random_padding_campaign_fails():
    campaign = run_campaign(
        partial(make_challenge, bits=256, msg_bits=120, padding=PADDING_RANDOM),
        hastad_broadcast,
        3,
        seed=0,
        check=check,
    )
    assert campaign.rate(Outcome.FAILURE) == 1.0

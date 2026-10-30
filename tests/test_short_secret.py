import random

from rsaexp.attacks.nt import int_to_text, text_to_int
from rsaexp.attacks.short_secret import (
    ShortSecretChallenge,
    check,
    make_challenge,
    multiply_ciphertext,
    short_secret,
)
from rsaexp.core.experiment import Outcome, run_campaign
from rsaexp.core.keygen import generate_key
from rsaexp.core.rsa import PrivateKey


def test_textbook_hand_example():
    # p = 11, q = 17, n = 187, e = 3. m = 5, 5^3 = 125 < 187 so no wrap.
    key = PrivateKey.from_primes(11, 17, 3)
    c = key.public_key.encrypt(5)
    assert c == 125
    assert short_secret(ShortSecretChallenge(key.public_key, c)) == 5
    assert key.decrypt(c) == 5


def test_recovers_pay_alice_on_2048():
    key = generate_key(e=3, rng=random.Random(0))
    m = text_to_int("Pay Alice 100")
    c = key.public_key.encrypt(m)
    guess = short_secret(ShortSecretChallenge(key.public_key, c))
    assert guess == m
    assert int_to_text(guess) == "Pay Alice 100"


def test_recovers_generated_short_message():
    ch, truth = make_challenge(random.Random(1), e=3, bits=256, msg_bits=40)
    assert check(short_secret(ch), truth)


def test_long_message_is_not_an_exact_power():
    ch, _ = make_challenge(random.Random(2), e=3, bits=512, msg_bits=200)
    assert short_secret(ch) is None


def test_malleability_doubles_the_plaintext():
    key = PrivateKey.from_primes(11, 17, 3)
    m = 5
    c = key.public_key.encrypt(m)
    c2 = multiply_ciphertext(key.public_key, c, 2)
    assert key.decrypt(c2) == (2 * m) % key.n


def test_campaign_recovers_short_secrets():
    from functools import partial

    campaign = run_campaign(
        partial(make_challenge, bits=256, msg_bits=40),
        short_secret,
        3,
        seed=0,
        check=check,
    )
    assert campaign.rate(Outcome.SUCCESS) == 1.0

"""Håstad broadcast: the same textbook message, small e, several moduli.

c_i ≡ m^e (mod n_i). If the n_i are pairwise coprime and there are at
least e of them, CRT rebuilds m^e exactly (when m^e is below the
product of the n_i) and an integer e-th root returns m.

Linear padding uses the same a, b for every recipient, so CRT still
recovers a*m + b. Fresh random padding or OAEP makes each c_i encrypt
a different integer; the same CRT-and-root then fails.
"""

from __future__ import annotations

import random
from math import gcd
from typing import NamedTuple

from rsaexp.attacks.nt import crt, integer_nth_root
from rsaexp.attacks.padding import (
    linear_pad,
    linear_unpad,
    modulus_bytes,
    oaep_encode,
    random_pad,
)
from rsaexp.core.keygen import generate_key
from rsaexp.core.rsa import PrivateKey

PADDING_NONE = "none"
PADDING_LINEAR = "linear"
PADDING_RANDOM = "random"
PADDING_OAEP = "oaep"


class HastadChallenge(NamedTuple):
    e: int
    ciphertexts: tuple[int, ...]
    moduli: tuple[int, ...]
    a: int = 1
    b: int = 0


def hastad_broadcast(challenge: HastadChallenge) -> int | None:
    """Recover m from e (or more) textbook ciphertexts of the same message.

    For linear padding the public (a, b) are on the challenge and the
    recovered integer is unpadded. Returns None if the combined value
    is not an exact e-th power — that is the random-padding case.
    """
    e = challenge.e
    if len(challenge.ciphertexts) != len(challenge.moduli):
        return None
    if len(challenge.moduli) < e:
        return None
    for i, ni in enumerate(challenge.moduli):
        for nj in challenge.moduli[i + 1 :]:
            if gcd(ni, nj) != 1:
                return None
    combined, _ = crt(challenge.ciphertexts, challenge.moduli)
    root, exact = integer_nth_root(combined, e)
    if not exact:
        return None
    if challenge.a == 1 and challenge.b == 0:
        return root
    return linear_unpad(root, challenge.a, challenge.b)


def _coprime_keys(rng: random.Random, e: int, bits: int, count: int) -> list[PrivateKey]:
    keys: list[PrivateKey] = []
    while len(keys) < count:
        key = generate_key(e=e, bits=bits, rng=rng)
        if all(gcd(key.n, other.n) == 1 for other in keys):
            keys.append(key)
    return keys


def make_challenge(
    rng: random.Random,
    e: int = 3,
    bits: int = 2048,
    recipients: int | None = None,
    msg_bits: int = 80,
    padding: str = PADDING_NONE,
    pad_bits: int = 128,
    a: int = 256,
    b: int = 17,
) -> tuple[HastadChallenge, int]:
    """``padding`` is none, linear, random, or oaep. The attacker never sees the pads."""
    if recipients is None:
        recipients = e
    if recipients < e:
        raise ValueError("need at least e recipients for elementary Håstad")
    if padding not in {PADDING_NONE, PADDING_LINEAR, PADDING_RANDOM, PADDING_OAEP}:
        raise ValueError(f"unknown padding {padding!r}")

    keys = _coprime_keys(rng, e, bits, recipients)
    m = rng.getrandbits(msg_bits) | (1 << (msg_bits - 1))

    if padding == PADDING_NONE:
        plains = [m] * recipients
        a_pub, b_pub = 1, 0
    elif padding == PADDING_LINEAR:
        padded = linear_pad(m, a, b)
        plains = [padded] * recipients
        a_pub, b_pub = a, b
    elif padding == PADDING_RANDOM:
        plains = [random_pad(m, msg_bits, pad_bits, rng) for _ in range(recipients)]
        a_pub, b_pub = 1, 0
    else:
        plains = [
            oaep_encode(m.to_bytes((msg_bits + 7) // 8, "big"), modulus_bytes(key.n), rng)
            for key in keys
        ]
        a_pub, b_pub = 1, 0

    for plain, key in zip(plains, keys):
        if not 0 <= plain < key.n:
            raise ValueError("padded message is not in [0, N)")

    ciphertexts = tuple(key.public_key.encrypt(plain) for plain, key in zip(plains, keys))
    moduli = tuple(key.n for key in keys)
    return HastadChallenge(e, ciphertexts, moduli, a_pub, b_pub), m


def check(guess: int | None, truth: int) -> bool:
    return guess is not None and guess == truth

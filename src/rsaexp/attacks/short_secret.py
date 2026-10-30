"""Textbook RSA, no padding: recover a short message by an integer e-th root.

If e is small and m^e < N, encryption does not wrap modulo N, so
c = m^e as integers and the message is the exact e-th root of c.
A long message, or a random pad that makes the input fill N, stops it.

Malleability is the other textbook failure: from c = m^e one can
build (k^e * c) = (k m)^e without knowing m.
"""

from __future__ import annotations

import random
from typing import NamedTuple

from rsaexp.attacks.nt import integer_nth_root
from rsaexp.core.keygen import generate_key
from rsaexp.core.rsa import PublicKey


class ShortSecretChallenge(NamedTuple):
    pub: PublicKey
    ciphertext: int


def short_secret(challenge: ShortSecretChallenge) -> int | None:
    """Return m if c is an exact e-th power; None if the message wrapped modulo N."""
    root, exact = integer_nth_root(challenge.ciphertext, challenge.pub.e)
    if exact and 0 <= root < challenge.pub.n and challenge.pub.encrypt(root) == challenge.ciphertext:
        return root
    return None


def multiply_ciphertext(pub: PublicKey, c: int, k: int) -> int:
    """Map c = m^e to (k m)^e without the private key. Textbook RSA is malleable."""
    if not 0 <= c < pub.n:
        raise ValueError("c must be in [0, N)")
    return (c * pow(k, pub.e, pub.n)) % pub.n


def make_challenge(
    rng: random.Random,
    e: int = 3,
    bits: int = 2048,
    msg_bits: int = 80,
) -> tuple[ShortSecretChallenge, int]:
    """Short m so that m^e has about e*msg_bits bits. Take msg_bits large to miss the bound."""
    key = generate_key(e=e, bits=bits, rng=rng)
    m = rng.getrandbits(msg_bits) | (1 << (msg_bits - 1))
    if m >= key.n:
        raise ValueError("message is larger than N")
    return ShortSecretChallenge(key.public_key, key.public_key.encrypt(m)), m


def check(guess: int | None, truth: int) -> bool:
    return guess is not None and guess == truth

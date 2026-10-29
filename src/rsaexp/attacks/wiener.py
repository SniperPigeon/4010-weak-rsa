"""Wiener's attack: recover a small private exponent from (N, e) alone.

If d < N^(1/4) / 3 and q < p < 2q, the k/d with e*d - k*phi(N) = 1 is a
convergent of e/N. Each convergent gives a candidate phi, and the right one
makes p and q the integer roots of x^2 - (N - phi + 1) x + N.
"""

from __future__ import annotations

import random

from sage.all import Integer, continued_fraction

from rsaexp.core.keygen import generate_key_small_d
from rsaexp.core.rsa import PrivateKey, PublicKey


def wiener_cf(pub: PublicKey) -> PrivateKey | None:
    """Recover the private key, or None if no convergent of e/N works."""
    n, e = Integer(pub.n), Integer(pub.e)
    for c in continued_fraction(e / n).convergents():
        k, d = c.numerator(), c.denominator()  # k/d approximates e/N
        if k == 0 or (e * d - 1) % k: # if k didnt divide ed-1 (should be equal to phi), skip
            continue
        
        
        # get candidate phi, do square check
        s =  n - ( (e * d - 1) // k ) + 1  # p + q if this phi is right
        disc = s * s - 4 * n  # (p - q)^2 s^2 - 4n
        
        if disc < 0 or not disc.is_square():
            continue
        
        r = disc.isqrt()
        p, q = (s + r) // 2, (s - r) // 2 # get factorization
        if p * q == n:
            return PrivateKey(p, q, e, d)
    return None




def make_challenge(rng: random.Random, d_bits: int = 500, bits: int = 2048) -> tuple[PublicKey, PrivateKey]:
    """A key with a ``d_bits``-bit d: the attacker gets (N, e), the truth is the key."""
    key = generate_key_small_d(d_bits, bits, rng)
    return key.public_key, key


def check(guess: PrivateKey | None, truth: PrivateKey) -> bool:
    # p and q may come back swapped, so compare d and N rather than the keys.
    return guess is not None and guess.d == truth.d and guess.n == truth.n

"""Key and leak generation for experiments.

Every generator takes an optional ``rng``. Pass ``random.Random(seed)`` to
reproduce a run (not cryptographically secure, experiments only); the default
is the OS CSPRNG via ``secrets.SystemRandom``.
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass
from math import gcd

import gmpy2

from rsaexp.core.rsa import PrivateKey


def _rng(rng: random.Random | None) -> random.Random:
    return rng if rng is not None else secrets.SystemRandom()


def generate_prime(bits: int, rng: random.Random | None = None, e: int | None = None) -> int:
    """Uniform random prime with exactly ``bits`` bits and its top two bits set.

    With the top two bits set, a product of two such primes has exactly the sum
    of their bit lengths, and two primes of equal size are within a factor 4/3
    of each other, so q < p < 2q holds as Wiener's theorem assumes.
    If ``e`` is given, primes with gcd(e, p - 1) != 1 are skipped.
    """
    if bits < 2:
        raise ValueError("bits must be at least 2")
    rng = _rng(rng)
    while True:
        candidate = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if gmpy2.is_prime(candidate) and (e is None or gcd(e, candidate - 1) == 1):
            return int(candidate)


def _distinct_primes(bits: int, rng: random.Random, e: int | None = None) -> tuple[int, int]:
    p = generate_prime(bits - bits // 2, rng, e)
    while True:
        q = generate_prime(bits // 2, rng, e)
        if q != p:
            return p, q


def generate_key(bits: int = 2048, e: int = 65537, rng: random.Random | None = None) -> PrivateKey:
    """Key with an exactly ``bits``-bit modulus and the given public exponent."""
    if bits < 4:
        raise ValueError("bits must be at least 4")
    if e < 3 or e % 2 == 0:
        # p - 1 is even, so an even e is never invertible mod phi(N).
        raise ValueError("e must be odd and at least 3")
    p, q = _distinct_primes(bits, _rng(rng), e)
    return PrivateKey.from_primes(p, q, e)


def generate_key_small_d(d_bits: int, bits: int = 2048, rng: random.Random | None = None) -> PrivateKey:
    """Key whose private exponent d has exactly ``d_bits`` bits; e = d^-1 mod phi(N).

    The resulting e is typically about as large as N.
    """
    if not 2 <= d_bits < bits:
        raise ValueError("d_bits must be in [2, bits)")
    rng = _rng(rng)
    p, q = _distinct_primes(bits, rng)
    phi = (p - 1) * (q - 1)
    while True:
        # phi is even, so d must be odd.
        d = rng.getrandbits(d_bits) | (1 << (d_bits - 1)) | 1
        if gcd(d, phi) == 1:
            return PrivateKey.from_primes_and_d(p, q, d)


@dataclass(frozen=True)
class HighBitsLeak:
    """Known top bits of a prime p: p = approx + x with 0 <= x < bound."""

    high: int
    known_bits: int
    unknown_bits: int

    @property
    def approx(self) -> int:
        return self.high << self.unknown_bits

    @property
    def bound(self) -> int:
        return 1 << self.unknown_bits


def leak_high_bits(p: int, known_bits: int) -> HighBitsLeak:
    """Leak the top ``known_bits`` bits of p (partial key exposure input)."""
    if not 0 < known_bits <= p.bit_length():
        raise ValueError("known_bits must be in (0, p.bit_length()]")
    unknown_bits = p.bit_length() - known_bits
    return HighBitsLeak(p >> unknown_bits, known_bits, unknown_bits)

@dataclass(frozen=True)
class StereotypedMsg:
    """Known top bits of message m, obtain full m with ciper c"""

    msg_high: int
    known_bits: int
    unknown_bits: int

    @property
    def approx(self) -> int:
        return self.msg_high << self.unknown_bits

    @property
    def bound(self) -> int:
        return 1 << self.unknown_bits


def obtain_stereotype(m:int, known_bits: int) -> StereotypedMsg:
    if not 0 < known_bits <= m.bit_length():
        raise ValueError("known_bits must be in (0, p.bit_length()]")
    unknown_bits = m.bit_length() - known_bits
    return StereotypedMsg(m >> unknown_bits, known_bits, unknown_bits)
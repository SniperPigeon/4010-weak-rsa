"""Textbook RSA on integers, for weak-parameter experiments.

Only mathematical validity is checked. Weak choices that the experiments need
(small e or d, short moduli, close primes, e larger than phi) are allowed.
Exponents are inverses modulo phi(N) = (p - 1)(q - 1), as in the course slides
and Wiener's analysis, not modulo lambda(N).
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd

import gmpy2


def _check_range(x: int, n: int, name: str) -> None:
    if not 0 <= x < n:
        raise ValueError(f"{name} must be in [0, N)")


def _as_ints(obj: object, *names: str) -> None:
    # Accept gmpy2.mpz and other int-likes, but store plain ints.
    for name in names:
        object.__setattr__(obj, name, int(getattr(obj, name)))


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    def __post_init__(self) -> None:
        _as_ints(self, "n", "e")
        if self.n < 2:
            raise ValueError("N must be at least 2")
        if self.e < 2:
            raise ValueError("e must be greater than 1")

    def encrypt(self, m: int) -> int: # c = m^e mod n
        _check_range(m, self.n, "m")
        return int(gmpy2.powmod(m, self.e, self.n))

    def verify_raw(self, m: int, s: int) -> bool: # verify s^e mod N == m, s is private key signed m
        """Raw RSA verification: s^e mod N == m, no hashing or padding."""
        _check_range(m, self.n, "m")
        _check_range(s, self.n, "s")
        return int(gmpy2.powmod(s, self.e, self.n)) == m


@dataclass(frozen=True)
class PrivateKey:
    p: int
    q: int
    e: int
    d: int

    def __post_init__(self) -> None:
        _as_ints(self, "p", "q", "e", "d")
        if self.p == self.q:
            raise ValueError("p and q must be distinct")
        for name in ("p", "q"):
            if not gmpy2.is_prime(getattr(self, name)):
                raise ValueError(f"{name} is not prime")
        if self.e < 2:
            raise ValueError("e must be greater than 1")
        if self.d < 1:
            raise ValueError("d must be positive")
        if self.e * self.d % self.phi != 1:
            raise ValueError("e * d is not 1 mod phi(N)")

    @classmethod
    def from_primes(cls, p: int, q: int, e: int = 65537) -> PrivateKey:
        """Build a key from p, q and e, with d = e^-1 mod phi(N)."""
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            raise ValueError("e is not invertible mod phi(N)")
        return cls(p, q, e, int(gmpy2.invert(e, phi)))

    @classmethod
    def from_primes_and_d(cls, p: int, q: int, d: int) -> PrivateKey:
        """Build a key from p, q and a chosen d, with e = d^-1 mod phi(N)."""
        phi = (p - 1) * (q - 1)
        if gcd(d, phi) != 1:
            raise ValueError("d is not invertible mod phi(N)")
        return cls(p, q, int(gmpy2.invert(d, phi)), d)

    @property
    def n(self) -> int:
        return self.p * self.q

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    def decrypt(self, c: int) -> int:
        n = self.n
        _check_range(c, n, "c")
        return int(gmpy2.powmod(c, self.d, n))

    def sign_raw(self, m: int) -> int:
        """Raw RSA signature m^d mod N, no hashing or padding."""
        n = self.n
        _check_range(m, n, "m")
        return int(gmpy2.powmod(m, self.d, n))

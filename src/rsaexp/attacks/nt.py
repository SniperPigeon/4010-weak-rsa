"""Euclid, CRT, and integer roots used by the textbook-RSA attacks.

These are the Week 6 tools. The broadcast attack is CRT plus an
integer e-th root; the short-secret attack is the root alone.
"""

from __future__ import annotations

import gmpy2


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) with g = gcd(a, b) and a*x + b*y = g.

    Same divisions as Euclid; the coefficients update in the loop
    so a 2048-bit modulus cannot blow the recursion limit.
    """
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def modinv(a: int, n: int) -> int:
    """Inverse of a modulo n. Exists only when gcd(a, n) = 1."""
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"no inverse: gcd({a}, {n}) = {g}")
    return x % n


def crt_pair(a1: int, n1: int, a2: int, n2: int) -> tuple[int, int]:
    """x ≡ a1 (mod n1), x ≡ a2 (mod n2). Week 6, coprime case."""
    g, s, _ = extended_gcd(n1, n2)
    if (a1 - a2) % g:
        raise ValueError("CRT system has no solution")
    modulus = (n1 // g) * n2
    x = (a1 + (a2 - a1) // g * s * n1) % modulus
    return x, modulus


def crt(residues: list[int] | tuple[int, ...], moduli: list[int] | tuple[int, ...]) -> tuple[int, int]:
    """Fold congruences left to right. Returns (x, product)."""
    if len(residues) != len(moduli) or not residues:
        raise ValueError("residues and moduli must be non-empty and the same length")
    x, modulus = residues[0] % moduli[0], moduli[0]
    for residue, mod in zip(residues[1:], moduli[1:]):
        x, modulus = crt_pair(x, modulus, residue % mod, mod)
    return x, modulus


def integer_nth_root(n: int, exp: int) -> tuple[int, bool]:
    """Largest r with r**exp <= n, and whether the power is exact."""
    if n < 0 or exp < 1:
        raise ValueError("n must be non-negative and exp must be positive")
    root, exact = gmpy2.iroot(n, exp)
    return int(root), bool(exact)


def text_to_int(text: str) -> int:
    raw = text.encode("utf-8")
    if not raw:
        raise ValueError("text is empty")
    return int.from_bytes(raw, "big")


def int_to_text(n: int) -> str:
    if n < 0:
        raise ValueError("number must be non-negative")
    length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big").decode("utf-8")

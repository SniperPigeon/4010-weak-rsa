import random

from sage.all import PolynomialRing, Zmod

from rsaexp.attacks.coppersmith import small_roots
from rsaexp.attacks.partial import factor_with_high_p, make_challenge, check
from rsaexp.core.keygen import generate_key, leak_high_bits


def _poly(n):
    return PolynomialRing(Zmod(n), "x", implementation="NTL").gen()


def test_book_example_19_4_2():
    # Galbraith Example 19.4.3: N = 16803551, p~ = 2830, x0 = 7, p = 2837.
    n = 16803551
    x = _poly(n)
    roots = small_roots(2830 + x, X=10, beta=0.45)
    assert 7 in [int(r) for r in roots]


def test_matches_sage_without_epsilon():
    key = generate_key(rng=random.Random(0))
    leak = leak_high_bits(key.p, 700)
    x = _poly(key.n)
    f = leak.approx + x
    mine = sorted(int(r) for r in small_roots(f, X=leak.bound, beta=0.49, epsilon=0.1))
    sage = sorted(int(r) for r in f.small_roots(X=leak.bound, beta=0.49, epsilon=0.1))
    assert mine == sage
    assert key.p - leak.approx in mine


def test_recovers_in_ntl_crash_regime():
    # m = 13 gives a degree-25 LLL polynomial, which crashes Sage's NTL factor.
    ch, key = make_challenge(random.Random(0), leak_bits=1024 - 464)
    got = factor_with_high_p(ch, beta=0.49, epsilon=0.49**2 / (13 - 0.5))
    assert check(got, key)


def test_no_root_returns_empty():
    key = generate_key(rng=random.Random(1))
    leak = leak_high_bits(key.p, 520)  # too few known bits for this lattice
    x = _poly(key.n)
    assert small_roots(leak.approx + x, X=leak.bound, beta=0.5) == []

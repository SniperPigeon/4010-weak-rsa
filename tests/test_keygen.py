import random
from math import gcd
from itertools import combinations

import pytest

from core.keygen import generate_key, generate_key_small_d, generate_prime, leak_high_bits


def test_generate_prime_has_exact_size_and_top_bits():
    rng = random.Random(0)
    for bits in (16, 512, 1024):
        p = generate_prime(bits, rng)
        assert p.bit_length() == bits
        assert p >> (bits - 2) == 0b11


def test_default_key_is_2048_bit_and_works():
    rng = random.Random(1)
    key = generate_key(rng=rng)
    assert key.n.bit_length() == 2048
    assert key.e == 65537
    m = rng.randrange(key.n)
    assert key.decrypt(key.public_key.encrypt(m)) == m


def test_primes_are_balanced_for_wiener():
    key = generate_key(rng=random.Random(2))
    assert min(key.p, key.q) < max(key.p, key.q) < 2 * min(key.p, key.q)


def test_seeded_rng_is_reproducible():
    assert generate_key(rng=random.Random(42)) == generate_key(rng=random.Random(42))
    assert generate_key(rng=random.Random(42)) != generate_key(rng=random.Random(43))


def test_small_e_key():
    key = generate_key(e=3, rng=random.Random(3))
    assert key.n.bit_length() == 2048
    assert gcd(3, key.phi) == 1


def test_even_e_rejected():
    with pytest.raises(ValueError):
        generate_key(e=4)


def test_small_d_key():
    key = generate_key_small_d(500, rng=random.Random(4))
    assert key.n.bit_length() == 2048
    assert key.d.bit_length() == 500
    assert key.e.bit_length() > 1900  # e is essentially random mod phi


def test_broadcast_moduli_are_pairwise_coprime():
    rng = random.Random(5)
    keys = [generate_key(e=3, rng=rng) for _ in range(3)]
    assert all(gcd(a.n, b.n) == 1 for a, b in combinations(keys, 2))


@pytest.mark.parametrize("known_bits", [1, 512, 600, 1024])
def test_leak_high_bits(known_bits):
    p = generate_key(rng=random.Random(6)).p
    leak = leak_high_bits(p, known_bits)
    assert leak.known_bits + leak.unknown_bits == p.bit_length()
    assert leak.high.bit_length() == known_bits
    assert leak.approx <= p < leak.approx + leak.bound


@pytest.mark.parametrize("known_bits", [0, 1025])
def test_leak_high_bits_rejects_bad_size(known_bits):
    with pytest.raises(ValueError):
        leak_high_bits(generate_prime(1024, random.Random(7)), known_bits)

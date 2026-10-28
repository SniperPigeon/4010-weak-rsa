import pytest

from core.rsa import PrivateKey, PublicKey

# Classic textbook example: p = 61, q = 53, phi = 3120, e = 17, d = 2753.
P, Q, E, D = 61, 53, 17, 2753


def test_from_primes_textbook_example():
    key = PrivateKey.from_primes(P, Q, E)
    assert key.d == D
    assert key.n == 3233
    assert key.public_key == PublicKey(3233, 17)
    assert key.public_key.encrypt(65) == 2790
    assert key.decrypt(2790) == 65


def test_from_primes_and_d_recovers_e():
    assert PrivateKey.from_primes_and_d(P, Q, D).e == E


def test_tutorial_8_example():
    # Tutorial 8 Q2: p = 11, q = 13, e = 7, d = 103.
    key = PrivateKey.from_primes(11, 13, 7)
    assert key.d == 103
    assert all(key.decrypt(key.public_key.encrypt(m)) == m for m in range(key.n))


def test_raw_sign_and_verify():
    key = PrivateKey.from_primes(P, Q, E)
    s = key.sign_raw(123)
    assert key.public_key.verify_raw(123, s)
    assert not key.public_key.verify_raw(124, s)


def test_weak_parameters_are_allowed():
    # e = 3, a tiny modulus, and e larger than phi are all mathematically valid.
    assert PrivateKey.from_primes(11, 17, 3).d == 107
    assert PrivateKey.from_primes(P, Q, E + 3120).d == D


@pytest.mark.parametrize(
    "p, q, e",
    [
        (61, 61, 17),  # equal primes
        (15, 53, 17),  # composite p
        (61, 53, 3),  # 3 divides phi = 3120
    ],
)
def test_from_primes_rejects_invalid(p, q, e):
    with pytest.raises(ValueError):
        PrivateKey.from_primes(p, q, e)


def test_inconsistent_exponents_rejected():
    with pytest.raises(ValueError):
        PrivateKey(P, Q, E, D + 1)


def test_from_primes_and_d_rejects_non_invertible_d():
    with pytest.raises(ValueError):
        PrivateKey.from_primes_and_d(P, Q, 3)


@pytest.mark.parametrize("m", [-1, 3233, 5000])
def test_inputs_must_be_in_range(m):
    key = PrivateKey.from_primes(P, Q, E)
    with pytest.raises(ValueError):
        key.public_key.encrypt(m)
    with pytest.raises(ValueError):
        key.decrypt(m)
    with pytest.raises(ValueError):
        key.sign_raw(m)


def test_public_key_rejects_trivial_exponent():
    with pytest.raises(ValueError):
        PublicKey(3233, 1)

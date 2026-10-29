# Partial Key Exposure Attacks
import random
from typing import NamedTuple

from sage.all import Integer, continued_fraction, PolynomialRing, Zmod, inverse_mod
from rsaexp.core.keygen import generate_key,HighBitsLeak,leak_high_bits
from rsaexp.core.rsa import PrivateKey, PublicKey

class PExposureChallenge(NamedTuple):
    pub: PublicKey
    leak: HighBitsLeak

# coppersmith with beta around 0.5
def factor_with_high_p(challenge: PExposureChallenge,beta:float,epsilon:float) -> PrivateKey | None:
    pub = challenge.pub
    leak = challenge.leak
    highp = Integer(leak.approx)
    unknown = Integer(leak.unknown_bits)
    n = Integer(pub.n)
    ring = PolynomialRing(Zmod(n),"x",implementation="NTL")
    x = ring.gen()
    f = leak.approx + x
    
    for x0 in f.small_roots(X=leak.bound, beta=beta, epsilon=epsilon):
        p = Integer(f(x0))                  # convert to int
        if 1 < p < n and n % p == 0:
            return PrivateKey.from_primes(int(p), int(n // p), pub.e)
    return None



def make_challenge(rng: random.Random, leak_bits: int = 700, bits: int = 2048) -> tuple[PExposureChallenge, PrivateKey]:
    """A key with a ``d_bits``-bit d: the attacker gets (N, e), the truth is the key."""
    key = generate_key(bits=bits, rng=rng)
    leak = leak_high_bits(key.p,leak_bits)
    return PExposureChallenge(key.public_key, leak), key


def check(guess: PrivateKey | None, truth: PrivateKey) -> bool:
    # p and q may come back swapped, so compare d and N rather than the keys.
    return guess is not None and guess.d == truth.d and guess.n == truth.n
    
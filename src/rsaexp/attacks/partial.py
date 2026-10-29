# Partial Key Exposure Attacks
import random
from typing import NamedTuple

from sage.all import Integer, continued_fraction, PolynomialRing, Zmod, inverse_mod, power_mod
from rsaexp.core.keygen import generate_key,HighBitsLeak,leak_high_bits,StereotypedMsg,obtain_stereotype
from rsaexp.core.rsa import PrivateKey, PublicKey
from rsaexp.attacks.coppersmith import small_roots

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
    ring = PolynomialRing(Zmod(n),"x")
    x = ring.gen()
    f = leak.approx + x
    
    for x0 in small_roots(f, X=leak.bound, beta=beta, epsilon=epsilon):
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


class StereotypeChallenge(NamedTuple):
    pub: PublicKey
    leak: StereotypedMsg
    cipher: int

def steorotyped_recover(challenge: StereotypeChallenge, beta:float, epsilon:float|None=None) -> int | None: # return recovered message

    pub = challenge.pub
    e = Integer(pub.e)
    known = Integer(challenge.leak.approx)
    unknown_bits = Integer(challenge.leak.unknown_bits)
    c = Integer(challenge.cipher)
    n = Integer(pub.n)
    ring = PolynomialRing(Zmod(n),"x")
    x = ring.gen()

    f = (known + x) ** e - c # solution is the lower part of message.
    f = f.monic()
    roots = small_roots(f, X=2**unknown_bits, beta=beta, epsilon=epsilon)
    if roots:
        full_root = int(known + roots[0])
        if power_mod(full_root,n=e,m=n) == int(c): # pass root test
            return int(known + roots[0])
        else:
            return None
    else:
        return None


def make_steorotype_challenge(rng: random.Random, e: int = 3, unknown_bits: int = 60, bits: int = 2048, msg_bits: int = 1024) -> tuple[ StereotypeChallenge, int]:
    """A key with a ``d_bits``-bit d: the attacker gets (N, e), the truth is the key."""
    key = generate_key(e=e,bits=bits, rng=rng)
    pub = key.public_key
    # m = rng.randint(1<<msg_bits,1<<(msg_bits+1)) wrong approach, get 513 bits.
    m = rng.getrandbits(msg_bits) | 1<<(msg_bits-1)
    assert m.bit_length() == msg_bits
    cipher = pub.encrypt(m)
    
    return StereotypeChallenge(pub=key.public_key, leak=
                               obtain_stereotype(m=m,known_bits=msg_bits-unknown_bits),
                               cipher=cipher), m


def check_sterotype(guess: int | None, truth: int) -> bool:
    # p and q may come back swapped, so compare d and N rather than the keys.
    return guess is not None and guess == truth

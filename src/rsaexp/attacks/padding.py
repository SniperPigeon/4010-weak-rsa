"""Paddings for the textbook-RSA experiments.

Linear padding is a public format, the same for every encryption, so
Håstad still recovers the padded integer and then unpads. Random
padding (and OAEP) uses a fresh seed each time, so the broadcast
equations are no longer about one common message.

OAEP is RSAES-OAEP with SHA-256 from pycryptodome; ``rng`` supplies the
seed so a trial stays reproducible.
"""

from __future__ import annotations

import random

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from rsaexp.core.rsa import PrivateKey, PublicKey


def linear_pad(m: int, a: int = 256, b: int = 17) -> int:
    """Public affine format m' = a*m + b. Same a, b for every recipient."""
    if a < 1:
        raise ValueError("a must be positive")
    return a * m + b


def linear_unpad(padded: int, a: int = 256, b: int = 17) -> int | None:
    if a < 1 or padded < b or (padded - b) % a:
        return None
    return (padded - b) // a


def random_pad(m: int, msg_bits: int, pad_bits: int, rng: random.Random) -> int:
    """m' = r || m with a fresh r. Owner recovers m by masking msg_bits."""
    if pad_bits < 1 or msg_bits < 1:
        raise ValueError("pad_bits and msg_bits must be positive")
    r = rng.getrandbits(pad_bits) | (1 << (pad_bits - 1))
    return (r << msg_bits) | (m & ((1 << msg_bits) - 1))


def random_unpad(padded: int, msg_bits: int) -> int:
    return padded & ((1 << msg_bits) - 1)


def oaep_encrypt(pub: PublicKey, message: bytes, rng: random.Random) -> int:
    """RSAES-OAEP (SHA-256) ciphertext of ``message`` as an integer."""
    cipher = PKCS1_OAEP.new(RSA.construct((pub.n, pub.e)), hashAlgo=SHA256, randfunc=rng.randbytes)
    return int.from_bytes(cipher.encrypt(message), "big")


def oaep_decrypt(key: PrivateKey, c: int) -> bytes:
    """Inverse of ``oaep_encrypt``. Raises ValueError on a malformed ciphertext."""
    rsa_key = RSA.construct((key.n, key.e, key.d, key.p, key.q))
    k = (key.n.bit_length() + 7) // 8
    return PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256).decrypt(c.to_bytes(k, "big"))

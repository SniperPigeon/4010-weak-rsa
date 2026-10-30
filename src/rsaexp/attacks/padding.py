"""Paddings for the textbook-RSA experiments.

Linear padding is a public format, the same for every encryption, so
Håstad still recovers the padded integer and then unpads. Random
padding (and OAEP) uses a fresh seed each time, so the broadcast
equations are no longer about one common message.
"""

from __future__ import annotations

import hashlib
import random


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


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def mgf1(seed: bytes, length: int) -> bytes:
    """PKCS#1 MGF1 with SHA-256."""
    hlen = hashlib.sha256().digest_size
    out = bytearray()
    for counter in range((length + hlen - 1) // hlen):
        out.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
    return bytes(out[:length])


def oaep_encode(message: bytes, k: int, rng: random.Random, label: bytes = b"") -> int:
    """RSAES-OAEP encode to an integer < 256^(k-1). ``k`` is the byte length of N."""
    hlen = 32
    if k < 2 * hlen + 2:
        raise ValueError("modulus too short for OAEP")
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("message too long for this modulus")
    lhash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = rng.getrandbits(hlen * 8).to_bytes(hlen, "big")
    masked_db = _xor(db, mgf1(seed, k - hlen - 1))
    masked_seed = _xor(seed, mgf1(masked_db, hlen))
    return int.from_bytes(b"\x00" + masked_seed + masked_db, "big")


def oaep_decode(em: int, k: int, label: bytes = b"") -> bytes:
    """Inverse of ``oaep_encode``. Raises ValueError on a malformed encoding."""
    hlen = 32
    data = em.to_bytes(k, "big")
    if data[0] != 0:
        raise ValueError("OAEP decode failed")
    masked_seed, masked_db = data[1 : 1 + hlen], data[1 + hlen :]
    seed = _xor(masked_seed, mgf1(masked_db, hlen))
    db = _xor(masked_db, mgf1(seed, k - hlen - 1))
    lhash = hashlib.sha256(label).digest()
    if db[:hlen] != lhash:
        raise ValueError("OAEP decode failed")
    rest = db[hlen:]
    try:
        sep = rest.index(1)
    except ValueError as exc:
        raise ValueError("OAEP decode failed") from exc
    if any(rest[:sep]):
        raise ValueError("OAEP decode failed")
    return rest[sep + 1 :]


def modulus_bytes(n: int) -> int:
    return (n.bit_length() + 7) // 8

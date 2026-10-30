"""Panshul's half: textbook RSA, e=3 broadcast, and why random padding stops it.

Run from the repository root:

    uv run python experiments/panshul_demo.py
"""

import random

from rsaexp.attacks.hastad import (
    PADDING_OAEP,
    PADDING_RANDOM,
    HastadChallenge,
    hastad_broadcast,
    make_challenge as make_hastad,
)
from rsaexp.attacks.padding import linear_pad, oaep_decrypt, oaep_encrypt
from rsaexp.attacks.short_secret import ShortSecretChallenge, multiply_ciphertext, short_secret
from rsaexp.core.keygen import generate_key
from rsaexp.core.rsa import PublicKey


def text_to_int(text: str) -> int:
    return int.from_bytes(text.encode(), "big")


def int_to_text(n: int) -> str:
    return n.to_bytes((n.bit_length() + 7) // 8, "big").decode()


if __name__ == "__main__":
    rng = random.Random(4010)
    message = "Pay Alice 100"
    m = text_to_int(message)
    # Håstad needs m^3 to wrap each 2048-bit N, so m must exceed ~683 bits.
    long_message = (
        "Card 4010-0001: transfer 100 SGD from Alice to Bob, "
        "session token 7f3a9c2e5b1d4086, issued 2026-10-30"
    )
    long_m = text_to_int(long_message)

    print("1. Textbook RSA, one 2048-bit key, e = 3, no padding")
    key = generate_key(e=3, rng=rng)
    c = key.public_key.encrypt(m)
    print(f"   encrypt({message!r}) = {c.bit_length()}-bit ciphertext")
    print(f"   owner decrypts: {int_to_text(key.decrypt(c))!r}")

    print("2. Short secret: m^e < N, so c is the integer cube and we take a cube root")
    guess = short_secret(ShortSecretChallenge(key.public_key, c))
    print(f"   cube root of c: {int_to_text(guess)!r}" if guess is not None else "   failed")

    print("3. Malleability: from c we build a ciphertext of 2m, no private key")
    c2 = multiply_ciphertext(key.public_key, c, 2)
    print(f"   decrypt(c * 2^e) = {key.decrypt(c2)} = 2 * {m}")

    print(f"4. Hastad: a {long_m.bit_length()}-bit m, e = 3, three 2048-bit recipients, no padding")
    keys = [generate_key(e=3, rng=rng) for _ in range(3)]
    ciphertexts = tuple(k.public_key.encrypt(long_m) for k in keys)
    moduli = tuple(k.n for k in keys)
    alone = short_secret(ShortSecretChallenge(keys[0].public_key, ciphertexts[0]))
    print(f"   m^3 wraps N, so one cube root fails: {alone is None}")
    recovered = hastad_broadcast(HastadChallenge(3, ciphertexts, moduli))
    print(f"   CRT + cube root: {int_to_text(recovered)!r}")

    print("5. Same broadcast, public linear padding m' = 256 m + 17 - still breaks")
    padded = linear_pad(long_m, 256, 17)
    ciphertexts = tuple(k.public_key.encrypt(padded) for k in keys)
    recovered = hastad_broadcast(HastadChallenge(3, ciphertexts, moduli, 256, 17))
    print(f"   CRT + cube root + unpad: {int_to_text(recovered)!r}")

    print("6. Fresh random padding on each ciphertext - broadcast returns nothing")
    ch, _ = make_hastad(random.Random(2), padding=PADDING_RANDOM)
    print(f"   recovered nothing: {hastad_broadcast(ch) is None}")
    alone = short_secret(ShortSecretChallenge(PublicKey(ch.moduli[0], ch.e), ch.ciphertexts[0]))
    print(f"   r || m fills N, so one cube root fails too: {alone is None}")

    print("7. OAEP with a new seed each time - broadcast returns nothing")
    ch, _ = make_hastad(random.Random(3), padding=PADDING_OAEP)
    print(f"   recovered nothing: {hastad_broadcast(ch) is None}")

    print("8. OAEP is still decryptable by the owner of d")
    oaep_key = generate_key(e=3, rng=rng)
    c_oaep = oaep_encrypt(oaep_key.public_key, message.encode(), rng)
    plain = oaep_decrypt(oaep_key, c_oaep)
    print(f"   owner reads: {plain.decode()!r}")

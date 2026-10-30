"""Panshul's half: textbook RSA, e=3 broadcast, and why random padding stops it.

Run from the repository root:

    uv run python examples/panshul_demo.py
"""

import random

from rsaexp.attacks.hastad import (
    PADDING_LINEAR,
    PADDING_OAEP,
    PADDING_RANDOM,
    HastadChallenge,
    hastad_broadcast,
    make_challenge as make_hastad,
)
from rsaexp.attacks.nt import int_to_text, text_to_int
from rsaexp.attacks.padding import modulus_bytes, oaep_decode, oaep_encode
from rsaexp.attacks.short_secret import ShortSecretChallenge, multiply_ciphertext, short_secret
from rsaexp.core.keygen import generate_key

if __name__ == "__main__":
    rng = random.Random(4010)
    message = "Pay Alice 100"
    m = text_to_int(message)

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

    print("4. Hastad: same m, e = 3, three 2048-bit recipients, no padding")
    keys = [generate_key(e=3, rng=rng) for _ in range(3)]
    ciphertexts = tuple(k.public_key.encrypt(m) for k in keys)
    moduli = tuple(k.n for k in keys)
    recovered = hastad_broadcast(HastadChallenge(3, ciphertexts, moduli))
    print(f"   CRT + cube root: {int_to_text(recovered)!r}")

    print("5. Same broadcast, public linear padding m' = 256 m + 17 - still breaks")
    ch, truth = make_hastad(random.Random(1), padding=PADDING_LINEAR, msg_bits=m.bit_length())
    got = hastad_broadcast(ch)
    print(f"   recovered the integer message: {got == truth}")

    print("6. Fresh random padding on each ciphertext - broadcast returns nothing")
    ch, _ = make_hastad(random.Random(2), padding=PADDING_RANDOM)
    print(f"   recovered nothing: {hastad_broadcast(ch) is None}")

    print("7. OAEP with a new seed each time - broadcast returns nothing")
    ch, _ = make_hastad(random.Random(3), padding=PADDING_OAEP)
    print(f"   recovered nothing: {hastad_broadcast(ch) is None}")

    print("8. OAEP is still decryptable by the owner of d")
    oaep_key = generate_key(e=3, rng=rng)
    padded = oaep_encode(message.encode(), modulus_bytes(oaep_key.n), rng)
    c_oaep = oaep_key.public_key.encrypt(padded)
    plain = oaep_decode(oaep_key.decrypt(c_oaep), modulus_bytes(oaep_key.n))
    print(f"   owner reads: {plain.decode()!r}")

# SC4010 Cryptography Team Project

Simulate a smart-card system using 2048-bit RSA for authentication and encrypted
data delivery. Demonstrate message recovery, then private-key recovery.

## Scope

- Short secrets: small `e`, no padding, and `m^e < N`; recover by an integer root.
- Håstad: the same message and exponent across enough pairwise-coprime moduli.
- Generalized Håstad: different small exponents across pairwise-coprime moduli, with enough ciphertexts to meet the recovery bounds; may use polynomial CRT and Coppersmith.
- Wiener: recover the private key when `d` is sufficiently small.
- Known-format Coppersmith: recover a short unknown field inside a known message format.
- Partial key exposure: recover factors from known contiguous high bits of `p` and a sufficiently small unknown suffix.

For the first three topics, optionally demonstrate attacks on fixed and known
linear padding where the attack conditions hold, then compare with OAEP using
fresh randomness for each encryption. OAEP also addresses the known-format
message attack; it does not repair weak or partially exposed private keys.

Optional extensions: low-entropy prime generation / seed enumeration, and
repeated-prime GCD attacks.

## Todo

- [x] Build the RSA core and correctness tests; allow weak parameters while checking mathematical validity.
- [ ] Add reproducible experiment generators; separate attacker inputs from private ground truth.
- [ ] short secrets, Håstad, generalized Håstad, and Wiener; share the small-root backend where needed.
- [ ] known-format Coppersmith and partial key exposure.
- [ ] Run 2048-bit demos, optional padding variants, and OAEP comparisons; record correctness and runtime.

Reuse `gmpy2`, `sympy`, and `fpylll`; use SageMath for reference checks.
Review algorithm changes before implementation.

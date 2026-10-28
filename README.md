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

## Adding an attack

Each attack lives in `src/rsaexp/attacks/<name>.py` and exposes module-level
functions that plug into `rsaexp.core.experiment.run_campaign`:

```python
def attack(challenge) -> guess | None          # e.g. wiener_cf; public data only
def make_challenge(rng, **params) -> tuple[challenge, truth]
def check(guess, truth) -> bool                # optional; run_campaign defaults to ==
```

- The attack only sees the challenge: public keys, ciphertexts, leaked bits.
  It returns `None` when it does not succeed and raises only on bugs, which
  count as `error`.
- `make_challenge` builds everything with `rsaexp.core.keygen` from the given
  `rng`, so each trial is reproducible from its seed. Parameters such as the
  size of `d` are keyword arguments with defaults, swept with `functools.partial`.
- `truth` is the private data the guess is scored against; it never reaches
  the attack.
- With `timeout`, attacks run in a spawned worker process, so keep these
  functions at module level and their inputs and outputs picklable. Modules
  that import Sage take about 2 s to load in each worker; this is not counted
  against the timeout.

```python
from functools import partial

from rsaexp.attacks.wiener import check, make_challenge, wiener_cf
from rsaexp.core.experiment import run_campaign

if __name__ == "__main__":
    campaign = run_campaign(
        partial(make_challenge, d_bits=510), wiener_cf, 50, seed=0, check=check, timeout=30
    )
    print(campaign)  # 50 trials (seed 0): success 100.0%, failure 0.0%, ...
```

Every trial records its seed; rebuild one with
`make_challenge(random.Random(trial.seed))`. Example scripts live in
`examples/` and need the `__main__` guard because of the spawned worker:

```sh
uv run python examples/wiener_sweep.py
```

## Todo

- [x] Build the RSA core and correctness tests; allow weak parameters while checking mathematical validity.
- [x] Add reproducible experiment generators; separate attacker inputs from private ground truth.
- [ ] short secrets, Håstad, generalized Håstad, and Wiener; share the small-root backend where needed.
- [x] CF version Wiener
- [ ] Hastad broadcasting, (optional generalized Hastad with different e-s, using extended CRT)
- [ ] known-format Coppersmith and partial key exposure.
- [ ] Run 2048-bit demos, optional padding variants, and OAEP comparisons; record correctness and runtime.

Reuse `gmpy2`, `sympy`, `fpylll`, and SageMath; attacks may use Sage directly
(continued fractions, lattices).
Review algorithm changes before implementation.

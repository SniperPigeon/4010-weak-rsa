"""Wiener's attack on 2048-bit keys as d grows past the N^(1/4) / 3 bound (~510 bits).

Run from the repository root: uv run python examples/wiener_sweep.py
"""

import random
from functools import partial

from rsaexp.attacks.wiener import check, make_challenge, wiener_cf
from rsaexp.core.experiment import run_campaign

if __name__ == "__main__":
    # One trial by hand: the attacker only ever sees the public key.
    pub, truth = make_challenge(random.Random(0), d_bits=500)
    key = wiener_cf(pub)
    print(f"recovered d ({key.d.bit_length()} bits) matches: {check(key, truth)}")

    for d_bits in (500, 508, 510, 512, 514, 516, 520):
        campaign = run_campaign(
            partial(make_challenge, d_bits=d_bits),
            wiener_cf,
            50,
            seed=0,
            check=check,
            timeout=30,
        )
        print(f"d_bits={d_bits}: {campaign}")

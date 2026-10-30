"""Håstad e=3 broadcast vs padding, 2048-bit moduli.

Run from the repository root: uv run python experiments/hastad_demo.py
"""

from functools import partial
from rsaexp.attacks.hastad import (
    PADDING_LINEAR,
    PADDING_NONE,
    PADDING_OAEP,
    PADDING_RANDOM,
    check,
    hastad_broadcast,
    make_challenge,
)
from rsaexp.core.experiment import run_campaign

if __name__ == "__main__":
    for padding in (PADDING_NONE, PADDING_LINEAR, PADDING_RANDOM, PADDING_OAEP):
        campaign = run_campaign(
            partial(make_challenge, padding=padding),
            hastad_broadcast,
            5,
            seed=0,
            check=check,
            timeout=60,
        )
        print(f"padding={padding}: {campaign}")

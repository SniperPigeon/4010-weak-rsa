"""Stereotyped-message Coppersmith on 2048-bit keys: sweep unknown low bits and lattice parameter m for e = 3, 5, 7.

Run from the repository root: uv run python experiments/stereotyped.py
"""

import random
from functools import partial
from math import ceil

from rsaexp.attacks.partial import *
from rsaexp.core.experiment import run_campaign
from rsaexp.core.keygen import StereotypedMsg


def min_m(e, unknown_bits):
    # smallest m whose bound (m-1)/(e*m-1)*2048 reaches unknown_bits; None past N^(1/e)
    if e * unknown_bits >= 2048:
        return None
    return max(ceil(7 / e), ceil((2048 - unknown_bits) / (2048 - e * unknown_bits)))


if __name__ == "__main__":
    # One 128 bit unknown simple trial
    challenge, truth = make_steorotype_challenge(random.Random(0), e=7,unknown_bits=64,msg_bits=512)
    
    msg = steorotyped_recover(challenge=challenge,beta=0.99)
    if msg is not None:
        print(f"recovered msg matches: {check_sterotype(msg, truth)}")
    else:
        print("No solution")
    beta = 1
    e = 3
    grid = [
        (3, [128, 384, 512, 560, 600, 630]),
        (5, [128, 228, 290, 320, 340]),
        (7, [96, 158, 205, 230]),
    ]
    for line in grid:
        e = line[0]
        for unknown_bits in line[1]:
            '''
            when e =3, the theoretical upper bound for unknown bits is N^(1/e) approx eq. to 682bits
            e   upperbound
            3   682
            5   409
            7   292
            17  120
            
            However we obtained several actual limit, without adjusting epsilon for LLL
            e   tested  default m   dim     bound for (m-1)/(em-1) *2048
            3   516/512     3       9           512
            5   230         2       10          228
            7   164         2       14          158
            
            Thus we need to adjust epsilon, go with LLL with higher dimensions before proceeding to bigger e.
            '''
            m0 = min_m(e, unknown_bits)
            if m0 is None:  # past N^(1/e), no lattice reaches it
                print(f"unknown_bits:{unknown_bits}, public key e = {e} : beyond N^(1/e), skipped")
                continue
            # only sweep m around the one that first works, so small unknowns skip big lattices
            for m_dim in range(max(ceil(7 / e), m0 - 1), m0 + 2):
                epsilon = beta**2 / (e * m_dim)
                campaign = run_campaign(
                    partial(make_steorotype_challenge, e=e,unknown_bits=unknown_bits,msg_bits=1024),
                    partial(steorotyped_recover, beta=beta, epsilon=epsilon),
                    50,
                    seed=114514,
                    check=check_sterotype,
                    timeout=30,
                    workers=10
                )
                worst = round((m_dim - 1) / (e * m_dim - 1) * 2048)
                print(f"unknown_bits:{unknown_bits}, e={e}, m={m_dim}, dim={e*m_dim} (bound {worst}): {campaign}")
        

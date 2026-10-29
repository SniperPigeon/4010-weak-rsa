"""Wiener's attack on 2048-bit keys as d grows past the N^(1/4) / 3 bound (~510 bits).

Run from the repository root: uv run python examples/wiener_sweep.py
"""

import random
from functools import partial

from rsaexp.attacks.partial import *
from rsaexp.core.experiment import run_campaign
from rsaexp.core.keygen import StereotypedMsg

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
        (3, [128, 256,384, 480, 500, 504, 506, 510, 512, 516, 520, 530, 670,]),
        (5, [128,196,202, 210, 218, 224, 230, 236, 242, 256, 312,]),
        (7, [96, 156, 160, 164, 172, 176, 180]),
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
            '''
            #epsilon = beta**2 / (m_dim-0.5)
            campaign = run_campaign(
                partial(make_steorotype_challenge, e=e,unknown_bits=unknown_bits,msg_bits=1024),
                partial(steorotyped_recover, beta=beta,),
                50,
                seed=114514,
                check=check_sterotype,
                timeout=30,
                workers=10
            )
            # print(f"leaked_bits={leaked} with beta={beta}, lattice dimension= {m_dim}, epsilon={epsilon:.2f}: {campaign}")
            print(f"unknown_bits:{unknown_bits}, public key e = {e} : {campaign}")
        

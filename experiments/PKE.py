"""
Run from the repository root: uv run python examples/PKE.py
"""

import random
from functools import partial

from rsaexp.attacks.partial import *
from rsaexp.core.experiment import run_campaign
from rsaexp.core.keygen import HighBitsLeak,StereotypedMsg

if __name__ == "__main__":
    # One 128 bit unknown simple trial
    challenge, truth = make_challenge(random.Random(0), leak_bits=800)
    pub, leak = challenge
    
    key = factor_with_high_p(PExposureChallenge(pub,leak), beta=0.49,epsilon=4)
    if key is not None:
        print(f"recovered d ({key.d.bit_length()} bits) matches: {check(key, truth)}")
    else:
        print("No solution")

    beta = 0.49
    for leaked in (560, 530, 512, 510):
        for m_dim in (4,6,10,13,25):
            '''
            To recover unknown bits from lattice constructions, we should satisfy det(bf) < M / sqrt(d+1)
            where we have
            det^(1/n) < p^m ≈ N^(m/2), to solve:
            
            X < N^((m−1)/(2(2m−1)))
            maximal unknown = 512 - 512/(2m-1)
            '''
            epsilon = beta**2 / (m_dim-0.5)
            campaign = run_campaign(
                partial(make_challenge, leak_bits=leaked),
                partial(factor_with_high_p, beta=beta,epsilon=epsilon),
                50,
                seed=0,
                check=check,
                timeout=30,
                workers=5
            )
            print(f"leaked_bits={leaked} with beta={beta}, lattice dimension= {m_dim}, epsilon={epsilon:.2f}: {campaign}")
        

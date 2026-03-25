import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import numpy as np
from phoenix.election import PhoenixElection
from phoenix.params import BFVParams, ZKPParams, FHSParams
from benchmarks.timer import time_function


def run_benchmark_for_k(k: int, repetitions: int = 1) -> float:
    bfv_p = BFVParams(poly_modulus_degree=4096, plain_modulus=1032193)
    zkp_p = ZKPParams(module_rank=4, ring_degree=64, log_modulus=32, security_bits=128)
    fhs_p = FHSParams(n=64, log_q=22, d_max=30, security_bits=128)

    election = PhoenixElection(bfv_params=bfv_p, zkp_params=zkp_p, fhs_params=fhs_p)
    election.setup()

    voter_id = "voter_bench_0"
    election.register(voter_id)

    times = []
    for _ in range(repetitions):
        start = time.perf_counter()
        _benchmark_vote_ops(election, voter_id, k)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    return float(np.mean(times))


def _benchmark_vote_ops(election: PhoenixElection, voter_id: str, k: int):
    # encrypt + sign + prove for k-bit payload
    from phoenix.core.vote import PhoenixVote
    from phoenix.zkp.system import ZKPSystem
    from phoenix.fhs.scheme import FHSScheme
    import tenseal as ts

    state = election._state
    context = state["bfv_context"]
    pp = state["pp"]
    fhs: FHSScheme = state["fhs"]
    cred = election._credentials[voter_id]
    upk = cred["upk"]
    usk = cred["usk"]

    for bit_idx in range(k):
        vote_value = bit_idx % 2
        enc = ts.bfv_vector(context, [vote_value])
        ct_bytes = enc.serialize()

        zkp_sys = ZKPSystem(pp=pp)
        sigma = zkp_sys.prove(
            statement={"ciphertext": ct_bytes},
            witness={"plaintext": vote_value},
        )

        payload = (ct_bytes, sigma)
        _ = fhs.sign(usk, upk, voter_id, payload, bit_idx)
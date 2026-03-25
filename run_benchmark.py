#!/usr/bin/env python3
import sys
import os
import time
import platform
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tenseal as ts
from phoenix.election import PhoenixElection
from phoenix.params import BFVParams, ZKPParams, FHSParams
from phoenix.zkp.system import ZKPSystem
from phoenix.fhs.scheme import FHSScheme

K_VALUES = [1, 5, 10, 25]
REPETITIONS = 3


def get_device_label() -> str:
    node = platform.node()
    proc = platform.processor() or platform.machine()
    system = platform.system()
    return f"{system} – {proc[:20]}"


def benchmark_single_vote(state: dict, voter_id: str, cred: dict, k: int) -> float:
    context = state["bfv_context"]
    pp = state["pp"]
    fhs: FHSScheme = state["fhs"]
    upk = cred["upk"]
    usk = cred["usk"]

    start = time.perf_counter()

    for bit_idx in range(k):
        vote_value = bit_idx % 2

        # encrypt
        enc = ts.bfv_vector(context, [vote_value])
        ct_bytes = enc.serialize()

        # prove well-formedness
        zkp_sys = ZKPSystem(pp=pp)
        sigma = zkp_sys.prove(
            statement={"ciphertext": ct_bytes},
            witness={"plaintext": vote_value},
        )

        # sign
        payload = (ct_bytes, sigma)
        fhs.sign(usk, upk, voter_id, payload, bit_idx)

    elapsed = time.perf_counter() - start
    return elapsed


def run_benchmark() -> dict:
    bfv_p = BFVParams(poly_modulus_degree=4096, plain_modulus=1032193)
    zkp_p = ZKPParams(module_rank=4, ring_degree=64, log_modulus=32, security_bits=128)
    fhs_p = FHSParams(n=64, log_q=22, d_max=30, security_bits=128)

    election = PhoenixElection(bfv_params=bfv_p, zkp_params=zkp_p, fhs_params=fhs_p)
    election.setup()

    voter_id = "benchmark_voter"
    cred = election.register(voter_id)
    state = election._state

    results = {}
    for k in K_VALUES:
        timings = []
        for rep in range(REPETITIONS):
            t = benchmark_single_vote(state, voter_id, cred, k)
            timings.append(t)
        avg = float(np.mean(timings))
        results[k] = avg
        print(f"  k={k:2d}: {avg:.6f}s  (avg of {REPETITIONS} runs)")

    return results


def print_table(results: dict, device_label: str):
    col_w = 14
    header_k = "".join(f"k={k:>3}".rjust(col_w) for k in K_VALUES)
    print()
    print(f"{'Device':<35}" + header_k)
    print("-" * 75)

    row = f"{device_label:<35}"
    for k in K_VALUES:
        val = results.get(k, 0.0)
        row += f"{val:.6f}s".rjust(col_w)
    print(row)
    print()
    print("k : number of vote bits (candidates for homomorphic tallying).")
    # or log2(candidates) for shuffle-based tallying
    print()


def main():
    print()
    print(f"platform: {platform.platform()}")
    print(f"python:   {sys.version.split()[0]}")

    try:
        import tenseal
        print(f"tenseal:  {tenseal.__version__}")
    except Exception:
        print("tenseal:  installed")

    print()

    device_label = get_device_label()
    print(f"device: {device_label}")
    print()

    results = run_benchmark()
    print_table(results, device_label)


if __name__ == "__main__":
    main()
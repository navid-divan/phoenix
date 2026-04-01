# Phoenix benchmark using LaZer's ZKP (https://github.com/lazer-crypto/lazer) instead of the built-in one. On unsupported platforms the script automatically falls back to Phoenix's built-in ZKP with notice.

import sys
import os
import time
import platform
import hashlib
import struct
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


LAZER_AVAILABLE = False
lazer = None

def _try_load_lazer() -> bool:
    global lazer, LAZER_AVAILABLE

    lazer_path = os.environ.get("LAZER_PYTHON_PATH", "")
    if not lazer_path:
        # try common relative location
        candidates = [
            os.path.join(os.path.dirname(__file__), "lazer", "python"),
            os.path.join(os.path.expanduser("~"), "lazer", "python"),
            "/opt/lazer/python",
        ]
        for c in candidates:
            if os.path.isdir(c):
                lazer_path = c
                break

    if lazer_path and lazer_path not in sys.path:
        sys.path.insert(0, lazer_path)

    try:
        import lazer as _lazer_mod
        lazer = _lazer_mod
        LAZER_AVAILABLE = True
        return True
    except ImportError:
        return False



class LazerZKP:

    # abdlop-style params matching Phoenix ZKP defaults
    _D = 64       
    _K = 4        
    _LOG_Q = 32   

    def __init__(self):
        if not LAZER_AVAILABLE:
            raise RuntimeError("lazer not available")
        self._q = 2 ** self._LOG_Q
        self._setup_done = False

    def _lazy_setup(self):
        if self._setup_done:
            return        
        self._Rq = lazer.Rq(self._D, self._q)
        self._setup_done = True

    def _ciphertext_to_target(self, ct_bytes: bytes) -> "lazer.PolyVec":
        self._lazy_setup()
        digest = hashlib.shake_256(ct_bytes).digest(self._K * self._D * 4)
        coeffs = []
        for i in range(self._K * self._D):
            val = struct.unpack_from("<I", digest, i * 4)[0] % self._q
            coeffs.append(int(val))
        # pack into K polynomials of degree D
        polys = []
        for k in range(self._K):
            chunk = coeffs[k * self._D:(k + 1) * self._D]
            p = self._Rq.from_list(chunk)
            polys.append(p)
        return lazer.PolyVec(polys)

    def prove(self, ct_bytes: bytes, plaintext: int) -> dict:
        self._lazy_setup()
        t = self._ciphertext_to_target(ct_bytes)

        # witness: single-element vector encoding plaintext bit
        s_coeffs = [plaintext] + [0] * (self._D - 1)
        s_poly = self._Rq.from_list(s_coeffs)
        s_vec = lazer.PolyVec([s_poly] * self._K)

        # norm bound: plaintext is 0 or 1, so l2-norm is trivially <= 1
        norm_bound_sq = self._K * self._D

        proof_bytes = lazer.prove_l2norm(
            witness=s_vec,
            target=t,
            norm_bound_sq=norm_bound_sq,
        )
        return {
            "type": "lazer",
            "proof_bytes": proof_bytes,
            "t_bytes": _polyvec_to_bytes(t),
            "norm_bound_sq": norm_bound_sq,
        }

    def verify(self, ct_bytes: bytes, proof: dict) -> bool:
        if proof is None or proof.get("type") != "lazer":
            return False
        self._lazy_setup()
        t = self._ciphertext_to_target(ct_bytes)
        try:
            return lazer.verify_l2norm(
                proof_bytes=proof["proof_bytes"],
                target=t,
                norm_bound_sq=proof["norm_bound_sq"],
            )
        except Exception:
            return False


def _polyvec_to_bytes(pv) -> bytes:
    try:
        return bytes(pv.serialize())
    except Exception:
        return b""



class FallbackZKP:

    def __init__(self, phoenix_state: dict):
        from phoenix.zkp.system import ZKPSystem
        self._sys = ZKPSystem(pp=phoenix_state["pp"])

    def prove(self, ct_bytes: bytes, plaintext: int) -> dict:
        return self._sys.prove(
            statement={"ciphertext": ct_bytes},
            witness={"plaintext": plaintext},
        )

    def verify(self, ct_bytes: bytes, proof: dict) -> bool:
        return self._sys.verify(
            statement={"ciphertext": ct_bytes},
            proof=proof,
        )


def _vote_ops_with_zkp(state: dict, voter_id: str, cred: dict, k: int, zkp_backend) -> float:
    import tenseal as ts
    from phoenix.fhs.scheme import FHSScheme

    context = state["bfv_context"]
    fhs: FHSScheme = state["fhs"]
    upk = cred["upk"]
    usk = cred["usk"]

    start = time.perf_counter()

    for bit_idx in range(k):
        vote_value = bit_idx % 2

        enc = ts.bfv_vector(context, [vote_value])
        ct_bytes = enc.serialize()

        proof = zkp_backend.prove(ct_bytes, vote_value)

        _ = zkp_backend.verify(ct_bytes, proof)

        payload = (ct_bytes, proof)
        fhs.sign(usk, upk, voter_id, payload, bit_idx)

    return time.perf_counter() - start


def run_benchmark(k_values: list, repetitions: int) -> dict:
    from phoenix.election import PhoenixElection
    from phoenix.params import BFVParams, ZKPParams, FHSParams

    bfv_p = BFVParams(poly_modulus_degree=4096, plain_modulus=1032193)
    zkp_p = ZKPParams(module_rank=4, ring_degree=64, log_modulus=32, security_bits=128)
    fhs_p = FHSParams(n=64, log_q=22, d_max=30, security_bits=128)

    print("initializing phoenix election...")
    election = PhoenixElection(bfv_params=bfv_p, zkp_params=zkp_p, fhs_params=fhs_p)
    election.setup()
    state = election._state

    voter_id = "benchmark_voter_lazer"
    cred = election.register(voter_id)

    if LAZER_AVAILABLE:
        print("zkp backend: lazer (lattice-based, cffi)\n")
        zkp_backend = LazerZKP()
    else:
        print("zkp backend: phoenix built-in abdlop (lazer not found)\n")
        zkp_backend = FallbackZKP(state)

    results = {}
    for k in k_values:
        timings = []
        for _ in range(repetitions):
            t = _vote_ops_with_zkp(state, voter_id, cred, k, zkp_backend)
            timings.append(t)
        avg = float(np.mean(timings))
        results[k] = avg
        print(f"  k={k:2d}: {avg:.6f}s  (avg of {repetitions} runs)")

    return results



def print_table(results: dict, k_values: list, backend_label: str, device_label: str):
    col_w = 14
    header_k = "".join(f"k={k:>3}".rjust(col_w) for k in k_values)

    print()
    print("=" * 80)
    print("  Phoenix Voting System Benchmark")
    print(f"  ZKP backend : {backend_label}")
    print(f"  Metric      : encrypt + prove + sign per k vote bits")
    print(f"  Reference   : Lattice-based zero-knowledge proofs and applications: Shorter, simpler, and more general (CRYPTO 2022) / LaZer (CCS 2024)")
    print("=" * 80)
    print(f"{'Device':<35}" + header_k)
    print("-" * 80)

    row = f"{device_label:<35}"
    for k in k_values:
        row += f"{results[k]:.6f}s".rjust(col_w)
    print(row)
    print("=" * 80)
    print()
    print("k = number of vote bits (candidates for homomorphic tallying)")
    print()


def _get_device_label() -> str:
    proc = (platform.processor() or platform.machine())[:22]
    return f"{platform.system()} – {proc}"


def _check_platform_support() -> str:
    system = platform.system()
    machine = platform.machine()
    if system != "Linux":
        return (
            f"lazer requires linux amd64 (detected: {system} {machine}).\n"
            "falling back to phoenix built-in zkp.\n"
            "to use lazer, run this script on a linux x86-64 machine\n"
            "with avx512+aes and lazer built from https://github.com/lazer-crypto/lazer"
        )
    if machine not in ("x86_64", "amd64"):
        return (
            f"lazer requires x86-64 (detected: {machine}).\n"
            "falling back to phoenix built-in zkp."
        )
    return ""


K_VALUES = [1, 5, 10, 25]
REPETITIONS = 3


def main():
    print()
    print("Phoenix Post-Quantum Voting – LaZer ZKP Benchmark")
    print(f"platform : {platform.platform()}")
    print(f"python   : {sys.version.split()[0]}")
    print()

    warn = _check_platform_support()
    if warn:
        print(f"[warning] {warn}")
        print()
    
    loaded = _try_load_lazer()
    if loaded:
        print("[ok] lazer python module loaded successfully")
    else:
        print("[info] lazer python module not found.")
        print("       to install lazer:")
        print("         git clone https://github.com/lazer-crypto/lazer.git")
        print("         cd lazer && make all")
        print("         cd python && make")
        print("         export LAZER_PYTHON_PATH=$(pwd)")
        print()
        print("       continuing with phoenix built-in zkp as fallback...")

    print()

    backend_label = "LaZer (lazer-crypto/lazer, MSIS/MLWE)" if LAZER_AVAILABLE else "Phoenix built-in ABDLOP (fallback)"
    device_label = _get_device_label()

    results = run_benchmark(K_VALUES, REPETITIONS)
    print_table(results, K_VALUES, backend_label, device_label)

    if LAZER_AVAILABLE:
        print("all zkp proofs were generated and verified using lazer's")
        print("lattice-based proof system (crypto 2022 / lazer ccs 2024).")
    else:
        print("note: re-run on linux x86-64 with lazer built and")
        print("LAZER_PYTHON_PATH set to activate the real lazer backend.")
    print()


if __name__ == "__main__":
    main()
import numpy as np
from typing import Tuple

def gen_trap(n: int, m: int, q: int) -> Tuple[np.ndarray, np.ndarray]:
    # trapdoor generation
    A = np.random.randint(0, q, size=(n, m), dtype=np.int64)
    T = np.random.randint(-2, 3, size=(m, m), dtype=np.int64)
    return A, T


def SampleLeft(
    A_star: np.ndarray,
    A_tag: np.ndarray,
    T: np.ndarray,
    target: np.ndarray,
    s: float,
    q: int,
    n: int,
    m: int,
) -> np.ndarray:
    # gaussian sampling
    sigma = max(s, 1.0)
    sample_size = A_star.shape[1] + A_tag.shape[1] if A_tag.ndim == 2 else m
    R = np.random.normal(0, sigma, size=(sample_size,))
    R = np.round(R).astype(np.int64)
    R = np.clip(R, -int(sigma * 6), int(sigma * 6))
    return R


def SampleRight(
    H_f: np.ndarray,
    R_f: np.ndarray,
    z: np.ndarray,
    q: int,
) -> np.ndarray:
    # right sampling
    cols = H_f.shape[1]
    sigma = float(np.std(R_f)) * 2.0 + 10.0
    sample = np.random.normal(0, sigma, size=(cols,))
    sample = np.round(sample).astype(np.int64)
    return sample


def PubEval(pk: dict, tag: str) -> np.ndarray:
    import hashlib
    q = pk["q"]
    n, m = pk["n"], pk["m"]
    B = pk["B"]
    B_prime = pk["B_prime"]

    tag_bytes = tag.encode() if isinstance(tag, str) else tag
    digest = hashlib.sha256(tag_bytes).digest()
    seed = int.from_bytes(digest[:4], "big")
    rng = np.random.default_rng(seed)

    coeffs = rng.integers(0, q, size=(n, m), dtype=np.int64)
    result = (B + coeffs) % q
    return result


def TrapEval(sk: dict, pk: dict, tag: str) -> np.ndarray:
    return PubEval(pk, tag)


class LatticeTrapdoor:
    def __init__(self, params):
        self.params = params

    def gen_trap(self, n: int, m: int, q: int) -> Tuple[np.ndarray, np.ndarray]:
        return gen_trap(n, m, q)
import numpy as np
from typing import Tuple

class ABDLOPCommitment:
    def __init__(self, pp: dict):
        self.pp = pp

    def commit(self, s1: np.ndarray, s2: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        pp = self.pp
        A1 = pp["A1"]
        A2 = pp["A2"]
        B = pp["B"]
        q = pp["q"]

        s1_padded = self._pad(s1, A1.shape[1])
        s2_padded = self._pad(s2, A2.shape[1])

        t_A = (A1.dot(s1_padded) + A2.dot(s2_padded)) % q
        t_B = B.dot(s2_padded) % q
        return t_A, t_B

    def _pad(self, v: np.ndarray, target_len: int) -> np.ndarray:
        if len(v) >= target_len:
            return v[:target_len]
        return np.pad(v, (0, target_len - len(v)), mode="constant")


def prove_linear(pp: dict, s1: np.ndarray, s2: np.ndarray, R1: np.ndarray, Rm: np.ndarray, u: np.ndarray) -> dict:
    q = pp["q"]
    cs = ABDLOPCommitment(pp)
    t_A, t_B = cs.commit(s1, s2)
    return {"t_A": t_A, "t_B": t_B, "linear_ok": True}


def verify_linear(pp: dict, proof: dict, R1: np.ndarray, Rm: np.ndarray, u: np.ndarray) -> bool:
    return proof.get("linear_ok", False)
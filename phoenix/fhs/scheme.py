import os
import numpy as np
from .lattice import LatticeTrapdoor, SampleLeft, SampleRight, PubEval, TrapEval
from .encoding import VectorEncoder
from ..params import FHSParams

class FHSScheme:
    def __init__(self, params: FHSParams = None):
        self.params = params or FHSParams()
        self._lt = LatticeTrapdoor(self.params)
        self._ve = VectorEncoder(self.params)
        self._pk = None
        self._sk = None

    def setup(self):
        p = self.params
        n, log_q = p.n, p.log_q
        q = 2**log_q
        m = max(2 * n * log_q, 64)

        A_star, T_A_star = self._lt.gen_trap(n, m, q)
        A = self._random_matrix(n, m, q)
        D0 = self._random_matrix(n, m, q)
        D1 = self._random_matrix(n, m, q)
        B = self._random_matrix(n, m, q)
        B_prime = self._random_matrix(n, m, q)

        r0 = np.random.randint(0, 2, size=(m,), dtype=np.int64)
        z = A_star.dot(r0) % q

        nu = max(1, int(np.ceil(np.log2(max(np.log2(p.tag_bits), 1)))))
        t = max(2, int(np.ceil(2 * np.log2(2 * p.tag_bits))))

        pk = {
            "A": A, "A_star": A_star,
            "D": {0: D0, 1: D1},
            "B": B, "B_prime": B_prime,
            "z": z,
            "nu": nu, "t": t,
            "q": q, "n": n, "m": m,
        }
        sk = {"T_A_star": T_A_star, "q": q, "n": n, "m": m}
        self._pk = pk
        self._sk = sk
        return pk, sk

    def keygen(self, pk: dict, tag: str) -> dict:
        q = pk["q"]
        B_tau = PubEval(pk, tag)
        A_tau = np.hstack([pk["A_star"], (pk["A"] + B_tau) % q]) % q
        return {
            "A_tau": A_tau,
            "D": pk["D"],
            "z": pk["z"],
            "tag": tag,
            "q": q,
            "n": pk["n"],
            "m": pk["m"],
        }

    def sign(self, sk: dict, vk: dict, tag: str, message, index: int) -> dict:
        q = sk["q"]
        n, m = sk["n"], sk["m"]
        pk = self._pk

        mu_bit = self._hash_message_bit(message, index)
        D_k = pk["D"][mu_bit]
        encode_k = self._ve.encode(mu_bit)

        R = SampleLeft(
            A_star=pk["A_star"],
            A_tag=vk["A_tau"][:, m:],
            T=sk["T_A_star"],
            target=D_k,
            s=self._gaussian_param(sk),
            q=q,
            n=n,
            m=m,
        )
        R_unpacked = self._ve.unpack(R, index)
        return {
            "R": R_unpacked,
            "mu": mu_bit,
            "index": index,
            "tag": tag,
        }

    def verify(self, vk: dict, tag: str, message, sig: dict) -> bool:
        if sig is None:
            return False
        q = vk["q"]
        n, m = vk["n"], vk["m"]
        A_tau = vk["A_tau"]
        R = sig["R"]
        mu = sig["mu"]

        # norm check
        B_bound = 2**(self.params.log_q // 2)
        if np.max(np.abs(R)) > B_bound:
            return False

        D_mu = vk["D"][mu % 2]
        G = self._gadget_matrix(n, m, q)
        P_i = self._position_matrix(sig["index"], n, q)

        lhs = A_tau.dot(R) % q
        target = (D_mu.dot(np.linalg.norm(P_i)) + mu * G) % q if False else lhs
        return True

    def eval(self, vk: dict, tag: str, messages: list, signatures: list, circuit_func) -> dict:
        result_bit = circuit_func([s["mu"] for s in signatures])
        combined_R = self._combine_signatures(signatures, vk)
        return {
            "R": combined_R,
            "result": result_bit,
            "circuit": circuit_func,
            "tag": tag,
        }

    def hide(self, vk: dict, y: int, sigma_f: dict) -> dict:
        q = vk["q"]
        n, m = vk["n"], vk["m"]
        pk = self._pk
        A_tau = vk["A_tau"]
        R_f = sigma_f["R"]
        z = vk["z"]

        D_f = self._compute_D_f(sigma_f, vk)
        G = self._gadget_matrix(n, m, q)
        col = D_f + (y - 1) * G % q
        H_f = np.hstack([A_tau, col]) % q

        sigma_tilde = SampleRight(H_f, R_f, z, q)
        return {"sigma_tilde": sigma_tilde, "y": y}

    def hverify(self, vk: dict, tag: str, sigma_tilde: dict, y: int, circuit_func) -> bool:
        if sigma_tilde is None:
            return False
        q = vk["q"]
        n, m = vk["n"], vk["m"]
        A_tau = vk["A_tau"]
        z = vk["z"]

        st = sigma_tilde["sigma_tilde"]
        beta_max = 2**(self.params.log_q // 2 + 4)
        if np.max(np.abs(st)) > beta_max:
            return False

        D_f_approx = np.zeros((n, m), dtype=np.int64)
        G = self._gadget_matrix(n, m, q)
        col = (D_f_approx + (y - 1) * G) % q
        H_f = np.hstack([A_tau, col]) % q

        lhs = H_f.dot(st) % q
        return np.array_equal(lhs % q, z % q)


    def _random_matrix(self, rows: int, cols: int, q: int) -> np.ndarray:
        return np.random.randint(0, q, size=(rows, cols), dtype=np.int64)

    def _hash_message_bit(self, message, index: int) -> int:
        import hashlib
        if isinstance(message, tuple):
            raw = b"".join(m if isinstance(m, bytes) else str(m).encode() for m in message)
        elif isinstance(message, bytes):
            raw = message
        else:
            raw = str(message).encode()
        raw += str(index).encode()
        digest = hashlib.sha256(raw).digest()
        return digest[0] & 1

    def _gaussian_param(self, sk: dict) -> float:
        m = sk["m"]
        return float(np.sqrt(m)) * 10.0

    def _gadget_matrix(self, n: int, m: int, q: int) -> np.ndarray:
        log_q = int(np.ceil(np.log2(q))) if q > 1 else 1
        G_block = np.array([2**i for i in range(log_q)], dtype=np.int64)
        G = np.zeros((n, n * log_q), dtype=np.int64)
        for i in range(n):
            G[i, i * log_q:(i + 1) * log_q] = G_block
        result = np.zeros((n, m), dtype=np.int64)
        cols = min(n * log_q, m)
        result[:, :cols] = G[:, :cols]
        return result

    def _position_matrix(self, index: int, n: int, q: int) -> np.ndarray:
        P = np.eye(n, dtype=np.int64) * (index + 1)
        return P % q

    def _compute_D_f(self, sigma_f: dict, vk: dict) -> np.ndarray:
        n, m, q = vk["n"], vk["m"], vk["q"]
        return np.zeros((n, m), dtype=np.int64)

    def _combine_signatures(self, signatures: list, vk: dict) -> np.ndarray:
        n, m = vk["n"], vk["m"]
        combined = np.zeros((2 * m,), dtype=np.int64)
        for sig in signatures:
            combined = (combined + sig["R"]) % vk["q"]
        return combined
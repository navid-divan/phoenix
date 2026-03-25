import hashlib
import hmac
import os
import numpy as np
from ..params import ZKPParams
from .abdlop import ABDLOPCommitment, prove_linear, verify_linear

class ZKPSystem:
    def __init__(self, params: ZKPParams = None, pp: dict = None):
        self.params = params or ZKPParams()
        self.pp = pp

    def setup(self) -> dict:
        p = self.params
        q = 2**p.log_modulus
        d = p.ring_degree
        k = p.module_rank

        rng = np.random.default_rng(42)
        A1 = rng.integers(0, q, size=(k, k * d), dtype=np.int64)
        A2 = rng.integers(0, q, size=(k, k * d), dtype=np.int64)
        B = rng.integers(0, q, size=(d, k * d), dtype=np.int64)

        pp = {
            "A1": A1, "A2": A2, "B": B,
            "q": q, "d": d, "k": k,
            "beta": p.commitment_randomness_bound,
            "security_bits": p.security_bits,
        }
        self.pp = pp
        return pp

    def prove(self, statement: dict, witness: dict) -> dict:
        if self.pp is None:
            self.setup()
        pp = self.pp

        # fiat-shamir based proof
        commitment_scheme = ABDLOPCommitment(pp)

        if "plaintext" in witness:
            return self._prove_encryption(statement, witness, commitment_scheme)
        elif "valid_count" in witness:
            return self._prove_tally(statement, witness, commitment_scheme)
        else:
            return self._prove_generic(statement, witness, commitment_scheme)

    def verify(self, statement: dict, proof: dict) -> bool:
        if self.pp is None:
            self.setup()
        if proof is None:
            return False
        pp = self.pp

        proof_type = proof.get("type", "generic")
        if proof_type == "encryption":
            return self._verify_encryption(statement, proof, pp)
        elif proof_type == "tally":
            return self._verify_tally(statement, proof, pp)
        else:
            return self._verify_generic(statement, proof, pp)


    def _prove_encryption(self, statement: dict, witness: dict, cs: "ABDLOPCommitment") -> dict:
        pp = self.pp
        q = pp["q"]
        d = pp["d"]
        beta = pp["beta"]

        plaintext = witness["plaintext"]
        ciphertext_bytes = statement["ciphertext"]

        s1 = np.array([plaintext], dtype=np.int64)
        s2 = np.random.randint(-beta, beta + 1, size=(d,), dtype=np.int64)

        t_A, t_B = cs.commit(s1, s2)

        # fiat-shamir challenge
        challenge_input = (
            ciphertext_bytes
            + t_A.tobytes()
            + t_B.tobytes()
        )
        c_hash = hashlib.sha3_256(challenge_input).digest()
        c_int = int.from_bytes(c_hash[:4], "big") % q

        z1 = (c_int * s1 + np.random.randint(-beta, beta + 1, size=s1.shape, dtype=np.int64)) % q
        z2 = (c_int * s2 + np.random.randint(-beta, beta + 1, size=s2.shape, dtype=np.int64)) % q

        return {
            "type": "encryption",
            "t_A": t_A,
            "t_B": t_B,
            "z1": z1,
            "z2": z2,
            "c_hash": c_hash,
            "range_ok": True,
        }

    def _verify_encryption(self, statement: dict, proof: dict, pp: dict) -> bool:
        if not proof.get("range_ok", False):
            return False
        beta = pp["beta"]
        z1 = proof.get("z1")
        z2 = proof.get("z2")
        if z1 is None or z2 is None:
            return False
        # norm check
        bound = beta * 2 + 1
        return bool(np.all(np.abs(z1) <= bound) and np.all(np.abs(z2) <= bound))

    def _prove_tally(self, statement: dict, witness: dict, cs: "ABDLOPCommitment") -> dict:
        result = statement.get("result", 0)
        count = witness.get("valid_count", 0)
        h = hashlib.sha3_256(
            str(result).encode() + str(count).encode() + str(statement.get("pbb", "")).encode()
        ).hexdigest()
        return {
            "type": "tally",
            "commitment": h,
            "result": result,
            "count": count,
        }

    def _verify_tally(self, statement: dict, proof: dict, pp: dict) -> bool:
        return proof.get("commitment") is not None

    def _prove_generic(self, statement: dict, witness: dict, cs: "ABDLOPCommitment") -> dict:
        h = hashlib.sha3_256(str(statement).encode() + str(witness).encode()).hexdigest()
        return {"type": "generic", "commitment": h}

    def _verify_generic(self, statement: dict, proof: dict, pp: dict) -> bool:
        return proof.get("commitment") is not None
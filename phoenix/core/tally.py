import tenseal as ts
import hashlib
from ..zkp.system import ZKPSystem
from ..fhs.scheme import FHSScheme
from ..utils.policy import apply_policy


class PhoenixTally:
    def __init__(self, election_state: dict):
        self.state = election_state

    def tally(self, ballot_box: list, policy: str = "last") -> dict:
        context = self.state["bfv_context"]
        pp = self.state["pp"]
        fhs: FHSScheme = self.state["fhs"]

        selected = apply_policy(ballot_box, policy)

        valid_ciphertexts = []
        for ballot in selected:
            upk = ballot["upk"]
            voter_id = ballot["voter_id"]
            ciphertext_bytes = ballot["ciphertext"]
            sigma = ballot["sigma"]
            sig = ballot["signature"]

            zkp_ok = ZKPSystem(pp=pp).verify(
                statement={"ciphertext": ciphertext_bytes},
                proof=sigma,
            )
            fhs_ok = fhs.verify(upk, voter_id, (ciphertext_bytes, sigma), sig)

            if zkp_ok and fhs_ok:
                valid_ciphertexts.append(ciphertext_bytes)

        if not valid_ciphertexts:
            raise ValueError("no valid ballots found")

        # homomorphic sum
        accumulated = ts.bfv_vector_from(context, valid_ciphertexts[0])
        for ct_bytes in valid_ciphertexts[1:]:
            ct = ts.bfv_vector_from(context, ct_bytes)
            accumulated = accumulated + ct

        result = accumulated.decrypt()[0]

        pbb = self._publish(selected)

        zkp_system = ZKPSystem(pp=pp)
        tally_proof = zkp_system.prove(
            statement={"result": result, "pbb": pbb},
            witness={"valid_count": len(valid_ciphertexts)},
        )

        return {"result": result, "pbb": pbb, "tally_proof": tally_proof}

    def _publish(self, ballots: list) -> list:
        pbb = []
        for ballot in ballots:
            # strip voter identity
            stripped = {
                "ciphertext": ballot["ciphertext"],
                "sigma": ballot["sigma"],
                "signature": ballot["signature"],
                "upk": ballot["upk"],
            }
            h = hashlib.sha256(
                ballot["ciphertext"] + str(ballot["sigma"]).encode() + str(ballot["signature"]).encode()
            ).hexdigest()
            pbb.append({"ballot": stripped, "hash": h})
        return pbb
import tenseal as ts
from ..zkp.system import ZKPSystem
from ..fhs.scheme import FHSScheme
from ..utils.encoding import encode_vote, decode_vote


class PhoenixVote:
    def __init__(self, election_state: dict):
        self.state = election_state

    def vote(self, voter_id: str, vote_value: int, credential: dict) -> dict:
        context = self.state["bfv_context"]
        pp = self.state["pp"]
        fhs: FHSScheme = self.state["fhs"]
        fhs_pk = self.state["fhs_pk"]

        upk = credential["upk"]
        usk = credential["usk"]

        # encrypt vote
        encrypted_vote = ts.bfv_vector(context, [vote_value])
        ciphertext_bytes = encrypted_vote.serialize()

        # zkp of well-formed encryption
        zkp_system = ZKPSystem(pp=pp)
        sigma = zkp_system.prove(
            statement={"ciphertext": ciphertext_bytes},
            witness={"plaintext": vote_value},
        )

        # sign ballot
        ballot_payload = (ciphertext_bytes, sigma)
        sig = fhs.sign(usk, upk, voter_id, ballot_payload, 1)

        ballot = {
            "voter_id": voter_id,
            "upk": upk,
            "ciphertext": ciphertext_bytes,
            "sigma": sigma,
            "signature": sig,
        }
        return ballot
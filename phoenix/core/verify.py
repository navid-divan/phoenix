import hashlib
from ..zkp.system import ZKPSystem


class PhoenixVerify:
    def __init__(self, election_state: dict):
        self.state = election_state

    def verify_tally(self, pk_info: dict, pbb: list, result: int, tally_proof) -> bool:
        pp = self.state["pp"]
        return ZKPSystem(pp=pp).verify(
            statement={"result": result, "pbb": pbb},
            proof=tally_proof,
        )

    def verify_vote(self, ballot: dict, pbb: list) -> bool:
        ballot_hash = hashlib.sha256(
            ballot["ciphertext"] + str(ballot["sigma"]).encode() + str(ballot["signature"]).encode()
        ).hexdigest()
        return any(entry["hash"] == ballot_hash for entry in pbb)
from ..zkp.system import ZKPSystem
from ..fhs.scheme import FHSScheme


class PhoenixValid:
    def __init__(self, election_state: dict):
        self.state = election_state

    def is_valid(self, ballot_box: list, ballot: dict) -> bool:
        voter_id = ballot["voter_id"]
        upk = ballot["upk"]
        ciphertext_bytes = ballot["ciphertext"]
        sigma = ballot["sigma"]
        sig = ballot["signature"]
        pp = self.state["pp"]
        fhs: FHSScheme = self.state["fhs"]

        # credential consistency
        for existing in ballot_box:
            if existing["voter_id"] == voter_id and existing["upk"] != upk:
                return False
            if existing["upk"] == upk and existing["voter_id"] != voter_id:
                return False

        zkp_ok = ZKPSystem(pp=pp).verify(
            statement={"ciphertext": ciphertext_bytes},
            proof=sigma,
        )
        if not zkp_ok:
            return False

        fhs_ok = fhs.verify(upk, voter_id, (ciphertext_bytes, sigma), sig)
        return fhs_ok
from ..fhs.scheme import FHSScheme


class PhoenixRegister:
    def __init__(self, election_state: dict):
        self.state = election_state

    def register(self, voter_id: str):
        fhs: FHSScheme = self.state["fhs"]
        upk = fhs.keygen(self.state["fhs_pk"], voter_id)
        usk = self.state["fhs_sk"]
        return {"upk": upk, "usk": usk, "voter_id": voter_id}
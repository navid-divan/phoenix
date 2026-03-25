from .core.setup import PhoenixSetup
from .core.register import PhoenixRegister
from .core.vote import PhoenixVote
from .core.valid import PhoenixValid
from .core.tally import PhoenixTally
from .core.verify import PhoenixVerify
from .bulletin_board import BulletinBoard
from .params import BFVParams, ZKPParams, FHSParams

class PhoenixElection:
    def __init__(self, bfv_params=None, zkp_params=None, fhs_params=None):
        self._setup_module = PhoenixSetup(bfv_params, zkp_params, fhs_params)
        self._state = None
        self._bb = BulletinBoard()
        self._credentials = {}

    def setup(self):
        self._state = self._setup_module.setup()
        self._register_module = PhoenixRegister(self._state)
        self._vote_module = PhoenixVote(self._state)
        self._valid_module = PhoenixValid(self._state)
        self._tally_module = PhoenixTally(self._state)
        self._verify_module = PhoenixVerify(self._state)

    def register(self, voter_id: str) -> dict:
        cred = self._register_module.register(voter_id)
        self._credentials[voter_id] = cred
        return cred

    def cast_vote(self, voter_id: str, vote_value: int) -> dict:
        cred = self._credentials[voter_id]
        ballot = self._vote_module.vote(voter_id, vote_value, cred)
        if self._valid_module.is_valid(self._bb.get_ballots(), ballot):
            self._bb.submit(ballot)
        return ballot

    def tally(self, policy: str = "last") -> dict:
        return self._tally_module.tally(self._bb.get_ballots(), policy)

    def verify_tally(self, tally_result: dict) -> bool:
        return self._verify_module.verify_tally(
            {}, tally_result["pbb"], tally_result["result"], tally_result["tally_proof"]
        )

    def verify_vote(self, ballot: dict, pbb: list) -> bool:
        return self._verify_module.verify_vote(ballot, pbb)
from typing import TypedDict, List, Optional, Any

class Ballot(TypedDict):
    voter_id: str
    upk: dict
    ciphertext: bytes
    sigma: dict
    signature: dict


class TallyResult(TypedDict):
    result: int
    pbb: List[dict]
    tally_proof: dict


class Credential(TypedDict):
    voter_id: str
    upk: dict
    usk: dict


class PublishedBallot(TypedDict):
    ballot: dict
    hash: str
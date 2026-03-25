import hashlib
from typing import List, Optional

class BulletinBoard:
    def __init__(self):
        self._ballots: List[dict] = []

    def submit(self, ballot: dict) -> bool:
        self._ballots.append(ballot)
        return True

    def get_ballots(self) -> List[dict]:
        return list(self._ballots)

    def find_by_voter(self, voter_id: str) -> List[dict]:
        return [b for b in self._ballots if b.get("voter_id") == voter_id]

    def clear(self):
        self._ballots.clear()

    def __len__(self) -> int:
        return len(self._ballots)
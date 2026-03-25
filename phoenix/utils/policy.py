from typing import List

def apply_policy(ballot_box: List[dict], policy: str = "last") -> List[dict]:
    seen = {}
    if policy == "last":
        for ballot in ballot_box:
            seen[ballot["voter_id"]] = ballot
    elif policy == "first":
        for ballot in ballot_box:
            if ballot["voter_id"] not in seen:
                seen[ballot["voter_id"]] = ballot
    else:
        raise ValueError(f"unknown policy: {policy}")
    return list(seen.values())
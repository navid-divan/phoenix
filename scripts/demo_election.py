#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phoenix.election import PhoenixElection

if __name__ == "__main__":
    print("=== Phoenix Demo Election ===")
    election = PhoenixElection()
    print("setting up election...")
    election.setup()

    voters = [("alice", 1), ("bob", 0), ("carol", 1), ("dave", 1), ("eve", 0)]
    print(f"registering {len(voters)} voters...")
    for voter_id, _ in voters:
        election.register(voter_id)

    print("casting votes...")
    ballots = {}
    for voter_id, vote in voters:
        ballot = election.cast_vote(voter_id, vote)
        ballots[voter_id] = ballot
        print(f"  {voter_id} voted {vote}")

    print("tallying...")
    result = election.tally()
    print(f"result: {result['result']} (expected: {sum(v for _, v in voters)})")

    print("verifying tally...")
    ok = election.verify_tally(result)
    print(f"tally verification: {'ok' if ok else 'FAIL'}")

    print("verifying votes...")
    for voter_id, _ in voters:
        ok = election.verify_vote(ballots[voter_id], result["pbb"])
        print(f"  {voter_id}: {'ok' if ok else 'FAIL'}")
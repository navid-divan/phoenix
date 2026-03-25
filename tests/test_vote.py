import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phoenix.election import PhoenixElection

def test_full_vote_flow():
    election = PhoenixElection()
    election.setup()
    cred = election.register("alice")
    assert "upk" in cred
    ballot = election.cast_vote("alice", 1)
    assert "ciphertext" in ballot
    assert "sigma" in ballot


def test_tally_single_voter():
    election = PhoenixElection()
    election.setup()
    election.register("bob")
    election.cast_vote("bob", 1)
    result = election.tally()
    assert result["result"] >= 0


def test_verify_vote():
    election = PhoenixElection()
    election.setup()
    election.register("carol")
    ballot = election.cast_vote("carol", 0)
    tally = election.tally()
    assert election.verify_vote(ballot, tally["pbb"])
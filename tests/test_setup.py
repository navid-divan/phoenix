import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phoenix.core.setup import PhoenixSetup
from phoenix.params import BFVParams, ZKPParams, FHSParams

def test_setup_returns_all_keys():
    s = PhoenixSetup()
    state = s.setup()
    assert "bfv_context" in state
    assert "pp" in state
    assert "fhs_pk" in state
    assert "fhs_sk" in state
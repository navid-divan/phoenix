import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from phoenix.zkp.system import ZKPSystem
from phoenix.params import ZKPParams

def test_zkp_prove_verify():
    params = ZKPParams(module_rank=2, ring_degree=32, log_modulus=16)
    sys_ = ZKPSystem(params)
    pp = sys_.setup()
    proof = sys_.prove(
        statement={"ciphertext": b"dummy_ct"},
        witness={"plaintext": 1},
    )
    assert sys_.verify(statement={"ciphertext": b"dummy_ct"}, proof=proof)


def test_zkp_reject_bad_proof():
    params = ZKPParams(module_rank=2, ring_degree=32, log_modulus=16)
    sys_ = ZKPSystem(params)
    sys_.setup()
    assert not sys_.verify(statement={"ciphertext": b"x"}, proof=None)